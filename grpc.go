package logger

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/meateam/elogrus/v4"
	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmgrpc"
	"go.elastic.co/apm/module/apmhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// DeciderFunc is a function type to decide whether to create a log for fullMethodName.
type DeciderFunc func(fullMethodName string) bool

// JSONPbMarshaller is a struct used to marshal a protobuf message to JSON.
type JSONPbMarshaller struct {
	proto.Message
}

// MarshalJSON marshals a protobuf message to JSON.
func (j *JSONPbMarshaller) MarshalJSON() ([]byte, error) {
	b := &bytes.Buffer{}
	if err := grpc_logrus.JsonPbMarshaller.Marshal(b, j.Message); err != nil {
		return nil, fmt.Errorf("jsonpb serializer failed: %v", err)
	}

	return b.Bytes(), nil
}

// NewLogger creates a `*logrus.Logger` with `elogrus` hook,
// which logs to elasticsearch, and returns it.
func NewLogger() *logrus.Logger {
	logLevel, err := logrus.ParseLevel(viper.GetString(configLogLevel))
	if err != nil {
		logLevel = logrus.ErrorLevel
	}

	log := logrus.New()
	log.SetLevel(logLevel)
	log.SetFormatter(&logrus.JSONFormatter{})

	elasticURL := viper.GetString(configElasticsearchURL)
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: viper.GetBool(configTLSSkipVerify), // ignore expired SSL certificates
		},
	}
	httpClient := &http.Client{Transport: transCfg}

	elasticOpts := []elastic.ClientOptionFunc{
		elastic.SetURL(strings.Split(elasticURL, ",")...),
		elastic.SetSniff(viper.GetBool(configElasticsearchSniff)),
		elastic.SetHttpClient(httpClient),
	}

	elasticUser := viper.GetString(configElasticsearchUser)
	elasticPassword := viper.GetString(configElasticsearchPassword)
	if elasticUser != "" && elasticPassword != "" {
		elasticOpts = append(elasticOpts, elastic.SetBasicAuth(elasticUser, elasticPassword))
	}

	elasticClient, err := elastic.NewClient(elasticOpts...)
	if err != nil {
		log.Error(err)
		return log
	}

	logIndex := strings.ToLower(viper.GetString(configLogIndex))
	hostName := viper.GetString(configHostName)
	elasticsearchHook, err := elogrus.NewElasticHookWithFunc(elasticClient, hostName, logLevel, func() string {
		year, month, day := time.Now().Date()
		return fmt.Sprintf("%s-%04d.%02d.%02d", logIndex, year, month, day)
	})
	if err != nil {
		log.Error(err)
		return log
	}

	// Add elasticsearch log hook.
	log.Hooks.Add(elasticsearchHook)
	return log
}

// ElasticsearchLoggerServerInterceptor sets up a `grpc.ServerOption` to intercept streams with
// `*logrus.Entry` of the logger, created with `NewLogger`, and the options given to it.
// Returns the `grpc.ServerOption` which will be used in `grpc.NewServer`
// to log all incoming calls.
func ElasticsearchLoggerServerInterceptor(
	logrusEntry *logrus.Entry,
	serverPayloadLoggingDecider DeciderFunc,
	extractInitialRequestDecider DeciderFunc,
	opts ...grpc_logrus.Option,
) []grpc.ServerOption {
	// Server stream interceptor set up for logging incoming initial requests,
	// and outgoing responses. Make sure we put the `grpc_ctxtags`
	// context before everything else.
	grpcStreamLoggingInterceptor := grpc_middleware.WithStreamServerChain(
		// Log incoming initial requests.
		grpc_ctxtags.StreamServerInterceptor(
			grpc_ctxtags.WithFieldExtractorForInitialReq(
				RequestExtractor(logrusEntry, extractInitialRequestDecider),
			),
		),
		// Add the "trace.id" from the stream's context to the logrus entry.
		addTraceIDToStreamContext(logrusEntry, opts...),
		// Log payload of stream requests.
		grpc_logrus.PayloadStreamServerInterceptor(
			logrusEntry,
			func(ctx context.Context, fullMethodName string, servingObject interface{}) bool { // Wrap decider.
				return serverPayloadLoggingDecider(fullMethodName)
			},
		),
	)

	serverUnaryOptions := []apmgrpc.ServerOption{apmgrpc.WithRecovery(), apmgrpc.WithServerRequestIgnorer(defaultUnaryServerRequestIgnorer())}

	// Server unary interceptor set up for logging incoming requests,
	// and outgoing responses. Make sure we put the `grpc_ctxtags`
	// context before everything else.
	grpcUnaryLoggingInterceptor := grpc_middleware.WithUnaryServerChain(
		// Elastic APM agent unary server interceptor for logging metrics to APM.
		apmgrpc.NewUnaryServerInterceptor(serverUnaryOptions...),
		// Add the "trace.id" from the stream's context.
		addTraceIDToUnaryContext(logrusEntry, opts...),
		// Log payload of unrary requests.
		grpc_logrus.PayloadUnaryServerInterceptor(
			logrusEntry,
			func(ctx context.Context, fullMethodName string, servingObject interface{}) bool { // Wrap decider.
				return serverPayloadLoggingDecider(fullMethodName)
			},
		),
	)

	return []grpc.ServerOption{grpcUnaryLoggingInterceptor, grpcStreamLoggingInterceptor}
}

// ExtractTraceParent gets a `context.Context` which holds the "Elastic-Apm-Traceparent",
// which is the HTTP header for trace propagation, and returns the trace id.
func ExtractTraceParent(ctx context.Context) string {
	// If apmhttp.TraceparentHeader is present in request's headers
	// then parse the trace id and return it.
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get(apmhttp.TraceparentHeader); len(values) == 1 {
			traceCtx, err := apmhttp.ParseTraceparentHeader(values[0])
			if err == nil {
				return traceCtx.Trace.String()
			}
		}
	}

	// If apmhttp.TraceparentHeader is not present then return the created
	// transaction's trace id from its context.
	tx := apm.TransactionFromContext(ctx)
	return tx.TraceContext().Trace.String()
}

// DefaultDecider logs every payload.
func DefaultDecider(string) bool {
	return true
}

// IgnoreServerMethodsDecider ignores logging the payload of method that
// is equal to any string of fullIgnoredMethodNames.
func IgnoreServerMethodsDecider(fullIgnoredMethodNames ...string) DeciderFunc {
	return func(fullMethodName string) bool {
		for _, ignoredMethodName := range fullIgnoredMethodNames {
			if ignoredMethodName == fullMethodName {
				return false
			}
		}
		return true
	}
}

// RequestExtractor extracts the request and logs it as json under the key "grpc.request.content".
// Pass decider function to not extract the requests for certain methods.
func RequestExtractor(entry *logrus.Entry, decider DeciderFunc) grpc_ctxtags.RequestFieldExtractorFunc {
	return func(fullMethod string, pbMsg interface{}) map[string]interface{} {
		if !decider(fullMethod) {
			return nil
		}

		if p, ok := pbMsg.(proto.Message); ok {
			entry.WithField("grpc.request.content", JSONPbMarshaller{p}).
				Info("server request payload logged as grpc.request.content field")
		}

		return nil
	}
}

// addTraceIDToStreamContext extracts the "trace.id" value from the stream's context and adds
// it as a field to logrusEntry.
func addTraceIDToStreamContext(
	logrusEntry *logrus.Entry,
	opts ...grpc_logrus.Option,
) grpc.StreamServerInterceptor {
	return func(srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler) error {
		// Add logrusEntry to the context.
		logCtx := ctxlogrus.ToContext(stream.Context(), logrusEntry)

		// Extract the "trace.id" from the stream's context.
		traceIDFields := logrus.Fields{
			"trace.id": ExtractTraceParent(stream.Context()),
		}

		// Overwrite the logrus entry to always log the "trace.id" field.
		*logrusEntry = *logrusEntry.WithFields(traceIDFields)

		// Add the "trace.id" field to logrusEntry.
		ctxlogrus.AddFields(logCtx, traceIDFields)

		return grpc_logrus.StreamServerInterceptor(
			ctxlogrus.Extract(logCtx),
			opts...,
		)(srv, stream, info, handler)
	}
}

// addTraceIDToUnaryContext extracts the "trace.id" value from the unary call's context and adds
// it as a field to logrusEntry.
func addTraceIDToUnaryContext(
	logrusEntry *logrus.Entry,
	opts ...grpc_logrus.Option,
) grpc.UnaryServerInterceptor {
	return func(ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (resp interface{}, err error) {
		// Add logrusEntry to the context.
		logCtx := ctxlogrus.ToContext(ctx, logrusEntry)

		// Extract the "trace.id" from the unary call's context.
		traceIDFields := logrus.Fields{
			"trace.id": ExtractTraceParent(ctx),
		}

		// Overwrite the logrus entry to always log the "trace.id" field.
		*logrusEntry = *logrusEntry.WithFields(traceIDFields)

		// Add the "trace.id" field to logrusEntry.
		ctxlogrus.AddFields(logCtx, traceIDFields)

		return grpc_logrus.UnaryServerInterceptor(logrusEntry, opts...)(ctx, req, info, handler)
	}
}

func defaultUnaryServerRequestIgnorer() apmgrpc.RequestIgnorerFunc {
	ignoreUrls := viper.GetString(configIgnoreURLs)

	return apmgrpc.NewRegexpRequestIgnorer(regexp.MustCompile(ignoreUrls))
}
