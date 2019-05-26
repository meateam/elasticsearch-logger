/*
Package logger is used to log all intercepted unary and stream calls.
The package exports the `NewLogger` function which sets up a logger with
the elogrus hook and returns it.

The logger can be configured using environment variables:

LOG_LEVEL (default: "error") - Defines the log level of the logger, possible values:
	"panic", "fatal", "error", "warn", "warning", "info", "debug", "trace"

LOG_INDEX (default: "log") - Defines the index to which the logs would be indexed to,
the logs would be indexed to index pattern LOG_INDEX-*,
where * is the current day's date in the format 'YYYY.MM.DD'

ELASTICSEARCH_URL (default: http://localhost:9200) - Defines the url of the elasticsearch server to index the logs to.

HOST_NAME (default: executable name) - Defines the host name of the server that is using the logger, which will
be logged under 'Host' field.

There's the `ElasticsearchLoggerServerInterceptor` function which sets up a `grpc.ServerOption`
to intercept streams and unary calls with `*logrus.Entry` of the logger, created with `NewLogger`,
and the options given to it. Returns the `grpc.ServerOption` which will be used in `grpc.NewServer`
to log all incoming stream and unary calls. It also sets up the APM agent's unary server interceptor
to log metrics to elastic APM.

The function `ExtractTraceParent` gets a `context.Context` which holds the "Elastic-Apm-Traceparent",
which is the HTTP header for trace propagation, and returns the trace id.
*/
package logger
