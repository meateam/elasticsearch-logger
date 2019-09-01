module github.com/meateam/elasticsearch-logger

go 1.12

require (
	github.com/elastic/go-sysinfo v1.1.0 // indirect
	github.com/elastic/go-windows v1.0.1 // indirect
	github.com/golang/protobuf v1.3.1
	github.com/google/go-cmp v0.3.1 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.0
	github.com/meateam/elogrus/v4 v4.0.2
	github.com/olivere/elastic/v7 v7.0.0
	github.com/prometheus/procfs v0.0.4 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/viper v1.3.2
	github.com/stretchr/testify v1.4.0 // indirect
	go.elastic.co/apm v1.5.0
	go.elastic.co/apm/module/apmgrpc v1.5.0
	go.elastic.co/apm/module/apmhttp v1.5.0
	golang.org/x/sys v0.0.0-20190830142957-1e83adbbebd0 // indirect
	google.golang.org/grpc v1.21.0
)

replace git.apache.org/thrift.git => github.com/apache/thrift v0.12.0
