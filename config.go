package logger

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	configLogLevel              = "log_level"
	configLogIndex              = "log_index"
	configElasticsearchURL      = "elasticsearch_url"
	configHostName              = "host_name"
	configElasticsearchUser     = "elasticsearch_user"
	configElasticsearchPassword = "elasticsearch_password"
	configTLSSkipVerify         = "tls_skip_verify"
	configIgnoreURLs            = "elastic_apm_ignore_urls"
	configElasticsearchSniff    = "elasticsearch_sniff"
)

func init() {
	viper.SetDefault(configLogLevel, logrus.ErrorLevel)
	viper.SetDefault(configLogIndex, "log")
	viper.SetDefault(configElasticsearchURL, "http://localhost:9200")
	viper.SetDefault(configElasticsearchUser, "")
	viper.SetDefault(configElasticsearchPassword, "")
	viper.SetDefault(configTLSSkipVerify, true)
	viper.SetDefault(configIgnoreURLs, "")
	viper.SetDefault(configElasticsearchSniff, false)

	hostName := filepath.Base(os.Args[0])
	if runtime.GOOS == "windows" {
		hostName = strings.TrimSuffix(hostName, filepath.Ext(hostName))
	}

	viper.SetDefault(configHostName, hostName)
	viper.AutomaticEnv()
}
