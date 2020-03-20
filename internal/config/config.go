package config

import (
	"github.com/spf13/viper"
)

var (
	Logging loggingConfig
	DB      databaseConfig
	Ksm     ksmConfig
	Sync    syncConfig
)

type configuration struct {
	Logging  loggingConfig
	Database databaseConfig
	Ksm      ksmConfig
	Sync     syncConfig
}

type loggingConfig struct {
	Path  string
	Level string
}

type databaseConfig struct {
	Host               string
	Port               string
	Name               string
	Username           string
	Password           string
	MaxIdleConnections int `mapstructure:"max_idle_connections"`
	MaxOpenConnections int `mapstructure:"max_open_connections"`
}

type ksmConfig struct {
	Urls []string
}

type syncConfig struct {
	Pool              []string
	AllowedSyncPool   []string
	Interval          int32
	ReSyncTimeout     int32
	ReSyncIpAddresses []string
	OldLimit          int32
	FastLevel         int32
	SecureLevel       int32
	DefaultLevel      int32
	DefaultTimeout    int32
}

func Load() {
	var conf *configuration
	err := viper.Unmarshal(&conf)
	if err != nil {
		panic(err)
	}

	Logging = conf.Logging
	DB = conf.Database
	Ksm = conf.Ksm
	Sync = conf.Sync
}
