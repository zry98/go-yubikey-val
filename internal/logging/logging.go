package logging

import (
	"github.com/sirupsen/logrus"
	"go-yubikey-val/internal/config"
	"os"
	"path"
)

var File *os.File

func Setup(commandName string) {
	LogFile, err := os.OpenFile(path.Join(config.Logging.Path, commandName+".log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		panic(err)
	}
	logrus.SetOutput(LogFile)

	switch config.Logging.Level {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "warn":
		logrus.SetLevel(logrus.WarnLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	case "fatal":
		logrus.SetLevel(logrus.FatalLevel)
	case "panic":
		logrus.SetLevel(logrus.PanicLevel)
	default:
		logrus.SetLevel(logrus.PanicLevel)
	}
}
