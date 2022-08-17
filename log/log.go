package log

import (
	"github.com/sirupsen/logrus"
)

const (
	TraceLevel Level = 0
	DebugLevel Level = 10
	InfoLevel  Level = 20
	WarnLevel  Level = 30
	ErrorLevel Level = 40
	FatalLevel Level = 50
	OffLevel   Level = 60
)

var (
	CurLevel = DebugLevel

	logger = logrus.WithField("pkg", "kms-sdk")
)

type Level = int

func SetLevel(level Level) {
	CurLevel = level
}

func Debug(a ...interface{}) {
	if CurLevel <= DebugLevel {
		logger.Debug(a...)
	}
}
func Debugf(format string, a ...interface{}) {
	if CurLevel <= DebugLevel {
		logger.Debugf(format, a...)
	}
}
func Info(a ...interface{}) {
	if CurLevel <= InfoLevel {
		logger.Info(a...)
	}
}
func Infof(format string, a ...interface{}) {
	if CurLevel <= InfoLevel {
		logger.Infof(format, a...)
	}
}
func Warn(a ...interface{}) {
	if CurLevel <= WarnLevel {
		logger.Warn(a...)
	}
}
func Warnf(format string, a ...interface{}) {
	if CurLevel <= WarnLevel {
		logger.Warnf(format, a...)
	}
}
func Error(a ...interface{}) {
	if CurLevel <= ErrorLevel {
		logger.Error(a...)
	}
}
func Errorf(format string, a ...interface{}) {
	if CurLevel <= ErrorLevel {
		logger.Errorf(format, a...)
	}
}
