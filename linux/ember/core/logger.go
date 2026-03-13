package core

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func InitLogger() {

	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
	}

	logFile, err := os.OpenFile("ember.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err == nil {
		fileWriter := zerolog.ConsoleWriter{
			Out:        logFile,
			NoColor:    true,
			TimeFormat: time.RFC3339,
		}
		multi := zerolog.MultiLevelWriter(consoleWriter, fileWriter)
		log.Logger = zerolog.New(multi).With().Timestamp().Logger()
	} else {
		log.Logger = zerolog.New(consoleWriter).With().Timestamp().Logger()
		log.Error().Msgf("Failed to open log file, using ONLY console logger: %v", err)
	}
}
