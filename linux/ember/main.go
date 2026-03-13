package main

import (
	"embed"
	"io/fs"
	"os"

	"bonfire/ember/cli"
	"bonfire/ember/core"
	"github.com/desertbit/grumble"
	"github.com/rs/zerolog/log"
)

//go:embed scripts
var scriptsFS embed.FS

func unpackScripts() {
	if _, err := os.Stat("scripts"); err == nil {
		return
	}

	log.Info().Msg("Unpacking embedded scripts...")

	err := fs.WalkDir(scriptsFS, "scripts", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return os.MkdirAll(path, 0755)
		}

		data, err := scriptsFS.ReadFile(path)
		if err != nil {
			return err
		}

		return os.WriteFile(path, data, 0755)
	})

	if err != nil {
		log.Error().Err(err).Msg("Failed to unpack scripts")
	}
}

func main() {
	core.InitLogger()
	unpackScripts()

	app := cli.New()

	defer func() {
		if err := app.SaveHosts(); err != nil {
			log.Error().Err(err).Msg("Error saving hosts")
		} else {
			log.Info().Msg("Hosts saved to config.")
		}
	}()

	grumble.Main(app.App)
}
