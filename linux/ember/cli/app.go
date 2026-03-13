package cli

import (
	"context"
	"os"
	"os/signal"

	"bonfire/ember/core"

	"github.com/desertbit/grumble"
	"github.com/rs/zerolog/log"
)

type App struct {
	*grumble.App
	hosts  core.HostMap
	ctx    context.Context
	cancel context.CancelFunc
}

func (a *App) SaveHosts() error {
	return core.SaveHosts(a.hosts)
}

func (a *App) AddCommand(cmd *grumble.Command) {
	oldRun := cmd.Run

	cmd.Run = func(c *grumble.Context) error {
		if oldRun == nil {
			return nil
		}
		a.ctx, a.cancel = signal.NotifyContext(context.Background(), os.Interrupt)
		err := oldRun(c)

		a.cancel()
		a.ctx, a.cancel = nil, nil
		return err
	}
	a.App.AddCommand(cmd)
}

func New() *App {
	app := &App{
		App: grumble.New(&grumble.Config{
			Name:        "ember",
			Description: "Ember - Yet another CCDC automation tool",
			HistoryFile: ".ember_history",
		}),
	}

	var err error
	app.hosts, err = core.LoadHosts()
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to load hosts from %s", core.GetConfigPath())
	}
	log.Info().Msgf("Loaded %d hosts from %s", len(app.hosts), core.GetConfigPath())

	app.registerScanCommand()
	app.registerListCommand()
	app.registerEditCommand()
	app.registerShellCommand()
	app.registerProfileCommand()
	app.registerTransferCommands()
	app.registerScriptCommand()
	app.registerRemoveCommand()
	app.registerRotateCommand()
	app.registerPassGenCommand()
	app.registerAddCommand()
	app.registerBaseCommand()

	return app
}
