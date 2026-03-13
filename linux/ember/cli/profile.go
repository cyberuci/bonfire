package cli

import (
	"time"

	"bonfire/ember/core"
	"github.com/desertbit/grumble"
	"github.com/rs/zerolog/log"
)

func (a *App) registerProfileCommand() {
	a.AddCommand(&grumble.Command{
		Name:    "profile",
		Aliases: []string{"pr"},
		Help:    "attempts to detect OS and hostnames for all discovered hosts via RDP/SSH",
		Args: func(a *grumble.Args) {
			a.Int("timeout", "Timeout in seconds per host", grumble.Default(2))
		},
		Run: func(c *grumble.Context) error {
			timeoutSec := c.Args.Int("timeout")
			timeout := time.Duration(timeoutSec) * time.Second

			log.Info().Msgf("Profiling hosts for hostnames and OS (timeout: %s)...", timeout)

			if len(a.hosts) == 0 {
				log.Info().Msg("No hosts to profile.")
				return nil
			}

			core.ProfileHosts(a.ctx, a.hosts, timeout)

			if err := core.SaveHosts(a.hosts); err != nil {
				log.Error().Err(err).Msg("Error saving hosts")
			} else {
				log.Info().Msg("Changes saved to config.")
			}

			return nil
		},
	})
}
