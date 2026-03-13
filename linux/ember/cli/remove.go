package cli

import (
	"fmt"

	"bonfire/ember/core"
	"github.com/desertbit/grumble"
	"github.com/rs/zerolog/log"
)

func (a *App) registerRemoveCommand() {
	a.AddCommand(&grumble.Command{
		Name:    "remove",
		Help:    "removes scanned hosts",
		Aliases: []string{"rm"},
		Args: func(a *grumble.Args) {
			a.String("host", "The host IP or alias to remove", grumble.Default(""))
		},
		Flags: func(f *grumble.Flags) {
			f.Bool("a", "all", false, "Remove all hosts")
		},
		Run: func(c *grumble.Context) error {
			deleteAll := c.Flags.Bool("all")
			hostQuery := c.Args.String("host")

			if deleteAll {
				a.hosts = make(core.HostMap)
				if err := core.SaveHosts(a.hosts); err != nil {
					return err
				}
				log.Info().Msg("Removed all hosts.")
				return nil
			}

			if hostQuery != "" {
				hostIP, err := a.hosts.ResolveHost(hostQuery)
				if err != nil {
					return err
				}

				delete(a.hosts, hostIP)
				if err := core.SaveHosts(a.hosts); err != nil {
					return err
				}
				log.Info().Msgf("Removed host %s.", hostIP)
				return nil
			}

			return fmt.Errorf("please specify a host to remove or use --all")
		},
	})
}
