package cli

import (
	"fmt"
	"time"

	"bonfire/ember/core"

	"github.com/desertbit/grumble"
	"github.com/rs/zerolog/log"
)

func (a *App) registerAddCommand() {
	a.AddCommand(&grumble.Command{
		Name:    "add",
		Aliases: []string{"a"},
		Help:    "manually add a host (scans and profiles before adding)",
		Args: func(a *grumble.Args) {
			a.String("ip", "The IP address of the host")
			a.String("password", "The password for the host")
			a.String("alias", "An optional alias for the host", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			ip := c.Args.String("ip")
			password := c.Args.String("password")
			alias := c.Args.String("alias")

			log.Info().Msgf("Scanning %s...", ip)

			cidr := ip + "/32"
			ports := commonPorts()

			timeout := uint(2)

			scanResults, err := core.RunTCPScan(a.ctx, cidr, ports, timeout, "root", password)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			hostEntry, found := scanResults[ip]
			if !found || len(hostEntry.Ports) == 0 {
				return fmt.Errorf("host %s not found or no open ports detected", ip)
			}

			log.Info().Msgf("Scan successful. Open ports: %v. Profiling...", hostEntry.Ports)

			core.ProfileHosts(a.ctx, scanResults, 2*time.Second)

			hostEntry = scanResults[ip]

			if alias != "" {
				hostEntry.Alias = alias
			}

			a.hosts[ip] = hostEntry

			if err := core.SaveHosts(a.hosts); err != nil {
				return err
			}

			log.Info().Msgf("Successfully added host %s (OS: %s, Alias: %s)", ip, hostEntry.OS, hostEntry.Alias)
			return nil
		},
	})
}
