package cli

import (
	"strconv"
	"strings"
	"time"

	"bonfire/ember/core"
	"github.com/desertbit/grumble"
	"github.com/rs/zerolog/log"
)

func commonPorts() []uint16 {
	return []uint16{
		22, 3389,
		88, 135, 389, 445, 5985,
		3306, 5432, 27017,
		53, 80, 443, 8080,
	}
}

func (a *App) registerScanCommand() {
	a.AddCommand(&grumble.Command{
		Name: "scan",
		Help: "performs a TCP port scan on the specified subnet to discover hosts",
		Args: func(a *grumble.Args) {
			a.String(ArgSubnet, "The subnet CIDR to scan")
			a.String(ArgPassword, "The password to use for authentication")
			a.Uint(ArgTimeout, "The maximum timeout, in seconds, to wait for a port to accept the connection", grumble.Default(uint(2)))
		},
		Flags: func(f *grumble.Flags) {
			f.Bool("n", "no-profile", false, "Skip OS/Hostname profiling after scan")
		},
		Run: func(c *grumble.Context) error {
			cidrString := c.Args.String(ArgSubnet)
			password := c.Args.String(ArgPassword)

			timeout := c.Args.Uint(ArgTimeout)
			noProfile := c.Flags.Bool("no-profile")
			username := "root"

			ports := commonPorts()
			var portsAsStrings []string
			for _, port := range ports {
				portsAsStrings = append(portsAsStrings, strconv.Itoa(int(port)))
			}

			log.Info().Msgf("rustscan -a %v -g -t %v -p %v", cidrString, timeout*1000, strings.Join(portsAsStrings, ","))

			hostMap, err := core.RunTCPScan(a.ctx, cidrString, ports, timeout, username, password)
			if err != nil {
				log.Warn().Msgf("Failed to run TCP scan: %v", err)
				return nil
			}

			if len(hostMap) == 0 {
				log.Warn().Msg("No open ports found on any hosts.")
			} else {

				for host, h := range hostMap {
					a.hosts[host] = h
				}

				if err := core.SaveHosts(a.hosts); err != nil {
					log.Error().Err(err).Msg("Error saving hosts after scan")
				}

				if !noProfile {
					log.Info().Msg("Profiling discovered hosts...")
					core.ProfileHosts(a.ctx, hostMap, time.Duration(timeout)*time.Second)

					for host, h := range hostMap {
						a.hosts[host] = h
					}

					if err := core.SaveHosts(a.hosts); err != nil {
						log.Error().Err(err).Msg("Error saving hosts after profiling")
					}
				}

				hostMap.Print()
			}
			return nil
		},
	})
}

const (
	ArgSubnet   = "subnet"
	ArgPassword = "password"
	ArgTimeout  = "timeout"
)
