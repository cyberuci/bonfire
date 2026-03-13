package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"bonfire/ember/core"
	"github.com/desertbit/grumble"
	"github.com/rs/zerolog/log"
)

func (a *App) registerBaseCommand() {
	a.AddCommand(&grumble.Command{
		Name: "base",
		Help: "runs initial baseline scripts",
		Args: func(a *grumble.Args) {
			a.String("host", "The host IP or alias to run on (optional, default: all)", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			hostQuery := c.Args.String("host")

			var targets []string
			if hostQuery != "" {
				ip, err := a.hosts.ResolveHost(hostQuery)
				if err != nil {
					return err
				}
				if h := a.hosts[ip]; h.OS != core.OSLinux {
					return fmt.Errorf("[%s] base hardening on %s hosts is not implemented", ip, h.OS)
				}
				targets = []string{ip}
			} else {
				targets = a.hosts.LinuxIPs()
			}

			if len(targets) == 0 {
				log.Warn().Msg("No Linux hosts to run base hardening on.")
				return nil
			}

			log.Info().Msg("--- Checking for iptables ---")
			var iptablesWg sync.WaitGroup
			for _, ip := range targets {
				iptablesWg.Add(1)
				go func(hostIP string) {
					defer iptablesWg.Done()
					if a.ctx.Err() != nil {
						return
					}
					timeout := 2 * time.Second
					code, _, err := a.hosts.RunSSHCommand(a.ctx, hostIP, "command -v iptables", timeout)
					if err != nil {
						if a.ctx.Err() != nil {
							return
						}
						log.Error().Err(err).Msgf("[%s] Failed to check iptables presence", hostIP)
						return
					}
					if code != 0 {
						displayName := hostIP
						if host, ok := a.hosts[hostIP]; ok && host.Alias != "" {
							displayName = host.Alias
						}
						log.Error().Msgf("[%s] iptables is NOT installed (host: %s). Firewall steps may fail or be skipped.", hostIP, displayName)
						return
					}
				}(ip)
			}
			iptablesWg.Wait()

			fwpPath, err := findScript("fwp")
			if err != nil {
				return fmt.Errorf("firewall parser (fwp) not found. Build it with: go build -o scripts/fwp scripts/fw.go")
			}

			steps := []struct {
				Desc   string
				Script string
				Args   []string
			}{
				{"Running PHP hardening", "php.sh", nil},
				{"Running SSH hardening", "ssh.sh", nil},
				{"Backing stuff up", "initial_backup.sh", []string{"/root/initial_backs"}},
				{"Running firewall", "firewall.sh", []string{"apply"}},
				{"Rotating passwords (local script)", "pass.sh", nil},
				{"Running ident", "ident.sh", nil},
			}

			runAcrossHosts := func(scriptName string, args []string, desc string) bool {

				if a.ctx.Err() != nil {
					return true
				}

				log.Info().Msgf("--- %s ---", desc)

				path, err := findScript(scriptName)
				if err != nil {
					log.Error().Err(err).Msgf("Failed to find script '%s'", scriptName)
					return false
				}

				var wg sync.WaitGroup
				for _, ip := range targets {
					wg.Add(1)
					go func(hostIP string) {
						defer wg.Done()

						timeout := 30 * time.Second

						code, out, err := a.hosts.RunScript(a.ctx, hostIP, path, args, true, timeout)
						if err != nil {
							if a.ctx.Err() != nil {
								log.Warn().Msgf("[%s] %s cancelled", hostIP, desc)
								return
							}
							log.Error().Err(err).Msgf("[%s] %s failed", hostIP, desc)
							return
						}
						if code != 0 {
							log.Error().Msgf("[%s] %s returned exit code %d\nOutput:\n%s", hostIP, desc, code, out)
						} else {
							log.Info().Msgf("[%s] %s completed successfully", hostIP, desc)
						}
					}(ip)
				}
				wg.Wait()
				return a.ctx.Err() != nil
			}

			for _, step := range steps {
				if cancelled := runAcrossHosts(step.Script, step.Args, step.Desc); cancelled {
					log.Warn().Msg("Base hardening cancelled.")
					return nil
				}
			}

			if a.ctx.Err() != nil {
				log.Warn().Msg("Base hardening cancelled.")
				return nil
			}
			log.Info().Msg("--- Downloading backup ---")

			var wg sync.WaitGroup
			for _, ip := range targets {
				wg.Add(1)
				go func(hostIP string) {
					defer wg.Done()
					remotePath := "/root/initial_backs"
					hostDir := filepath.Join("downloads", hostIP)

					if err := os.MkdirAll(hostDir, 0755); err != nil {
						log.Error().Err(err).Msgf("[%s] Failed to create download directory", hostIP)
						return
					}

					log.Info().Msgf("[%s] Downloading %s to %s...", hostIP, remotePath, hostDir)
					if err := a.hosts.DownloadDirectory(a.ctx, hostIP, remotePath, hostDir); err != nil {
						if a.ctx.Err() != nil {
							log.Warn().Msgf("[%s] Backup download cancelled", hostIP)
							return
						}
						log.Error().Err(err).Msgf("[%s] Failed to download backup", hostIP)
					} else {
						log.Info().Msgf("[%s] Backup downloaded successfully", hostIP)
					}
				}(ip)
			}
			wg.Wait()

			if a.ctx.Err() != nil {
				log.Warn().Msg("Base hardening cancelled.")
				return nil
			}

			log.Info().Msg("--- Uploading firewall parser ---")
			var fwWg sync.WaitGroup
			for _, ip := range targets {
				fwWg.Add(1)
				go func(hostIP string) {
					defer fwWg.Done()
					if err := a.hosts.UploadFileSFTPWithMode(a.ctx, hostIP, fwpPath, "fwp", 0755); err != nil {
						if a.ctx.Err() != nil {
							log.Warn().Msgf("[%s] Firewall parser upload cancelled", hostIP)
							return
						}
						log.Error().Err(err).Msgf("[%s] Failed to upload firewall parser", hostIP)
					} else {
						log.Info().Msgf("[%s] Firewall parser uploaded", hostIP)
					}
				}(ip)
			}
			fwWg.Wait()

			log.Info().Msg("Base hardening sequence complete.")
			return nil
		},
	})
}
