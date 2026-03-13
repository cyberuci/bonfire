package cli

import (
	"fmt"
	"os"
	"syscall"

	"bonfire/ember/core"
	"github.com/desertbit/grumble"
	"github.com/rs/zerolog/log"
	"golang.org/x/term"
)

func (a *App) registerRotateCommand() {
	a.AddCommand(&grumble.Command{
		Name:    "rotate",
		Aliases: []string{"rot"},
		Help:    "rotates root passwords on remote hosts using a password list or static password",
		Args: func(a *grumble.Args) {

			a.String("host", "The host IP or alias to rotate (optional, default: all)", grumble.Default(""))
		},
		Flags: func(f *grumble.Flags) {
			f.String("p", "password", "", "Specify a static password to use for all hosts")
			f.String("d", "db", "passwords.db", "Path to the passwords CSV database")
			f.String("s", "script", "pass_for.sh", "Path to the rotation script")
			f.Int("l", "limit", 30, "Only use the first N passwords from the database (0 = all)")
		},
		Run: func(c *grumble.Context) error {
			hostQuery := c.Args.String("host")
			staticPass := c.Flags.String("password")
			dbPath := c.Flags.String("db")
			scriptName := c.Flags.String("script")
			limit := c.Flags.Int("limit")

			scriptPath, err := findScript(scriptName)
			if err != nil {
				return err
			}
			log.Info().Msgf("Resolved rotation script to: %s", scriptPath)

			var targets []string
			if hostQuery != "" {
				ip, err := a.hosts.ResolveHost(hostQuery)
				if err != nil {
					return err
				}
				if h := a.hosts[ip]; h.OS != core.OSLinux {
					return fmt.Errorf("[%s] password rotation on %s hosts is not implemented", ip, h.OS)
				}
				targets = []string{ip}
			} else {
				targets = a.hosts.LinuxIPs()
			}

			if len(targets) == 0 {
				log.Warn().Msg("No Linux hosts to rotate.")
				return nil
			}

			var passwords []core.PasswordEntry

			if staticPass == "" {

				if _, err := os.Stat(dbPath); os.IsNotExist(err) {
					fmt.Printf("Password database %s not found. Create it? [y/N]: ", dbPath)
					var response string
					fmt.Scanln(&response)
					if response == "y" || response == "Y" {
						fmt.Print("Enter seed: ")
						seed, err := term.ReadPassword(int(syscall.Stdin))
						fmt.Println()
						if err != nil {
							return fmt.Errorf("failed to read seed: %w", err)
						}

						if len(seed) == 0 {
							return fmt.Errorf("seed cannot be empty")
						}

						log.Info().Msg("Generating passwords...")
						genPasswords, err := core.GeneratePasswords(seed, 90)
						if err != nil {
							return err
						}

						if err := core.SavePasswords(dbPath, genPasswords); err != nil {
							return fmt.Errorf("failed to save generated passwords to %s: %w", dbPath, err)
						}
						log.Info().Msgf("Generated and saved %d passwords to %s", len(genPasswords), dbPath)
					}
				}

				var err error
				passwords, err = core.LoadPasswords(dbPath)
				if err != nil {
					return fmt.Errorf("failed to load passwords from %s: %v", dbPath, err)
				}
				if len(passwords) == 0 {
					return fmt.Errorf("no passwords available in %s", dbPath)
				}
				log.Info().Msgf("Loaded %d passwords from %s", len(passwords), dbPath)
			} else {
				log.Info().Msg("Using static password for rotation.")
			}

			successCount := core.RotateHosts(a.ctx, a.hosts, targets, passwords, staticPass, scriptPath, limit)

			if successCount > 0 {
				if err := core.SaveHosts(a.hosts); err != nil {
					log.Error().Err(err).Msg("Failed to save hosts file")
				} else {
					log.Info().Msg("Hosts file updated.")
				}
			}

			return nil
		},
	})
}
