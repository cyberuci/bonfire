package cli

import (
	"fmt"
	"os"
	"slices"
	"syscall"

	"bonfire/ember/core"
	"github.com/desertbit/grumble"
	"github.com/rs/zerolog/log"
	"golang.org/x/term"
)

func (a *App) registerPassGenCommand() {
	a.AddCommand(&grumble.Command{
		Name:    "passgen",
		Help:    "generates a list of passwords using a seed from stdin",
		Aliases: []string{"gen"},
		Flags: func(f *grumble.Flags) {
			f.String("o", "output", "passwords.db", "The output CSV file")
			f.Uint64("c", "count", 90, "Number of passwords to generate")
		},
		Run: func(c *grumble.Context) error {
			outputFile := c.Flags.String("output")
			count := c.Flags.Uint64("count")

			if count == 0 {
				return fmt.Errorf("count cannot be zero")
			}

			if _, err := os.Stat(outputFile); err == nil {
				log.Warn().Msgf("Output file %s already exists. It will be overwritten.", outputFile)
			}

			fmt.Print("Enter seed: ")
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				return fmt.Errorf("failed to read seed: %w", err)
			}

			if len(bytePassword) == 0 {
				return fmt.Errorf("seed cannot be empty")
			}

			log.Info().Msg("Generating passwords...")
			passwords, err := core.GeneratePasswords(bytePassword, count)
			if err != nil {
				return err
			}

			if err := core.SavePasswords(outputFile, passwords); err != nil {
				return fmt.Errorf("failed to save passwords to %s: %w", outputFile, err)
			}

			for ip, host := range a.hosts {
				arrayIdx := slices.IndexFunc(passwords, func(p core.PasswordEntry) bool {
					return p.Password == host.Password
				})
				if arrayIdx != -1 {
					passwordIdx := passwords[arrayIdx].ID
					host.PasswordIndex = &passwordIdx
				} else if host.PasswordIndex != nil {
					log.Warn().Msgf("Cleared PasswordIndex for %s as its password is no longer in the DB.", ip)
					host.PasswordIndex = nil
				}
				a.hosts[ip] = host
			}

			if err := core.SaveHosts(a.hosts); err != nil {
				log.Error().Err(err).Msg("Failed to save updated host indices")
			} else {
				log.Info().Msg("Host indices synchronized with new passwords.")
			}

			log.Info().Msgf("Successfully generated %d passwords to %s", len(passwords), outputFile)
			return nil
		},
	})
}
