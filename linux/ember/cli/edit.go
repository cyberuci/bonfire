package cli

import (
	"fmt"
	"slices"
	"strconv"

	"bonfire/ember/core"
	"github.com/desertbit/grumble"
	"github.com/rs/zerolog/log"
)

func (a *App) registerEditCommand() {

	editCmd := &grumble.Command{
		Name:    "edit",
		Aliases: []string{"e"},
		Help:    "edit host details (username, password, alias)",
		Run: func(c *grumble.Context) error {
			return fmt.Errorf("please specify a subcommand (username, password, alias)")
		},
	}

	runEdit := func(c *grumble.Context, update func(*core.Host, string)) error {
		query := c.Args.String("host")
		value := c.Args.String("value")

		hostIP, err := a.hosts.ResolveHost(query)
		if err != nil {
			return err
		}

		entry := a.hosts[hostIP]
		update(&entry, value)
		a.hosts[hostIP] = entry

		log.Info().Msgf("Updated %s (%s)", hostIP, entry.Alias)
		return nil
	}

	editSubcommandArgs := func(a *grumble.Args) {
		a.String("host", "The host IP, alias, or prefix to edit")
		a.String("value", "The new value")
	}

	editCmd.AddCommand(&grumble.Command{
		Name:    "password",
		Aliases: []string{"pass", "p", "pw"},
		Help:    "sets the password credential for a specific host",
		Args:    editSubcommandArgs,
		Run: func(c *grumble.Context) error {
			return runEdit(c, func(h *core.Host, v string) {
				h.Password = v
				h.PasswordIndex = nil
			})
		},
	})

	editCmd.AddCommand(&grumble.Command{
		Name:    "username",
		Aliases: []string{"user", "u"},
		Help:    "sets the username credential for a specific host",
		Args:    editSubcommandArgs,
		Run: func(c *grumble.Context) error {
			return runEdit(c, func(h *core.Host, v string) {
				h.Username = v
			})
		},
	})

	editCmd.AddCommand(&grumble.Command{
		Name:    "alias",
		Aliases: []string{"a"},
		Help:    "sets a friendly alias for a specific host",
		Args:    editSubcommandArgs,
		Run: func(c *grumble.Context) error {
			return runEdit(c, func(h *core.Host, v string) {
				h.Alias = v
			})
		},
	})

	editCmd.AddCommand(&grumble.Command{
		Name:    "index",
		Aliases: []string{"idx"},
		Help:    "sets the password index for a specific host (empty to unset)",
		Args:    editSubcommandArgs,
		Flags: func(f *grumble.Flags) {
			f.String("d", "db", "passwords.db", "Path to the passwords CSV database")
		},
		Run: func(c *grumble.Context) error {
			query := c.Args.String("host")
			value := c.Args.String("value")
			dbPath := c.Flags.String("db")

			hostIP, err := a.hosts.ResolveHost(query)
			if err != nil {
				return err
			}

			entry := a.hosts[hostIP]
			if value == "" {
				entry.PasswordIndex = nil
			} else {
				idx, err := strconv.Atoi(value)
				if err != nil {
					return fmt.Errorf("invalid index %q: must be an integer", value)
				}

				passwords, err := core.LoadPasswords(dbPath)
				if err != nil {
					return fmt.Errorf("failed to load passwords from %s: %w", dbPath, err)
				}

				var foundPass string
				idxFound := slices.IndexFunc(passwords, func(p core.PasswordEntry) bool {
					return p.ID == idx
				})
				if idxFound != -1 {
					foundPass = passwords[idxFound].Password
				}

				if foundPass == "" {
					return fmt.Errorf("index %d not found in %s", idx, dbPath)
				}

				entry.PasswordIndex = &idx
				entry.Password = foundPass
			}
			a.hosts[hostIP] = entry

			if err := core.SaveHosts(a.hosts); err != nil {
				log.Error().Err(err).Msg("Failed to save hosts file")
			}

			log.Info().Msgf("Updated %s (%s)", hostIP, entry.Alias)
			return nil
		},
	})

	a.AddCommand(editCmd)
}
