package cli

import (
	"github.com/desertbit/grumble"
)

func (a *App) registerListCommand() {
	a.AddCommand(&grumble.Command{
		Name:    "list",
		Aliases: []string{"ls"},
		Help:    "displays a table of all hosts found during previous scans",
		Run: func(c *grumble.Context) error {
			a.hosts.Print()
			return nil
		},
	})
}
