package cli

import (
	"fmt"
	"os"
	"time"

	"bonfire/ember/core"
	"github.com/desertbit/grumble"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func (a *App) registerShellCommand() {
	a.AddCommand(&grumble.Command{
		Name:    "shell",
		Aliases: []string{"sh"},
		Help:    "initiates an interactive SSH session with a target host",
		Args: func(a *grumble.Args) {
			a.String("host", "The host IP, alias, or prefix to connect to")
		},
		Run: func(c *grumble.Context) error {
			query := c.Args.String("host")

			hostIP, err := a.hosts.ResolveHost(query)
			if err != nil {
				return err
			}

			host := a.hosts[hostIP]
			log.Info().Msgf("Connecting to %s (%s) as %s...", hostIP, host.Alias, host.Username)

			client, err := core.ConnectSSHContext(a.ctx, hostIP, host.Username, host.Password, 5*time.Second)
			if err != nil {
				return fmt.Errorf("SSH connection failed: %v", err)
			}
			defer client.Close()

			session, err := client.NewSession()
			if err != nil {
				return fmt.Errorf("failed to create session: %v", err)
			}
			defer session.Close()

			session.Stdout = os.Stdout
			session.Stderr = os.Stderr
			session.Stdin = os.Stdin

			modes := ssh.TerminalModes{
				ssh.ECHO:          1,
				ssh.TTY_OP_ISPEED: 14400,
				ssh.TTY_OP_OSPEED: 14400,
			}

			fd := int(os.Stdin.Fd())

			width, height, err := term.GetSize(fd)
			if err != nil {

				width, height = 80, 24
			}

			termType := os.Getenv("TERM")
			if termType == "" {
				termType = "xterm-256color"
			}

			if err := session.RequestPty(termType, height, width, modes); err != nil {
				return fmt.Errorf("request for pseudo terminal failed: %v", err)
			}

			oldState, err := term.MakeRaw(fd)
			if err != nil {
				return fmt.Errorf("failed to set raw mode: %v", err)
			}

			defer term.Restore(fd, oldState)

			if err := session.Shell(); err != nil {
				return fmt.Errorf("failed to start shell: %v", err)
			}

			if err := session.Wait(); err != nil {

				if _, ok := err.(*ssh.ExitError); !ok {

					return fmt.Errorf("ssh session ended with error: %v", err)
				}
			}

			return nil
		},
	})
}
