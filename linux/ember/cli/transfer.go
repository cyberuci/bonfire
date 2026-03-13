package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"bonfire/ember/core"
	"github.com/desertbit/grumble"
	"github.com/rs/zerolog/log"
)

func (a *App) registerTransferCommands() {
	a.AddCommand(&grumble.Command{
		Name:    "upload",
		Aliases: []string{"up"},
		Help:    "transfers a file from the local machine to a remote host via SFTP",
		Args: func(a *grumble.Args) {
			a.String("host", "The host IP or alias (use 'all' for all hosts)")
			a.String("local_path", "The local file path to upload")
			a.String("remote_path", "The remote destination path (optional)", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			hostQuery := c.Args.String("host")
			localPath := c.Args.String("local_path")
			remotePath := c.Args.String("remote_path")

			var targets []string
			if hostQuery == "all" {
				targets = a.hosts.SortedHostIPs()
				if len(targets) == 0 {
					log.Warn().Msg("No hosts available to upload to.")
					return nil
				}
			} else {
				hostIP, err := a.hosts.ResolveHost(hostQuery)
				if err != nil {
					return err
				}
				targets = []string{hostIP}
			}

			if remotePath == "" {

				remotePath = filepath.Base(localPath)
			}

			var lastErr error
			for _, hostIP := range targets {
				log.Info().Msgf("Uploading '%s' to %s:%s ...", localPath, hostIP, remotePath)
				if err := a.hosts.UploadFile(a.ctx, hostIP, localPath, remotePath); err != nil {
					log.Error().Err(err).Msgf("Failed to upload to %s", hostIP)
					lastErr = err
				}
			}

			if lastErr != nil && len(targets) > 1 {
				return fmt.Errorf("upload completed with errors on some hosts")
			}
			return lastErr
		},
	})

	a.AddCommand(&grumble.Command{
		Name:    "download",
		Aliases: []string{"down"},
		Help:    "transfers a file from a remote host to the local machine via SFTP",
		Args: func(a *grumble.Args) {
			a.String("host", "The host IP or alias (use 'all' for all hosts)")
			a.String("remote_path", "The remote file path to download")
		},
		Run: func(c *grumble.Context) error {
			hostQuery := c.Args.String("host")
			remotePath := c.Args.String("remote_path")

			var targets []string
			if hostQuery == "all" {
				targets = a.hosts.LinuxIPs()
				if len(targets) == 0 {
					log.Warn().Msg("No Linux hosts available to download from.")
					return nil
				}
			} else {
				hostIP, err := a.hosts.ResolveHost(hostQuery)
				if err != nil {
					return err
				}
				if h := a.hosts[hostIP]; h.OS != core.OSLinux {
					return fmt.Errorf("[%s] download from %s hosts is not implemented", hostIP, h.OS)
				}
				targets = []string{hostIP}
			}

			if err := os.MkdirAll("downloads", 0755); err != nil {
				return fmt.Errorf("failed to create downloads directory: %w", err)
			}

			var lastErr error
			for _, hostIP := range targets {

				hostDir := filepath.Join("downloads", hostIP)
				if err := os.MkdirAll(hostDir, 0755); err != nil {
					log.Error().Err(err).Msgf("Failed to create host directory for %s", hostIP)
					lastErr = err
					continue
				}

				hostEntry := a.hosts[hostIP]
				if hostEntry.Alias != "" && hostEntry.Alias != hostIP {
					aliasLink := filepath.Join("downloads", hostEntry.Alias)

					_ = os.Remove(aliasLink)

					if err := os.Symlink(hostIP, aliasLink); err != nil {
						log.Warn().Err(err).Msgf("Failed to create symlink for alias %s", hostEntry.Alias)
					}
				}

				log.Info().Msgf("Downloading %s:%s into '%s' ...", hostIP, remotePath, hostDir)

				if err := a.hosts.DownloadDirectory(a.ctx, hostIP, remotePath, hostDir); err != nil {
					log.Error().Err(err).Msgf("Failed to download from %s", hostIP)
					lastErr = err
				}
			}

			if lastErr != nil && len(targets) > 1 {
				return fmt.Errorf("download completed with errors on some hosts")
			}
			return lastErr
		},
	})
}
