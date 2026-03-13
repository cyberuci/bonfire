package cli

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"bonfire/ember/core"
	"github.com/desertbit/grumble"
	"github.com/rs/zerolog/log"
)

func findScript(name string) (string, error) {

	if _, err := os.Stat(name); err == nil {
		return name, nil
	}

	searchDir := "scripts"
	if _, err := os.Stat(searchDir); os.IsNotExist(err) {
		return "", fmt.Errorf("script '%s' not found and './scripts/' directory does not exist", name)
	}

	var matches []string
	err := filepath.WalkDir(searchDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() && d.Name() == filepath.Base(name) {
			matches = append(matches, path)
		}
		return nil
	})

	if err != nil {
		return "", fmt.Errorf("error searching for script: %w", err)
	}

	if len(matches) == 0 {
		return "", fmt.Errorf("script '%s' not found in './scripts/'", name)
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("ambiguous script name '%s', found multiple matches: %v", name, matches)
	}

	return matches[0], nil
}

func (a *App) registerScriptCommand() {
	a.AddCommand(&grumble.Command{
		Name:    "script",
		Aliases: []string{"sc"},
		Help:    "run a local script on remote host(s)",
		Args: func(a *grumble.Args) {
			a.String("path", "The local path or filename of the script")
			a.StringList("script_args", "Arguments to pass to the script", grumble.Default([]string{}))
		},
		Flags: func(f *grumble.Flags) {
			f.String("H", "host", "", "Specific host to run on (default: all)")
			f.Bool("u", "upload", true, "Upload the script before running")
		},
		Run: func(c *grumble.Context) error {
			scriptName := c.Args.String("path")
			scriptArgs := c.Args.StringList("script_args")
			host := c.Flags.String("host")
			upload := c.Flags.Bool("upload")

			scriptPath, err := findScript(scriptName)
			if err != nil {
				return err
			}
			log.Info().Msgf("Resolved script to: %s", scriptPath)

			timeout := 30 * time.Second

			if host != "" {

				hostIP, err := a.hosts.ResolveHost(host)
				if err != nil {
					return err
				}

				if h := a.hosts[hostIP]; h.OS != core.OSLinux {
					return fmt.Errorf("[%s] script execution on %s hosts is not implemented", hostIP, h.OS)
				}

				log.Info().Msgf("Running script '%s' on %s...", scriptPath, hostIP)
				code, out, err := a.hosts.RunScript(a.ctx, hostIP, scriptPath, scriptArgs, upload, timeout)
				if err != nil {
					log.Error().Err(err).Msgf("Script execution failed on %s", hostIP)
					return err
				}

				log.Info().Msgf("[%s] Exit Code: %d", hostIP, code)
				if len(out) > 0 {
					log.Info().Msgf("[%s] Output:\n%s", hostIP, out)
				}

			} else {

				if len(a.hosts) == 0 {
					log.Warn().Msg("No hosts found to run script on.")
					return nil
				}

				targets := a.hosts.LinuxIPs()

				if len(targets) == 0 {
					log.Warn().Msg("No Linux hosts found to run script on.")
					return nil
				}

				log.Info().Msgf("Running script '%s' on %d Linux hosts...", scriptPath, len(targets))

				var wg sync.WaitGroup
				type result struct {
					IP     string
					Code   int
					Output string
					Err    error
				}
				results := make(chan result, len(targets))

				for _, ip := range targets {
					wg.Add(1)
					go func(targetIP string) {
						defer wg.Done()
						code, out, err := a.hosts.RunScript(a.ctx, targetIP, scriptPath, scriptArgs, upload, timeout)
						results <- result{IP: targetIP, Code: code, Output: out, Err: err}
					}(ip)
				}

				go func() {
					wg.Wait()
					close(results)
				}()

				for res := range results {
					if res.Err != nil {
						log.Error().Err(res.Err).Msgf("[%s] Failed", res.IP)
					} else {
						log.Info().Msgf("[%s] Exit Code: %d", res.IP, res.Code)
						if len(res.Output) > 0 {

							log.Info().Msgf("[%s] Output:\n%s", res.IP, res.Output)
						}
					}
				}
			}

			return nil
		},
	})
}
