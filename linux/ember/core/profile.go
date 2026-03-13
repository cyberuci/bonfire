package core

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type ProfileResult struct {
	IP   string
	Name string
	Src  string
	OS   string
}

func profileHost(ctx context.Context, wg *sync.WaitGroup, ip string, host Host, timeout time.Duration, resultChan chan<- ProfileResult) {
	defer wg.Done()
	res := ProfileResult{IP: ip}

	res.OS = DetectOS(ctx, ip, host.Ports, timeout)

	hasRDP := slices.Contains(host.Ports, 3389)
	hasSSH := slices.Contains(host.Ports, 22)

	if hasRDP {
		name, err := GrabRDPHostname(ctx, ip, timeout)
		if err == nil && name != "" {
			res.Name = name
			res.Src = "RDP"
			resultChan <- res
			return
		}
	}

	if hasSSH {
		name, err := GrabSSHHostname(ctx, ip, host.Username, host.Password, timeout)
		if err == nil && name != "" {
			res.Name = name
			res.Src = "SSH"
			resultChan <- res
			return
		}
	}

	if res.OS != OSUnknown && res.OS != "" {
		resultChan <- res
	}
}

func ProfileHosts(ctx context.Context, hosts HostMap, timeout time.Duration) {
	wg := sync.WaitGroup{}
	resultChan := make(chan ProfileResult)

	for ip, host := range hosts {
		wg.Add(1)
		go profileHost(ctx, &wg, ip, host, timeout, resultChan)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	updatedCount := 0
	for res := range resultChan {
		entry := hosts[res.IP]
		changed := false

		if res.Name != "" && entry.Alias != res.Name {
			entry.Alias = res.Name
			log.Info().Msgf("[+] %s: Found hostname '%s' via %s", res.IP, res.Name, res.Src)
			changed = true
		}

		if res.OS != OSUnknown && res.OS != "" && entry.OS != res.OS {
			entry.OS = res.OS
			if res.OS == OSLinux {
				entry.Username = "root"
			} else if res.OS == OSWindows {
				entry.Username = "Administrator"
			}
			log.Info().Msgf("[+] %s: Detected OS '%s'", res.IP, res.OS)
			changed = true
		}

		if changed {
			hosts[res.IP] = entry
			updatedCount++
		}
	}
}
