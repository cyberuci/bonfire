package core

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

func RotateHosts(ctx context.Context, hosts HostMap, targets []string, passwords []PasswordEntry, staticPass string, scriptPath string, limit int) int {
	log.Info().Msgf("Starting rotation for %d hosts...", len(targets))

	type assignment struct {
		IP       string
		Password string
		Index    *int
	}

	var assignments []assignment
	var usedIDs = make(map[int]bool)

	for _, h := range hosts {
		if h.PasswordIndex != nil {
			usedIDs[*h.PasswordIndex] = true
		}
	}

	if staticPass != "" {
		for _, ip := range targets {
			assignments = append(assignments, assignment{IP: ip, Password: staticPass})
		}
	} else {

		available := make(map[int]string)
		for _, p := range passwords {
			id := p.ID
			if limit > 0 && id >= limit {
				continue
			}
			if usedIDs[id] {
				continue
			}
			available[id] = p.Password
		}

		for _, ip := range targets {
			if len(available) == 0 {
				log.Error().Msgf("[%s] No passwords left in pool", ip)
				break
			}

			ids := make([]int, 0, len(available))
			for id := range available {
				ids = append(ids, id)
			}
			pick := ids[rand.Intn(len(ids))]

			assignments = append(assignments, assignment{
				IP:       ip,
				Password: available[pick],
				Index:    &pick,
			})
			usedIDs[pick] = true
			delete(available, pick)
		}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	successCount := 0

	for _, a := range assignments {
		wg.Add(1)
		go func(a assignment) {
			defer wg.Done()

			if err := rotateHost(ctx, hosts, a.IP, a.Password, scriptPath); err != nil {
				log.Error().Err(err).Msgf("[%s] Rotation failed", a.IP)
				return
			}

			log.Info().Msgf("[%s] Success! Password changed.", a.IP)

			mu.Lock()
			defer mu.Unlock()
			entry := hosts[a.IP]
			entry.Password = a.Password
			entry.PasswordIndex = a.Index
			hosts[a.IP] = entry
			successCount++
		}(a)
	}

	wg.Wait()

	return successCount
}

func rotateHost(ctx context.Context, hosts HostMap, hostIP string, newPass string, scriptPath string) error {
	host := hosts[hostIP]
	user := host.Username
	if user == "" {
		user = "root"
	}

	args := []string{user, newPass}
	timeout := 30 * time.Second

	code, out, err := hosts.RunScript(ctx, hostIP, scriptPath, args, true, timeout)
	if err != nil {
		return fmt.Errorf("script execution failed: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("script returned exit code %d: %s", code, out)
	}

	log.Info().Msgf("[%s] Script executed successfully. Verifying...", hostIP)

	client, err := ConnectSSHContext(ctx, hostIP, user, newPass, 5*time.Second)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	client.Close()

	return nil
}
