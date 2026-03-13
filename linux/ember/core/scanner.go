package core

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"
)

func incrementIP(ip net.IP) {
	for octet := len(ip) - 1; octet >= 0; octet-- {
		ip[octet]++
		if ip[octet] > 0 {
			break
		}
	}
}

func IsPortOpen(ctx context.Context, host string, timeout uint, port uint16) (bool, error) {
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	dialer := net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return false, err
		}
		return false, nil
	}
	conn.Close()
	return true, nil
}

func RunTCPScan(ctx context.Context, cidrStr string, ports []uint16, timeout uint, user, pass string) (HostMap, error) {
	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, err
	}

	hostMap := make(HostMap)
	var mu sync.Mutex
	var wg sync.WaitGroup

	scanError := make(chan error)
	for ip := cidr.IP.Mask(cidr.Mask); cidr.Contains(ip); incrementIP(ip) {

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		ipStr := ip.String()
		for _, port := range ports {
			wg.Add(1)
			go func(h string, p uint16) {
				defer wg.Done()
				open, err := IsPortOpen(ctx, h, timeout, p)
				if err != nil {
					select {
					case scanError <- err:
					case <-ctx.Done():
					}
				}
				if open {
					mu.Lock()
					entry := hostMap[h]
					entry.Ports = append(entry.Ports, p)

					entry.Username = user
					entry.Password = pass
					hostMap[h] = entry
					mu.Unlock()
				}
			}(ipStr, port)
		}
	}

	done := make(chan struct{})

	go func() {
		wg.Wait()
		done <- struct{}{}
	}()

	select {

	case err := <-scanError:
		return nil, err

	case <-done:
		return hostMap, nil
	}
}
