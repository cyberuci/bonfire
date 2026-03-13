package core

import (
	"bufio"
	"context"
	"net"
	"slices"
	"strings"
	"time"
)

func DetectOS(ctx context.Context, hostIP string, ports []uint16, timeout time.Duration) string {
	hasPort := func(p uint16) bool {
		return slices.Contains(ports, p)
	}

	if hasPort(5985) || hasPort(5986) {
		return OSWindows
	}

	if hasPort(22) {
		banner := grabSSHBanner(ctx, hostIP, timeout)
		lowerBanner := strings.ToLower(banner)

		if strings.Contains(lowerBanner, "windows") {
			return OSWindows
		} else {
			return OSLinux
		}
	}

	if hasPort(445) || hasPort(135) {
		return OSWindows
	}

	if hasPort(3389) {

		return OSWindows
	}

	return OSUnknown
}

func grabSSHBanner(ctx context.Context, hostIP string, timeout time.Duration) string {
	target := net.JoinHostPort(hostIP, "22")
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(banner)
}
