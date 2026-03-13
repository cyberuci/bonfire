package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

func GrabRDPHostname(ctx context.Context, hostIP string, timeout time.Duration) (string, error) {
	target := net.JoinHostPort(hostIP, "3389")

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return "", fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, conf)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("tls handshake failed: %v", err)
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("no peer certificates presented")
	}

	leaf := state.PeerCertificates[0]

	hostname := leaf.Subject.CommonName
	if hostname == "" {
		return "", fmt.Errorf("certificate has no CommonName")
	}

	return hostname, nil
}
