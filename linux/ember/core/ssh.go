package core

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func ConnectSSH(hostIP string, user string, password string, timeout time.Duration) (*ssh.Client, error) {
	return ConnectSSHContext(context.Background(), hostIP, user, password, timeout)
}

func ConnectSSHContext(ctx context.Context, hostIP string, user string, password string, timeout time.Duration) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	target := net.JoinHostPort(hostIP, "22")

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %v", err)
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, target, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create ssh client conn: %v", err)
	}

	return ssh.NewClient(c, chans, reqs), nil
}

func (h HostMap) RunSSHCommand(ctx context.Context, hostIP, cmd string, timeout time.Duration) (int, string, error) {
	resolvedIP, err := h.ResolveHost(hostIP)
	if err != nil {
		return -1, "", err
	}

	host, ok := h[resolvedIP]
	if !ok {
		return -1, "", fmt.Errorf("host %s not found", resolvedIP)
	}

	user := host.Username
	if user == "" {
		user = "root"
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, err := ConnectSSHContext(cmdCtx, resolvedIP, user, host.Password, timeout)
	if err != nil {
		return -1, "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return -1, "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	done := make(chan error, 1)
	go func() {
		done <- session.Run(cmd)
	}()

	select {
	case <-cmdCtx.Done():

		_ = session.Close()
		_ = client.Close()
		output := stdoutBuf.String() + stderrBuf.String()
		if ctx.Err() != nil {

			return -1, output, ctx.Err()
		}
		return -1, output, fmt.Errorf("command timed out after %s", timeout)
	case err = <-done:

	}

	output := stdoutBuf.String() + stderrBuf.String()

	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			return exitErr.ExitStatus(), output, nil
		}
		return -1, output, err
	}

	return 0, output, nil
}

func (h HostMap) RunScript(ctx context.Context, hostIP, scriptPath string, args []string, upload bool, timeout time.Duration) (int, string, error) {
	resolvedIP, err := h.ResolveHost(hostIP)
	if err != nil {
		return -1, "", err
	}

	remotePath := scriptPath

	if upload {
		remotePath = "./" + filepath.Base(scriptPath)

		if err := h.UploadFileSFTPWithMode(ctx, resolvedIP, scriptPath, remotePath, 0755); err != nil {
			return -1, "", fmt.Errorf("upload failed: %w", err)
		}
	}

	fullCmd := remotePath
	for _, arg := range args {
		fullCmd += " " + arg
	}

	return h.RunSSHCommand(ctx, resolvedIP, fullCmd, timeout)
}

func GrabSSHHostname(ctx context.Context, hostIP, user, password string, timeout time.Duration) (string, error) {
	client, err := ConnectSSHContext(ctx, hostIP, user, password, timeout)
	if err != nil {
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	output, err := session.Output("cat /etc/hostname")
	if err != nil {
		return "", fmt.Errorf("failed to run command: %v", err)
	}

	hostname := strings.TrimSpace(string(output))
	if hostname == "" {
		return "", fmt.Errorf("returned hostname is empty")
	}

	return hostname, nil
}
