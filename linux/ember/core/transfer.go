package core

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

func (h HostMap) UploadFile(ctx context.Context, hostIP, localPath, remotePath string) error {
	host, ok := h[hostIP]
	if !ok {
		return fmt.Errorf("host %s not found in scan results", hostIP)
	}

	useSMB := false
	for _, p := range host.Ports {
		if p == 445 || p == 139 {
			useSMB = true
			break
		}
	}

	if useSMB {
		log.Info().Msgf("Attempting SMB upload to %s...", hostIP)

		user := host.Username
		if user == "" {
			user = "Administrator"
		}

		err := UploadFileSMB(ctx, hostIP, user, host.Password, localPath, remotePath)
		if err == nil {
			return nil
		}
		log.Warn().Err(err).Msg("SMB upload failed, falling back to SFTP")
	}

	return h.uploadFileSFTP(ctx, hostIP, localPath, remotePath)
}

func (h HostMap) DownloadFile(ctx context.Context, hostIP, remotePath, localPath string) error {
	host, ok := h[hostIP]
	if !ok {
		return fmt.Errorf("host %s not found in scan results", hostIP)
	}

	useSMB := false
	for _, p := range host.Ports {
		if p == 445 || p == 139 {
			useSMB = true
			break
		}
	}

	if useSMB {
		log.Info().Msgf("Attempting SMB download from %s...", hostIP)
		user := host.Username
		if user == "" {
			user = "Administrator"
		}
		err := DownloadFileSMB(ctx, hostIP, user, host.Password, remotePath, localPath)
		if err == nil {
			return nil
		}
		log.Warn().Err(err).Msg("SMB download failed, falling back to SFTP")
	}

	return h.downloadFileSFTP(ctx, hostIP, remotePath, localPath)
}

func (h HostMap) uploadFileSFTP(ctx context.Context, hostIP, localPath, remotePath string) error {
	return h.UploadFileSFTPWithMode(ctx, hostIP, localPath, remotePath, 0644)
}

func (h HostMap) UploadFileSFTPWithMode(ctx context.Context, hostIP, localPath, remotePath string, mode os.FileMode) error {
	client, sftpClient, err := h.getSFTPConnection(ctx, hostIP)
	if err != nil {
		return err
	}
	defer client.Close()
	defer sftpClient.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			sftpClient.Close()
			client.Close()
		case <-done:
		}
	}()

	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %v", err)
	}
	defer localFile.Close()

	remoteFile, err := sftpClient.Create(remotePath)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("failed to create remote file: %v", err)
	}
	defer remoteFile.Close()

	if err := remoteFile.Chmod(mode); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("failed to chmod remote file: %v", err)
	}

	bytes, err := io.Copy(remoteFile, localFile)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("failed to upload file via SFTP: %v", err)
	}

	log.Info().Msgf("Uploaded %d bytes to SFTP %s:%s (mode: %o)", bytes, hostIP, remotePath, mode)
	return nil
}

func (h HostMap) downloadFileSFTP(ctx context.Context, hostIP, remotePath, localPath string) error {
	client, sftpClient, err := h.getSFTPConnection(ctx, hostIP)
	if err != nil {
		return err
	}
	defer client.Close()
	defer sftpClient.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			sftpClient.Close()
			client.Close()
		case <-done:
		}
	}()

	remoteFile, err := sftpClient.Open(remotePath)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("failed to open remote file: %v", err)
	}
	defer remoteFile.Close()

	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return fmt.Errorf("failed to create local directory: %v", err)
	}

	localFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %v", err)
	}
	defer localFile.Close()

	bytes, err := io.Copy(localFile, remoteFile)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("failed to download file via SFTP: %v", err)
	}

	log.Info().Msgf("Downloaded %d bytes from SFTP %s:%s", bytes, hostIP, remotePath)
	return nil
}

func (h HostMap) getSFTPConnection(ctx context.Context, hostIP string) (*ssh.Client, *sftp.Client, error) {
	host, ok := h[hostIP]
	if !ok {
		return nil, nil, fmt.Errorf("host %s not found in scan results", hostIP)
	}

	if host.Username == "" {
		host.Username = "root"
	}

	client, err := ConnectSSHContext(ctx, hostIP, host.Username, host.Password, 5*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh connection failed: %v", err)
	}

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		return nil, nil, fmt.Errorf("sftp subsystem failed: %v", err)
	}

	return client, sftpClient, nil
}

func (h HostMap) DownloadDirectory(ctx context.Context, hostIP, remotePath, localPath string) error {
	host, ok := h[hostIP]
	if !ok {
		return fmt.Errorf("host %s not found", hostIP)
	}

	user := host.Username
	if user == "" {
		user = "root"
	}

	client, err := ConnectSSHContext(ctx, hostIP, user, host.Password, 10*time.Second)
	if err != nil {
		return fmt.Errorf("ssh connection failed: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	cmd := fmt.Sprintf("tar c %s", remotePath)

	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("failed to start tar command: %w", err)
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			session.Close()
			client.Close()
		case <-done:
		}
	}()

	if err := untar(stdout, localPath); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("failed to untar: %w", err)
	}

	if err := session.Wait(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("tar command failed: %w", err)
	}

	log.Info().Msgf("Downloaded directory %s:%s to %s", hostIP, remotePath, localPath)
	return nil
}

func untar(r io.Reader, dest string) error {
	tr := tar.NewReader(r)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		relName := header.Name
		if filepath.IsAbs(relName) {
			rel, err := filepath.Rel("/", relName)
			if err != nil {
				return fmt.Errorf("failed to make path relative: %w", err)
			}
			relName = rel
		}

		target := filepath.Join(dest, relName)
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) && target != filepath.Clean(dest) {
			return fmt.Errorf("illegal file path: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}
	return nil
}
