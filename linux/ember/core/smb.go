package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/srvs/srvsvc/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/well_known"
	"github.com/oiweiwei/go-msrpc/smb2"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	smb2_fork "github.com/oiweiwei/go-smb2.fork"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

func init() {

	gssapi.AddMechanism(ssp.NTLM)
}

func ListSMBShares(hostIP, username, password string) (*srvsvc.ShareEnum, error) {

	gssapi.AddCredential(credential.NewFromPassword(username, password))

	ctx := gssapi.NewSecurityContext(context.Background())

	logger := log.Logger.Level(zerolog.Disabled)

	dialer := smb2.NewDialer(
		smb2.WithDialect(smb2.SMB311),
		smb2.WithSecurity(gssapi.WithTargetName(hostIP)),
	)

	opts := []dcerpc.Option{
		dcerpc.WithLogger(logger),
		well_known.EndpointMapper(),
		dcerpc.WithSMBDialer(dialer),
	}

	cc, err := dcerpc.Dial(ctx, hostIP, opts...)
	if err != nil {
		return nil, fmt.Errorf("dcerpc dial failed: %w", err)
	}
	defer cc.Close(ctx)

	cli, err := srvsvc.NewSrvsvcClient(ctx, cc, dcerpc.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("failed to create srvsvc client: %w", err)
	}

	enums, err := cli.ShareEnum(ctx, &srvsvc.ShareEnumRequest{
		ServerName: "",
		Info: &srvsvc.ShareEnum{
			Level: 503,
			ShareInfo: &srvsvc.ShareEnumUnion{
				Value: &srvsvc.ShareEnumUnion_Level503{Level503: &srvsvc.ShareInfo503Container{}},
			},
		},
		PreferredMaximumLength: 0xffffffff,
	})

	if err != nil {
		return nil, fmt.Errorf("ShareEnum failed: %w", err)
	}

	return enums.Info, nil
}

func UploadFileSMB(ctx context.Context, hostIP, username, password, localPath, remotePath string) error {

	fs, err := connectSMBFilesystem(ctx, hostIP, username, password, remotePath)
	if err != nil {
		return err
	}
	defer fs.Umount()

	_, relPath := parseRemotePath(remotePath)

	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer localFile.Close()

	remoteFile, err := fs.Create(relPath)
	if err != nil {

		return fmt.Errorf("failed to create remote file '%s': %w", relPath, err)
	}
	defer remoteFile.Close()

	bytes, err := io.Copy(remoteFile, localFile)
	if err != nil {
		return fmt.Errorf("failed to upload file to SMB: %w", err)
	}

	log.Info().Msgf("Uploaded %d bytes to SMB %s:%s", bytes, hostIP, remotePath)
	return nil
}

func DownloadFileSMB(ctx context.Context, hostIP, username, password, remotePath, localPath string) error {
	fs, err := connectSMBFilesystem(ctx, hostIP, username, password, remotePath)
	if err != nil {
		return err
	}
	defer fs.Umount()

	_, relPath := parseRemotePath(remotePath)

	remoteFile, err := fs.Open(relPath)
	if err != nil {
		return fmt.Errorf("failed to open remote file '%s': %w", relPath, err)
	}
	defer remoteFile.Close()

	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return fmt.Errorf("failed to create local directory: %w", err)
	}

	localFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer localFile.Close()

	bytes, err := io.Copy(localFile, remoteFile)
	if err != nil {
		return fmt.Errorf("failed to download file from SMB: %w", err)
	}

	log.Info().Msgf("Downloaded %d bytes from SMB %s:%s", bytes, hostIP, remotePath)
	return nil
}

func connectSMBFilesystem(ctx context.Context, host, user, pass, fullRemotePath string) (*smb2_fork.Share, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", host+":445")
	if err != nil {
		return nil, fmt.Errorf("failed to dial SMB: %w", err)
	}

	dialer := &smb2_fork.Dialer{
		Initiator: &smb2_fork.NTLMInitiator{
			User:     user,
			Password: pass,
		},
	}

	s, err := dialer.Dial(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to dial SMB session: %w", err)
	}

	shareName, _ := parseRemotePath(fullRemotePath)
	fs, err := s.Mount(shareName)
	if err != nil {
		s.Logoff()
		return nil, fmt.Errorf("failed to mount share '%s': %w", shareName, err)
	}

	return fs, nil
}

func parseRemotePath(p string) (share, path string) {

	p = strings.ReplaceAll(p, "/", "\\")
	p = strings.TrimPrefix(p, "\\\\")

	parts := strings.SplitN(p, "\\", 2)
	if len(parts) == 2 {

		return parts[0], parts[1]
	}

	return "C$", p
}
