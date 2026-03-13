package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"bonfire/ember/core"

	"github.com/bluekeyes/go-gitdiff/gitdiff"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/pelletier/go-toml/v2"
)

const defaultSSHTimeout = 30 * time.Second

func registerEmberTools(s *server.MCPServer, hosts core.HostMap, configPath string) {
	s.AddTool(
		mcp.NewTool("run_command",
			mcp.WithDescription("Run a shell command on a remote host via SSH. Commands run as the host's configured user (usually root)."),
			mcp.WithString("host", mcp.Required(), mcp.Description("Host IP address from ember.toml")),
			mcp.WithString("command", mcp.Required(), mcp.Description("Shell command to execute")),
			mcp.WithNumber("timeout", mcp.Description("Timeout in seconds (default: 30)")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			host := getArg(args, "host")
			cmd := getArg(args, "command")
			if host == "" || cmd == "" {
				return errResult("host and command are required"), nil
			}

			timeout := defaultSSHTimeout
			if t, ok := getArgFloat(args, "timeout"); ok {
				timeout = time.Duration(t) * time.Second
			}

			resolvedIP, err := hosts.ResolveHost(host)
			if err != nil {
				return errResult(fmt.Sprintf("Could not resolve host '%s': %v\nAvailable hosts:\n%s", host, err, listEmberHosts(hosts))), nil
			}

			exitCode, output, err := hosts.RunSSHCommand(ctx, resolvedIP, cmd, timeout)
			if err != nil {
				return errResult(fmt.Sprintf("SSH error on %s (%s): %v", host, resolvedIP, err)), nil
			}

			result := fmt.Sprintf("Host: %s (%s)\nExit code: %d\n\n%s", hosts[resolvedIP].Alias, resolvedIP, exitCode, output)
			return textResult(result), nil
		},
	)

	s.AddTool(
		mcp.NewTool("read_file",
			mcp.WithDescription("Read a file from a remote host via SSH."),
			mcp.WithString("host", mcp.Required(), mcp.Description("Host IP address")),
			mcp.WithString("path", mcp.Required(), mcp.Description("Absolute file path to read")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			host := getArg(args, "host")
			path := getArg(args, "path")
			if host == "" || path == "" {
				return errResult("host and path are required"), nil
			}

			resolvedIP, err := hosts.ResolveHost(host)
			if err != nil {
				return errResult(fmt.Sprintf("Could not resolve host '%s': %v\nAvailable hosts:\n%s", host, err, listEmberHosts(hosts))), nil
			}

			_, output, err := hosts.RunSSHCommand(ctx, resolvedIP, fmt.Sprintf("cat %q", path), defaultSSHTimeout)
			if err != nil {
				return errResult(fmt.Sprintf("Failed to read file: %v", err)), nil
			}
			return textResult(output), nil
		},
	)

	s.AddTool(
		mcp.NewTool("write_file",
			mcp.WithDescription("Write content to a file on a remote host. DANGEROUS: Always confirm with user before calling."),
			mcp.WithString("host", mcp.Required(), mcp.Description("Host IP address")),
			mcp.WithString("path", mcp.Required(), mcp.Description("Absolute file path to write")),
			mcp.WithString("content", mcp.Required(), mcp.Description("File content to write")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			host := getArg(args, "host")
			path := getArg(args, "path")
			content := getArg(args, "content")
			if host == "" || path == "" {
				return errResult("host, path, and content are required"), nil
			}

			resolvedIP, err := hosts.ResolveHost(host)
			if err != nil {
				return errResult(fmt.Sprintf("Could not resolve host '%s': %v\nAvailable hosts:\n%s", host, err, listEmberHosts(hosts))), nil
			}

			cmd := fmt.Sprintf("cat > %q << 'EOF'\n%s\nEOF", path, content)
			exitCode, output, err := hosts.RunSSHCommand(ctx, resolvedIP, cmd, defaultSSHTimeout)
			if err != nil {
				return errResult(fmt.Sprintf("Failed to write file: %v", err)), nil
			}
			if exitCode != 0 {
				return errResult(fmt.Sprintf("Write failed (exit %d): %s", exitCode, output)), nil
			}
			return textResult(fmt.Sprintf("Successfully wrote to %s on %s", path, resolvedIP)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("run_fwp",
			mcp.WithDescription("Run the firewall log parser (fwp) on a remote host to see blocked and allowed traffic. Supports filtering by protocol and time range."),
			mcp.WithString("host", mcp.Required(), mcp.Description("Host IP address")),
			mcp.WithString("since", mcp.Description("Time filter, e.g., '5m', '1h', '30s'")),
			mcp.WithString("protocol", mcp.Description("Filter by protocol: tcp, udp, icmp")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			host := getArg(args, "host")
			if host == "" {
				return errResult("host is required"), nil
			}

			resolvedIP, err := hosts.ResolveHost(host)
			if err != nil {
				return errResult(fmt.Sprintf("Could not resolve host '%s': %v\nAvailable hosts:\n%s", host, err, listEmberHosts(hosts))), nil
			}

			hosts.RunSSHCommand(ctx, resolvedIP, "chmod +x ~/fwp 2>/dev/null", 5*time.Second)

			cmd := "~/fwp"
			if since := getArg(args, "since"); since != "" {
				cmd += fmt.Sprintf(" -since %s", since)
			}
			if proto := getArg(args, "protocol"); proto != "" {
				cmd += fmt.Sprintf(" -proto %s", proto)
			}

			_, output, err := hosts.RunSSHCommand(ctx, resolvedIP, cmd, defaultSSHTimeout)
			if err != nil {
				return errResult(fmt.Sprintf("Failed to run fwp: %v", err)), nil
			}
			return textResult(output), nil
		},
	)

	s.AddTool(
		mcp.NewTool("ember_list_hosts",
			mcp.WithDescription("List all hosts from ember.toml with their IPs, aliases, OS, ports, and credentials."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return textResult(listEmberHosts(hosts)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("upload_file",
			mcp.WithDescription("Upload a local file to a remote host via SFTP. Confirm with user first."),
			mcp.WithString("host", mcp.Required(), mcp.Description("Host IP address")),
			mcp.WithString("local_path", mcp.Required(), mcp.Description("Local file path")),
			mcp.WithString("remote_path", mcp.Required(), mcp.Description("Remote destination path")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			host := getArg(args, "host")
			localPath := getArg(args, "local_path")
			remotePath := getArg(args, "remote_path")
			if host == "" || localPath == "" || remotePath == "" {
				return errResult("host, local_path, and remote_path are required"), nil
			}

			resolvedIP, err := hosts.ResolveHost(host)
			if err != nil {
				return errResult(fmt.Sprintf("Could not resolve host '%s': %v\nAvailable hosts:\n%s", host, err, listEmberHosts(hosts))), nil
			}

			if err := hosts.UploadFile(ctx, resolvedIP, localPath, remotePath); err != nil {
				return errResult(fmt.Sprintf("Upload failed: %v", err)), nil
			}
			return textResult(fmt.Sprintf("Uploaded %s to %s:%s", localPath, resolvedIP, remotePath)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("download_file",
			mcp.WithDescription("Download a file from a remote host via SFTP."),
			mcp.WithString("host", mcp.Required(), mcp.Description("Host IP address")),
			mcp.WithString("remote_path", mcp.Required(), mcp.Description("Remote file path")),
			mcp.WithString("local_path", mcp.Required(), mcp.Description("Local destination path")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			host := getArg(args, "host")
			remotePath := getArg(args, "remote_path")
			localPath := getArg(args, "local_path")
			if host == "" || remotePath == "" || localPath == "" {
				return errResult("host, remote_path, and local_path are required"), nil
			}

			resolvedIP, err := hosts.ResolveHost(host)
			if err != nil {
				return errResult(fmt.Sprintf("Could not resolve host '%s': %v\nAvailable hosts:\n%s", host, err, listEmberHosts(hosts))), nil
			}

			if err := hosts.DownloadFile(ctx, resolvedIP, remotePath, localPath); err != nil {
				return errResult(fmt.Sprintf("Download failed: %v", err)), nil
			}
			return textResult(fmt.Sprintf("Downloaded %s:%s to %s", resolvedIP, remotePath, localPath)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("patch_file",
			mcp.WithDescription("Apply a unified diff to a file on a remote host. Reads the current file, validates the patch applies cleanly, and writes the result. Shows which hunks applied before writing. CONFIRM WITH USER before calling."),
			mcp.WithString("host", mcp.Required(), mcp.Description("Host IP address")),
			mcp.WithString("path", mcp.Required(), mcp.Description("Absolute file path to patch")),
			mcp.WithString("patch", mcp.Required(), mcp.Description("Unified diff string to apply")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			host := getArg(args, "host")
			path := getArg(args, "path")
			patchStr := getArg(args, "patch")
			if host == "" || path == "" || patchStr == "" {
				return errResult("host, path, and patch are required"), nil
			}

			resolvedIP, err := hosts.ResolveHost(host)
			if err != nil {
				return errResult(fmt.Sprintf("Could not resolve host '%s': %v\nAvailable hosts:\n%s", host, err, listEmberHosts(hosts))), nil
			}

			_, current, err := hosts.RunSSHCommand(ctx, resolvedIP, fmt.Sprintf("cat %q", path), defaultSSHTimeout)
			if err != nil {
				return errResult(fmt.Sprintf("Failed to read %s: %v", path, err)), nil
			}

			files, _, err := gitdiff.Parse(strings.NewReader(patchStr))
			if err != nil {
				return errResult(fmt.Sprintf("Failed to parse patch: %v", err)), nil
			}
			if len(files) == 0 {
				return errResult("No file diffs found in patch"), nil
			}

			var fileDiff *gitdiff.File
			for _, f := range files {
				if f.OldName == path || f.NewName == path ||
					strings.HasSuffix(path, f.OldName) || strings.HasSuffix(path, f.NewName) {
					fileDiff = f
					break
				}
			}
			if fileDiff == nil {
				fileDiff = files[0]
			}

			var out strings.Builder
			src := strings.NewReader(current)
			if err := gitdiff.Apply(&out, src, fileDiff); err != nil {
				return errResult(fmt.Sprintf("Patch did not apply cleanly: %v\nThe file may have changed since the diff was generated.", err)), nil
			}
			patched := out.String()

			hunkCount := len(fileDiff.TextFragments)

			tmpPath := path + ".hypernova.tmp"
			writeCmd := fmt.Sprintf("cat > %q << 'EOF'\n%sEOF", tmpPath, patched)
			exitCode, output, err := hosts.RunSSHCommand(ctx, resolvedIP, writeCmd, defaultSSHTimeout)
			if err != nil {
				return errResult(fmt.Sprintf("Failed to write patched file: %v", err)), nil
			}
			if exitCode != 0 {
				return errResult(fmt.Sprintf("Write failed (exit %d): %s", exitCode, output)), nil
			}

			mvCmd := fmt.Sprintf("mv %q %q", tmpPath, path)
			exitCode, output, err = hosts.RunSSHCommand(ctx, resolvedIP, mvCmd, defaultSSHTimeout)
			if err != nil {
				return errResult(fmt.Sprintf("Failed to move patched file into place: %v", err)), nil
			}
			if exitCode != 0 {
				return errResult(fmt.Sprintf("Move failed (exit %d): %s", exitCode, output)), nil
			}

			return textResult(fmt.Sprintf("Successfully patched %s on %s (%d hunks applied)", path, resolvedIP, hunkCount)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("ember_update_host",
			mcp.WithDescription("Update a host entry in ember.toml (alias, OS, username, password, password_index). CONFIRM WITH USER FIRST. Changes are persisted to disk."),
			mcp.WithString("host", mcp.Required(), mcp.Description("Host IP address to update")),
			mcp.WithString("alias", mcp.Description("New alias")),
			mcp.WithString("os", mcp.Description("OS type (Linux, Windows)")),
			mcp.WithString("username", mcp.Description("SSH username")),
			mcp.WithString("password", mcp.Description("SSH password")),
			mcp.WithNumber("password_index", mcp.Description("Password index into passwords.db (omit to leave unchanged)")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			query := getArg(args, "host")
			if query == "" {
				return errResult("host is required"), nil
			}
			ip, err := hosts.ResolveHost(query)
			if err != nil {
				return errResult(fmt.Sprintf("could not resolve host '%s': %v", query, err)), nil
			}
			h := hosts[ip]
			if v := getArg(args, "alias"); v != "" {
				h.Alias = v
			}
			if v := getArg(args, "os"); v != "" {
				h.OS = v
			}
			if v := getArg(args, "username"); v != "" {
				h.Username = v
			}
			if v := getArg(args, "password"); v != "" {
				h.Password = v
			}
			if f, ok := getArgFloat(args, "password_index"); ok {
				idx := int(f)
				h.PasswordIndex = &idx
			}
			hosts[ip] = h

			data, err := toml.Marshal(hosts)
			if err != nil {
				return errResult(fmt.Sprintf("failed to marshal config: %v", err)), nil
			}
			if err := os.WriteFile(configPath, data, 0644); err != nil {
				return errResult(fmt.Sprintf("failed to write config: %v", err)), nil
			}
			return textResult(fmt.Sprintf("Updated host %s: alias=%s os=%s user=%s passIndex=%v", ip, h.Alias, h.OS, h.Username, h.PasswordIndex)), nil
		},
	)
}

func listEmberHosts(hosts core.HostMap) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Ember hosts (%d total):\n\n", len(hosts)))
	for _, ip := range hosts.SortedHostIPs() {
		h := hosts[ip]
		ports := strings.Trim(fmt.Sprint(h.Ports), "[]")
		passIdx := "none"
		if h.PasswordIndex != nil {
			passIdx = fmt.Sprintf("%d", *h.PasswordIndex)
		}
		sb.WriteString(fmt.Sprintf("  %s (%s) [%s]\n    Ports: %s | User: %s | Pass Index: %s\n",
			ip, h.Alias, h.OS, ports, h.Username, passIdx))
	}
	return sb.String()
}
