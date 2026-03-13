package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"

	"bonfire/ember/core"
	nspb "bonfire/northstar/proto"
	"bonfire/northstar/proto/northstarconnect"

	"connectrpc.com/connect"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/pelletier/go-toml/v2"
)

func loadHostsFrom(path string) (core.HostMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	var hosts core.HostMap
	if err := toml.Unmarshal(data, &hosts); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	if hosts == nil {
		hosts = make(core.HostMap)
	}
	return hosts, nil
}

func main() {
	emberConfig := flag.String("ember-config", "ember.toml", "Path to ember.toml")
	northstarURL := flag.String("northstar-url", "", "Northstar server URL")
	flag.Parse()

	hosts, err := loadHostsFrom(*emberConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load ember config: %v\n", err)
		hosts = make(core.HostMap)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	var nsClient northstarconnect.NorthstarClient
	if *northstarURL != "" {
		nsClient = northstarconnect.NewNorthstarClient(httpClient, *northstarURL)
	}

	s := server.NewMCPServer("hypernova", "1.0.0",
		server.WithToolCapabilities(true),
	)

	registerEmberTools(s, hosts, *emberConfig)
	if nsClient != nil {
		registerNorthstarTools(s, nsClient)
	}

	if err := server.ServeStdio(s); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		os.Exit(1)
	}
}

func nsCtx() context.Context {
	return context.Background()
}

func formatHost(h *nspb.Host) string {
	ports := ""
	for i, p := range h.HostPorts {
		wl := ""
		if p.Whitelisted {
			wl = " (whitelisted)"
		}
		if i > 0 {
			ports += ", "
		}
		ports += fmt.Sprintf("%d%s", p.Port, wl)
	}

	services := ""
	for i, s := range h.Services {
		scored := ""
		if s.Scored {
			scored = " [SCORED]"
		}
		disabled := ""
		if s.Disabled {
			disabled = " [DISABLED]"
		}
		if i > 0 {
			services += ", "
		}
		services += fmt.Sprintf("%s%s%s", s.Name, scored, disabled)
	}

	fw := "off"
	if h.FirewallEnabled {
		fw = "on"
	}

	passIdx := "none"
	if h.PasswordIndex != nil {
		passIdx = fmt.Sprintf("%d", *h.PasswordIndex)
	}

	return fmt.Sprintf("Host: %s (ID: %d, Role: %s)\n  IP: %s | OS: %s | Firewall: %s | Password Index: %s\n  Ports: %s\n  Services: %s",
		h.Hostname, h.Id, h.Role, h.Ip, h.OsType, fw, passIdx, ports, services)
}

func formatService(s *nspb.Service) string {
	scored := ""
	if s.Scored {
		scored = " [SCORED]"
	}
	disabled := ""
	if s.Disabled {
		disabled = " [DISABLED]"
	}

	ports := ""
	for i, p := range s.ServicePorts {
		if i > 0 {
			ports += ", "
		}
		ports += fmt.Sprintf("%d", p.Port)
	}

	deps := ""
	for i, d := range s.Dependencies {
		if i > 0 {
			deps += ", "
		}
		deps += fmt.Sprintf("%s on %s", d.DependsOnName, d.DependsOnHost)
	}
	if deps == "" {
		deps = "none"
	}

	passIdx := "none"
	if s.PasswordIndex != nil {
		passIdx = fmt.Sprintf("%d", *s.PasswordIndex)
	}

	ldap := ""
	if s.LdapAuthentication {
		ldap = " [LDAP]"
	}

	return fmt.Sprintf("Service: %s%s%s%s\n  Host ID: %d | Tech: %s | Ports: %s | Password Index: %s\n  Dependencies: %s\n  Backed up: %t | Hardened: %t",
		s.Name, scored, disabled, ldap, s.HostId, s.Technology, ports, passIdx, deps, s.BackedUp, s.Hardened)
}

func getArg(args map[string]interface{}, key string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getArgFloat(args map[string]interface{}, key string) (float64, bool) {
	if v, ok := args[key]; ok {
		if f, ok := v.(float64); ok {
			return f, true
		}
	}
	return 0, false
}

func getArgBool(args map[string]interface{}, key string) (bool, bool) {
	if v, ok := args[key]; ok {
		if b, ok := v.(bool); ok {
			return b, true
		}
	}
	return false, false
}

func errResult(msg string) *mcp.CallToolResult {
	return mcp.NewToolResultError(msg)
}

func textResult(text string) *mcp.CallToolResult {
	return mcp.NewToolResultText(text)
}

func connectReq[T any](msg *T) *connect.Request[T] {
	return connect.NewRequest(msg)
}
