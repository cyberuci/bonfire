package main

import (
	"context"
	"fmt"
	"strings"

	nspb "bonfire/northstar/proto"
	"bonfire/northstar/proto/northstarconnect"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const northstarFormatSummary = "summary"
const northstarFormatJSON = "json"

func getNorthstarFormat(args map[string]interface{}) string {
	format := strings.ToLower(getArg(args, "format"))
	if format == "" {
		return northstarFormatSummary
	}
	return format
}

func northstarJSON(msg proto.Message) (*mcp.CallToolResult, error) {
	data, err := (protojson.MarshalOptions{
		EmitUnpopulated: true,
		UseProtoNames:   true,
		Indent:          "  ",
	}).Marshal(msg)
	if err != nil {
		return errResult(fmt.Sprintf("Northstar protojson error: %v", err)), nil
	}
	return textResult(string(data)), nil
}

func resolveHostID(ctx context.Context, client northstarconnect.NorthstarClient, query string) (uint32, string, error) {
	resp, err := client.ListHosts(ctx, connectReq(&nspb.Empty{}))
	if err != nil {
		return 0, "", fmt.Errorf("failed to list hosts: %w", err)
	}

	query = strings.ToLower(query)
	var matches []*nspb.Host

	for _, h := range resp.Msg.Hosts {
		if strings.ToLower(h.Hostname) == query || h.Ip == query {
			return h.Id, h.Hostname, nil
		}
		if strings.HasPrefix(strings.ToLower(h.Hostname), query) || strings.HasPrefix(h.Ip, query) {
			matches = append(matches, h)
		}
	}

	if len(matches) == 1 {
		return matches[0].Id, matches[0].Hostname, nil
	}
	if len(matches) > 1 {
		names := make([]string, len(matches))
		for i, m := range matches {
			names[i] = fmt.Sprintf("%s (%s, ID %d)", m.Hostname, m.Ip, m.Id)
		}
		return 0, "", fmt.Errorf("ambiguous match for '%s': %s", query, strings.Join(names, ", "))
	}

	available := make([]string, len(resp.Msg.Hosts))
	for i, h := range resp.Msg.Hosts {
		available[i] = fmt.Sprintf("%s (%s, ID %d)", h.Hostname, h.Ip, h.Id)
	}
	return 0, "", fmt.Errorf("no host found matching '%s'. Available: %s", query, strings.Join(available, ", "))
}

func registerNorthstarTools(s *server.MCPServer, client northstarconnect.NorthstarClient) {
	s.AddTool(
		mcp.NewTool("northstar_list_hosts",
			mcp.WithDescription("List all hosts from Northstar with their ports, services, network, and firewall status. Use to understand the infrastructure."),
			mcp.WithString("format", mcp.Description("Output format: summary (default) or json")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			resp, err := client.ListHosts(ctx, connectReq(&nspb.Empty{}))
			if err != nil {
				return errResult(fmt.Sprintf("Northstar error: %v", err)), nil
			}
			if getNorthstarFormat(req.GetArguments()) == northstarFormatJSON {
				return northstarJSON(resp.Msg)
			}
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("Hosts (%d total):\n\n", len(resp.Msg.Hosts)))
			for _, h := range resp.Msg.Hosts {
				sb.WriteString(formatHost(h))
				sb.WriteString("\n\n")
			}
			return textResult(sb.String()), nil
		},
	)

	s.AddTool(
		mcp.NewTool("northstar_list_services",
			mcp.WithDescription("List all services from Northstar with scored status, dependencies, ports, and technology. Use to understand what's running and what depends on what."),
			mcp.WithString("format", mcp.Description("Output format: summary (default) or json")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			resp, err := client.ListServices(ctx, connectReq(&nspb.Empty{}))
			if err != nil {
				return errResult(fmt.Sprintf("Northstar error: %v", err)), nil
			}
			if getNorthstarFormat(req.GetArguments()) == northstarFormatJSON {
				return northstarJSON(resp.Msg)
			}
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("Services (%d total):\n\n", len(resp.Msg.Services)))
			for _, s := range resp.Msg.Services {
				sb.WriteString(formatService(s))
				sb.WriteString("\n\n")
			}
			return textResult(sb.String()), nil
		},
	)

	s.AddTool(
		mcp.NewTool("northstar_list_networks",
			mcp.WithDescription("List all networks from Northstar with CIDR ranges and descriptions."),
			mcp.WithString("format", mcp.Description("Output format: summary (default) or json")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			resp, err := client.ListNetworks(ctx, connectReq(&nspb.Empty{}))
			if err != nil {
				return errResult(fmt.Sprintf("Northstar error: %v", err)), nil
			}
			if getNorthstarFormat(req.GetArguments()) == northstarFormatJSON {
				return northstarJSON(resp.Msg)
			}
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("Networks (%d total):\n\n", len(resp.Msg.Networks)))
			for _, n := range resp.Msg.Networks {
				sb.WriteString(fmt.Sprintf("  %s: %s - %s\n", n.Name, n.Cidr, n.Description))
			}
			return textResult(sb.String()), nil
		},
	)

	s.AddTool(
		mcp.NewTool("northstar_list_websites",
			mcp.WithDescription("List all websites tracked in Northstar with URLs, credentials, and enumeration status."),
			mcp.WithString("format", mcp.Description("Output format: summary (default) or json")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			resp, err := client.ListWebsites(ctx, connectReq(&nspb.Empty{}))
			if err != nil {
				return errResult(fmt.Sprintf("Northstar error: %v", err)), nil
			}
			if getNorthstarFormat(req.GetArguments()) == northstarFormatJSON {
				return northstarJSON(resp.Msg)
			}
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("Websites (%d total):\n\n", len(resp.Msg.Websites)))
			for _, w := range resp.Msg.Websites {
				enumerated := ""
				if w.Enumerated {
					enumerated = " [ENUMERATED]"
				}
				passIdx := "none"
				if w.PasswordIndex != nil {
					passIdx = fmt.Sprintf("%d", *w.PasswordIndex)
				}
				sb.WriteString(fmt.Sprintf("  %s%s\n    URL: %s | User: %s | Pass Index: %s | Service ID: %d\n",
					w.Name, enumerated, w.Url, w.Username, passIdx, w.ServiceId))
			}
			return textResult(sb.String()), nil
		},
	)

	s.AddTool(
		mcp.NewTool("northstar_list_injects",
			mcp.WithDescription("List all injects (competition tasks) with deadlines, assignees, and completion status."),
			mcp.WithString("format", mcp.Description("Output format: summary (default) or json")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			resp, err := client.ListInjects(ctx, connectReq(&nspb.Empty{}))
			if err != nil {
				return errResult(fmt.Sprintf("Northstar error: %v", err)), nil
			}
			if getNorthstarFormat(req.GetArguments()) == northstarFormatJSON {
				return northstarJSON(resp.Msg)
			}
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("Injects (%d total):\n\n", len(resp.Msg.Injects)))
			for _, inj := range resp.Msg.Injects {
				completed := ""
				if inj.Completed {
					completed = " [COMPLETED]"
				}
				assignees := make([]string, len(inj.Assignees))
				for i, a := range inj.Assignees {
					assignees[i] = a.Name
				}
				due := "no deadline"
				if inj.Due != nil {
					due = inj.Due.AsTime().Format("2006-01-02 15:04")
				}
				sb.WriteString(fmt.Sprintf("  #%s: %s%s\n    Due: %s | Assignees: %s\n    %s\n",
					inj.Number, inj.Title, completed, due, strings.Join(assignees, ", "), inj.Description))
			}
			return textResult(sb.String()), nil
		},
	)

	s.AddTool(
		mcp.NewTool("northstar_list_passwords",
			mcp.WithDescription("List password entries from Northstar (indices and assignments only, no plaintext)."),
			mcp.WithString("format", mcp.Description("Output format: summary (default) or json")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			resp, err := client.ListPasswords(ctx, connectReq(&nspb.Empty{}))
			if err != nil {
				return errResult(fmt.Sprintf("Northstar error: %v", err)), nil
			}
			if getNorthstarFormat(req.GetArguments()) == northstarFormatJSON {
				return northstarJSON(resp.Msg)
			}
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("Passwords (%d entries):\n\n", len(resp.Msg.Passwords)))
			for _, p := range resp.Msg.Passwords {
				assignments := ""
				for _, a := range p.Assignments {
					assignments += fmt.Sprintf(" [%s: %s]", a.Type, a.Label)
				}
				sb.WriteString(fmt.Sprintf("  #%d (%s): %s%s\n", p.Index, p.Category, p.Comment, assignments))
			}
			return textResult(sb.String()), nil
		},
	)

	s.AddTool(
		mcp.NewTool("northstar_update_service",
			mcp.WithDescription("Update a service in Northstar. CONFIRM WITH USER FIRST. Can update scored, disabled, backed_up, hardened, ldap_authentication status, and ports."),
			mcp.WithNumber("id", mcp.Required(), mcp.Description("Service ID")),
			mcp.WithString("name", mcp.Description("Service name")),
			mcp.WithString("technology", mcp.Description("Technology stack")),
			mcp.WithBoolean("scored", mcp.Description("Whether service is scored")),
			mcp.WithBoolean("disabled", mcp.Description("Whether service is disabled")),
			mcp.WithBoolean("backed_up", mcp.Description("Whether service is backed up")),
			mcp.WithBoolean("hardened", mcp.Description("Whether service is hardened")),
			mcp.WithBoolean("ldap_authentication", mcp.Description("Whether service uses LDAP")),
			mcp.WithString("ports", mcp.Description("Comma-separated list of port numbers to replace existing ports (e.g. '80,443')")),
			mcp.WithString("format", mcp.Description("Output format: summary (default) or json")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			id, ok := getArgFloat(args, "id")
			if !ok {
				return errResult("id is required"), nil
			}

			listResp, err := client.ListServices(ctx, connectReq(&nspb.Empty{}))
			if err != nil {
				return errResult(fmt.Sprintf("Northstar error fetching services: %v", err)), nil
			}
			var current *nspb.Service
			for _, s := range listResp.Msg.Services {
				if s.Id == uint32(id) {
					current = s
					break
				}
			}
			if current == nil {
				return errResult(fmt.Sprintf("no service found with ID %d", uint32(id))), nil
			}

			updateReq := &nspb.UpdateServiceRequest{
				Id:                 current.Id,
				Name:               current.Name,
				Technology:         current.Technology,
				Scored:             current.Scored,
				Disabled:           current.Disabled,
				BackedUp:           current.BackedUp,
				Hardened:           current.Hardened,
				LdapAuthentication: current.LdapAuthentication,
			}

			if v := getArg(args, "name"); v != "" {
				updateReq.Name = v
			}
			if v := getArg(args, "technology"); v != "" {
				updateReq.Technology = v
			}
			if v, ok := getArgBool(args, "scored"); ok {
				updateReq.Scored = v
			}
			if v, ok := getArgBool(args, "disabled"); ok {
				updateReq.Disabled = v
			}
			if v, ok := getArgBool(args, "backed_up"); ok {
				updateReq.BackedUp = v
			}
			if v, ok := getArgBool(args, "hardened"); ok {
				updateReq.Hardened = v
			}
			if v, ok := getArgBool(args, "ldap_authentication"); ok {
				updateReq.LdapAuthentication = v
			}

			resp, err := client.UpdateService(ctx, connectReq(updateReq))
			if err != nil {
				return errResult(fmt.Sprintf("Northstar error: %v", err)), nil
			}

			if portsStr := getArg(args, "ports"); portsStr != "" {

				for _, sp := range current.ServicePorts {
					if _, err := client.DeleteServicePort(ctx, connectReq(&nspb.DeleteServicePortRequest{
						ServiceId: current.Id,
						Port:      sp.Port,
					})); err != nil {
						return errResult(fmt.Sprintf("Error deleting service port %d: %v", sp.Port, err)), nil
					}
				}

				portStrs := strings.Split(portsStr, ",")
				for _, ps := range portStrs {
					ps = strings.TrimSpace(ps)
					var port uint32
					if _, err := fmt.Sscanf(ps, "%d", &port); err == nil {
						if _, err := client.AddServicePort(ctx, connectReq(&nspb.AddServicePortRequest{
							ServiceId: current.Id,
							Port:      port,
						})); err != nil {
							return errResult(fmt.Sprintf("Error adding service port %d: %v", port, err)), nil
						}
					}
				}

				listResp, err = client.ListServices(ctx, connectReq(&nspb.Empty{}))
				if err == nil {
					for _, s := range listResp.Msg.Services {
						if s.Id == uint32(id) {
							resp.Msg = s
							break
						}
					}
				}
			}

			if getNorthstarFormat(args) == northstarFormatJSON {
				return northstarJSON(resp.Msg)
			}
			return textResult(fmt.Sprintf("Updated service:\n%s", formatService(resp.Msg))), nil
		},
	)

	s.AddTool(
		mcp.NewTool("northstar_update_host",
			mcp.WithDescription("Update a host in Northstar. CONFIRM WITH USER FIRST."),
			mcp.WithNumber("id", mcp.Required(), mcp.Description("Host ID")),
			mcp.WithString("hostname", mcp.Description("Hostname")),
			mcp.WithString("ip", mcp.Description("IP address")),
			mcp.WithString("os_type", mcp.Description("OS type")),
			mcp.WithString("role", mcp.Description("Host role")),
			mcp.WithBoolean("firewall_enabled", mcp.Description("Firewall enabled status")),
			mcp.WithString("format", mcp.Description("Output format: summary (default) or json")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			id, ok := getArgFloat(req.GetArguments(), "id")
			if !ok {
				return errResult("id is required"), nil
			}

			listResp, err := client.ListHosts(ctx, connectReq(&nspb.Empty{}))
			if err != nil {
				return errResult(fmt.Sprintf("Northstar error fetching hosts: %v", err)), nil
			}
			var current *nspb.Host
			for _, h := range listResp.Msg.Hosts {
				if h.Id == uint32(id) {
					current = h
					break
				}
			}
			if current == nil {
				return errResult(fmt.Sprintf("no host found with ID %d", uint32(id))), nil
			}

			updateReq := &nspb.UpdateHostRequest{
				Id:              current.Id,
				Hostname:        current.Hostname,
				Ip:              current.Ip,
				OsType:          current.OsType,
				Role:            current.Role,
				FirewallEnabled: current.FirewallEnabled,
			}
			if current.PasswordIndex != nil {
				v := int32(*current.PasswordIndex)
				updateReq.PasswordIndex = &v
			}

			if v := getArg(req.GetArguments(), "hostname"); v != "" {
				updateReq.Hostname = v
			}
			if v := getArg(req.GetArguments(), "ip"); v != "" {
				updateReq.Ip = v
			}
			if v := getArg(req.GetArguments(), "os_type"); v != "" {
				updateReq.OsType = v
			}
			if v := getArg(req.GetArguments(), "role"); v != "" {
				updateReq.Role = v
			}
			if v, ok := getArgBool(req.GetArguments(), "firewall_enabled"); ok {
				updateReq.FirewallEnabled = v
			}

			resp, err := client.UpdateHost(ctx, connectReq(updateReq))
			if err != nil {
				return errResult(fmt.Sprintf("Northstar error: %v", err)), nil
			}
			if getNorthstarFormat(req.GetArguments()) == northstarFormatJSON {
				return northstarJSON(resp.Msg)
			}
			return textResult(fmt.Sprintf("Updated host:\n%s", formatHost(resp.Msg))), nil
		},
	)

	s.AddTool(
		mcp.NewTool("northstar_add_service",
			mcp.WithDescription("Add a new service to a host in Northstar. CONFIRM WITH USER FIRST. You can specify the host by name/IP (host) or by numeric ID (host_id). Ports are automatically synced to the host's port list."),
			mcp.WithString("host", mcp.Description("Host name or IP to add service to (resolved to ID automatically)")),
			mcp.WithNumber("host_id", mcp.Description("Host ID to add service to (use this OR host, not both)")),
			mcp.WithString("name", mcp.Required(), mcp.Description("Service name")),
			mcp.WithString("technology", mcp.Description("Technology stack")),
			mcp.WithBoolean("scored", mcp.Description("Whether service is scored")),
			mcp.WithString("ports", mcp.Description("Comma-separated list of port numbers (e.g. '80,443')")),
			mcp.WithString("format", mcp.Description("Output format: summary (default) or json")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			name := getArg(args, "name")
			if name == "" {
				return errResult("name is required"), nil
			}

			var hostID uint32
			var hostLabel string
			if hid, ok := getArgFloat(args, "host_id"); ok {
				hostID = uint32(hid)
				hostLabel = fmt.Sprintf("ID %d", hostID)
			} else if hostQuery := getArg(args, "host"); hostQuery != "" {
				resolved, hostname, err := resolveHostID(ctx, client, hostQuery)
				if err != nil {
					return errResult(fmt.Sprintf("Could not resolve host: %v", err)), nil
				}
				hostID = resolved
				hostLabel = hostname
			} else {
				return errResult("either host or host_id is required"), nil
			}

			addReq := &nspb.AddServiceRequest{
				HostId: hostID,
				Name:   name,
			}
			if v := getArg(args, "technology"); v != "" {
				addReq.Technology = v
			}
			if v, ok := getArgBool(args, "scored"); ok {
				addReq.Scored = v
			}
			if portsStr := getArg(args, "ports"); portsStr != "" {
				portStrs := strings.Split(portsStr, ",")
				for _, ps := range portStrs {
					ps = strings.TrimSpace(ps)
					var port uint32
					if _, err := fmt.Sscanf(ps, "%d", &port); err == nil {
						addReq.Ports = append(addReq.Ports, port)
					}
				}
			}

			resp, err := client.AddService(ctx, connectReq(addReq))
			if err != nil {
				return errResult(fmt.Sprintf("Northstar error: %v", err)), nil
			}
			if getNorthstarFormat(args) == northstarFormatJSON {
				return northstarJSON(resp.Msg)
			}
			return textResult(fmt.Sprintf("Added service to %s:\n%s", hostLabel, formatService(resp.Msg))), nil
		},
	)

	s.AddTool(
		mcp.NewTool("northstar_add_host_port",
			mcp.WithDescription("Add a port to a host in Northstar. CONFIRM WITH USER FIRST."),
			mcp.WithNumber("host_id", mcp.Required(), mcp.Description("Host ID")),
			mcp.WithNumber("port", mcp.Required(), mcp.Description("Port number")),
			mcp.WithBoolean("whitelisted", mcp.Description("Whether port is whitelisted in firewall")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			hostID, ok := getArgFloat(args, "host_id")
			if !ok {
				return errResult("host_id is required"), nil
			}
			port, ok := getArgFloat(args, "port")
			if !ok {
				return errResult("port is required"), nil
			}
			addReq := &nspb.AddHostPortRequest{
				HostId: uint32(hostID),
				Port:   uint32(port),
			}
			if v, ok := getArgBool(args, "whitelisted"); ok {
				addReq.Whitelisted = v
			}
			_, err := client.AddHostPort(ctx, connectReq(addReq))
			if err != nil {
				return errResult(fmt.Sprintf("Northstar error: %v", err)), nil
			}
			return textResult(fmt.Sprintf("Added port %d to host ID %d", uint32(port), uint32(hostID))), nil
		},
	)

	s.AddTool(
		mcp.NewTool("northstar_delete_host_port",
			mcp.WithDescription("Remove a port from a host in Northstar. CONFIRM WITH USER FIRST."),
			mcp.WithNumber("host_id", mcp.Required(), mcp.Description("Host ID")),
			mcp.WithNumber("port", mcp.Required(), mcp.Description("Port number")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			hostID, ok := getArgFloat(args, "host_id")
			if !ok {
				return errResult("host_id is required"), nil
			}
			port, ok := getArgFloat(args, "port")
			if !ok {
				return errResult("port is required"), nil
			}
			_, err := client.DeleteHostPort(ctx, connectReq(&nspb.DeleteHostPortRequest{
				HostId: uint32(hostID),
				Port:   uint32(port),
			}))
			if err != nil {
				return errResult(fmt.Sprintf("Northstar error: %v", err)), nil
			}
			return textResult(fmt.Sprintf("Deleted port %d from host ID %d", uint32(port), uint32(hostID))), nil
		},
	)

	s.AddTool(
		mcp.NewTool("northstar_add_host",
			mcp.WithDescription("Add a new host to Northstar. CONFIRM WITH USER FIRST."),
			mcp.WithString("ip", mcp.Required(), mcp.Description("Host IP address")),
			mcp.WithString("hostname", mcp.Description("Hostname/alias")),
			mcp.WithString("os_type", mcp.Description("OS type (Linux, Windows)")),
			mcp.WithBoolean("firewall_enabled", mcp.Description("Firewall enabled status")),
			mcp.WithNumber("network_id", mcp.Description("Network ID to assign to")),
			mcp.WithString("format", mcp.Description("Output format: summary (default) or json")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			ip := getArg(req.GetArguments(), "ip")
			if ip == "" {
				return errResult("ip is required"), nil
			}

			addReq := &nspb.AddHostRequest{Ip: ip}
			if v := getArg(req.GetArguments(), "hostname"); v != "" {
				addReq.Hostname = &v
			}
			if v := getArg(req.GetArguments(), "os_type"); v != "" {
				addReq.OsType = v
			}
			if v, ok := getArgBool(req.GetArguments(), "firewall_enabled"); ok {
				addReq.FirewallEnabled = v
			}
			if v, ok := getArgFloat(req.GetArguments(), "network_id"); ok {
				nid := uint32(v)
				addReq.NetworkId = &nid
			}

			resp, err := client.AddHost(ctx, connectReq(addReq))
			if err != nil {
				return errResult(fmt.Sprintf("Northstar error: %v", err)), nil
			}
			if getNorthstarFormat(req.GetArguments()) == northstarFormatJSON {
				return northstarJSON(resp.Msg)
			}
			return textResult(fmt.Sprintf("Added host:\n%s", formatHost(resp.Msg))), nil
		},
	)
}
