package core

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/rs/zerolog/log"
)

func (h HostMap) Print() {
	var buf bytes.Buffer
	table := tablewriter.NewWriter(&buf)
	table.Header([]string{"IP", "Alias", "OS", "Ports", "User", "Pass", "Pass #"})

	for _, hostIP := range h.SortedHostIPs() {
		h := h[hostIP]

		portsStr := strings.Trim(fmt.Sprint(h.Ports), "[]")

		pidxStr := ""
		if h.PasswordIndex != nil {
			pidxStr = fmt.Sprint(*h.PasswordIndex)
		}

		table.Append([]string{
			hostIP,
			h.Alias,
			h.OS,
			portsStr,
			h.Username,
			h.Password,
			pidxStr,
		})
	}
	table.Render()
	log.Info().Msg("\n" + buf.String())
}

func (h HostMap) ResolveHost(query string) (string, error) {

	if _, ok := h[query]; ok {
		return query, nil
	}

	for ip, host := range h {
		if host.Alias == query {
			return ip, nil
		}
	}

	if strings.HasPrefix(query, ".") {
		var matches []string
		for ip := range h {
			if strings.HasSuffix(ip, query) {
				matches = append(matches, ip)
			}
		}
		if len(matches) == 1 {
			return matches[0], nil
		}
		if len(matches) > 1 {
			return "", fmt.Errorf("ambiguous host suffix '%s', matches: %v", query, matches)
		}
	}

	var matches []string
	for ip, host := range h {
		if strings.HasPrefix(ip, query) || (host.Alias != "" && strings.HasPrefix(host.Alias, query)) {
			matches = append(matches, ip)
		}
	}

	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("ambiguous match for '%s': found %v", query, matches)
	}

	return "", fmt.Errorf("no host found matching '%s'", query)
}
