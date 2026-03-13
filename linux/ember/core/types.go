package core

import (
	"sort"

	"github.com/rs/zerolog/log"
)

const (
	OSLinux   = "Linux"
	OSWindows = "Windows"
	OSUnknown = "Unknown"
)

type Host struct {
	Ports         []uint16
	Username      string
	Password      string
	PasswordIndex *int `toml:",omitempty"`
	Alias         string
	OS            string
}

type HostMap map[string]Host

func (hm HostMap) SortedHostIPs() []string {
	ips := make([]string, 0, len(hm))
	for ip := range hm {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips
}

func (hm HostMap) LinuxIPs() []string {
	var ips []string
	for _, ip := range hm.SortedHostIPs() {
		if hm[ip].OS == OSLinux {
			ips = append(ips, ip)
		} else {
			log.Warn().Msgf("[%s] Skipping non-Linux host (OS: %q)", ip, hm[ip].OS)
		}
	}
	return ips
}
