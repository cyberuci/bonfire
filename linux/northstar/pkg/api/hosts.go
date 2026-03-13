package api

import (
	"context"
	"fmt"
	"net"

	"bonfire/northstar/pkg/store"
	northstar "bonfire/northstar/proto"
	"connectrpc.com/connect"
	"github.com/pelletier/go-toml/v2"
)

type ImportedHostConfig struct {
	Ports         []int  `toml:"Ports"`
	Username      string `toml:"Username"`
	Password      string `toml:"Password"`
	PasswordIndex *int   `toml:"PasswordIndex"`
	Alias         string `toml:"Alias"`
	OS            string `toml:"OS"`
}

func (s *NorthstarServer) toProtoHost(h store.Host) *northstar.Host {
	ph := &northstar.Host{
		Id:              uint32(h.ID),
		Hostname:        h.Hostname,
		Ip:              h.IP,
		OsType:          h.OSType,
		OsVersion:       h.OSVersion,
		Role:            h.Role,
		FirewallEnabled: h.FirewallEnabled,
	}
	if h.PasswordIndex != nil {
		pi := int32(*h.PasswordIndex)
		ph.PasswordIndex = &pi
	}
	if h.NetworkID != nil {
		ni := uint32(*h.NetworkID)
		ph.NetworkId = &ni
	}
	for _, hp := range h.HostPorts {
		ph.HostPorts = append(ph.HostPorts, &northstar.HostPort{
			HostId:      uint32(hp.HostID),
			Port:        uint32(hp.Port),
			Whitelisted: hp.Whitelisted,
		})
	}

	for _, s := range h.Services {
		ps := &northstar.Service{
			Id:                 uint32(s.ID),
			HostId:             uint32(s.HostID),
			Name:               s.Name,
			Technology:         s.Technology,
			Scored:             s.Scored,
			Disabled:           s.Disabled,
			BackedUp:           s.BackedUp,
			Hardened:           s.Hardened,
			LdapAuthentication: s.LDAPAuthentication,
		}
		if s.PasswordIndex != nil {
			pi := int32(*s.PasswordIndex)
			ps.PasswordIndex = &pi
		}

		for _, sp := range s.ServicePorts {
			ps.ServicePorts = append(ps.ServicePorts, &northstar.ServicePort{
				ServiceId: uint32(sp.ServiceID),
				Port:      uint32(sp.Port),
			})
		}

		for _, dep := range s.Dependencies {
			depProto := &northstar.ServiceDependency{
				ServiceId:     uint32(dep.ServiceID),
				DependsOnId:   uint32(dep.DependsOnID),
				DependsOnName: dep.DependsOnService.Name,
			}
			ps.Dependencies = append(ps.Dependencies, depProto)
		}

		for _, w := range s.Websites {
			var serviceID uint32
			if w.ServiceID != nil {
				serviceID = uint32(*w.ServiceID)
			}
			pw := &northstar.Website{
				Id:          uint32(w.ID),
				ServiceId:   serviceID,
				Name:        w.Name,
				Url:         w.URL,
				Username:    w.Username,
				OldPassword: w.OldPassword,
			}
			if w.PasswordIndex != nil {
				pi := int32(*w.PasswordIndex)
				pw.PasswordIndex = &pi
			}
			ps.Websites = append(ps.Websites, pw)
		}

		ph.Services = append(ph.Services, ps)
	}

	return ph
}

func (s *NorthstarServer) AddHost(
	ctx context.Context,
	req *connect.Request[northstar.AddHostRequest],
) (*connect.Response[northstar.Host], error) {
	var hostname string
	if req.Msg.Hostname != nil {
		hostname = *req.Msg.Hostname
	}
	host := store.Host{
		Hostname:        hostname,
		IP:              req.Msg.Ip,
		OSType:          req.Msg.OsType,
		FirewallEnabled: req.Msg.FirewallEnabled,
	}
	if req.Msg.PasswordIndex != nil {
		pi := int(*req.Msg.PasswordIndex)
		host.PasswordIndex = &pi
	}
	if req.Msg.NetworkId != nil {
		ni := uint(*req.Msg.NetworkId)
		host.NetworkID = &ni
	}

	for _, port := range req.Msg.Ports {
		host.HostPorts = append(host.HostPorts, store.HostPort{
			Port:        uint16(port),
			Whitelisted: false,
		})
	}

	if result := s.db.Create(&host); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("hosts")

	return connect.NewResponse(s.toProtoHost(host)), nil
}

func (s *NorthstarServer) ListHosts(
	ctx context.Context,
	req *connect.Request[northstar.Empty],
) (*connect.Response[northstar.HostList], error) {
	var hosts []store.Host
	if result := s.db.Preload("HostPorts").Preload("Services").Preload("Services.Websites").Preload("Services.ServicePorts").Preload("Services.Dependencies").Preload("Services.Dependencies.DependsOnService").Find(&hosts); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	var protoHosts []*northstar.Host
	for _, h := range hosts {
		protoHosts = append(protoHosts, s.toProtoHost(h))
	}

	return connect.NewResponse(&northstar.HostList{
		Hosts: protoHosts,
	}), nil
}

func (s *NorthstarServer) UpdateHost(
	ctx context.Context,
	req *connect.Request[northstar.UpdateHostRequest],
) (*connect.Response[northstar.Host], error) {
	var host store.Host
	if result := s.db.Preload("HostPorts").Preload("Services").Preload("Services.Websites").Preload("Services.ServicePorts").Preload("Services.Dependencies").Preload("Services.Dependencies.DependsOnService").First(&host, req.Msg.Id); result.Error != nil {
		return nil, connect.NewError(connect.CodeNotFound, result.Error)
	}

	host.Hostname = req.Msg.Hostname
	host.IP = req.Msg.Ip
	host.OSType = req.Msg.OsType
	host.OSVersion = req.Msg.OsVersion
	host.Role = req.Msg.Role
	host.FirewallEnabled = req.Msg.FirewallEnabled
	if req.Msg.PasswordIndex != nil {
		pi := int(*req.Msg.PasswordIndex)
		host.PasswordIndex = &pi
	} else {
		host.PasswordIndex = nil
	}
	if req.Msg.NetworkId != nil {
		ni := uint(*req.Msg.NetworkId)
		host.NetworkID = &ni
	} else {
		host.NetworkID = nil
	}

	if req.Msg.NetworkId == nil {
		hostIP := net.ParseIP(host.IP)
		if hostIP != nil {
			var networks []store.Network
			if err := s.db.Find(&networks).Error; err == nil {
				for _, n := range networks {
					if n.CIDR == "" {
						continue
					}
					_, cidr, err := net.ParseCIDR(n.CIDR)
					if err != nil {
						continue
					}
					if cidr.Contains(hostIP) {
						networkID := n.ID
						host.NetworkID = &networkID
						break
					}
				}
			}
		}
	}

	if result := s.db.Save(&host); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("hosts")

	return connect.NewResponse(s.toProtoHost(host)), nil
}

func (s *NorthstarServer) DeleteHost(
	ctx context.Context,
	req *connect.Request[northstar.DeleteHostRequest],
) (*connect.Response[northstar.Empty], error) {
	if result := s.db.Delete(&store.Host{}, req.Msg.Id); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("hosts")
	s.hub.Broadcast("services")
	s.hub.Broadcast("websites")

	return connect.NewResponse(&northstar.Empty{}), nil
}

func (s *NorthstarServer) UpdateHostPort(
	ctx context.Context,
	req *connect.Request[northstar.UpdateHostPortRequest],
) (*connect.Response[northstar.HostPort], error) {
	var hostPort store.HostPort
	if result := s.db.Where("host_id = ? AND port = ?", req.Msg.HostId, req.Msg.Port).First(&hostPort); result.Error != nil {
		return nil, connect.NewError(connect.CodeNotFound, result.Error)
	}

	hostPort.Whitelisted = req.Msg.Whitelisted

	if result := s.db.Save(&hostPort); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("hosts")

	return connect.NewResponse(&northstar.HostPort{
		HostId:      uint32(hostPort.HostID),
		Port:        uint32(hostPort.Port),
		Whitelisted: hostPort.Whitelisted,
	}), nil
}

func (s *NorthstarServer) AddHostPort(
	ctx context.Context,
	req *connect.Request[northstar.AddHostPortRequest],
) (*connect.Response[northstar.HostPort], error) {
	hostPort := store.HostPort{
		HostID:      uint(req.Msg.HostId),
		Port:        uint16(req.Msg.Port),
		Whitelisted: req.Msg.Whitelisted,
	}

	if result := s.db.Create(&hostPort); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("hosts")

	return connect.NewResponse(&northstar.HostPort{
		HostId:      uint32(hostPort.HostID),
		Port:        uint32(hostPort.Port),
		Whitelisted: hostPort.Whitelisted,
	}), nil
}

func (s *NorthstarServer) DeleteHostPort(
	ctx context.Context,
	req *connect.Request[northstar.DeleteHostPortRequest],
) (*connect.Response[northstar.Empty], error) {
	if result := s.db.Where("host_id = ? AND port = ?", req.Msg.HostId, req.Msg.Port).Delete(&store.HostPort{}); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("hosts")

	return connect.NewResponse(&northstar.Empty{}), nil
}

func (s *NorthstarServer) ImportHosts(
	ctx context.Context,
	req *connect.Request[northstar.ImportHostsRequest],
) (*connect.Response[northstar.ImportHostsResponse], error) {
	var importedHosts map[string]ImportedHostConfig
	if err := toml.Unmarshal([]byte(req.Msg.TomlContent), &importedHosts); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("failed to parse TOML: %w", err))
	}

	resp := &northstar.ImportHostsResponse{}

	var networks []store.Network
	if err := s.db.Find(&networks).Error; err != nil {
		resp.Errors = append(resp.Errors, fmt.Sprintf("Failed to load networks for CIDR matching: %v", err))
	}

	for ip, config := range importedHosts {
		var hosts []store.Host

		s.db.Where("ip = ?", ip).Find(&hosts)

		isNew := len(hosts) == 0

		if isNew {

			host := store.Host{
				IP:              ip,
				Hostname:        config.Alias,
				OSType:          config.OS,
				FirewallEnabled: false,
			}
			host.PasswordIndex = nil
			if config.PasswordIndex != nil {
				pi := *config.PasswordIndex
				host.PasswordIndex = &pi
			}

			hostIP := net.ParseIP(ip)
			if hostIP != nil {
				for _, n := range networks {
					if n.CIDR == "" {
						continue
					}
					_, cidr, err := net.ParseCIDR(n.CIDR)
					if err != nil {
						continue
					}
					if cidr.Contains(hostIP) {
						networkID := n.ID
						host.NetworkID = &networkID
						break
					}
				}
			}

			if err := s.db.Create(&host).Error; err != nil {
				resp.Errors = append(resp.Errors, fmt.Sprintf("Failed to create host %s: %v", ip, err))
				continue
			}
			resp.HostsImported++

			for _, p := range config.Ports {
				s.db.Create(&store.HostPort{
					HostID:      host.ID,
					Port:        uint16(p),
					Whitelisted: false,
				})
			}
		} else {
			host := hosts[0]

			host.Hostname = config.Alias
			host.OSType = config.OS
			host.PasswordIndex = nil
			if config.PasswordIndex != nil {
				pi := *config.PasswordIndex
				host.PasswordIndex = &pi
			}
			if err := s.db.Save(&host).Error; err != nil {
				resp.Errors = append(resp.Errors, fmt.Sprintf("Failed to update host %s: %v", ip, err))
				continue
			}
			resp.HostsUpdated++

			if host.NetworkID == nil {
				hostIP := net.ParseIP(ip)
				if hostIP != nil {
					for _, n := range networks {
						if n.CIDR == "" {
							continue
						}
						_, cidr, err := net.ParseCIDR(n.CIDR)
						if err != nil {
							continue
						}
						if cidr.Contains(hostIP) {
							networkID := n.ID
							host.NetworkID = &networkID
							if err := s.db.Model(&host).Update("network_id", networkID).Error; err != nil {
								resp.Errors = append(resp.Errors, fmt.Sprintf("Failed to link host %s to network: %v", ip, err))
							}
							break
						}
					}
				}
			}

			var existingPorts []store.HostPort
			if err := s.db.Where("host_id = ?", host.ID).Find(&existingPorts).Error; err != nil {
				resp.Errors = append(resp.Errors, fmt.Sprintf("Failed to load existing ports for host %s: %v", ip, err))
				continue
			}
			existingPortSet := make(map[uint16]bool)
			for _, ep := range existingPorts {
				existingPortSet[ep.Port] = true
			}
			for _, p := range config.Ports {
				if !existingPortSet[uint16(p)] {
					if err := s.db.Create(&store.HostPort{
						HostID:      host.ID,
						Port:        uint16(p),
						Whitelisted: false,
					}).Error; err != nil {
						resp.Errors = append(resp.Errors, fmt.Sprintf("Failed to add port %d for %s: %v", p, ip, err))
					}
				}
			}
		}
	}

	s.hub.Broadcast("hosts")

	return connect.NewResponse(resp), nil
}

func (s *NorthstarServer) ClearHosts(
	ctx context.Context,
	req *connect.Request[northstar.Empty],
) (*connect.Response[northstar.Empty], error) {
	tx := s.db.Begin()

	if err := tx.Where("1 = 1").Delete(&store.HostPort{}).Error; err != nil {
		tx.Rollback()
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Where("1 = 1").Delete(&store.ServicePort{}).Error; err != nil {
		tx.Rollback()
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Where("1 = 1").Delete(&store.Website{}).Error; err != nil {
		tx.Rollback()
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Where("1 = 1").Delete(&store.Service{}).Error; err != nil {
		tx.Rollback()
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Where("1 = 1").Delete(&store.Host{}).Error; err != nil {
		tx.Rollback()
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if err := tx.Commit().Error; err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	s.hub.Broadcast("hosts")
	s.hub.Broadcast("services")
	s.hub.Broadcast("websites")

	return connect.NewResponse(&northstar.Empty{}), nil
}
