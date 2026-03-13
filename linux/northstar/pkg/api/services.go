package api

import (
	"context"

	"bonfire/northstar/pkg/store"
	northstar "bonfire/northstar/proto"
	"connectrpc.com/connect"
)

func (s *NorthstarServer) toProtoService(src store.Service) *northstar.Service {
	ps := &northstar.Service{
		Id:                 uint32(src.ID),
		HostId:             uint32(src.HostID),
		Name:               src.Name,
		Technology:         src.Technology,
		Scored:             src.Scored,
		Disabled:           src.Disabled,
		BackedUp:           src.BackedUp,
		Hardened:           src.Hardened,
		LdapAuthentication: src.LDAPAuthentication,
	}
	if src.PasswordIndex != nil {
		pi := int32(*src.PasswordIndex)
		ps.PasswordIndex = &pi
	}

	for _, sp := range src.ServicePorts {
		ps.ServicePorts = append(ps.ServicePorts, &northstar.ServicePort{
			ServiceId: uint32(sp.ServiceID),
			Port:      uint32(sp.Port),
		})
	}

	for _, w := range src.Websites {
		ps.Websites = append(ps.Websites, s.toProtoWebsite(w))
	}

	for _, dep := range src.Dependencies {
		depProto := &northstar.ServiceDependency{
			ServiceId:     uint32(dep.ServiceID),
			DependsOnId:   uint32(dep.DependsOnID),
			DependsOnName: dep.DependsOnService.Name,
		}
		ps.Dependencies = append(ps.Dependencies, depProto)
	}

	return ps
}

func (s *NorthstarServer) toProtoWebsite(w store.Website) *northstar.Website {
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
		Enumerated:  w.Enumerated,
	}
	if w.PasswordIndex != nil {
		pi := int32(*w.PasswordIndex)
		pw.PasswordIndex = &pi
	}
	return pw
}

func (s *NorthstarServer) ListServices(
	ctx context.Context,
	req *connect.Request[northstar.Empty],
) (*connect.Response[northstar.ServiceList], error) {
	var services []store.Service
	if result := s.db.Preload("ServicePorts").Preload("Websites").Preload("Dependencies").Preload("Dependencies.DependsOnService").Find(&services); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	var protoServices []*northstar.Service
	for _, src := range services {
		protoServices = append(protoServices, s.toProtoService(src))
	}

	return connect.NewResponse(&northstar.ServiceList{
		Services: protoServices,
	}), nil
}

func (s *NorthstarServer) AddService(
	ctx context.Context,
	req *connect.Request[northstar.AddServiceRequest],
) (*connect.Response[northstar.Service], error) {
	src := store.Service{
		HostID:     uint(req.Msg.HostId),
		Name:       req.Msg.Name,
		Technology: req.Msg.Technology,
		Scored:     req.Msg.Scored,
	}
	if req.Msg.PasswordIndex != nil {
		pi := int(*req.Msg.PasswordIndex)
		src.PasswordIndex = &pi
	}

	for _, port := range req.Msg.Ports {
		src.ServicePorts = append(src.ServicePorts, store.ServicePort{
			Port: uint16(port),
		})
	}

	if result := s.db.Create(&src); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	for _, port := range src.ServicePorts {
		s.db.FirstOrCreate(&store.HostPort{}, store.HostPort{
			HostID: src.HostID,
			Port:   port.Port,
		})
	}

	s.hub.Broadcast("services")
	s.hub.Broadcast("hosts")

	return connect.NewResponse(s.toProtoService(src)), nil
}

func (s *NorthstarServer) UpdateService(
	ctx context.Context,
	req *connect.Request[northstar.UpdateServiceRequest],
) (*connect.Response[northstar.Service], error) {
	var src store.Service
	if result := s.db.Preload("ServicePorts").Preload("Websites").Preload("Dependencies").Preload("Dependencies.DependsOnService").First(&src, req.Msg.Id); result.Error != nil {
		return nil, connect.NewError(connect.CodeNotFound, result.Error)
	}

	src.Name = req.Msg.Name
	src.Technology = req.Msg.Technology
	src.Scored = req.Msg.Scored
	src.Disabled = req.Msg.Disabled
	src.BackedUp = req.Msg.BackedUp
	src.Hardened = req.Msg.Hardened
	src.LDAPAuthentication = req.Msg.LdapAuthentication

	var oldHostID uint
	if req.Msg.HostId != nil {
		oldHostID = src.HostID
		src.HostID = uint(*req.Msg.HostId)
	}

	if req.Msg.PasswordIndex != nil {
		pi := int(*req.Msg.PasswordIndex)
		src.PasswordIndex = &pi
	} else {
		src.PasswordIndex = nil
	}

	if result := s.db.Save(&src); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	if req.Msg.HostId != nil && oldHostID != src.HostID {
		for _, port := range src.ServicePorts {
			s.db.FirstOrCreate(&store.HostPort{}, store.HostPort{
				HostID: src.HostID,
				Port:   port.Port,
			})
		}
	}

	s.hub.Broadcast("services")
	s.hub.Broadcast("hosts")

	return connect.NewResponse(s.toProtoService(src)), nil
}

func (s *NorthstarServer) DeleteService(
	ctx context.Context,
	req *connect.Request[northstar.DeleteServiceRequest],
) (*connect.Response[northstar.Empty], error) {
	if result := s.db.Delete(&store.Service{}, req.Msg.Id); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("services")

	return connect.NewResponse(&northstar.Empty{}), nil
}

func (s *NorthstarServer) AddServicePort(
	ctx context.Context,
	req *connect.Request[northstar.AddServicePortRequest],
) (*connect.Response[northstar.ServicePort], error) {
	servicePort := store.ServicePort{
		ServiceID: uint(req.Msg.ServiceId),
		Port:      uint16(req.Msg.Port),
	}

	if result := s.db.Create(&servicePort); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	var svc store.Service
	if err := s.db.Select("host_id").First(&svc, servicePort.ServiceID).Error; err == nil {
		s.db.FirstOrCreate(&store.HostPort{}, store.HostPort{
			HostID: svc.HostID,
			Port:   servicePort.Port,
		})
	}

	s.hub.Broadcast("services")
	s.hub.Broadcast("hosts")

	return connect.NewResponse(&northstar.ServicePort{
		ServiceId: uint32(servicePort.ServiceID),
		Port:      uint32(servicePort.Port),
	}), nil
}

func (s *NorthstarServer) DeleteServicePort(
	ctx context.Context,
	req *connect.Request[northstar.DeleteServicePortRequest],
) (*connect.Response[northstar.Empty], error) {
	if result := s.db.Where("service_id = ? AND port = ?", req.Msg.ServiceId, req.Msg.Port).Delete(&store.ServicePort{}); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("services")
	s.hub.Broadcast("websites")
	s.hub.Broadcast("hosts")

	return connect.NewResponse(&northstar.Empty{}), nil
}

func (s *NorthstarServer) AddServiceDependency(
	ctx context.Context,
	req *connect.Request[northstar.AddServiceDependencyRequest],
) (*connect.Response[northstar.Empty], error) {
	dep := store.ServiceDependency{
		ServiceID:   uint(req.Msg.ServiceId),
		DependsOnID: uint(req.Msg.DependsOnId),
	}

	if result := s.db.Create(&dep); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("services")

	return connect.NewResponse(&northstar.Empty{}), nil
}

func (s *NorthstarServer) DeleteServiceDependency(
	ctx context.Context,
	req *connect.Request[northstar.DeleteServiceDependencyRequest],
) (*connect.Response[northstar.Empty], error) {
	if result := s.db.Where("service_id = ? AND depends_on_id = ?", req.Msg.ServiceId, req.Msg.DependsOnId).Delete(&store.ServiceDependency{}); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("services")

	return connect.NewResponse(&northstar.Empty{}), nil
}
