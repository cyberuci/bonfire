package api

import (
	"context"
	"errors"
	"net"
	"strings"

	"bonfire/northstar/pkg/store"
	northstar "bonfire/northstar/proto"
	"connectrpc.com/connect"
)

func (s *NorthstarServer) ListAllowedIPs(
	ctx context.Context,
	req *connect.Request[northstar.Empty],
) (*connect.Response[northstar.AllowedIPList], error) {
	var allowedIPs []store.AllowedIP
	if result := s.db.Find(&allowedIPs); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	var protoIPs []*northstar.AllowedIP
	for _, ip := range allowedIPs {
		protoIPs = append(protoIPs, &northstar.AllowedIP{
			Id:          uint32(ip.ID),
			Cidr:        ip.CIDR,
			Description: ip.Description,
		})
	}

	return connect.NewResponse(&northstar.AllowedIPList{AllowedIps: protoIPs}), nil
}

func (s *NorthstarServer) AddAllowedIP(
	ctx context.Context,
	req *connect.Request[northstar.AddAllowedIPRequest],
) (*connect.Response[northstar.AllowedIP], error) {
	if err := validateCIDR(req.Msg.Cidr); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	allowedIP := store.AllowedIP{
		CIDR:        req.Msg.Cidr,
		Description: req.Msg.Description,
	}

	if result := s.db.Create(&allowedIP); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("allowed_ips")

	return connect.NewResponse(&northstar.AllowedIP{
		Id:          uint32(allowedIP.ID),
		Cidr:        allowedIP.CIDR,
		Description: allowedIP.Description,
	}), nil
}

func (s *NorthstarServer) UpdateAllowedIP(
	ctx context.Context,
	req *connect.Request[northstar.UpdateAllowedIPRequest],
) (*connect.Response[northstar.AllowedIP], error) {
	if err := validateCIDR(req.Msg.Cidr); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	var allowedIP store.AllowedIP
	if result := s.db.First(&allowedIP, req.Msg.Id); result.Error != nil {
		return nil, connect.NewError(connect.CodeNotFound, result.Error)
	}

	allowedIP.CIDR = req.Msg.Cidr
	allowedIP.Description = req.Msg.Description

	if result := s.db.Save(&allowedIP); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("allowed_ips")

	return connect.NewResponse(&northstar.AllowedIP{
		Id:          uint32(allowedIP.ID),
		Cidr:        allowedIP.CIDR,
		Description: allowedIP.Description,
	}), nil
}

func (s *NorthstarServer) DeleteAllowedIP(
	ctx context.Context,
	req *connect.Request[northstar.DeleteAllowedIPRequest],
) (*connect.Response[northstar.Empty], error) {
	if result := s.db.Delete(&store.AllowedIP{}, req.Msg.Id); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("allowed_ips")

	return connect.NewResponse(&northstar.Empty{}), nil
}

func validateCIDR(input string) error {
	value := strings.TrimSpace(input)
	if value == "" {
		return errors.New("CIDR cannot be empty")
	}

	if !strings.Contains(value, "/") {
		if strings.Contains(value, ":") {
			value += "/128"
		} else {
			value += "/32"
		}
	}

	if _, _, err := net.ParseCIDR(value); err != nil {
		return errors.New("Invalid CIDR format")
	}

	return nil
}
