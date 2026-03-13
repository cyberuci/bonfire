package api

import (
	"context"

	"bonfire/northstar/pkg/store"
	northstar "bonfire/northstar/proto"
	"connectrpc.com/connect"
)

func (s *NorthstarServer) ListNetworks(
	ctx context.Context,
	req *connect.Request[northstar.Empty],
) (*connect.Response[northstar.NetworkList], error) {
	var networks []store.Network
	if result := s.db.Find(&networks); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	var protoNetworks []*northstar.Network
	for _, n := range networks {
		protoNetworks = append(protoNetworks, &northstar.Network{
			Id:          uint32(n.ID),
			Name:        n.Name,
			Cidr:        n.CIDR,
			Description: n.Description,
		})
	}

	return connect.NewResponse(&northstar.NetworkList{Networks: protoNetworks}), nil
}

func (s *NorthstarServer) AddNetwork(
	ctx context.Context,
	req *connect.Request[northstar.AddNetworkRequest],
) (*connect.Response[northstar.Network], error) {
	network := store.Network{
		Name:        req.Msg.Name,
		CIDR:        req.Msg.Cidr,
		Description: req.Msg.Description,
	}

	if result := s.db.Create(&network); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("networks")

	return connect.NewResponse(&northstar.Network{
		Id:          uint32(network.ID),
		Name:        network.Name,
		Cidr:        network.CIDR,
		Description: network.Description,
	}), nil
}

func (s *NorthstarServer) UpdateNetwork(
	ctx context.Context,
	req *connect.Request[northstar.UpdateNetworkRequest],
) (*connect.Response[northstar.Network], error) {
	var network store.Network
	if result := s.db.First(&network, req.Msg.Id); result.Error != nil {
		return nil, connect.NewError(connect.CodeNotFound, result.Error)
	}

	network.Name = req.Msg.Name
	network.CIDR = req.Msg.Cidr
	network.Description = req.Msg.Description

	if result := s.db.Save(&network); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("networks")

	return connect.NewResponse(&northstar.Network{
		Id:          uint32(network.ID),
		Name:        network.Name,
		Cidr:        network.CIDR,
		Description: network.Description,
	}), nil
}

func (s *NorthstarServer) DeleteNetwork(
	ctx context.Context,
	req *connect.Request[northstar.DeleteNetworkRequest],
) (*connect.Response[northstar.Empty], error) {
	if result := s.db.Delete(&store.Network{}, req.Msg.Id); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("networks")
	s.hub.Broadcast("hosts")

	return connect.NewResponse(&northstar.Empty{}), nil
}
