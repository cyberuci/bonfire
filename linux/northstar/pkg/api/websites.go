package api

import (
	"context"
	"errors"

	"bonfire/northstar/pkg/store"
	northstar "bonfire/northstar/proto"
	"connectrpc.com/connect"
	"gorm.io/gorm"
)

func (s *NorthstarServer) ListWebsites(
	ctx context.Context,
	req *connect.Request[northstar.Empty],
) (*connect.Response[northstar.WebsiteList], error) {
	var websites []store.Website
	if result := s.db.Find(&websites); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	var protoWebsites []*northstar.Website
	for _, w := range websites {
		protoWebsites = append(protoWebsites, s.toProtoWebsite(w))
	}

	return connect.NewResponse(&northstar.WebsiteList{
		Websites: protoWebsites,
	}), nil
}

func (s *NorthstarServer) AddWebsite(
	ctx context.Context,
	req *connect.Request[northstar.AddWebsiteRequest],
) (*connect.Response[northstar.Website], error) {
	website := store.Website{
		Name:        req.Msg.Name,
		URL:         req.Msg.Url,
		Username:    req.Msg.Username,
		OldPassword: req.Msg.OldPassword,
		Enumerated:  req.Msg.Enumerated,
	}
	if req.Msg.PasswordIndex != nil {
		pi := int(*req.Msg.PasswordIndex)
		website.PasswordIndex = &pi
	}

	if req.Msg.ServiceId != 0 {
		serviceID := uint(req.Msg.ServiceId)
		website.ServiceID = &serviceID
	}

	if result := s.db.Create(&website); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("websites")
	s.hub.Broadcast("services")

	return connect.NewResponse(s.toProtoWebsite(website)), nil
}

func (s *NorthstarServer) UpdateWebsite(
	ctx context.Context,
	req *connect.Request[northstar.UpdateWebsiteRequest],
) (*connect.Response[northstar.Website], error) {
	var website store.Website
	if result := s.db.First(&website, req.Msg.Id); result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, result.Error)
		}
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	website.Name = req.Msg.Name
	website.URL = req.Msg.Url
	website.Username = req.Msg.Username
	website.OldPassword = req.Msg.OldPassword
	website.Enumerated = req.Msg.Enumerated

	if req.Msg.PasswordIndex != nil {
		pi := int(*req.Msg.PasswordIndex)
		website.PasswordIndex = &pi
	} else {
		website.PasswordIndex = nil
	}

	if req.Msg.ServiceId != nil {
		if *req.Msg.ServiceId == 0 {
			website.ServiceID = nil
		} else {
			serviceID := uint(*req.Msg.ServiceId)
			website.ServiceID = &serviceID
		}
	}

	if result := s.db.Save(&website); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("websites")
	s.hub.Broadcast("services")

	return connect.NewResponse(s.toProtoWebsite(website)), nil
}

func (s *NorthstarServer) DeleteWebsite(
	ctx context.Context,
	req *connect.Request[northstar.DeleteWebsiteRequest],
) (*connect.Response[northstar.Empty], error) {
	if result := s.db.Delete(&store.Website{}, req.Msg.Id); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("websites")
	s.hub.Broadcast("services")

	return connect.NewResponse(&northstar.Empty{}), nil
}
