package api

import (
	"context"

	"bonfire/northstar/pkg/store"
	northstar "bonfire/northstar/proto"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *NorthstarServer) toProtoInject(src store.Inject) *northstar.Inject {
	pi := &northstar.Inject{
		Id:            uint32(src.ID),
		Number:        src.Number,
		Title:         src.Title,
		Description:   src.Description,
		Content:       src.Content,
		Due:           timestamppb.New(src.Due),
		Completed:     src.Completed,
		SubmissionUrl: src.SubmissionURL,
	}

	for _, a := range src.Assignees {
		pi.Assignees = append(pi.Assignees, &northstar.Assignee{
			Id:       uint32(a.ID),
			Name:     a.Name,
			InjectId: uint32(a.InjectID),
		})
	}

	return pi
}

func (s *NorthstarServer) ListInjects(
	ctx context.Context,
	req *connect.Request[northstar.Empty],
) (*connect.Response[northstar.InjectList], error) {
	var injects []store.Inject

	if result := s.db.Preload("Assignees").Find(&injects); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	var protoInjects []*northstar.Inject
	for _, src := range injects {
		protoInjects = append(protoInjects, s.toProtoInject(src))
	}

	return connect.NewResponse(&northstar.InjectList{
		Injects: protoInjects,
	}), nil
}

func (s *NorthstarServer) AddInject(
	ctx context.Context,
	req *connect.Request[northstar.AddInjectRequest],
) (*connect.Response[northstar.Inject], error) {
	src := store.Inject{
		Number:      req.Msg.Number,
		Title:       req.Msg.Title,
		Description: req.Msg.Description,
		Content:     req.Msg.Content,
		Due:         req.Msg.Due.AsTime(),
	}

	for _, name := range req.Msg.AssigneeNames {
		src.Assignees = append(src.Assignees, store.Assignee{
			Name: name,
		})
	}

	if result := s.db.Create(&src); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("injects")

	return connect.NewResponse(s.toProtoInject(src)), nil
}

func (s *NorthstarServer) UpdateInject(
	ctx context.Context,
	req *connect.Request[northstar.UpdateInjectRequest],
) (*connect.Response[northstar.Inject], error) {
	var src store.Inject

	if result := s.db.Preload("Assignees").First(&src, req.Msg.Id); result.Error != nil {
		return nil, connect.NewError(connect.CodeNotFound, result.Error)
	}

	src.Number = req.Msg.Number
	src.Title = req.Msg.Title
	src.Description = req.Msg.Description
	src.Content = req.Msg.Content
	src.Completed = req.Msg.Completed
	if req.Msg.Due != nil {
		src.Due = req.Msg.Due.AsTime()
	}
	src.SubmissionURL = req.Msg.SubmissionUrl

	if err := s.db.Model(&src).Association("Assignees").Clear(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	var newAssignees []store.Assignee
	for _, name := range req.Msg.AssigneeNames {
		newAssignees = append(newAssignees, store.Assignee{Name: name})
	}
	src.Assignees = newAssignees

	if result := s.db.Save(&src); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("injects")

	return connect.NewResponse(s.toProtoInject(src)), nil
}

func (s *NorthstarServer) DeleteInject(
	ctx context.Context,
	req *connect.Request[northstar.DeleteInjectRequest],
) (*connect.Response[northstar.Empty], error) {
	if result := s.db.Delete(&store.Inject{}, req.Msg.Id); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("injects")

	return connect.NewResponse(&northstar.Empty{}), nil
}
