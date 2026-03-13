package api

import (
	"context"
	"fmt"

	"bonfire/northstar/pkg/store"
	northstar "bonfire/northstar/proto"
	"connectrpc.com/connect"
)

func categoryForIndex(i int) string {
	if i < 30 {
		return "linux"
	}
	if i < 60 {
		return "windows"
	}
	return "misc"
}

func (s *NorthstarServer) ListPasswords(
	ctx context.Context,
	req *connect.Request[northstar.Empty],
) (*connect.Response[northstar.PasswordList], error) {
	var entries []store.PasswordEntry
	if result := s.db.Order("`index` ASC").Find(&entries); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	assignments := make(map[int][]*northstar.PasswordAssignment)

	var hosts []store.Host
	s.db.Where("password_index IS NOT NULL").Find(&hosts)
	for _, h := range hosts {
		if h.PasswordIndex != nil {
			label := h.Hostname
			if label == "" {
				label = h.IP
			}
			assignments[*h.PasswordIndex] = append(assignments[*h.PasswordIndex], &northstar.PasswordAssignment{
				Type:     "host",
				Label:    label,
				EntityId: uint32(h.ID),
			})
		}
	}

	var services []store.Service
	s.db.Where("password_index IS NOT NULL").Find(&services)
	for _, svc := range services {
		if svc.PasswordIndex != nil {
			assignments[*svc.PasswordIndex] = append(assignments[*svc.PasswordIndex], &northstar.PasswordAssignment{
				Type:     "service",
				Label:    svc.Name,
				EntityId: uint32(svc.ID),
			})
		}
	}

	var websites []store.Website
	s.db.Where("password_index IS NOT NULL").Find(&websites)
	for _, w := range websites {
		if w.PasswordIndex != nil {
			assignments[*w.PasswordIndex] = append(assignments[*w.PasswordIndex], &northstar.PasswordAssignment{
				Type:     "website",
				Label:    w.Name,
				EntityId: uint32(w.ID),
			})
		}
	}

	var protoEntries []*northstar.PasswordEntry
	for _, e := range entries {
		protoEntries = append(protoEntries, &northstar.PasswordEntry{
			Index:       int32(e.Index),
			Category:    e.Category,
			Comment:     e.Comment,
			Assignments: assignments[e.Index],
		})
	}

	return connect.NewResponse(&northstar.PasswordList{Passwords: protoEntries}), nil
}

func (s *NorthstarServer) SeedPasswords(
	ctx context.Context,
	req *connect.Request[northstar.Empty],
) (*connect.Response[northstar.SeedPasswordsResponse], error) {

	var count int64
	s.db.Model(&store.PasswordEntry{}).Count(&count)
	if count > 0 {
		return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("passwords already seeded (%d entries exist)", count))
	}

	var entries []store.PasswordEntry
	for i := 0; i < 90; i++ {
		entries = append(entries, store.PasswordEntry{
			Index:    i,
			Category: categoryForIndex(i),
		})
	}

	if result := s.db.Create(&entries); result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}

	s.hub.Broadcast("passwords")

	return connect.NewResponse(&northstar.SeedPasswordsResponse{
		Count: int32(len(entries)),
	}), nil
}

func (s *NorthstarServer) UpdatePasswordComment(
	ctx context.Context,
	req *connect.Request[northstar.UpdatePasswordCommentRequest],
) (*connect.Response[northstar.Empty], error) {
	result := s.db.Model(&store.PasswordEntry{}).
		Where("`index` = ?", req.Msg.Index).
		Update("comment", req.Msg.Comment)

	if result.Error != nil {
		return nil, connect.NewError(connect.CodeInternal, result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("password index %d not found", req.Msg.Index))
	}

	s.hub.Broadcast("passwords")

	return connect.NewResponse(&northstar.Empty{}), nil
}

func (s *NorthstarServer) ClearPasswords(
	ctx context.Context,
	req *connect.Request[northstar.Empty],
) (*connect.Response[northstar.Empty], error) {
	tx := s.db.Begin()

	if err := tx.Model(&store.Host{}).Where("password_index IS NOT NULL").Update("password_index", nil).Error; err != nil {
		tx.Rollback()
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Model(&store.Service{}).Where("password_index IS NOT NULL").Update("password_index", nil).Error; err != nil {
		tx.Rollback()
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Model(&store.Website{}).Where("password_index IS NOT NULL").Update("password_index", nil).Error; err != nil {
		tx.Rollback()
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if err := tx.Where("1 = 1").Delete(&store.PasswordEntry{}).Error; err != nil {
		tx.Rollback()
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if err := tx.Commit().Error; err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	s.hub.Broadcast("passwords")

	return connect.NewResponse(&northstar.Empty{}), nil
}
