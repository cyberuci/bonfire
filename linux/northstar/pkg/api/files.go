package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"bonfire/northstar/pkg/store"
	"bonfire/northstar/proto"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *NorthstarServer) ListFiles(ctx context.Context, req *connect.Request[northstar.Empty]) (*connect.Response[northstar.FileList], error) {
	var dbFiles []store.File
	if err := s.db.Order("uploaded_at desc").Find(&dbFiles).Error; err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to list files: %w", err))
	}

	files := make([]*northstar.File, len(dbFiles))
	for i, f := range dbFiles {
		files[i] = &northstar.File{
			Id:          uint32(f.ID),
			Name:        f.Name,
			Size:        f.Size,
			Url:         f.URL,
			Description: f.Description,
			UploadedAt:  timestamppb.New(f.UploadedAt),
		}
	}

	return connect.NewResponse(&northstar.FileList{Files: files}), nil
}

func (s *NorthstarServer) UpdateFile(ctx context.Context, req *connect.Request[northstar.UpdateFileRequest]) (*connect.Response[northstar.File], error) {
	var file store.File
	if err := s.db.First(&file, req.Msg.Id).Error; err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("file not found: %w", err))
	}

	file.Name = req.Msg.Name
	file.Description = req.Msg.Description

	if err := s.db.Save(&file).Error; err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update file: %w", err))
	}

	s.hub.Broadcast("files")

	return connect.NewResponse(&northstar.File{
		Id:          uint32(file.ID),
		Name:        file.Name,
		Size:        file.Size,
		Url:         file.URL,
		Description: file.Description,
		UploadedAt:  timestamppb.New(file.UploadedAt),
	}), nil
}

func (s *NorthstarServer) DeleteFile(ctx context.Context, req *connect.Request[northstar.DeleteFileRequest]) (*connect.Response[northstar.Empty], error) {
	var file store.File
	if err := s.db.First(&file, req.Msg.Id).Error; err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("file not found: %w", err))
	}

	relPath := filepath.Join(UploadDir, filepath.Base(file.URL))
	if err := os.Remove(relPath); err != nil && !os.IsNotExist(err) {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to delete file from disk: %w", err))
	}

	if err := s.db.Delete(&file).Error; err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to delete file: %w", err))
	}

	s.hub.Broadcast("files")

	return connect.NewResponse(&northstar.Empty{}), nil
}
