package api

import (
	"net/http"

	"bonfire/northstar/proto/northstarconnect"
	"gorm.io/gorm"
)

type NorthstarServer struct {
	northstarconnect.UnimplementedNorthstarHandler
	db  *gorm.DB
	hub *Hub
}

func NewNorthstarServer(db *gorm.DB) *NorthstarServer {
	return &NorthstarServer{
		db:  db,
		hub: NewHub(),
	}
}

func (s *NorthstarServer) WebSocketHandler() http.Handler {
	return s.hub.Handler()
}
