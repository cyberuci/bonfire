package api

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"golang.org/x/net/websocket"
)

type InvalidationEvent struct {
	Type string `json:"type"`
}

type client struct {
	conn *websocket.Conn
	send chan []byte
}

type Hub struct {
	mu      sync.Mutex
	clients map[*client]struct{}
}

func NewHub() *Hub {
	return &Hub{
		clients: make(map[*client]struct{}),
	}
}

func (h *Hub) Broadcast(resourceType string) {
	event := InvalidationEvent{Type: resourceType}
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	for c := range h.clients {
		select {
		case c.send <- data:
		default:

		}
	}
}

func (h *Hub) Handler() http.Handler {
	return websocket.Handler(func(ws *websocket.Conn) {
		c := &client{
			conn: ws,
			send: make(chan []byte, 64),
		}

		h.mu.Lock()
		h.clients[c] = struct{}{}
		h.mu.Unlock()

		defer ws.Close()

		done := make(chan struct{})
		go func() {
			defer close(done)
			for msg := range c.send {
				if _, err := ws.Write(msg); err != nil {
					log.Printf("ws: failed to write to client: %v", err)
					_ = ws.Close()
					return
				}
			}
		}()

		buf := make([]byte, 1024)
		for {
			if _, err := ws.Read(buf); err != nil {
				break
			}
		}

		h.mu.Lock()
		delete(h.clients, c)
		h.mu.Unlock()

		close(c.send)
		<-done
	})
}
