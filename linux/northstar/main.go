package main

import (
	"crypto/tls"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"gorm.io/gorm"

	"bonfire/northstar/pkg/api"
	"bonfire/northstar/pkg/certs"
	"bonfire/northstar/pkg/store"
	"bonfire/northstar/proto/northstarconnect"
)

//go:embed ui/dist/*
var uiDist embed.FS

func main() {

	if err := os.MkdirAll(api.UploadDir, 0755); err != nil {
		log.Fatalf("failed to create upload directory: %v", err)
	}
	isDev := flag.Bool("dev", false, "run in development mode")
	httpPort := flag.String("http", ":8080", "HTTP port (redirects to HTTPS)")
	httpsPort := flag.String("https", ":8443", "HTTPS port")
	flag.Parse()

	db, err := store.New("northstar.db")
	if err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}

	mux := http.NewServeMux()

	northstarServer := api.NewNorthstarServer(db)

	path, handler := northstarconnect.NewNorthstarHandler(northstarServer)
	mux.Handle(path, handler)

	mux.HandleFunc("/api/upload", northstarServer.HandleUpload)

	mux.HandleFunc("/api/upload-file", northstarServer.HandleFileUpload)

	mux.Handle("/api/ws", northstarServer.WebSocketHandler())

	mux.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir(api.UploadDir))))

	if *isDev {
		fmt.Println("Dev mode enabled: Proxying UI requests to http://localhost:5173")
		target, _ := url.Parse("http://localhost:5173")
		proxy := httputil.NewSingleHostReverseProxy(target)
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			proxy.ServeHTTP(w, r)
		})
	} else {
		uiFS, err := fs.Sub(uiDist, "ui/dist")
		if err != nil {
			log.Fatalf("failed to create sub filesystem: %v", err)
		}

		fileServer := http.FileServer(http.FS(uiFS))

		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

			f, err := uiFS.Open(r.URL.Path[1:])
			if err == nil {
				f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}

			index, err := uiFS.Open("index.html")
			if err != nil {
				http.Error(w, "index.html not found", http.StatusInternalServerError)
				return
			}
			index.Close()

			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
		})
	}

	tlsCert, err := certs.GenerateInMemoryCert()
	if err != nil {
		log.Fatalf("failed to generate in-memory certs: %v", err)
	}

	go func() {
		fmt.Printf("HTTP Server listening on %s (redirecting to HTTPS)\n", *httpPort)
		redirectMux := http.NewServeMux()
		redirectMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}

			targetHost := host
			if *httpsPort != ":443" {
				targetHost = host + *httpsPort
			}

			targetURL := "https://" + targetHost + r.URL.RequestURI()
			http.Redirect(w, r, targetURL, http.StatusMovedPermanently)
		})

		httpListener, err := net.Listen("tcp", *httpPort)
		if err != nil {
			log.Fatalf("HTTP listener error: %v", err)
		}

		httpServer := &http.Server{
			Handler: redirectMux,
		}

		if err := httpServer.Serve(&aclListener{Listener: httpListener, db: db}); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	server := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*tlsCert},
		},
	}

	httpsListener, err := net.Listen("tcp", *httpsPort)
	if err != nil {
		log.Fatalf("HTTPS listener error: %v", err)
	}

	tlsListener := tls.NewListener(&aclListener{Listener: httpsListener, db: db}, server.TLSConfig)

	fmt.Printf("HTTPS Server listening on %s\n", *httpsPort)
	if err := server.Serve(tlsListener); err != nil {
		log.Fatalf("HTTPS server error: %v", err)
	}
}

type aclListener struct {
	net.Listener
	db *gorm.DB
}

func (l *aclListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		if l.isAllowed(conn.RemoteAddr()) {
			return conn, nil
		}

		conn.Close()
	}
}

func (l *aclListener) isAllowed(addr net.Addr) bool {
	var allowedIPs []store.AllowedIP
	if err := l.db.Find(&allowedIPs).Error; err != nil {
		return false
	}

	if len(allowedIPs) == 0 {
		ipStr, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			ipStr = addr.String()
		}
		ip := net.ParseIP(ipStr)
		if ip != nil && (ip.IsLoopback() || ip.String() == "127.0.0.1" || ip.String() == "::1") {
			return true
		}
		return false
	}

	ipStr, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		ipStr = addr.String()
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, aip := range allowedIPs {
		_, network, err := net.ParseCIDR(aip.CIDR)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}
