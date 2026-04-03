package gui

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

//go:embed web/*
var webAssets embed.FS

// Server is the GUI HTTP server
type Server struct {
	mu           sync.RWMutex
	config       *Config
	httpServer   *http.Server
	listener     net.Listener
	api          *API
	wsHub        *Hub
	authToken    string
	running      bool
	onChatSend   func(text string)
}

// Config configures the GUI server
type Config struct {
	ListenAddr string        // Default: "127.0.0.1:9999"
	AuthToken  string        // If empty, generated randomly
	AutoOpen   bool          // Open browser on start
	DaemonAddr string        // Daemon RPC address (if separate)
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		ListenAddr: "127.0.0.1:9999",
		AutoOpen:   true,
	}
}

// New creates a new GUI server
func New(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:9999"
	}

	// Generate auth token if not provided
	authToken := cfg.AuthToken
	if authToken == "" {
		tokenBytes := make([]byte, 16)
		if _, err := rand.Read(tokenBytes); err != nil {
			return nil, fmt.Errorf("generate auth token: %w", err)
		}
		authToken = hex.EncodeToString(tokenBytes)
	}

	s := &Server{
		config:    cfg,
		authToken: authToken,
		wsHub:     NewHub(),
	}

	s.api = NewAPI(s)

	return s, nil
}

// Start starts the GUI server
func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}

	// Create HTTP mux
	mux := http.NewServeMux()

	// API routes (require auth)
	mux.Handle("/api/", s.authMiddleware(http.HandlerFunc(s.api.ServeHTTP)))

	// WebSocket (requires auth via query param)
	mux.HandleFunc("/ws", s.handleWebSocket)

	// Static files
	webFS, err := fs.Sub(webAssets, "web")
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("create web filesystem: %w", err)
	}
	mux.Handle("/", http.FileServer(http.FS(webFS)))

	s.httpServer = &http.Server{
		Addr:         s.config.ListenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Start WebSocket hub
	go s.wsHub.Run()

	// Start HTTP server
	ln, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("listen: %w", err)
	}

	s.listener = ln
	s.running = true
	s.mu.Unlock()

	// Open browser if configured
	if s.config.AutoOpen {
		go func() {
			time.Sleep(100 * time.Millisecond)
			s.openBrowser()
		}()
	}

	return s.httpServer.Serve(ln)
}

// Stop stops the GUI server
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.wsHub.Close()

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			return err
		}
	}

	s.running = false
	return nil
}

// URL returns the server URL with auth token
func (s *Server) URL() string {
	return fmt.Sprintf("http://%s/?token=%s", s.Addr(), s.authToken)
}

// Addr returns the actual listening address
func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.config.ListenAddr
}

// AuthToken returns the auth token
func (s *Server) AuthToken() string {
	return s.authToken
}

// authMiddleware checks the auth token
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check Authorization header
		auth := r.Header.Get("Authorization")
		if auth == "Bearer "+s.authToken {
			next.ServeHTTP(w, r)
			return
		}

		// Check query parameter
		if r.URL.Query().Get("token") == s.authToken {
			next.ServeHTTP(w, r)
			return
		}

		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Check auth via query param
	if r.URL.Query().Get("token") != s.authToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	s.wsHub.ServeWs(w, r)
}

// Broadcast sends a message to all connected clients
func (s *Server) Broadcast(msgType string, data interface{}) {
	s.wsHub.Broadcast(Message{
		Type: msgType,
		Data: data,
	})
}

// openBrowser opens the default browser to the GUI URL
func (s *Server) openBrowser() {
	url := s.URL()
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return
	}

	cmd.Start()
}

// SetChatHandler sets the callback invoked when a client sends a chat message
func (s *Server) SetChatHandler(handler func(text string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChatSend = handler
}

// BroadcastChat adds a chat message to history and broadcasts it to all clients
func (s *Server) BroadcastChat(sender, text string, timestamp int64) {
	msg := ChatMsg{
		Sender:    sender,
		Text:      text,
		Timestamp: timestamp,
	}
	s.api.AddChatMessage(msg)
	s.Broadcast("chat", msg)
}

// SetStatus updates the mesh status and broadcasts to clients
func (s *Server) SetStatus(status *Status) {
	s.api.SetStatus(status)
	s.Broadcast("status", status)
}

// SetPeers updates the peer list and broadcasts to clients
func (s *Server) SetPeers(peers []*Peer) {
	s.api.SetPeers(peers)
	s.Broadcast("peers", peers)
}
