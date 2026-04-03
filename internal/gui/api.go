package gui

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ChatMsg represents a chat message
type ChatMsg struct {
	Sender    string `json:"sender"`
	Text      string `json:"text"`
	Timestamp int64  `json:"timestamp"`
}

// API handles REST API requests
type API struct {
	server   *Server
	mu       sync.RWMutex
	status   *Status
	peers    []*Peer
	chatMsgs []ChatMsg
}

// Status represents the mesh status
type Status struct {
	Connected   bool      `json:"connected"`
	NodeID      string    `json:"node_id"`
	MeshName    string    `json:"mesh_name"`
	MeshIP      string    `json:"mesh_ip"`
	Transport   string    `json:"transport"`
	Uptime      int64     `json:"uptime_seconds"`
	PeerCount   int       `json:"peer_count"`
	BytesSent   uint64    `json:"bytes_sent"`
	BytesRecv   uint64    `json:"bytes_recv"`
	LastUpdated time.Time `json:"last_updated"`
}

// Peer represents a connected peer
type Peer struct {
	NodeID        string    `json:"node_id"`
	MeshIP        string    `json:"mesh_ip"`
	Endpoint      string    `json:"endpoint,omitempty"`
	Roles         []string  `json:"roles"`
	Connected     bool      `json:"connected"`
	LastHandshake time.Time `json:"last_handshake"`
	BytesSent     uint64    `json:"bytes_sent"`
	BytesRecv     uint64    `json:"bytes_recv"`
	Latency       int64     `json:"latency_ms"`
}

// NewAPI creates a new API handler
func NewAPI(server *Server) *API {
	return &API{
		server:   server,
		status:   &Status{},
		peers:    make([]*Peer, 0),
		chatMsgs: make([]ChatMsg, 0),
	}
}

// ServeHTTP handles API requests
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Remove /api/ prefix
	path := strings.TrimPrefix(r.URL.Path, "/api")

	switch {
	case path == "/status" && r.Method == "GET":
		a.handleGetStatus(w, r)
	case path == "/peers" && r.Method == "GET":
		a.handleGetPeers(w, r)
	case path == "/connect" && r.Method == "POST":
		a.handleConnect(w, r)
	case path == "/disconnect" && r.Method == "POST":
		a.handleDisconnect(w, r)
	case path == "/stats" && r.Method == "GET":
		a.handleGetStats(w, r)
	case path == "/chat" && r.Method == "GET":
		a.handleGetChat(w, r)
	case path == "/chat" && r.Method == "POST":
		a.handlePostChat(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleGetStatus returns the current mesh status
func (a *API) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	status := a.status
	a.mu.RUnlock()

	a.writeJSON(w, status)
}

// handleGetPeers returns the list of peers
func (a *API) handleGetPeers(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	peers := a.peers
	a.mu.RUnlock()

	a.writeJSON(w, peers)
}

// handleConnect initiates a connection
func (a *API) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// TODO: Actually connect to daemon
	// For now, return success
	a.writeJSON(w, map[string]string{"status": "connecting"})
}

// handleDisconnect disconnects from the mesh
func (a *API) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	// TODO: Actually disconnect
	a.writeJSON(w, map[string]string{"status": "disconnecting"})
}

// handleGetStats returns traffic statistics
func (a *API) handleGetStats(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	status := a.status
	a.mu.RUnlock()

	stats := map[string]interface{}{
		"bytes_sent": status.BytesSent,
		"bytes_recv": status.BytesRecv,
		"peer_count": status.PeerCount,
		"uptime":     status.Uptime,
	}

	a.writeJSON(w, stats)
}

// handleGetChat returns the chat message history
func (a *API) handleGetChat(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	msgs := a.chatMsgs
	a.mu.RUnlock()

	a.writeJSON(w, msgs)
}

// handlePostChat receives a new chat message from the client
func (a *API) handlePostChat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if a.server != nil && a.server.onChatSend != nil {
		a.server.onChatSend(req.Text)
	}

	a.writeJSON(w, map[string]string{"status": "sent"})
}

// AddChatMessage appends a chat message, capped at 200 entries
func (a *API) AddChatMessage(msg ChatMsg) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.chatMsgs = append(a.chatMsgs, msg)
	if len(a.chatMsgs) > 200 {
		a.chatMsgs = a.chatMsgs[len(a.chatMsgs)-200:]
	}
}

// SetStatus updates the status
func (a *API) SetStatus(status *Status) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status = status
}

// SetPeers updates the peers list
func (a *API) SetPeers(peers []*Peer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.peers = peers
}

// writeJSON writes a JSON response
func (a *API) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// writeError writes an error response
func (a *API) writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
