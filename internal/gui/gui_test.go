package gui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewServer(t *testing.T) {
	s, err := New(nil)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	if s.authToken == "" {
		t.Error("authToken should be generated")
	}
	if len(s.authToken) != 32 { // 16 bytes hex encoded
		t.Errorf("authToken length = %d, want 32", len(s.authToken))
	}
}

func TestServerURL(t *testing.T) {
	s, _ := New(&Config{
		ListenAddr: "127.0.0.1:9999",
		AuthToken:  "test-token",
	})

	url := s.URL()
	expected := "http://127.0.0.1:9999/?token=test-token"
	if url != expected {
		t.Errorf("URL = %q, want %q", url, expected)
	}
}

func TestAPIGetStatus(t *testing.T) {
	s, _ := New(&Config{AuthToken: "test"})
	s.api.SetStatus(&Status{
		Connected: true,
		NodeID:    "node-1",
		MeshIP:    "10.100.0.1",
		Transport: "https-mimic",
	})

	req := httptest.NewRequest("GET", "/api/status?token=test", nil)
	w := httptest.NewRecorder()

	handler := s.authMiddleware(http.HandlerFunc(s.api.ServeHTTP))
	handler.ServeHTTP(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", res.StatusCode)
	}

	var status Status
	json.NewDecoder(res.Body).Decode(&status)

	if !status.Connected {
		t.Error("Connected should be true")
	}
	if status.NodeID != "node-1" {
		t.Errorf("NodeID = %q, want %q", status.NodeID, "node-1")
	}
}

func TestAPIGetPeers(t *testing.T) {
	s, _ := New(&Config{AuthToken: "test"})
	s.api.SetPeers([]*Peer{
		{NodeID: "peer-1", MeshIP: "10.100.0.2", Connected: true},
		{NodeID: "peer-2", MeshIP: "10.100.0.3", Connected: false},
	})

	req := httptest.NewRequest("GET", "/api/peers?token=test", nil)
	w := httptest.NewRecorder()

	handler := s.authMiddleware(http.HandlerFunc(s.api.ServeHTTP))
	handler.ServeHTTP(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", res.StatusCode)
	}

	var peers []*Peer
	json.NewDecoder(res.Body).Decode(&peers)

	if len(peers) != 2 {
		t.Errorf("len(peers) = %d, want 2", len(peers))
	}
}

func TestAPIUnauthorized(t *testing.T) {
	s, _ := New(&Config{AuthToken: "secret"})

	// No token
	req := httptest.NewRequest("GET", "/api/status", nil)
	w := httptest.NewRecorder()

	handler := s.authMiddleware(http.HandlerFunc(s.api.ServeHTTP))
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", w.Code)
	}

	// Wrong token
	req = httptest.NewRequest("GET", "/api/status?token=wrong", nil)
	w = httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", w.Code)
	}
}

func TestAPIAuthHeader(t *testing.T) {
	s, _ := New(&Config{AuthToken: "test-token"})

	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	handler := s.authMiddleware(http.HandlerFunc(s.api.ServeHTTP))
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", w.Code)
	}
}

func TestAPIConnect(t *testing.T) {
	s, _ := New(&Config{AuthToken: "test"})

	body := strings.NewReader(`{"passphrase":"secret"}`)
	req := httptest.NewRequest("POST", "/api/connect?token=test", body)
	w := httptest.NewRecorder()

	handler := s.authMiddleware(http.HandlerFunc(s.api.ServeHTTP))
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", w.Code)
	}
}

func TestAPIConnectReportsState(t *testing.T) {
	s, _ := New(&Config{AuthToken: "test"})
	s.api.SetStatus(&Status{Connected: true})

	body := strings.NewReader(`{"passphrase":"secret"}`)
	req := httptest.NewRequest("POST", "/api/connect?token=test", body)
	w := httptest.NewRecorder()
	s.authMiddleware(http.HandlerFunc(s.api.ServeHTTP)).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", w.Code)
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "connected" {
		t.Errorf("status = %q, want \"connected\" (no handler should report real state)", resp["status"])
	}
}

func TestAPIConnectHandler(t *testing.T) {
	s, _ := New(&Config{AuthToken: "test"})
	var got string
	s.SetConnectionHandlers(func(passphrase string) error {
		got = passphrase
		return nil
	}, nil)

	body := strings.NewReader(`{"passphrase":"secret"}`)
	req := httptest.NewRequest("POST", "/api/connect?token=test", body)
	w := httptest.NewRecorder()
	s.authMiddleware(http.HandlerFunc(s.api.ServeHTTP)).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", w.Code)
	}
	if got != "secret" {
		t.Errorf("onConnect passphrase = %q, want \"secret\"", got)
	}
}

func TestAPIDisconnect(t *testing.T) {
	s, _ := New(&Config{AuthToken: "test"})

	// No handler wired: disconnect is unavailable.
	req := httptest.NewRequest("POST", "/api/disconnect?token=test", nil)
	w := httptest.NewRecorder()
	s.authMiddleware(http.HandlerFunc(s.api.ServeHTTP)).ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("no-handler StatusCode = %d, want 503", w.Code)
	}

	// Handler wired: it is invoked and reports disconnecting.
	called := false
	s.SetConnectionHandlers(nil, func() error {
		called = true
		return nil
	})
	req = httptest.NewRequest("POST", "/api/disconnect?token=test", nil)
	w = httptest.NewRecorder()
	s.authMiddleware(http.HandlerFunc(s.api.ServeHTTP)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("handler StatusCode = %d, want 200", w.Code)
	}
	if !called {
		t.Error("onDisconnect was not invoked")
	}
}

func TestAPINotFound(t *testing.T) {
	s, _ := New(&Config{AuthToken: "test"})

	req := httptest.NewRequest("GET", "/api/unknown?token=test", nil)
	w := httptest.NewRecorder()

	handler := s.authMiddleware(http.HandlerFunc(s.api.ServeHTTP))
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("StatusCode = %d, want 404", w.Code)
	}
}

func TestHub(t *testing.T) {
	hub := NewHub()
	go hub.Run()
	defer hub.Close()

	// Initial client count should be 0
	if hub.ClientCount() != 0 {
		t.Errorf("ClientCount = %d, want 0", hub.ClientCount())
	}
}

func TestHubBroadcast(t *testing.T) {
	hub := NewHub()
	go hub.Run()
	defer hub.Close()

	// Broadcast should not block even with no clients
	hub.Broadcast(Message{Type: "test", Data: "hello"})
}

func TestStaticFiles(t *testing.T) {
	// Check that web assets are embedded
	data, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	if !strings.Contains(string(data), "ghostwire") {
		t.Error("index.html should contain 'ghostwire'")
	}

	if !strings.Contains(string(data), "<!DOCTYPE html>") {
		t.Error("index.html should be valid HTML")
	}
}

func TestServerStartStop(t *testing.T) {
	// Use a random available port
	s, err := New(&Config{
		ListenAddr: "127.0.0.1:0",
		AutoOpen:   false,
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	// Start in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.Stop(ctx); err != nil {
		t.Errorf("Stop error: %v", err)
	}
}

func TestBroadcast(t *testing.T) {
	s, _ := New(&Config{AuthToken: "test"})

	// Initialize hub
	go s.wsHub.Run()
	defer s.wsHub.Close()

	// Broadcast should not panic
	s.Broadcast("test", map[string]string{"key": "value"})
}

func TestSetStatus(t *testing.T) {
	s, _ := New(&Config{AuthToken: "test"})
	go s.wsHub.Run()
	defer s.wsHub.Close()

	status := &Status{
		Connected: true,
		NodeID:    "test-node",
	}

	s.SetStatus(status)

	// Verify API has updated status
	req := httptest.NewRequest("GET", "/api/status?token=test", nil)
	w := httptest.NewRecorder()

	handler := s.authMiddleware(http.HandlerFunc(s.api.ServeHTTP))
	handler.ServeHTTP(w, req)

	var got Status
	json.NewDecoder(w.Body).Decode(&got)

	if got.NodeID != "test-node" {
		t.Errorf("NodeID = %q, want %q", got.NodeID, "test-node")
	}
}

func TestSetPeers(t *testing.T) {
	s, _ := New(&Config{AuthToken: "test"})
	go s.wsHub.Run()
	defer s.wsHub.Close()

	peers := []*Peer{
		{NodeID: "peer-1", MeshIP: "10.0.0.1"},
	}

	s.SetPeers(peers)

	// Verify API has updated peers
	req := httptest.NewRequest("GET", "/api/peers?token=test", nil)
	w := httptest.NewRecorder()

	handler := s.authMiddleware(http.HandlerFunc(s.api.ServeHTTP))
	handler.ServeHTTP(w, req)

	var got []*Peer
	json.NewDecoder(w.Body).Decode(&got)

	if len(got) != 1 || got[0].NodeID != "peer-1" {
		t.Error("Peers not updated correctly")
	}
}
