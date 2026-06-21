package gui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestGUIIntegration(t *testing.T) {
	// Create server on random port
	s, err := New(&Config{
		ListenAddr: "127.0.0.1:0",
		AutoOpen:   false,
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	// Start server in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Get the actual address and token
	addr := s.Addr()
	token := s.AuthToken()
	t.Logf("Server running at: http://%s/?token=%s", addr, token)

	// Set some status data
	s.SetStatus(&Status{
		Connected: true,
		NodeID:    "test-node-1",
		MeshName:  "test-mesh",
		MeshIP:    "10.100.0.1",
		Transport: "https-mimic",
		Uptime:    3600,
		PeerCount: 2,
		BytesSent: 1024 * 1024,
		BytesRecv: 2048 * 1024,
	})

	s.SetPeers([]*Peer{
		{NodeID: "peer-1", MeshIP: "10.100.0.2", Connected: true, Latency: 25},
		{NodeID: "peer-2", MeshIP: "10.100.0.3", Connected: false, Latency: 0},
	})

	// Make HTTP requests to test the API
	client := &http.Client{Timeout: 5 * time.Second}

	// Test /api/status
	statusURL := fmt.Sprintf("http://%s/api/status?token=%s", addr, token)
	resp, err := client.Get(statusURL)
	if err != nil {
		t.Fatalf("GET /api/status error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /api/status status = %d, want 200", resp.StatusCode)
	}

	var status Status
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode status error: %v", err)
	}

	if status.NodeID != "test-node-1" {
		t.Errorf("status.NodeID = %q, want %q", status.NodeID, "test-node-1")
	}
	if !status.Connected {
		t.Error("status.Connected should be true")
	}
	if status.BytesSent != 1024*1024 {
		t.Errorf("status.BytesSent = %d, want %d", status.BytesSent, 1024*1024)
	}

	// Test /api/peers
	peersURL := fmt.Sprintf("http://%s/api/peers?token=%s", addr, token)
	resp, err = client.Get(peersURL)
	if err != nil {
		t.Fatalf("GET /api/peers error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /api/peers status = %d, want 200", resp.StatusCode)
	}

	var peers []*Peer
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		t.Fatalf("decode peers error: %v", err)
	}

	if len(peers) != 2 {
		t.Errorf("len(peers) = %d, want 2", len(peers))
	}
	if peers[0].NodeID != "peer-1" {
		t.Errorf("peers[0].NodeID = %q, want %q", peers[0].NodeID, "peer-1")
	}

	// Test /api/stats
	statsURL := fmt.Sprintf("http://%s/api/stats?token=%s", addr, token)
	resp, err = client.Get(statsURL)
	if err != nil {
		t.Fatalf("GET /api/stats error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /api/stats status = %d, want 200", resp.StatusCode)
	}

	// Test unauthorized access
	badURL := fmt.Sprintf("http://%s/api/status?token=wrong", addr)
	resp, err = client.Get(badURL)
	if err != nil {
		t.Fatalf("GET with bad token error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET with bad token status = %d, want 401", resp.StatusCode)
	}

	// Test static file serving (index.html)
	indexURL := fmt.Sprintf("http://%s/?token=%s", addr, token)
	resp, err = client.Get(indexURL)
	if err != nil {
		t.Fatalf("GET / error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET / status = %d, want 200", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Logf("GET / Content-Type = %q (expected text/html)", contentType)
	}

	// Stop server
	if err := s.Stop(context.Background()); err != nil {
		t.Errorf("Stop error: %v", err)
	}

	t.Log("GUI integration test passed")
}
