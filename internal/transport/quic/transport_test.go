package quic

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestQUICAuthRoundTrip verifies the HMAC-based auth: a client with the matching
// mesh secret is accepted, and one with a wrong secret is rejected server-side.
func TestQUICAuthRoundTrip(t *testing.T) {
	secret := []byte("test-mesh-secret-0123456789abcdef")
	server, err := New(&Config{ServerName: "localhost", MeshSecret: secret})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	ln, err := server.Listen(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	accept := func() chan error {
		ch := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if conn != nil {
				conn.Close()
			}
			ch <- err
		}()
		return ch
	}

	// dial returns the live client connection (kept open until the server has
	// accepted, so closing it doesn't race the server's auth read).
	dial := func(sec []byte) (net.Conn, error) {
		c, err := New(&Config{ServerName: "localhost", MeshSecret: sec})
		if err != nil {
			t.Fatalf("New client: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return c.Dial(ctx, ln.Addr().String())
	}

	// Matching secret: server must accept.
	good := accept()
	conn, err := dial(secret)
	if err != nil {
		t.Fatalf("dial with good secret: %v", err)
	}
	select {
	case err := <-good:
		if err != nil {
			t.Fatalf("accept with good secret returned error: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("accept (good secret) timed out")
	}
	conn.Close()

	// Wrong secret: server must reject in verifyAuth.
	bad := accept()
	badConn, _ := dial([]byte("WRONG-secret-0123456789abcdefghij"))
	select {
	case err := <-bad:
		if err == nil {
			t.Fatal("accept with wrong secret should have failed auth")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("accept (bad secret) timed out")
	}
	if badConn != nil {
		badConn.Close()
	}
}
