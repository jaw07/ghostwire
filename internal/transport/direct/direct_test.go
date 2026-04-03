package direct

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestTCPDialAndListen(t *testing.T) {
	tr := New(&Config{Network: "tcp"})
	defer tr.Close()

	ctx := context.Background()
	ln, err := tr.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	msg := []byte("hello over direct TCP transport")

	var wg sync.WaitGroup
	var serverData []byte

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer conn.Close()
		serverData, _ = io.ReadAll(conn)
	}()

	conn, err := tr.Dial(ctx, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Write(msg)
	conn.Close()

	wg.Wait()

	if string(serverData) != string(msg) {
		t.Fatalf("got %q, want %q", serverData, msg)
	}
}

func TestUDPDialAndListen_SingleClient(t *testing.T) {
	tr := New(&Config{Network: "udp"})
	defer tr.Close()

	ctx := context.Background()
	ln, err := tr.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	// Send a UDP packet to the listener
	clientConn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	msg := []byte("hello via UDP")
	clientConn.Write(msg)

	// Accept the virtual connection
	serverConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer serverConn.Close()

	buf := make([]byte, 1024)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf[:n]) != string(msg) {
		t.Fatalf("got %q, want %q", buf[:n], msg)
	}
}

func TestUDPListener_MultipleClients(t *testing.T) {
	tr := New(&Config{Network: "udp"})
	defer tr.Close()

	ctx := context.Background()
	ln, err := tr.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	numClients := 3
	messages := make([]string, numClients)
	for i := range messages {
		messages[i] = string(rune('A'+i)) + "-client-data"
	}

	// Send from multiple clients
	for i := 0; i < numClients; i++ {
		conn, err := net.Dial("udp", addr)
		if err != nil {
			t.Fatalf("client %d dial: %v", i, err)
		}
		conn.Write([]byte(messages[i]))
		conn.Close()
	}

	// Accept all virtual connections
	received := make(map[string]bool)
	for i := 0; i < numClients; i++ {
		serverConn, err := ln.Accept()
		if err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}

		buf := make([]byte, 1024)
		n, err := serverConn.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		received[string(buf[:n])] = true
		serverConn.Close()
	}

	for _, msg := range messages {
		if !received[msg] {
			t.Errorf("missing message %q", msg)
		}
	}
	t.Logf("All %d UDP clients properly demuxed", numClients)
}

func TestUDPListener_SubsequentReadsFromSameClient(t *testing.T) {
	tr := New(&Config{Network: "udp"})
	defer tr.Close()

	ctx := context.Background()
	ln, err := tr.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	clientConn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	// Send first packet
	clientConn.Write([]byte("packet-1"))

	// Accept virtual connection
	serverConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer serverConn.Close()

	buf := make([]byte, 1024)
	n, _ := serverConn.Read(buf)
	if string(buf[:n]) != "packet-1" {
		t.Fatalf("first read: got %q", buf[:n])
	}

	// Send second packet from same client
	clientConn.Write([]byte("packet-2"))

	// Read should get the second packet (same virtual connection)
	time.Sleep(50 * time.Millisecond)
	n, err = serverConn.Read(buf)
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if string(buf[:n]) != "packet-2" {
		t.Fatalf("second read: got %q, want %q", buf[:n], "packet-2")
	}
	t.Log("Subsequent reads from same client properly routed to same vconn")
}

func TestUDPVirtualConn_WriteBack(t *testing.T) {
	tr := New(&Config{Network: "udp"})
	defer tr.Close()

	ctx := context.Background()
	ln, err := tr.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	// Client sends to listener
	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	clientConn, err := net.ListenUDP("udp", clientAddr)
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientConn.Close()

	serverAddr, _ := net.ResolveUDPAddr("udp", addr)
	clientConn.WriteToUDP([]byte("ping"), serverAddr)

	// Accept virtual connection
	serverConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer serverConn.Close()

	buf := make([]byte, 1024)
	n, _ := serverConn.Read(buf)
	if string(buf[:n]) != "ping" {
		t.Fatalf("got %q", buf[:n])
	}

	// Write back through virtual connection
	serverConn.Write([]byte("pong"))

	// Client should receive the reply
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = clientConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("client got %q, want %q", buf[:n], "pong")
	}
	t.Log("UDP bidirectional communication through virtual connection: PASS")
}

func TestTransportName(t *testing.T) {
	tr := New(nil)
	if tr.Name() != "direct" {
		t.Fatalf("got %q, want %q", tr.Name(), "direct")
	}
}

func TestTransportClose_RejectsDial(t *testing.T) {
	tr := New(&Config{Network: "tcp"})
	tr.Close()

	ctx := context.Background()
	_, err := tr.Dial(ctx, "127.0.0.1:1234")
	if err == nil {
		t.Fatal("expected error dialing closed transport")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Network != "udp" {
		t.Fatalf("default network: got %q, want %q", cfg.Network, "udp")
	}
}
