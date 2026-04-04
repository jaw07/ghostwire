package mavlink

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestForwarderCreateAndListLinks(t *testing.T) {
	f := NewForwarder()
	defer f.StopAll()

	err := f.CreateLink(LinkConfig{
		Name:       "test-link",
		Protocol:   "tcp",
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "127.0.0.1:9999",
	})
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	links := f.List()
	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}
	li := links[0]
	if li.Name != "test-link" {
		t.Errorf("name = %q, want %q", li.Name, "test-link")
	}
	if li.Protocol != "tcp" {
		t.Errorf("protocol = %q, want %q", li.Protocol, "tcp")
	}
	if li.Status != "listening" {
		t.Errorf("status = %q, want %q", li.Status, "listening")
	}
}

func TestForwarderRemoveLink(t *testing.T) {
	f := NewForwarder()
	defer f.StopAll()

	err := f.CreateLink(LinkConfig{
		Name:       "to-remove",
		Protocol:   "tcp",
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "127.0.0.1:9999",
	})
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	if err := f.RemoveLink("to-remove"); err != nil {
		t.Fatalf("RemoveLink: %v", err)
	}

	links := f.List()
	if len(links) != 0 {
		t.Fatalf("expected 0 links after remove, got %d", len(links))
	}
}

func TestForwarderDuplicateName(t *testing.T) {
	f := NewForwarder()
	defer f.StopAll()

	cfg := LinkConfig{
		Name:       "dup",
		Protocol:   "tcp",
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "127.0.0.1:9999",
	}

	if err := f.CreateLink(cfg); err != nil {
		t.Fatalf("first CreateLink: %v", err)
	}

	err := f.CreateLink(cfg)
	if err == nil {
		t.Fatal("expected error on duplicate name, got nil")
	}
}

func TestForwarderTCPForward(t *testing.T) {
	// Start a TCP echo server to act as the remote FC.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	f := NewForwarder()
	defer f.StopAll()

	err = f.CreateLink(LinkConfig{
		Name:       "tcp-fwd",
		Protocol:   "tcp",
		ListenAddr: "127.0.0.1:0",
		TargetAddr: echoLn.Addr().String(),
	})
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	links := f.List()
	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}
	listenAddr := links[0].ListenAddr

	// Connect as GCS.
	conn, err := net.DialTimeout("tcp", listenAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello mavlink")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Close write side so the echo server sees EOF and echoes back.
	conn.(*net.TCPConn).CloseWrite()

	buf, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != string(msg) {
		t.Errorf("got %q, want %q", buf, msg)
	}
}

func TestForwarderUDPForward(t *testing.T) {
	// Start a UDP echo server to act as the remote FC.
	echoAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	echoConn, err := net.ListenUDP("udp", echoAddr)
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoConn.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echoConn.WriteToUDP(buf[:n], addr)
		}
	}()

	f := NewForwarder()
	defer f.StopAll()

	err = f.CreateLink(LinkConfig{
		Name:       "udp-fwd",
		Protocol:   "udp",
		ListenAddr: "127.0.0.1:0",
		TargetAddr: echoConn.LocalAddr().String(),
	})
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	links := f.List()
	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}
	listenAddr := links[0].ListenAddr

	// Connect as GCS via UDP.
	gcsAddr, _ := net.ResolveUDPAddr("udp", listenAddr)
	gcsConn, err := net.DialUDP("udp", nil, gcsAddr)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer gcsConn.Close()

	msg := []byte("hello udp mavlink")
	if _, err := gcsConn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	gcsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := gcsConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf[:n]) != string(msg) {
		t.Errorf("got %q, want %q", buf[:n], msg)
	}

	// Verify stats were tracked.
	links = f.List()
	fmt.Printf("UDP link stats: sent=%d recv=%d conns=%d\n",
		links[0].BytesSent, links[0].BytesRecv, links[0].ActiveConns)
}
