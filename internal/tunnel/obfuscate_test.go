package tunnel

import (
	"bytes"
	"net"
	"testing"
)

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	return r.c, cli
}

// TestObfuscatedTransportRoundTrip exercises the full post-knock stack with the
// obfuscation layer enabled: ObfuscatedConn over wsConn over TCP. It verifies
// that packets round-trip intact with boundaries preserved (one Write -> one
// Read), which is what the WireGuard bind relies on.
func TestObfuscatedTransportRoundTrip(t *testing.T) {
	rawSrv, rawCli := tcpPair(t)
	defer rawSrv.Close()
	defer rawCli.Close()

	// WebSocket framing: the client writes the length mask, the server reads
	// it — do them concurrently since the mask exchange is synchronous.
	type wsRes struct {
		ws  *wsConn
		err error
	}
	srvCh := make(chan wsRes, 1)
	go func() {
		ws, err := newWSConnServer(rawSrv)
		srvCh <- wsRes{ws, err}
	}()
	cliWS, err := newWSConn(rawCli)
	if err != nil {
		t.Fatalf("client ws: %v", err)
	}
	sr := <-srvCh
	if sr.err != nil {
		t.Fatalf("server ws: %v", sr.err)
	}

	b := &HTTPSBind{obfuscate: true}
	client := b.maybeObfuscate(cliWS)
	server := b.maybeObfuscate(sr.ws)

	big := make([]byte, 1300)
	for i := range big {
		big[i] = byte(i)
	}
	packets := [][]byte{[]byte("ping"), big, {0x00, 0x00}, []byte("pong")}

	go func() {
		for _, p := range packets {
			if _, err := client.Write(p); err != nil {
				return
			}
		}
	}()

	for i, want := range packets {
		buf := make([]byte, 65536)
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("read packet %d: %v", i, err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Errorf("packet %d: got %d bytes, want %d", i, n, len(want))
		}
	}
}

// TestMaybeObfuscatePassthrough confirms the layer is off by default.
func TestMaybeObfuscatePassthrough(t *testing.T) {
	b := &HTTPSBind{obfuscate: false}
	srv, cli := tcpPair(t)
	defer srv.Close()
	defer cli.Close()
	if got := b.maybeObfuscate(cli); got != net.Conn(cli) {
		t.Error("maybeObfuscate must return the conn unchanged when disabled")
	}
}
