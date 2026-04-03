package tunnel_test

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// --- In-memory conn.Bind ---

// memEndpoint implements conn.Endpoint for in-memory routing.
type memEndpoint struct {
	addr string
}

func (e *memEndpoint) ClearSrc()           {}
func (e *memEndpoint) SrcToString() string { return "" }
func (e *memEndpoint) DstToString() string { return e.addr }
func (e *memEndpoint) DstToBytes() []byte  { return []byte(e.addr) }
func (e *memEndpoint) DstIP() netip.Addr {
	a, _ := netip.ParseAddr(e.addr)
	return a
}
func (e *memEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

// memBind implements conn.Bind backed by in-memory channels.
// Packets sent via Send() are delivered to the peer's receive channel.
type memBind struct {
	mu      sync.Mutex
	recvCh  chan memPacket
	peers   map[string]*memBind // endpoint addr -> peer bind
	closed  bool
}

type memPacket struct {
	data     []byte
	endpoint conn.Endpoint
}

func newMemBind() *memBind {
	return &memBind{
		recvCh: make(chan memPacket, 256),
		peers:  make(map[string]*memBind),
	}
}

// wire connects two memBinds so that traffic sent to addrB arrives at bindB and vice versa.
func wire(bindA *memBind, addrA string, bindB *memBind, addrB string) {
	bindA.mu.Lock()
	bindA.peers[addrB] = bindB
	bindA.mu.Unlock()

	bindB.mu.Lock()
	bindB.peers[addrA] = bindA
	bindB.mu.Unlock()
}

func (b *memBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	// Reopen if previously closed (WireGuard calls Close then Open on Up)
	if b.closed {
		b.recvCh = make(chan memPacket, 256)
		b.closed = false
	}
	b.mu.Unlock()

	recv := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		pkt, ok := <-b.recvCh
		if !ok {
			return 0, net.ErrClosed
		}
		n := copy(bufs[0], pkt.data)
		sizes[0] = n
		eps[0] = pkt.endpoint
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, port, nil
}

func (b *memBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.closed = true
		close(b.recvCh)
	}
	return nil
}

func (b *memBind) SetMark(uint32) error { return nil }
func (b *memBind) BatchSize() int       { return 1 }

func (b *memBind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	dst := endpoint.DstToString()
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return net.ErrClosed
	}
	peer, ok := b.peers[dst]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("no peer for %s", dst)
	}

	// Find our own address by searching the peer's table
	var srcAddr string
	peer.mu.Lock()
	if peer.closed {
		peer.mu.Unlock()
		return net.ErrClosed
	}
	for addr, bind := range peer.peers {
		if bind == b {
			srcAddr = addr
			break
		}
	}
	peer.mu.Unlock()

	for _, buf := range bufs {
		data := make([]byte, len(buf))
		copy(data, buf)
		// Hold peer lock while writing to prevent race with Close()
		peer.mu.Lock()
		if peer.closed {
			peer.mu.Unlock()
			return net.ErrClosed
		}
		select {
		case peer.recvCh <- memPacket{data: data, endpoint: &memEndpoint{addr: srcAddr}}:
		default:
		}
		peer.mu.Unlock()
	}
	return nil
}

func (b *memBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &memEndpoint{addr: s}, nil
}

var _ conn.Bind = (*memBind)(nil)
var _ conn.Endpoint = (*memEndpoint)(nil)

// --- Test node ---

type testNode struct {
	name       string
	privateKey [32]byte
	publicKey  [32]byte
	meshIP     netip.Addr
	bind       *memBind
	wgDev      *device.Device
	net        *netstack.Net
}

func newTestNode(t *testing.T, name string, ip string) *testNode {
	t.Helper()

	// Generate keypair
	var private [32]byte
	// Deterministic keys from name for reproducibility
	h := []byte(name + "-ghostwire-test-key-seed-padding!")
	copy(private[:], h[:32])
	// Clamp for X25519
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	var public [32]byte
	curve25519.ScalarBaseMult(&public, &private)

	meshIP := netip.MustParseAddr(ip)

	// Create userspace TUN via netstack (no root needed)
	tunDev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{meshIP},
		nil, // no DNS
		1420,
	)
	if err != nil {
		t.Fatalf("CreateNetTUN for %s: %v", name, err)
	}

	bind := newMemBind()
	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", name))
	wgDev := device.NewDevice(tunDev, bind, logger)

	// Configure private key
	ipc := fmt.Sprintf("private_key=%s\n", hex.EncodeToString(private[:]))
	if err := wgDev.IpcSet(ipc); err != nil {
		t.Fatalf("IpcSet private key for %s: %v", name, err)
	}

	return &testNode{
		name:       name,
		privateKey: private,
		publicKey:  public,
		meshIP:     meshIP,
		bind:       bind,
		wgDev:      wgDev,
		net:        tnet,
	}
}

func (n *testNode) addPeer(t *testing.T, peer *testNode, peerAddr string) {
	t.Helper()
	ipc := fmt.Sprintf(
		"public_key=%s\nallowed_ip=%s/32\nendpoint=%s\npersistent_keepalive_interval=1\n",
		hex.EncodeToString(peer.publicKey[:]),
		peer.meshIP.String(),
		peerAddr,
	)
	if err := n.wgDev.IpcSet(ipc); err != nil {
		t.Fatalf("%s: add peer %s: %v", n.name, peer.name, err)
	}
}

func (n *testNode) close() {
	n.wgDev.Close()
	n.bind.Close()
}

// --- Tests ---

func TestTwoNodeTunnel(t *testing.T) {
	t.Log("Creating two WireGuard nodes with in-memory transport...")
	nodeA := newTestNode(t, "alpha", "10.0.0.1")
	defer nodeA.close()

	nodeB := newTestNode(t, "bravo", "10.0.0.2")
	defer nodeB.close()

	// Wire the binds together
	wire(nodeA.bind, "10.0.0.1:1", nodeB.bind, "10.0.0.2:1")

	// Bring devices up first (opens the bind)
	nodeA.wgDev.Up()
	nodeB.wgDev.Up()

	// Now add peers (triggers handshake with bind already open)
	nodeA.addPeer(t, nodeB, "10.0.0.2:1")
	nodeB.addPeer(t, nodeA, "10.0.0.1:1")

	t.Log("WireGuard handshake should happen automatically...")
	time.Sleep(2 * time.Second)

	// --- Test TCP traffic A -> B ---
	t.Log("Testing TCP: alpha -> bravo...")
	testMessage := []byte("Hello from alpha through the WireGuard tunnel!")
	var wg sync.WaitGroup
	var serverErr error
	var received []byte

	// Start TCP listener on bravo
	wg.Add(1)
	go func() {
		defer wg.Done()
		ln, err := nodeB.net.ListenTCP(&net.TCPAddr{Port: 7777})
		if err != nil {
			serverErr = fmt.Errorf("listen: %w", err)
			return
		}
		defer ln.Close()

		conn, err := ln.Accept()
		if err != nil {
			serverErr = fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			serverErr = fmt.Errorf("read: %w", err)
			return
		}
		received = buf[:n]

		// Echo it back
		conn.Write(received)
	}()

	// Give listener time to start
	time.Sleep(200 * time.Millisecond)

	// Connect from alpha
	conn, err := nodeA.net.DialContextTCPAddrPort(
		t.Context(),
		netip.AddrPortFrom(nodeB.meshIP, 7777),
	)
	if err != nil {
		t.Fatalf("alpha dial bravo: %v", err)
	}

	// Send data
	_, err = conn.Write(testMessage)
	if err != nil {
		t.Fatalf("alpha write: %v", err)
	}

	// Read echo
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("alpha read echo: %v", err)
	}
	conn.Close()

	wg.Wait()

	if serverErr != nil {
		t.Fatalf("bravo server error: %v", serverErr)
	}

	t.Logf("  Sent:     %q", testMessage)
	t.Logf("  Received: %q", received)
	t.Logf("  Echo:     %q", buf[:n])

	if string(received) != string(testMessage) {
		t.Fatalf("bravo received %q, want %q", received, testMessage)
	}
	if string(buf[:n]) != string(testMessage) {
		t.Fatalf("echo mismatch: got %q, want %q", buf[:n], testMessage)
	}
	t.Log("  TCP round-trip through encrypted tunnel: PASS")
}

func TestThreeNodeMesh(t *testing.T) {
	t.Log("Creating three-node mesh: alpha, bravo, charlie...")
	nodeA := newTestNode(t, "alpha-3", "10.0.0.1")
	defer nodeA.close()

	nodeB := newTestNode(t, "bravo-3", "10.0.0.2")
	defer nodeB.close()

	nodeC := newTestNode(t, "charlie-3", "10.0.0.3")
	defer nodeC.close()

	// Wire all pairs
	wire(nodeA.bind, "10.0.0.1:1", nodeB.bind, "10.0.0.2:1")
	wire(nodeA.bind, "10.0.0.1:1", nodeC.bind, "10.0.0.3:1")
	wire(nodeB.bind, "10.0.0.2:1", nodeC.bind, "10.0.0.3:1")

	// Bring all up first (opens the binds)
	nodeA.wgDev.Up()
	nodeB.wgDev.Up()
	nodeC.wgDev.Up()

	// Now add all peers to each node (full mesh)
	nodeA.addPeer(t, nodeB, "10.0.0.2:1")
	nodeA.addPeer(t, nodeC, "10.0.0.3:1")

	nodeB.addPeer(t, nodeA, "10.0.0.1:1")
	nodeB.addPeer(t, nodeC, "10.0.0.3:1")

	nodeC.addPeer(t, nodeA, "10.0.0.1:1")
	nodeC.addPeer(t, nodeB, "10.0.0.2:1")

	t.Log("Waiting for WireGuard handshakes...")
	time.Sleep(2 * time.Second)

	// Test all 6 directional paths concurrently
	type pathTest struct {
		from, to *testNode
		msg      string
	}
	paths := []pathTest{
		{nodeA, nodeB, "alpha->bravo"},
		{nodeA, nodeC, "alpha->charlie"},
		{nodeB, nodeA, "bravo->alpha"},
		{nodeB, nodeC, "bravo->charlie"},
		{nodeC, nodeA, "charlie->alpha"},
		{nodeC, nodeB, "charlie->bravo"},
	}

	basePort := 9000
	var mu sync.Mutex
	results := make(map[string]bool)
	var wg sync.WaitGroup

	for i, p := range paths {
		port := basePort + i
		wg.Add(1)
		go func(p pathTest, port int) {
			defer wg.Done()

			// Listener on 'to' node
			ln, err := p.to.net.ListenTCP(&net.TCPAddr{Port: port})
			if err != nil {
				t.Errorf("%s: listen on port %d: %v", p.msg, port, err)
				return
			}
			defer ln.Close()

			// Accept in background
			type acceptResult struct {
				data []byte
				err  error
			}
			acceptCh := make(chan acceptResult, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					acceptCh <- acceptResult{err: err}
					return
				}
				defer c.Close()
				buf := make([]byte, 4096)
				n, err := c.Read(buf)
				if err != nil && err != io.EOF {
					acceptCh <- acceptResult{err: err}
					return
				}
				acceptCh <- acceptResult{data: buf[:n]}
			}()

			time.Sleep(100 * time.Millisecond)

			// Dial from 'from' node
			c, err := p.from.net.DialContextTCPAddrPort(
				t.Context(),
				netip.AddrPortFrom(p.to.meshIP, uint16(port)),
			)
			if err != nil {
				t.Errorf("%s: dial: %v", p.msg, err)
				return
			}
			defer c.Close()

			payload := fmt.Sprintf("mesh-test:%s", p.msg)
			c.Write([]byte(payload))
			c.CloseWrite()

			// Wait for server to receive
			select {
			case res := <-acceptCh:
				if res.err != nil {
					t.Errorf("%s: server: %v", p.msg, res.err)
					return
				}
				if string(res.data) != payload {
					t.Errorf("%s: got %q, want %q", p.msg, res.data, payload)
					return
				}
				mu.Lock()
				results[p.msg] = true
				mu.Unlock()
			case <-time.After(5 * time.Second):
				t.Errorf("%s: timeout waiting for data", p.msg)
			}
		}(p, port)
	}

	wg.Wait()

	t.Log("Results:")
	for _, p := range paths {
		status := "FAIL"
		if results[p.msg] {
			status = "PASS"
		}
		t.Logf("  %s: %s", p.msg, status)
	}

	if len(results) != len(paths) {
		t.Fatalf("Only %d/%d paths succeeded", len(results), len(paths))
	}
	t.Logf("All %d mesh paths passed encrypted traffic successfully!", len(paths))
}

func TestBulkDataTransfer(t *testing.T) {
	t.Log("Testing bulk data transfer (1MB) through encrypted tunnel...")
	nodeA := newTestNode(t, "sender", "10.0.0.1")
	defer nodeA.close()

	nodeB := newTestNode(t, "receiver", "10.0.0.2")
	defer nodeB.close()

	wire(nodeA.bind, "10.0.0.1:1", nodeB.bind, "10.0.0.2:1")
	nodeA.wgDev.Up()
	nodeB.wgDev.Up()
	nodeA.addPeer(t, nodeB, "10.0.0.2:1")
	nodeB.addPeer(t, nodeA, "10.0.0.1:1")

	time.Sleep(2 * time.Second)

	// Generate 1MB of test data
	dataSize := 1024 * 1024
	sendData := make([]byte, dataSize)
	for i := range sendData {
		sendData[i] = byte(i % 251) // Prime modulus for pattern detection
	}

	var wg sync.WaitGroup
	var recvData []byte
	var serverErr error

	// Receiver
	wg.Add(1)
	go func() {
		defer wg.Done()
		ln, err := nodeB.net.ListenTCP(&net.TCPAddr{Port: 5555})
		if err != nil {
			serverErr = fmt.Errorf("listen: %w", err)
			return
		}
		defer ln.Close()

		c, err := ln.Accept()
		if err != nil {
			serverErr = fmt.Errorf("accept: %w", err)
			return
		}
		defer c.Close()

		recvData, serverErr = io.ReadAll(c)
	}()

	time.Sleep(200 * time.Millisecond)

	// Sender
	start := time.Now()
	c, err := nodeA.net.DialContextTCPAddrPort(
		t.Context(),
		netip.AddrPortFrom(nodeB.meshIP, 5555),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	written := 0
	for written < len(sendData) {
		chunk := 32 * 1024
		if written+chunk > len(sendData) {
			chunk = len(sendData) - written
		}
		n, err := c.Write(sendData[written : written+chunk])
		if err != nil {
			t.Fatalf("write at offset %d: %v", written, err)
		}
		written += n
	}
	c.Close()
	wg.Wait()
	elapsed := time.Since(start)

	if serverErr != nil {
		t.Fatalf("receiver error: %v", serverErr)
	}

	t.Logf("  Sent:     %d bytes", len(sendData))
	t.Logf("  Received: %d bytes", len(recvData))
	t.Logf("  Time:     %v", elapsed)
	if elapsed.Seconds() > 0 {
		t.Logf("  Rate:     %.1f MB/s", float64(len(sendData))/elapsed.Seconds()/1024/1024)
	}

	if len(recvData) != len(sendData) {
		t.Fatalf("size mismatch: got %d, want %d", len(recvData), len(sendData))
	}

	for i := range sendData {
		if sendData[i] != recvData[i] {
			t.Fatalf("data mismatch at byte %d: got %d, want %d", i, recvData[i], sendData[i])
		}
	}
	t.Log("  1MB bulk transfer with byte-level verification: PASS")
}
