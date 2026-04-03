package mavlink

import (
	"net"
	"testing"
	"time"
)

// mavlinkHeartbeat returns a minimal valid MAVLink v1 HEARTBEAT frame (message ID 0).
// Layout: STX LEN SEQ SYS COMP MSGID [payload(9 bytes)] CRC_LOW CRC_HIGH
// Total = HeaderSizeV1(6) + 9 payload + CRCSize(2) = 17 bytes.
func mavlinkHeartbeat() []byte {
	const payloadLen = 9
	frame := make([]byte, HeaderSizeV1+payloadLen+CRCSize)
	frame[0] = MagicV1    // STX
	frame[1] = payloadLen // payload length
	frame[2] = 0          // sequence
	frame[3] = 1          // system ID
	frame[4] = 1          // component ID
	frame[5] = 0          // message ID: HEARTBEAT = 0
	// bytes 6..14 are the payload (all zeros)
	// bytes 15..16 are the CRC (zeros — IsMAVLink only checks the magic byte)
	return frame
}

// sendUDP sends data from an ephemeral UDP socket to addr and returns the dialed conn.
func sendUDP(t *testing.T, addr net.Addr, data []byte) *net.UDPConn {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp4", addr.String())
	if err != nil {
		t.Fatalf("resolve proxy addr: %v", err)
	}
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		t.Fatalf("dial UDP: %v", err)
	}
	if _, err := conn.Write(data); err != nil {
		conn.Close()
		t.Fatalf("write UDP: %v", err)
	}
	return conn
}

// TestProxyStats verifies that a freshly created proxy reports zero stats.
func TestProxyStats(t *testing.T) {
	p := NewProxy(&ProxyConfig{ListenAddr: "127.0.0.1:0"})
	s := p.Stats()

	if s.PacketsReceived != 0 {
		t.Errorf("PacketsReceived = %d, want 0", s.PacketsReceived)
	}
	if s.PacketsForwarded != 0 {
		t.Errorf("PacketsForwarded = %d, want 0", s.PacketsForwarded)
	}
	if s.PacketsDropped != 0 {
		t.Errorf("PacketsDropped = %d, want 0", s.PacketsDropped)
	}
	if s.BytesReceived != 0 {
		t.Errorf("BytesReceived = %d, want 0", s.BytesReceived)
	}
	if s.BytesForwarded != 0 {
		t.Errorf("BytesForwarded = %d, want 0", s.BytesForwarded)
	}
}

// TestProxyForwardAndReceive sends a MAVLink heartbeat to the proxy and checks
// that PacketsReceived reaches 1 within a reasonable timeout.
func TestProxyForwardAndReceive(t *testing.T) {
	received := make(chan *PacketInfo, 1)

	p := NewProxy(&ProxyConfig{
		ListenAddr: "127.0.0.1:0",
		OnPacket: func(data []byte, info *PacketInfo) {
			select {
			case received <- info:
			default:
			}
		},
	})

	if err := p.Start(); err != nil {
		t.Fatalf("proxy Start: %v", err)
	}
	t.Cleanup(p.Stop)

	// Send a valid MAVLink heartbeat frame.
	client := sendUDP(t, p.ListenAddr(), mavlinkHeartbeat())
	defer client.Close()

	// Wait for OnPacket to fire or time out.
	select {
	case info := <-received:
		if info == nil {
			t.Fatal("OnPacket received nil PacketInfo for valid frame")
		}
		if info.MessageID != 0 {
			t.Errorf("MessageID = %d, want 0 (HEARTBEAT)", info.MessageID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for MAVLink packet")
	}

	// Verify stats.
	s := p.Stats()
	if s.PacketsReceived != 1 {
		t.Errorf("PacketsReceived = %d, want 1", s.PacketsReceived)
	}
	if s.BytesReceived == 0 {
		t.Error("BytesReceived = 0, want > 0")
	}
}

// TestProxyDeliverNoClient verifies Deliver returns an error before any client connects.
func TestProxyDeliverNoClient(t *testing.T) {
	p := NewProxy(&ProxyConfig{ListenAddr: "127.0.0.1:0"})

	if err := p.Start(); err != nil {
		t.Fatalf("proxy Start: %v", err)
	}
	t.Cleanup(p.Stop)

	if err := p.Deliver([]byte("hello")); err == nil {
		t.Error("Deliver with no client: expected error, got nil")
	}
}

// TestProxyDropsNonMAVLink verifies that non-MAVLink datagrams increment PacketsDropped.
func TestProxyDropsNonMAVLink(t *testing.T) {
	p := NewProxy(&ProxyConfig{ListenAddr: "127.0.0.1:0"})

	if err := p.Start(); err != nil {
		t.Fatalf("proxy Start: %v", err)
	}
	t.Cleanup(p.Stop)

	// Send garbage bytes that are not MAVLink.
	client := sendUDP(t, p.ListenAddr(), []byte("not mavlink data"))
	defer client.Close()

	// Poll briefly for the drop counter to appear.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s := p.Stats()
		if s.PacketsReceived == 1 {
			if s.PacketsDropped == 0 {
				t.Error("PacketsDropped = 0 after non-MAVLink datagram, want >= 1")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for non-MAVLink packet to be received")
}
