package routing

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// NATType represents the type of NAT a node is behind
type NATType uint8

const (
	NATNone           NATType = iota // No NAT, public IP
	NATFull                          // Full cone NAT (easiest)
	NATRestricted                    // Address-restricted cone
	NATPortRestricted                // Port-restricted cone
	NATSymmetric                     // Symmetric NAT (hardest)
	NATUnknown                       // Not yet determined
)

func (n NATType) String() string {
	switch n {
	case NATNone:
		return "none"
	case NATFull:
		return "full-cone"
	case NATRestricted:
		return "restricted"
	case NATPortRestricted:
		return "port-restricted"
	case NATSymmetric:
		return "symmetric"
	default:
		return "unknown"
	}
}

// CanHolePunch returns true if hole punching is likely to work
func (n NATType) CanHolePunch() bool {
	return n == NATNone || n == NATFull || n == NATRestricted || n == NATPortRestricted
}

// NATInfo contains information about a node's NAT
type NATInfo struct {
	Type       NATType
	PublicAddr string // External IP:port as seen by others
	LocalAddr  string // Local bound address
	Hairpin    bool   // Whether hairpin NAT is supported
}

// HolePunchRequest is sent via relay to coordinate hole punching
type HolePunchRequest struct {
	FromNodeID string `json:"from"`
	ToNodeID   string `json:"to"`
	FromAddr   string `json:"from_addr"` // Sender's public address
	ToAddr     string `json:"to_addr"`   // Recipient's public address
	Nonce      []byte `json:"nonce"`
	Timestamp  int64  `json:"ts"`
}

// HolePunchResponse is the response to a hole punch request
type HolePunchResponse struct {
	FromNodeID string `json:"from"`
	ToNodeID   string `json:"to"`
	Success    bool   `json:"success"`
	Addr       string `json:"addr"` // Address where peer can be reached
	Nonce      []byte `json:"nonce"`
}

// NATTraversal handles NAT traversal and hole punching
type NATTraversal struct {
	localID   string
	localInfo NATInfo
	conn      net.PacketConn
	relayAddr string // Relay node for coordination
	mu        sync.RWMutex

	// Pending hole punch operations
	pending   map[string]chan *HolePunchResponse
	pendingMu sync.Mutex

	// Discovered peer addresses
	peerAddrs   map[string]string
	peerAddrsMu sync.RWMutex

	// STUN servers for NAT detection
	stunServers []string
}

// NewNATTraversal creates a new NAT traversal handler
func NewNATTraversal(localID string, conn net.PacketConn) *NATTraversal {
	return &NATTraversal{
		localID:   localID,
		conn:      conn,
		pending:   make(map[string]chan *HolePunchResponse),
		peerAddrs: make(map[string]string),
		stunServers: []string{
			"stun.l.google.com:19302",
			"stun1.l.google.com:19302",
		},
	}
}

// SetRelayAddr sets the relay address for coordination
func (nt *NATTraversal) SetRelayAddr(addr string) {
	nt.mu.Lock()
	defer nt.mu.Unlock()
	nt.relayAddr = addr
}

// DetectNAT determines the local NAT type
func (nt *NATTraversal) DetectNAT(ctx context.Context) (*NATInfo, error) {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	// Try to discover external address via STUN
	var externalAddrs []string
	for _, server := range nt.stunServers {
		addr, err := nt.stunQuery(ctx, server)
		if err != nil {
			continue
		}
		externalAddrs = append(externalAddrs, addr)
	}

	if len(externalAddrs) == 0 {
		// Couldn't reach STUN servers
		nt.localInfo = NATInfo{
			Type:      NATUnknown,
			LocalAddr: nt.conn.LocalAddr().String(),
		}
		return &nt.localInfo, nil
	}

	// Check if all STUN servers see the same address
	allSame := true
	for i := 1; i < len(externalAddrs); i++ {
		if externalAddrs[i] != externalAddrs[0] {
			allSame = false
			break
		}
	}

	if !allSame {
		// Different STUN servers see different ports = symmetric NAT
		nt.localInfo = NATInfo{
			Type:       NATSymmetric,
			PublicAddr: externalAddrs[0],
			LocalAddr:  nt.conn.LocalAddr().String(),
		}
	} else {
		// Same external address - at least port-restricted or better
		// More detailed detection would require additional STUN tests
		localAddr := nt.conn.LocalAddr().String()
		if externalAddrs[0] == localAddr {
			nt.localInfo = NATInfo{
				Type:       NATNone,
				PublicAddr: externalAddrs[0],
				LocalAddr:  localAddr,
			}
		} else {
			nt.localInfo = NATInfo{
				Type:       NATPortRestricted, // Conservative assumption
				PublicAddr: externalAddrs[0],
				LocalAddr:  localAddr,
			}
		}
	}

	return &nt.localInfo, nil
}

// stunQuery performs a simple STUN binding request
func (nt *NATTraversal) stunQuery(ctx context.Context, server string) (string, error) {
	addr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return "", err
	}

	// Simple STUN binding request
	// Magic cookie: 0x2112A442
	stunReq := []byte{
		0x00, 0x01, // Binding Request
		0x00, 0x00, // Message length
		0x21, 0x12, 0xa4, 0x42, // Magic cookie
		// Transaction ID (12 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
	}

	if _, err := nt.conn.WriteTo(stunReq, addr); err != nil {
		return "", err
	}

	// Read response
	buf := make([]byte, 256)
	nt.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := nt.conn.ReadFrom(buf)
	if err != nil {
		return "", err
	}

	// Parse STUN response for XOR-MAPPED-ADDRESS
	return parseSTUNResponse(buf[:n])
}

// parseSTUNResponse extracts the mapped address from a STUN response
func parseSTUNResponse(data []byte) (string, error) {
	if len(data) < 20 {
		return "", fmt.Errorf("invalid STUN response")
	}

	// Skip header (20 bytes) and parse attributes
	pos := 20
	for pos < len(data)-4 {
		attrType := uint16(data[pos])<<8 | uint16(data[pos+1])
		attrLen := uint16(data[pos+2])<<8 | uint16(data[pos+3])
		pos += 4

		if pos+int(attrLen) > len(data) {
			break
		}

		// XOR-MAPPED-ADDRESS = 0x0020
		if attrType == 0x0020 && attrLen >= 8 {
			family := data[pos+1]
			if family == 0x01 { // IPv4
				xport := uint16(data[pos+2])<<8 | uint16(data[pos+3])
				port := xport ^ 0x2112 // XOR with magic cookie high bits

				// XOR IP with magic cookie
				ip := make(net.IP, 4)
				ip[0] = data[pos+4] ^ 0x21
				ip[1] = data[pos+5] ^ 0x12
				ip[2] = data[pos+6] ^ 0xa4
				ip[3] = data[pos+7] ^ 0x42

				return fmt.Sprintf("%s:%d", ip.String(), port), nil
			}
		}

		// MAPPED-ADDRESS = 0x0001 (fallback)
		if attrType == 0x0001 && attrLen >= 8 {
			family := data[pos+1]
			if family == 0x01 { // IPv4
				port := uint16(data[pos+2])<<8 | uint16(data[pos+3])
				ip := net.IP(data[pos+4 : pos+8])
				return fmt.Sprintf("%s:%d", ip.String(), port), nil
			}
		}

		pos += int(attrLen)
		// Align to 4-byte boundary
		if attrLen%4 != 0 {
			pos += 4 - int(attrLen%4)
		}
	}

	return "", fmt.Errorf("no mapped address in STUN response")
}

// InitiateHolePunch starts a hole punch operation with a peer
func (nt *NATTraversal) InitiateHolePunch(ctx context.Context, peerID string, peerAddr string) (string, error) {
	nt.mu.RLock()
	relayAddr := nt.relayAddr
	localInfo := nt.localInfo
	nt.mu.RUnlock()

	if relayAddr == "" {
		return "", fmt.Errorf("no relay configured for hole punch coordination")
	}

	// Create hole punch request with a random nonce. Previously the nonce was
	// all-zero, so acks carried no replay protection and weren't bound to a
	// specific request.
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate hole-punch nonce: %w", err)
	}
	req := &HolePunchRequest{
		FromNodeID: nt.localID,
		ToNodeID:   peerID,
		FromAddr:   localInfo.PublicAddr,
		ToAddr:     peerAddr,
		Nonce:      nonce,
		Timestamp:  time.Now().UnixNano(),
	}

	// Register pending response
	respCh := make(chan *HolePunchResponse, 1)
	nt.pendingMu.Lock()
	nt.pending[peerID] = respCh
	nt.pendingMu.Unlock()

	defer func() {
		nt.pendingMu.Lock()
		delete(nt.pending, peerID)
		nt.pendingMu.Unlock()
	}()

	// Send coordination request to relay
	relayUDP, err := net.ResolveUDPAddr("udp", relayAddr)
	if err != nil {
		return "", fmt.Errorf("resolve relay: %w", err)
	}

	data, _ := json.Marshal(req)
	coordMsg := append([]byte{0x01}, data...) // 0x01 = hole punch request
	if _, err := nt.conn.WriteTo(coordMsg, relayUDP); err != nil {
		return "", fmt.Errorf("send to relay: %w", err)
	}

	// Start sending hole punch packets to peer
	peerUDP, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return "", fmt.Errorf("resolve peer: %w", err)
	}

	// Send multiple punch packets
	punchPacket := append([]byte{0x02}, nonce...) // 0x02 = hole punch
	for i := 0; i < 5; i++ {
		nt.conn.WriteTo(punchPacket, peerUDP)
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for response
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case resp := <-respCh:
		if resp.Success {
			// Store the discovered address
			nt.peerAddrsMu.Lock()
			nt.peerAddrs[peerID] = resp.Addr
			nt.peerAddrsMu.Unlock()
			return resp.Addr, nil
		}
		return "", fmt.Errorf("hole punch failed")
	case <-time.After(5 * time.Second):
		return "", fmt.Errorf("hole punch timeout")
	}
}

// HandleHolePunchRequest processes an incoming hole punch coordination request.
//
// SECURITY: this sends packets to req.FromAddr, an address named in the
// request. Before wiring NAT traversal into production, the caller MUST
// authenticate that the request actually came from the trusted relay
// (e.g. verify the source against nt.relayAddr and authenticate the request),
// and rate-limit per source — otherwise a forged request turns this node into
// a UDP reflector toward an arbitrary victim. As a minimal guard we refuse
// obviously non-routable targets and require a present nonce.
func (nt *NATTraversal) HandleHolePunchRequest(req *HolePunchRequest) {
	if len(req.Nonce) != 16 {
		return
	}
	peerUDP, err := net.ResolveUDPAddr("udp", req.FromAddr)
	if err != nil || peerUDP.IP == nil ||
		peerUDP.IP.IsLoopback() || peerUDP.IP.IsUnspecified() || peerUDP.IP.IsMulticast() {
		return
	}

	// Send multiple punch packets
	punchPacket := append([]byte{0x02}, req.Nonce...)
	for i := 0; i < 5; i++ {
		nt.conn.WriteTo(punchPacket, peerUDP)
		time.Sleep(50 * time.Millisecond)
	}
}

// HandleHolePunchPacket processes a received hole punch packet
func (nt *NATTraversal) HandleHolePunchPacket(data []byte, from net.Addr) {
	if len(data) < 17 || data[0] != 0x02 {
		return
	}

	// We received a punch packet - the hole is open!
	// Send back an ack
	ackPacket := append([]byte{0x03}, data[1:17]...) // 0x03 = hole punch ack
	nt.conn.WriteTo(ackPacket, from)
}

// HandleHolePunchAck processes a hole punch acknowledgment
func (nt *NATTraversal) HandleHolePunchAck(data []byte, from net.Addr, peerID string) {
	if len(data) < 17 || data[0] != 0x03 {
		return
	}

	nt.pendingMu.Lock()
	ch, ok := nt.pending[peerID]
	nt.pendingMu.Unlock()

	if ok {
		resp := &HolePunchResponse{
			FromNodeID: peerID,
			ToNodeID:   nt.localID,
			Success:    true,
			Addr:       from.String(),
			Nonce:      data[1:17],
		}
		select {
		case ch <- resp:
		default:
		}
	}
}

// GetPeerAddr returns the discovered address for a peer
func (nt *NATTraversal) GetPeerAddr(peerID string) string {
	nt.peerAddrsMu.RLock()
	defer nt.peerAddrsMu.RUnlock()
	return nt.peerAddrs[peerID]
}

// GetLocalInfo returns the local NAT info
func (nt *NATTraversal) GetLocalInfo() NATInfo {
	nt.mu.RLock()
	defer nt.mu.RUnlock()
	return nt.localInfo
}
