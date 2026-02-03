package policy

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// PacketVerdict is the result of packet inspection
type PacketVerdict uint8

const (
	VerdictAllow PacketVerdict = iota
	VerdictDrop
	VerdictLog
)

// Stats tracks policy enforcement statistics
type Stats struct {
	Allowed   uint64
	Denied    uint64
	Evaluated uint64
}

// Enforcer inspects packets and enforces policies
type Enforcer struct {
	engine     *Engine
	localID    string
	localRoles []string
	localComp  string

	// Peer information cache
	peerInfo   map[string]*PeerInfo
	peerInfoMu sync.RWMutex

	// Statistics
	stats Stats

	// Logging
	logDenied bool
	onDeny    func(*Request, *Decision)
}

// PeerInfo caches information about a peer for policy evaluation
type PeerInfo struct {
	NodeID      string
	Roles       []string
	Compartment string
	MeshIP      netip.Addr
	LastUpdated time.Time
}

// NewEnforcer creates a new policy enforcer
func NewEnforcer(engine *Engine, localID string, localRoles []string, localComp string) *Enforcer {
	return &Enforcer{
		engine:     engine,
		localID:    localID,
		localRoles: localRoles,
		localComp:  localComp,
		peerInfo:   make(map[string]*PeerInfo),
		logDenied:  true,
	}
}

// SetOnDeny sets a callback for denied packets
func (e *Enforcer) SetOnDeny(fn func(*Request, *Decision)) {
	e.onDeny = fn
}

// RegisterPeer adds or updates peer information
func (e *Enforcer) RegisterPeer(info *PeerInfo) {
	e.peerInfoMu.Lock()
	defer e.peerInfoMu.Unlock()
	info.LastUpdated = time.Now()
	e.peerInfo[info.NodeID] = info
}

// RemovePeer removes a peer
func (e *Enforcer) RemovePeer(nodeID string) {
	e.peerInfoMu.Lock()
	defer e.peerInfoMu.Unlock()
	delete(e.peerInfo, nodeID)
}

// GetPeerByIP looks up a peer by mesh IP
func (e *Enforcer) GetPeerByIP(ip netip.Addr) *PeerInfo {
	e.peerInfoMu.RLock()
	defer e.peerInfoMu.RUnlock()

	for _, info := range e.peerInfo {
		if info.MeshIP == ip {
			return info
		}
	}
	return nil
}

// CheckPacket evaluates a packet against policies
// Returns allow/deny verdict
func (e *Enforcer) CheckPacket(packet []byte, direction string) PacketVerdict {
	atomic.AddUint64(&e.stats.Evaluated, 1)

	// Parse IP header
	if len(packet) < 20 {
		atomic.AddUint64(&e.stats.Denied, 1)
		return VerdictDrop
	}

	version := packet[0] >> 4
	if version != 4 {
		// For now, only support IPv4 in mesh
		atomic.AddUint64(&e.stats.Denied, 1)
		return VerdictDrop
	}

	// Extract addresses
	srcIP, _ := netip.AddrFromSlice(packet[12:16])
	dstIP, _ := netip.AddrFromSlice(packet[16:20])

	// Extract protocol
	protocol := packet[9]
	protoStr := protocolToString(protocol)

	// Extract port (for TCP/UDP)
	var dstPort uint16
	ihl := int(packet[0]&0x0F) * 4
	if (protocol == 6 || protocol == 17) && len(packet) >= ihl+4 {
		dstPort = binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	}

	// Build request
	req := &Request{
		Protocol:  protoStr,
		Direction: direction,
	}

	if direction == "egress" {
		// Outbound: we are source
		req.SourceNodeID = e.localID
		req.SourceRoles = e.localRoles
		req.SourceCompartment = e.localComp
		req.SourceIP = srcIP

		// Look up destination peer
		destPeer := e.GetPeerByIP(dstIP)
		if destPeer != nil {
			req.DestNodeID = destPeer.NodeID
			req.DestRoles = destPeer.Roles
			req.DestCompartment = destPeer.Compartment
		}
		req.DestIP = dstIP
		req.DestPort = dstPort
	} else {
		// Inbound: peer is source
		srcPeer := e.GetPeerByIP(srcIP)
		if srcPeer != nil {
			req.SourceNodeID = srcPeer.NodeID
			req.SourceRoles = srcPeer.Roles
			req.SourceCompartment = srcPeer.Compartment
		}
		req.SourceIP = srcIP

		req.DestNodeID = e.localID
		req.DestRoles = e.localRoles
		req.DestCompartment = e.localComp
		req.DestIP = dstIP
		req.DestPort = dstPort
	}

	// Evaluate policy
	decision := e.engine.Evaluate(req)

	if decision.Effect == EffectAllow {
		atomic.AddUint64(&e.stats.Allowed, 1)
		return VerdictAllow
	}

	atomic.AddUint64(&e.stats.Denied, 1)

	if e.logDenied && e.onDeny != nil {
		e.onDeny(req, decision)
	}

	return VerdictDrop
}

// CheckConnection evaluates a connection attempt (higher level than packet)
func (e *Enforcer) CheckConnection(srcNodeID string, dstNodeID string, dstPort uint16, protocol string) *Decision {
	e.peerInfoMu.RLock()
	srcPeer := e.peerInfo[srcNodeID]
	dstPeer := e.peerInfo[dstNodeID]
	e.peerInfoMu.RUnlock()

	req := &Request{
		SourceNodeID: srcNodeID,
		DestNodeID:   dstNodeID,
		DestPort:     dstPort,
		Protocol:     protocol,
		Direction:    "egress",
	}

	if srcPeer != nil {
		req.SourceRoles = srcPeer.Roles
		req.SourceCompartment = srcPeer.Compartment
		req.SourceIP = srcPeer.MeshIP
	}

	if dstPeer != nil {
		req.DestRoles = dstPeer.Roles
		req.DestCompartment = dstPeer.Compartment
		req.DestIP = dstPeer.MeshIP
	}

	return e.engine.Evaluate(req)
}

// Stats returns current statistics
func (e *Enforcer) Stats() Stats {
	return Stats{
		Allowed:   atomic.LoadUint64(&e.stats.Allowed),
		Denied:    atomic.LoadUint64(&e.stats.Denied),
		Evaluated: atomic.LoadUint64(&e.stats.Evaluated),
	}
}

// ResetStats resets the statistics counters
func (e *Enforcer) ResetStats() {
	atomic.StoreUint64(&e.stats.Allowed, 0)
	atomic.StoreUint64(&e.stats.Denied, 0)
	atomic.StoreUint64(&e.stats.Evaluated, 0)
}

func protocolToString(proto uint8) string {
	switch proto {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	default:
		return "unknown"
	}
}

// ConnectionTracker tracks active connections for stateful filtering
type ConnectionTracker struct {
	mu    sync.RWMutex
	conns map[string]*trackedConn
	ttl   time.Duration
}

type trackedConn struct {
	srcIP    netip.Addr
	dstIP    netip.Addr
	srcPort  uint16
	dstPort  uint16
	protocol string
	created  time.Time
	lastSeen time.Time
	packets  uint64
	bytes    uint64
}

// NewConnectionTracker creates a connection tracker
func NewConnectionTracker(ttl time.Duration) *ConnectionTracker {
	ct := &ConnectionTracker{
		conns: make(map[string]*trackedConn),
		ttl:   ttl,
	}

	// Start cleanup goroutine
	go ct.cleanup()

	return ct
}

// Track records a connection
func (ct *ConnectionTracker) Track(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, protocol string, bytes int) {
	key := connKey(srcIP, dstIP, srcPort, dstPort, protocol)

	ct.mu.Lock()
	defer ct.mu.Unlock()

	conn, exists := ct.conns[key]
	if !exists {
		conn = &trackedConn{
			srcIP:    srcIP,
			dstIP:    dstIP,
			srcPort:  srcPort,
			dstPort:  dstPort,
			protocol: protocol,
			created:  time.Now(),
		}
		ct.conns[key] = conn
	}

	conn.lastSeen = time.Now()
	conn.packets++
	conn.bytes += uint64(bytes)
}

// IsTracked checks if a reverse connection is tracked (for stateful allow)
func (ct *ConnectionTracker) IsTracked(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, protocol string) bool {
	// Check reverse direction
	key := connKey(dstIP, srcIP, dstPort, srcPort, protocol)

	ct.mu.RLock()
	defer ct.mu.RUnlock()

	conn, exists := ct.conns[key]
	if !exists {
		return false
	}

	// Check if still valid
	return time.Since(conn.lastSeen) < ct.ttl
}

func (ct *ConnectionTracker) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ct.mu.Lock()
		now := time.Now()
		for key, conn := range ct.conns {
			if now.Sub(conn.lastSeen) > ct.ttl {
				delete(ct.conns, key)
			}
		}
		ct.mu.Unlock()
	}
}

func connKey(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, protocol string) string {
	return srcIP.String() + ":" + string(rune(srcPort)) + "->" +
		dstIP.String() + ":" + string(rune(dstPort)) + "/" + protocol
}
