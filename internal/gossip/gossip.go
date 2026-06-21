package gossip

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// Config holds gossip protocol configuration
type Config struct {
	// BindAddr is the address to bind the gossip listener
	BindAddr string

	// GossipInterval is how often to run the gossip cycle
	GossipInterval time.Duration

	// ProbeInterval is how often to probe a random member
	ProbeInterval time.Duration

	// ProbeTimeout is how long to wait for a probe response
	ProbeTimeout time.Duration

	// IndirectChecks is the number of indirect probes to use
	IndirectChecks int

	// SuspicionTimeout is how long before suspect -> dead
	SuspicionTimeout time.Duration

	// RetransmitMult affects how many times messages are retransmitted
	RetransmitMult int

	// MeshSecret is used to authenticate gossip messages
	MeshSecret []byte
}

// DefaultConfig returns default gossip configuration
func DefaultConfig() *Config {
	return &Config{
		BindAddr:         ":7947",
		GossipInterval:   1 * time.Second,
		ProbeInterval:    500 * time.Millisecond,
		ProbeTimeout:     500 * time.Millisecond,
		IndirectChecks:   3,
		SuspicionTimeout: 5 * time.Second,
		RetransmitMult:   4,
	}
}

// MessageType identifies the type of gossip message
type MessageType uint8

const (
	MsgPing MessageType = iota
	MsgPingReq
	MsgAck
	MsgNack
	MsgSync
	MsgSyncResp
	MsgBroadcast
	MsgChat
)

// Message is a gossip protocol message
type Message struct {
	Type      MessageType     `json:"type"`
	SeqNo     uint64          `json:"seq"`
	From      string          `json:"from"`
	Target    string          `json:"target,omitempty"`
	Members   []*Member       `json:"members,omitempty"`
	Digest    []byte          `json:"digest,omitempty"`
	Timestamp int64           `json:"ts"`
	HMAC      []byte          `json:"hmac,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

// Gossip implements the SWIM gossip protocol
type Gossip struct {
	cfg     *Config
	members *MemberList
	self    *Member

	conn     net.PacketConn
	seqNo    uint64
	seqMu    sync.Mutex
	shutdown chan struct{}
	wg       sync.WaitGroup

	// Pending probe acks
	ackCh map[uint64]chan *Message
	ackMu sync.Mutex

	// Broadcast queue for disseminating updates
	broadcasts   []broadcastItem
	broadcastsMu sync.Mutex

	// Suspicion timers
	suspicion   map[string]*time.Timer
	suspicionMu sync.Mutex

	// Replay deduplication: seen message hashes with expiry
	seenMsgs   map[uint64]int64 // hash -> expiry unix nano
	seenMsgsMu sync.Mutex

	// Custom message handler
	onCustomMessage   func(msgType MessageType, from string, payload []byte)
	onCustomMessageMu sync.RWMutex
}

type broadcastItem struct {
	msg        *Message
	retransmit int
}

// New creates a new gossip instance
func New(cfg *Config, self *Member) (*Gossip, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	ml := NewMemberList(self)

	g := &Gossip{
		cfg:       cfg,
		members:   ml,
		self:      self,
		shutdown:  make(chan struct{}),
		ackCh:     make(map[uint64]chan *Message),
		suspicion: make(map[string]*time.Timer),
		seenMsgs:  make(map[uint64]int64),
	}

	return g, nil
}

// Start begins the gossip protocol
func (g *Gossip) Start() error {
	var err error
	g.conn, err = net.ListenPacket("udp4", g.cfg.BindAddr)
	if err != nil {
		return fmt.Errorf("bind gossip: %w", err)
	}

	g.wg.Add(3)
	go g.receiveLoop()
	go g.probeLoop()
	go g.gossipLoop()

	return nil
}

// Stop shuts down the gossip protocol
func (g *Gossip) Stop() error {
	close(g.shutdown)
	if g.conn != nil {
		g.conn.Close()
	}
	g.wg.Wait()
	return nil
}

// Members returns the member list
func (g *Gossip) Members() *MemberList {
	return g.members
}

// Join adds bootstrap peers to the member list
func (g *Gossip) Join(peers []*Member) error {
	for _, peer := range peers {
		g.members.Merge(peer)
	}

	// Sync with each peer
	for _, peer := range peers {
		if len(peer.Endpoints) > 0 {
			g.syncWith(peer.Endpoints[0])
		}
	}

	return nil
}

// Broadcast queues a message for dissemination to all members
func (g *Gossip) Broadcast(members []*Member) {
	msg := &Message{
		Type:      MsgBroadcast,
		From:      g.self.NodeID,
		Members:   members,
		Timestamp: time.Now().UnixNano(),
	}

	g.queueBroadcast(msg)
}

// BroadcastPayload sends a custom typed message with an arbitrary payload
// directly to all alive members. Unlike member broadcasts which are piggybacked
// on pings, payload messages are sent as standalone UDP messages.
func (g *Gossip) BroadcastPayload(msgType MessageType, payload []byte) {
	msg := &Message{
		Type:      msgType,
		From:      g.self.NodeID,
		Payload:   json.RawMessage(payload),
		Timestamp: time.Now().UnixNano(),
	}

	// Send directly to all alive members
	members := g.members.AliveMembers()
	for _, m := range members {
		if len(m.Endpoints) > 0 {
			addr, err := net.ResolveUDPAddr("udp", m.Endpoints[0])
			if err == nil {
				g.sendTo(msg, addr)
			}
		}
	}
}

// SetCustomHandler registers a callback that is invoked whenever a custom
// message (e.g. MsgChat) is received. It is safe to call concurrently.
func (g *Gossip) SetCustomHandler(handler func(msgType MessageType, from string, payload []byte)) {
	g.onCustomMessageMu.Lock()
	defer g.onCustomMessageMu.Unlock()
	g.onCustomMessage = handler
}

func (g *Gossip) handleCustomBroadcast(msg *Message) {
	// Invoke handler if registered.
	g.onCustomMessageMu.RLock()
	h := g.onCustomMessage
	g.onCustomMessageMu.RUnlock()

	if h != nil {
		h(msg.Type, msg.From, []byte(msg.Payload))
	}

	// Re-queue to propagate to other peers.
	g.queueBroadcast(msg)
}

func (g *Gossip) queueBroadcast(msg *Message) {
	g.broadcastsMu.Lock()
	defer g.broadcastsMu.Unlock()

	g.broadcasts = append(g.broadcasts, broadcastItem{
		msg:        msg,
		retransmit: g.retransmitLimit(),
	})
}

func (g *Gossip) retransmitLimit() int {
	return g.cfg.RetransmitMult * (g.members.Size() + 1)
}

func (g *Gossip) getBroadcasts(limit int) []*Message {
	g.broadcastsMu.Lock()
	defer g.broadcastsMu.Unlock()

	var result []*Message
	var remaining []broadcastItem

	for _, item := range g.broadcasts {
		if len(result) < limit {
			result = append(result, item.msg)
			item.retransmit--
			if item.retransmit > 0 {
				remaining = append(remaining, item)
			}
		} else {
			remaining = append(remaining, item)
		}
	}

	g.broadcasts = remaining
	return result
}

func (g *Gossip) nextSeqNo() uint64 {
	g.seqMu.Lock()
	defer g.seqMu.Unlock()
	g.seqNo++
	return g.seqNo
}

// receiveLoop handles incoming gossip messages
func (g *Gossip) receiveLoop() {
	defer g.wg.Done()

	buf := make([]byte, 65536)
	for {
		select {
		case <-g.shutdown:
			return
		default:
		}

		g.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, addr, err := g.conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			continue
		}

		var msg Message
		if err := json.Unmarshal(buf[:n], &msg); err != nil {
			continue
		}

		// Verify HMAC if mesh secret is set
		if len(g.cfg.MeshSecret) > 0 && !g.verifyHMAC(&msg) {
			continue
		}

		g.handleMessage(&msg, addr)
	}
}

func (g *Gossip) handleMessage(msg *Message, from net.Addr) {
	switch msg.Type {
	case MsgPing:
		g.handlePing(msg, from)
	case MsgPingReq:
		g.handlePingReq(msg, from)
	case MsgAck, MsgNack:
		g.handleAck(msg)
	case MsgSync:
		g.handleSync(msg, from)
	case MsgSyncResp:
		g.handleSyncResp(msg)
	case MsgBroadcast:
		g.handleBroadcast(msg)
	case MsgChat:
		g.handleCustomBroadcast(msg)
	}
}

func (g *Gossip) handlePing(msg *Message, from net.Addr) {
	// Update member info if included
	for _, m := range msg.Members {
		g.members.Merge(m)
	}

	// Send ack with our state
	ack := &Message{
		Type:      MsgAck,
		SeqNo:     msg.SeqNo,
		From:      g.self.NodeID,
		Members:   []*Member{g.members.Self()},
		Timestamp: time.Now().UnixNano(),
	}

	// Piggyback pending broadcasts (extract members from broadcast messages)
	for _, broadcast := range g.getBroadcasts(5) {
		ack.Members = append(ack.Members, broadcast.Members...)
	}

	g.sendTo(ack, from)
}

func (g *Gossip) handlePingReq(msg *Message, from net.Addr) {
	// Probe the target on behalf of the requester
	target := g.members.Get(msg.Target)
	if target == nil || len(target.Endpoints) == 0 {
		// Send NACK
		nack := &Message{
			Type:      MsgNack,
			SeqNo:     msg.SeqNo,
			From:      g.self.NodeID,
			Target:    msg.Target,
			Timestamp: time.Now().UnixNano(),
		}
		g.sendTo(nack, from)
		return
	}

	// Probe the target
	ctx, cancel := context.WithTimeout(context.Background(), g.cfg.ProbeTimeout)
	defer cancel()

	if g.probe(ctx, target) {
		// Forward ack to requester
		ack := &Message{
			Type:      MsgAck,
			SeqNo:     msg.SeqNo,
			From:      g.self.NodeID,
			Target:    msg.Target,
			Timestamp: time.Now().UnixNano(),
		}
		g.sendTo(ack, from)
	} else {
		// Send NACK
		nack := &Message{
			Type:      MsgNack,
			SeqNo:     msg.SeqNo,
			From:      g.self.NodeID,
			Target:    msg.Target,
			Timestamp: time.Now().UnixNano(),
		}
		g.sendTo(nack, from)
	}
}

func (g *Gossip) handleAck(msg *Message) {
	g.ackMu.Lock()
	ch, ok := g.ackCh[msg.SeqNo]
	g.ackMu.Unlock()

	if ok {
		select {
		case ch <- msg:
		default:
		}
	}

	// Process piggybacked member updates
	for _, m := range msg.Members {
		g.members.Merge(m)
	}

	// Clear suspicion if this was from a suspected node
	if msg.Target != "" {
		g.clearSuspicion(msg.Target)
	}
}

func (g *Gossip) handleSync(msg *Message, from net.Addr) {
	// Full state sync requested
	all := g.members.Members(nil)
	all = append(all, g.members.Self())

	resp := &Message{
		Type:      MsgSyncResp,
		SeqNo:     msg.SeqNo,
		From:      g.self.NodeID,
		Members:   all,
		Timestamp: time.Now().UnixNano(),
	}

	g.sendTo(resp, from)
}

func (g *Gossip) handleSyncResp(msg *Message) {
	for _, m := range msg.Members {
		g.members.Merge(m)
	}
}

func (g *Gossip) handleBroadcast(msg *Message) {
	for _, m := range msg.Members {
		if g.members.Merge(m) {
			// Re-broadcast if we updated our state
			g.queueBroadcast(msg)
		}
	}
}

// probeLoop periodically probes random members
func (g *Gossip) probeLoop() {
	defer g.wg.Done()

	ticker := time.NewTicker(g.cfg.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-g.shutdown:
			return
		case <-ticker.C:
			g.probeRandom()
		}
	}
}

func (g *Gossip) probeRandom() {
	target := g.members.RandomMember()
	if target == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), g.cfg.ProbeTimeout)
	defer cancel()

	if !g.probe(ctx, target) {
		// Direct probe failed, try indirect
		g.indirectProbe(target)
	}
}

func (g *Gossip) probe(ctx context.Context, target *Member) bool {
	if len(target.Endpoints) == 0 {
		return false
	}

	seqNo := g.nextSeqNo()
	ackCh := make(chan *Message, 1)

	g.ackMu.Lock()
	g.ackCh[seqNo] = ackCh
	g.ackMu.Unlock()

	defer func() {
		g.ackMu.Lock()
		delete(g.ackCh, seqNo)
		g.ackMu.Unlock()
	}()

	ping := &Message{
		Type:      MsgPing,
		SeqNo:     seqNo,
		From:      g.self.NodeID,
		Members:   []*Member{g.members.Self()},
		Timestamp: time.Now().UnixNano(),
	}

	// Piggyback broadcasts (extract members from broadcast messages)
	for _, broadcast := range g.getBroadcasts(3) {
		ping.Members = append(ping.Members, broadcast.Members...)
	}

	addr, err := net.ResolveUDPAddr("udp", target.Endpoints[0])
	if err != nil {
		return false
	}

	start := time.Now()
	g.sendTo(ping, addr)

	select {
	case <-ctx.Done():
		return false
	case ack := <-ackCh:
		// Update RTT
		rtt := time.Since(start)
		g.members.Merge(&Member{
			NodeID:      target.NodeID,
			State:       StateAlive,
			Incarnation: target.Incarnation,
			LastSeen:    time.Now(),
			RTT:         rtt,
		})

		// Process ack payload
		for _, m := range ack.Members {
			g.members.Merge(m)
		}
		return true
	}
}

func (g *Gossip) indirectProbe(target *Member) {
	// Ask random members to probe the target
	helpers := g.members.RandomMembers(g.cfg.IndirectChecks, target.NodeID)
	if len(helpers) == 0 {
		g.suspect(target)
		return
	}

	seqNo := g.nextSeqNo()
	ackCh := make(chan *Message, len(helpers))

	g.ackMu.Lock()
	g.ackCh[seqNo] = ackCh
	g.ackMu.Unlock()

	defer func() {
		g.ackMu.Lock()
		delete(g.ackCh, seqNo)
		g.ackMu.Unlock()
	}()

	pingReq := &Message{
		Type:      MsgPingReq,
		SeqNo:     seqNo,
		From:      g.self.NodeID,
		Target:    target.NodeID,
		Timestamp: time.Now().UnixNano(),
	}

	for _, helper := range helpers {
		if len(helper.Endpoints) > 0 {
			addr, _ := net.ResolveUDPAddr("udp", helper.Endpoints[0])
			g.sendTo(pingReq, addr)
		}
	}

	// Wait for any ack
	timeout := time.NewTimer(g.cfg.ProbeTimeout * 2)
	defer timeout.Stop()

	select {
	case <-timeout.C:
		g.suspect(target)
	case <-ackCh:
		// Target is alive via indirect probe
		g.clearSuspicion(target.NodeID)
	}
}

func (g *Gossip) suspect(target *Member) {
	if !g.members.MarkSuspect(target.NodeID) {
		return
	}

	// Broadcast suspicion
	updated := g.members.Get(target.NodeID)
	if updated != nil {
		g.Broadcast([]*Member{updated})
	}

	// Start suspicion timer
	g.suspicionMu.Lock()
	defer g.suspicionMu.Unlock()

	if _, exists := g.suspicion[target.NodeID]; exists {
		return
	}

	g.suspicion[target.NodeID] = time.AfterFunc(g.cfg.SuspicionTimeout, func() {
		g.confirmDead(target.NodeID)
	})
}

func (g *Gossip) clearSuspicion(nodeID string) {
	g.suspicionMu.Lock()
	defer g.suspicionMu.Unlock()

	if timer, exists := g.suspicion[nodeID]; exists {
		timer.Stop()
		delete(g.suspicion, nodeID)
	}

	g.members.MarkAlive(nodeID)
}

func (g *Gossip) confirmDead(nodeID string) {
	g.suspicionMu.Lock()
	delete(g.suspicion, nodeID)
	g.suspicionMu.Unlock()

	// Only confirm death if still suspect — a node that refuted to Alive during
	// the suspicion window (higher incarnation via gossip) must not be killed.
	if g.members.MarkDeadIfSuspect(nodeID) {
		// Broadcast death
		dead := g.members.Get(nodeID)
		if dead != nil {
			g.Broadcast([]*Member{dead})
		}
	}
}

// gossipLoop periodically syncs state with random peers
func (g *Gossip) gossipLoop() {
	defer g.wg.Done()

	ticker := time.NewTicker(g.cfg.GossipInterval)
	defer ticker.Stop()

	for {
		select {
		case <-g.shutdown:
			return
		case <-ticker.C:
			g.gossipRound()
		}
	}
}

func (g *Gossip) gossipRound() {
	target := g.members.RandomMember()
	if target == nil || len(target.Endpoints) == 0 {
		return
	}

	// Send state digest
	digest := g.computeDigest()
	sync := &Message{
		Type:      MsgSync,
		SeqNo:     g.nextSeqNo(),
		From:      g.self.NodeID,
		Digest:    digest,
		Timestamp: time.Now().UnixNano(),
	}

	addr, _ := net.ResolveUDPAddr("udp", target.Endpoints[0])
	g.sendTo(sync, addr)
}

func (g *Gossip) syncWith(endpoint string) {
	addr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return
	}

	sync := &Message{
		Type:      MsgSync,
		SeqNo:     g.nextSeqNo(),
		From:      g.self.NodeID,
		Members:   []*Member{g.members.Self()},
		Timestamp: time.Now().UnixNano(),
	}

	g.sendTo(sync, addr)
}

func (g *Gossip) computeDigest() []byte {
	h := sha256.New()
	members := g.members.Members(nil)
	for _, m := range members {
		binary.Write(h, binary.BigEndian, m.Incarnation)
		h.Write([]byte(m.NodeID))
		h.Write([]byte{byte(m.State)})
	}
	return h.Sum(nil)
}

func (g *Gossip) sendTo(msg *Message, addr net.Addr) error {
	if len(g.cfg.MeshSecret) > 0 {
		g.signHMAC(msg)
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = g.conn.WriteTo(data, addr)
	return err
}

func (g *Gossip) hmacMessage(msg *Message) []byte {
	mac := hmac.New(sha256.New, g.cfg.MeshSecret)
	binary.Write(mac, binary.BigEndian, msg.Timestamp)
	mac.Write([]byte(msg.From))
	mac.Write([]byte{byte(msg.Type)})
	binary.Write(mac, binary.BigEndian, msg.SeqNo)
	mac.Write([]byte(msg.Target))
	mac.Write(msg.Digest)
	for _, m := range msg.Members {
		// Authenticate ALL routing-relevant fields, not just identity/state.
		// Previously Endpoints/PublicKey/MeshIP were unprotected, so an on-path
		// attacker could rewrite a peer's WireGuard pubkey or endpoint in a
		// validly-signed gossip message and have it accepted (peer/route
		// poisoning). NUL separators disambiguate the concatenation (these
		// fields never contain NUL).
		mac.Write([]byte(m.NodeID))
		mac.Write([]byte{0})
		mac.Write([]byte{byte(m.State)})
		binary.Write(mac, binary.BigEndian, m.Incarnation)
		mac.Write([]byte(m.PublicKey))
		mac.Write([]byte{0})
		mac.Write([]byte(m.MeshIP.String()))
		mac.Write([]byte{0})
		mac.Write([]byte(m.Transport))
		mac.Write([]byte{0})
		for _, ep := range m.Endpoints {
			mac.Write([]byte(ep))
			mac.Write([]byte{0})
		}
		mac.Write([]byte{1}) // section separator
		for _, r := range m.Roles {
			mac.Write([]byte(r))
			mac.Write([]byte{0})
		}
		mac.Write([]byte{2}) // member terminator
	}
	mac.Write(msg.Payload)
	return mac.Sum(nil)[:16]
}

func (g *Gossip) signHMAC(msg *Message) {
	msg.HMAC = g.hmacMessage(msg)
}

func (g *Gossip) verifyHMAC(msg *Message) bool {
	// Check timestamp freshness first (within 30 seconds)
	ts := time.Unix(0, msg.Timestamp)
	if time.Since(ts).Abs() > 30*time.Second {
		return false
	}

	expected := g.hmacMessage(msg)
	if subtle.ConstantTimeCompare(msg.HMAC, expected) != 1 {
		return false
	}

	// Reject replayed messages using a hash of (From, SeqNo, Timestamp)
	msgHash := g.messageHash(msg)
	now := time.Now().UnixNano()
	expiry := now + int64(30*time.Second)

	g.seenMsgsMu.Lock()
	// Prune expired entries (bounded to prevent unbounded growth)
	if len(g.seenMsgs) > 10000 {
		for k, exp := range g.seenMsgs {
			if now > exp {
				delete(g.seenMsgs, k)
			}
		}
	}
	if _, seen := g.seenMsgs[msgHash]; seen {
		g.seenMsgsMu.Unlock()
		return false // Replay rejected
	}
	g.seenMsgs[msgHash] = expiry
	g.seenMsgsMu.Unlock()

	return true
}

func (g *Gossip) messageHash(msg *Message) uint64 {
	h := sha256.New()
	h.Write([]byte(msg.From))
	binary.Write(h, binary.BigEndian, msg.SeqNo)
	binary.Write(h, binary.BigEndian, msg.Timestamp)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8])
}
