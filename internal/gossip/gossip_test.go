package gossip

import (
	"encoding/json"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// ============================================================
// member.go tests
// ============================================================

func makeMember(id string, state MemberState, incarnation uint64) *Member {
	return &Member{
		NodeID:      id,
		MeshIP:      netip.MustParseAddr("10.0.0.1"),
		Endpoints:   []string{"127.0.0.1:7946"},
		State:       state,
		Incarnation: incarnation,
		LastSeen:    time.Now(),
	}
}

func TestNewMemberList(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)

	if ml == nil {
		t.Fatal("NewMemberList returned nil")
	}

	got := ml.Self()
	if got.NodeID != "self" {
		t.Fatalf("Self().NodeID = %q, want %q", got.NodeID, "self")
	}

	if ml.Size() != 0 {
		t.Fatalf("Size() = %d, want 0 (self is not in members map)", ml.Size())
	}
}

// --- Merge tests ---

func TestMerge_NewMember(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)

	peer := makeMember("peer1", StateAlive, 1)
	updated := ml.Merge(peer)

	if !updated {
		t.Fatal("Merge of new member should return true")
	}
	if ml.Size() != 1 {
		t.Fatalf("Size() = %d, want 1", ml.Size())
	}
	got := ml.Get("peer1")
	if got == nil {
		t.Fatal("Get(peer1) returned nil after Merge")
	}
	if got.NodeID != "peer1" {
		t.Fatalf("got NodeID = %q, want %q", got.NodeID, "peer1")
	}
}

func TestMerge_HigherIncarnationWins(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)

	ml.Merge(makeMember("peer1", StateAlive, 1))

	// Update with higher incarnation
	updated := makeMember("peer1", StateSuspect, 5)
	if !ml.Merge(updated) {
		t.Fatal("Merge with higher incarnation should return true")
	}
	got := ml.Get("peer1")
	if got.Incarnation != 5 {
		t.Fatalf("Incarnation = %d, want 5", got.Incarnation)
	}
	if got.State != StateSuspect {
		t.Fatalf("State = %v, want Suspect", got.State)
	}
}

func TestMerge_LowerIncarnationIgnored(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)

	ml.Merge(makeMember("peer1", StateAlive, 5))

	if ml.Merge(makeMember("peer1", StateDead, 3)) {
		t.Fatal("Merge with lower incarnation should return false")
	}
	got := ml.Get("peer1")
	if got.State != StateAlive {
		t.Fatalf("State should remain Alive, got %v", got.State)
	}
}

func TestMerge_SameIncarnation_StatePrecedence(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)

	// Start alive at incarnation 1
	ml.Merge(makeMember("peer1", StateAlive, 1))

	// Same incarnation, suspect > alive
	if !ml.Merge(makeMember("peer1", StateSuspect, 1)) {
		t.Fatal("Suspect should beat Alive at same incarnation")
	}
	if ml.Get("peer1").State != StateSuspect {
		t.Fatal("State should be Suspect")
	}

	// Same incarnation, dead > suspect
	if !ml.Merge(makeMember("peer1", StateDead, 1)) {
		t.Fatal("Dead should beat Suspect at same incarnation")
	}
	if ml.Get("peer1").State != StateDead {
		t.Fatal("State should be Dead")
	}
}

func TestMerge_SameIncarnation_LowerStateFails(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)

	ml.Merge(makeMember("peer1", StateSuspect, 1))

	// Alive < Suspect, should not update
	if ml.Merge(makeMember("peer1", StateAlive, 1)) {
		t.Fatal("Alive should not beat Suspect at same incarnation")
	}
	if ml.Get("peer1").State != StateSuspect {
		t.Fatal("State should still be Suspect")
	}
}

func TestMerge_SelfIgnored(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)

	if ml.Merge(makeMember("self", StateAlive, 99)) {
		t.Fatal("Merge of self should return false")
	}
}

func TestMerge_OnJoinCallback(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)

	var mu sync.Mutex
	var joined string
	ml.SetCallbacks(
		func(m *Member) { mu.Lock(); joined = m.NodeID; mu.Unlock() },
		nil,
		nil,
	)

	ml.Merge(makeMember("peer1", StateAlive, 1))

	// Callback is async, wait a bit
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if joined != "peer1" {
		t.Fatalf("onJoin got %q, want %q", joined, "peer1")
	}
}

func TestMerge_OnUpdateCallback(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)

	var mu sync.Mutex
	var updated string
	ml.SetCallbacks(
		nil,
		nil,
		func(m *Member) { mu.Lock(); updated = m.NodeID; mu.Unlock() },
	)

	ml.Merge(makeMember("peer1", StateAlive, 1))
	ml.Merge(makeMember("peer1", StateAlive, 2)) // higher incarnation triggers onUpdate

	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if updated != "peer1" {
		t.Fatalf("onUpdate got %q, want %q", updated, "peer1")
	}
}

// --- MarkSuspect / MarkDead / MarkAlive ---

func TestMarkSuspect(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)
	ml.Merge(makeMember("peer1", StateAlive, 1))

	if !ml.MarkSuspect("peer1") {
		t.Fatal("MarkSuspect should return true for alive member")
	}
	if ml.Get("peer1").State != StateSuspect {
		t.Fatal("State should be Suspect")
	}
}

func TestMarkSuspect_AlreadySuspect(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)
	ml.Merge(makeMember("peer1", StateSuspect, 1))

	if ml.MarkSuspect("peer1") {
		t.Fatal("MarkSuspect should return false for non-alive member")
	}
}

func TestMarkSuspect_NonExistent(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)

	if ml.MarkSuspect("ghost") {
		t.Fatal("MarkSuspect should return false for non-existent member")
	}
}

func TestMarkDead(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)
	ml.Merge(makeMember("peer1", StateAlive, 1))

	if !ml.MarkDead("peer1") {
		t.Fatal("MarkDead should return true for alive member")
	}
	if ml.Get("peer1").State != StateDead {
		t.Fatal("State should be Dead")
	}
}

func TestMarkDead_AlreadyDead(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)
	ml.Merge(makeMember("peer1", StateDead, 1))

	if ml.MarkDead("peer1") {
		t.Fatal("MarkDead should return false for already-dead member")
	}
}

func TestMarkAlive(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)
	ml.Merge(makeMember("peer1", StateAlive, 1))
	ml.MarkSuspect("peer1")

	if !ml.MarkAlive("peer1") {
		t.Fatal("MarkAlive should return true for suspect member")
	}
	if ml.Get("peer1").State != StateAlive {
		t.Fatal("State should be Alive")
	}
}

func TestMarkAlive_AlreadyAlive(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)
	ml.Merge(makeMember("peer1", StateAlive, 1))

	if ml.MarkAlive("peer1") {
		t.Fatal("MarkAlive should return false for already-alive member")
	}
}

func TestMarkAlive_NonExistent(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)

	if ml.MarkAlive("ghost") {
		t.Fatal("MarkAlive should return false for non-existent member")
	}
}

// --- RandomMember / RandomMembers ---

func TestRandomMember_Empty(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)

	if ml.RandomMember() != nil {
		t.Fatal("RandomMember should return nil when no other members")
	}
}

func TestRandomMember_ReturnsAlive(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)
	ml.Merge(makeMember("peer1", StateAlive, 1))

	m := ml.RandomMember()
	if m == nil {
		t.Fatal("RandomMember should return a member")
	}
	if m.NodeID != "peer1" {
		t.Fatalf("got %q, want peer1", m.NodeID)
	}
}

func TestRandomMembers_Count(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)
	for i := 0; i < 10; i++ {
		ml.Merge(makeMember("peer"+string(rune('A'+i)), StateAlive, 1))
	}

	got := ml.RandomMembers(3)
	if len(got) != 3 {
		t.Fatalf("RandomMembers(3) returned %d, want 3", len(got))
	}
}

func TestRandomMembers_Exclude(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)
	ml.Merge(makeMember("peerA", StateAlive, 1))
	ml.Merge(makeMember("peerB", StateAlive, 1))
	ml.Merge(makeMember("peerC", StateAlive, 1))

	got := ml.RandomMembers(10, "peerA")
	for _, m := range got {
		if m.NodeID == "peerA" {
			t.Fatal("RandomMembers should exclude peerA")
		}
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 members after exclusion, got %d", len(got))
	}
}

func TestRandomMembers_MoreThanAvailable(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)
	ml.Merge(makeMember("peerA", StateAlive, 1))

	got := ml.RandomMembers(5)
	if len(got) != 1 {
		t.Fatalf("expected 1 (capped), got %d", len(got))
	}
}

// --- AliveMembers / RelayMembers ---

func TestAliveMembers(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)
	ml.Merge(makeMember("alive1", StateAlive, 1))
	ml.Merge(makeMember("suspect1", StateSuspect, 1))
	ml.Merge(makeMember("dead1", StateDead, 1))

	alive := ml.AliveMembers()
	if len(alive) != 1 {
		t.Fatalf("AliveMembers() = %d, want 1", len(alive))
	}
	if alive[0].NodeID != "alive1" {
		t.Fatalf("expected alive1, got %s", alive[0].NodeID)
	}
}

func TestRelayMembers(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)

	relay := makeMember("relay1", StateAlive, 1)
	relay.Roles = []string{"relay"}
	ml.Merge(relay)

	admin := makeMember("admin1", StateAlive, 1)
	admin.Roles = []string{"admin"}
	ml.Merge(admin)

	normal := makeMember("normal1", StateAlive, 1)
	ml.Merge(normal)

	deadRelay := makeMember("deadRelay", StateDead, 1)
	deadRelay.Roles = []string{"relay"}
	ml.Merge(deadRelay)

	relays := ml.RelayMembers()
	if len(relays) != 2 {
		t.Fatalf("RelayMembers() = %d, want 2", len(relays))
	}
}

// --- Count / Size ---

func TestCount(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)
	ml.Merge(makeMember("a", StateAlive, 1))
	ml.Merge(makeMember("b", StateAlive, 1))
	ml.Merge(makeMember("c", StateSuspect, 1))
	ml.Merge(makeMember("d", StateDead, 1))

	counts := ml.Count()
	if counts[StateAlive] != 2 {
		t.Fatalf("Alive count = %d, want 2", counts[StateAlive])
	}
	if counts[StateSuspect] != 1 {
		t.Fatalf("Suspect count = %d, want 1", counts[StateSuspect])
	}
	if counts[StateDead] != 1 {
		t.Fatalf("Dead count = %d, want 1", counts[StateDead])
	}
}

func TestSize(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	ml := NewMemberList(self)
	ml.Merge(makeMember("a", StateAlive, 1))
	ml.Merge(makeMember("b", StateDead, 1))

	if ml.Size() != 2 {
		t.Fatalf("Size() = %d, want 2", ml.Size())
	}
}

// --- Clone ---

func TestMemberClone_DeepCopy(t *testing.T) {
	orig := &Member{
		NodeID:      "node1",
		MeshIP:      netip.MustParseAddr("10.0.0.1"),
		Endpoints:   []string{"1.2.3.4:7946"},
		Roles:       []string{"relay"},
		PublicKey:   "pk1",
		State:       StateAlive,
		Incarnation: 5,
		Metadata:    map[string]string{"key": "val"},
	}

	clone := orig.Clone()

	// Mutate clone, ensure original is unaffected
	clone.NodeID = "changed"
	clone.Endpoints[0] = "changed"
	clone.Roles[0] = "changed"
	clone.Metadata["key"] = "changed"
	clone.Incarnation = 999

	if orig.NodeID != "node1" {
		t.Fatal("Clone mutated original NodeID")
	}
	if orig.Endpoints[0] != "1.2.3.4:7946" {
		t.Fatal("Clone mutated original Endpoints")
	}
	if orig.Roles[0] != "relay" {
		t.Fatal("Clone mutated original Roles")
	}
	if orig.Metadata["key"] != "val" {
		t.Fatal("Clone mutated original Metadata")
	}
	if orig.Incarnation != 5 {
		t.Fatal("Clone mutated original Incarnation")
	}
}

// --- HasRole / IsRelay ---

func TestHasRole(t *testing.T) {
	m := &Member{Roles: []string{"relay", "dns"}}
	if !m.HasRole("relay") {
		t.Fatal("HasRole(relay) should be true")
	}
	if !m.HasRole("dns") {
		t.Fatal("HasRole(dns) should be true")
	}
	if m.HasRole("admin") {
		t.Fatal("HasRole(admin) should be false")
	}
}

func TestIsRelay(t *testing.T) {
	tests := []struct {
		roles  []string
		expect bool
	}{
		{[]string{"relay"}, true},
		{[]string{"admin"}, true},
		{[]string{"relay", "dns"}, true},
		{[]string{"dns"}, false},
		{nil, false},
	}
	for _, tt := range tests {
		m := &Member{Roles: tt.roles}
		if m.IsRelay() != tt.expect {
			t.Errorf("IsRelay() for roles %v = %v, want %v", tt.roles, m.IsRelay(), tt.expect)
		}
	}
}

// --- UpdateSelf ---

func TestUpdateSelf(t *testing.T) {
	self := makeMember("self", StateAlive, 0)
	ml := NewMemberList(self)

	before := ml.Self().Incarnation

	ml.UpdateSelf(func(m *Member) {
		m.Endpoints = []string{"5.6.7.8:9999"}
	})

	after := ml.Self()
	if after.Incarnation != before+1 {
		t.Fatalf("Incarnation = %d, want %d", after.Incarnation, before+1)
	}
	if len(after.Endpoints) != 1 || after.Endpoints[0] != "5.6.7.8:9999" {
		t.Fatalf("Endpoints not updated: %v", after.Endpoints)
	}
}

// ============================================================
// gossip.go tests
// ============================================================

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.BindAddr == "" {
		t.Fatal("BindAddr should not be empty")
	}
	if cfg.GossipInterval <= 0 {
		t.Fatal("GossipInterval should be positive")
	}
	if cfg.ProbeInterval <= 0 {
		t.Fatal("ProbeInterval should be positive")
	}
	if cfg.ProbeTimeout <= 0 {
		t.Fatal("ProbeTimeout should be positive")
	}
	if cfg.IndirectChecks <= 0 {
		t.Fatal("IndirectChecks should be positive")
	}
	if cfg.SuspicionTimeout <= 0 {
		t.Fatal("SuspicionTimeout should be positive")
	}
	if cfg.RetransmitMult <= 0 {
		t.Fatal("RetransmitMult should be positive")
	}
}

func TestNew(t *testing.T) {
	self := makeMember("node1", StateAlive, 1)
	g, err := New(nil, self)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if g == nil {
		t.Fatal("New() returned nil")
	}
	if g.Members().Size() != 0 {
		t.Fatalf("expected 0 members, got %d", g.Members().Size())
	}
	if g.Members().Self().NodeID != "node1" {
		t.Fatalf("Self().NodeID = %q, want node1", g.Members().Self().NodeID)
	}
}

func TestNew_WithConfig(t *testing.T) {
	cfg := &Config{
		BindAddr:       ":9999",
		RetransmitMult: 10,
	}
	self := makeMember("node1", StateAlive, 1)
	g, err := New(cfg, self)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if g.cfg.BindAddr != ":9999" {
		t.Fatalf("BindAddr = %q, want :9999", g.cfg.BindAddr)
	}
}

// --- HMAC tests ---

func newGossipWithSecret(secret []byte) *Gossip {
	self := makeMember("node1", StateAlive, 1)
	cfg := DefaultConfig()
	cfg.MeshSecret = secret
	g, _ := New(cfg, self)
	return g
}

func TestHMAC_SignVerify_RoundTrip(t *testing.T) {
	g := newGossipWithSecret([]byte("test-secret-key"))

	msg := &Message{
		Type:      MsgPing,
		SeqNo:     42,
		From:      "node1",
		Target:    "node2",
		Timestamp: time.Now().UnixNano(),
		Members: []*Member{
			{NodeID: "node1", State: StateAlive, Incarnation: 1},
		},
	}

	g.signHMAC(msg)

	if len(msg.HMAC) == 0 {
		t.Fatal("signHMAC should set HMAC field")
	}

	if !g.verifyHMAC(msg) {
		t.Fatal("verifyHMAC should return true for freshly signed message")
	}
}

func TestHMAC_TamperedMessage(t *testing.T) {
	g := newGossipWithSecret([]byte("test-secret-key"))

	msg := &Message{
		Type:      MsgPing,
		SeqNo:     42,
		From:      "node1",
		Timestamp: time.Now().UnixNano(),
	}
	g.signHMAC(msg)

	// Tamper with From
	msg.From = "attacker"
	if g.verifyHMAC(msg) {
		t.Fatal("verifyHMAC should fail for tampered From")
	}
}

func TestHMAC_ExpiredTimestamp(t *testing.T) {
	g := newGossipWithSecret([]byte("test-secret-key"))

	msg := &Message{
		Type:      MsgPing,
		SeqNo:     1,
		From:      "node1",
		Timestamp: time.Now().Add(-31 * time.Second).UnixNano(),
	}
	g.signHMAC(msg)

	if g.verifyHMAC(msg) {
		t.Fatal("verifyHMAC should fail for expired timestamp (>30s)")
	}
}

func TestHMAC_FutureTimestamp(t *testing.T) {
	g := newGossipWithSecret([]byte("test-secret-key"))

	msg := &Message{
		Type:      MsgPing,
		SeqNo:     1,
		From:      "node1",
		Timestamp: time.Now().Add(31 * time.Second).UnixNano(),
	}
	g.signHMAC(msg)

	if g.verifyHMAC(msg) {
		t.Fatal("verifyHMAC should fail for future timestamp (>30s)")
	}
}

func TestHMAC_DifferentSecret(t *testing.T) {
	g1 := newGossipWithSecret([]byte("secret-1"))
	g2 := newGossipWithSecret([]byte("secret-2"))

	msg := &Message{
		Type:      MsgPing,
		SeqNo:     1,
		From:      "node1",
		Timestamp: time.Now().UnixNano(),
	}
	g1.signHMAC(msg)

	if g2.verifyHMAC(msg) {
		t.Fatal("verifyHMAC should fail with different mesh secret")
	}
}

func TestHMAC_ChangingType(t *testing.T) {
	g := newGossipWithSecret([]byte("test-secret-key"))

	msg := &Message{
		Type:      MsgPing,
		SeqNo:     1,
		From:      "node1",
		Timestamp: time.Now().UnixNano(),
	}
	g.signHMAC(msg)

	msg.Type = MsgAck
	if g.verifyHMAC(msg) {
		t.Fatal("verifyHMAC should fail when Type changes")
	}
}

func TestHMAC_ChangingSeqNo(t *testing.T) {
	g := newGossipWithSecret([]byte("test-secret-key"))

	msg := &Message{
		Type:      MsgPing,
		SeqNo:     1,
		From:      "node1",
		Timestamp: time.Now().UnixNano(),
	}
	g.signHMAC(msg)

	msg.SeqNo = 999
	if g.verifyHMAC(msg) {
		t.Fatal("verifyHMAC should fail when SeqNo changes")
	}
}

func TestHMAC_ChangingTarget(t *testing.T) {
	g := newGossipWithSecret([]byte("test-secret-key"))

	msg := &Message{
		Type:      MsgPing,
		SeqNo:     1,
		From:      "node1",
		Target:    "node2",
		Timestamp: time.Now().UnixNano(),
	}
	g.signHMAC(msg)

	msg.Target = "node3"
	if g.verifyHMAC(msg) {
		t.Fatal("verifyHMAC should fail when Target changes")
	}
}

func TestHMAC_ChangingMembers(t *testing.T) {
	g := newGossipWithSecret([]byte("test-secret-key"))

	msg := &Message{
		Type:      MsgPing,
		SeqNo:     1,
		From:      "node1",
		Timestamp: time.Now().UnixNano(),
		Members: []*Member{
			{NodeID: "peer1", State: StateAlive, Incarnation: 1},
		},
	}
	g.signHMAC(msg)

	msg.Members[0].NodeID = "peer2"
	if g.verifyHMAC(msg) {
		t.Fatal("verifyHMAC should fail when Members change")
	}
}

func TestHMAC_ChangingDigest(t *testing.T) {
	g := newGossipWithSecret([]byte("test-secret-key"))

	msg := &Message{
		Type:      MsgSync,
		SeqNo:     1,
		From:      "node1",
		Timestamp: time.Now().UnixNano(),
		Digest:    []byte{0x01, 0x02, 0x03},
	}
	g.signHMAC(msg)

	msg.Digest = []byte{0xff, 0xfe}
	if g.verifyHMAC(msg) {
		t.Fatal("verifyHMAC should fail when Digest changes")
	}
}

// --- Broadcast ---

func TestBroadcast(t *testing.T) {
	self := makeMember("node1", StateAlive, 1)
	g, _ := New(DefaultConfig(), self)

	members := []*Member{
		makeMember("peer1", StateAlive, 1),
		makeMember("peer2", StateDead, 2),
	}
	g.Broadcast(members)

	g.broadcastsMu.Lock()
	count := len(g.broadcasts)
	g.broadcastsMu.Unlock()

	if count != 1 {
		t.Fatalf("broadcast queue has %d items, want 1", count)
	}
}

func TestBroadcast_MultipleQueued(t *testing.T) {
	self := makeMember("node1", StateAlive, 1)
	g, _ := New(DefaultConfig(), self)

	g.Broadcast([]*Member{makeMember("a", StateAlive, 1)})
	g.Broadcast([]*Member{makeMember("b", StateAlive, 1)})
	g.Broadcast([]*Member{makeMember("c", StateAlive, 1)})

	g.broadcastsMu.Lock()
	count := len(g.broadcasts)
	g.broadcastsMu.Unlock()

	if count != 3 {
		t.Fatalf("broadcast queue has %d items, want 3", count)
	}
}

// --- retransmitLimit ---

func TestRetransmitLimit(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	cfg := DefaultConfig()
	cfg.RetransmitMult = 4
	g, _ := New(cfg, self)

	// No other members, Size() = 0, limit = 4 * (0 + 1) = 4
	if got := g.retransmitLimit(); got != 4 {
		t.Fatalf("retransmitLimit() = %d, want 4 (0 members)", got)
	}

	// Add 3 members, limit = 4 * (3 + 1) = 16
	g.members.Merge(makeMember("a", StateAlive, 1))
	g.members.Merge(makeMember("b", StateAlive, 1))
	g.members.Merge(makeMember("c", StateAlive, 1))

	if got := g.retransmitLimit(); got != 16 {
		t.Fatalf("retransmitLimit() = %d, want 16 (3 members)", got)
	}
}

// --- getBroadcasts ---

func TestGetBroadcasts_DecreasesRetransmit(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	cfg := DefaultConfig()
	cfg.RetransmitMult = 1 // retransmitLimit = 1*(0+1) = 1
	g, _ := New(cfg, self)

	g.Broadcast([]*Member{makeMember("a", StateAlive, 1)})

	// First get: returns message, retransmit goes from 1 to 0 (removed)
	msgs := g.getBroadcasts(10)
	if len(msgs) != 1 {
		t.Fatalf("getBroadcasts returned %d, want 1", len(msgs))
	}

	// Second get: queue should be empty
	msgs = g.getBroadcasts(10)
	if len(msgs) != 0 {
		t.Fatalf("getBroadcasts returned %d, want 0 (exhausted)", len(msgs))
	}
}

func TestGetBroadcasts_LimitRespected(t *testing.T) {
	self := makeMember("self", StateAlive, 1)
	cfg := DefaultConfig()
	cfg.RetransmitMult = 10
	g, _ := New(cfg, self)

	g.Broadcast([]*Member{makeMember("a", StateAlive, 1)})
	g.Broadcast([]*Member{makeMember("b", StateAlive, 1)})
	g.Broadcast([]*Member{makeMember("c", StateAlive, 1)})

	msgs := g.getBroadcasts(2)
	if len(msgs) != 2 {
		t.Fatalf("getBroadcasts(2) returned %d, want 2", len(msgs))
	}
}

// --- BroadcastPayload / MsgChat ---

func TestBroadcastChat(t *testing.T) {
	self := makeMember("node1", StateAlive, 1)
	cfg := DefaultConfig()
	cfg.MeshSecret = []byte("test-secret-32-bytes-long-xxxxx")
	g, _ := New(cfg, self)

	// BroadcastPayload sends directly to alive members.
	// With no alive members, it just returns (no crash).
	payload := []byte(`{"text":"hello mesh"}`)
	g.BroadcastPayload(MsgChat, payload) // should not panic

	// Test that handleCustomBroadcast re-queues for further propagation
	msg := &Message{
		Type:    MsgChat,
		From:    "node2",
		Payload: json.RawMessage(payload),
	}
	g.handleCustomBroadcast(msg)

	msgs := g.getBroadcasts(10)
	if len(msgs) != 1 {
		t.Fatalf("getBroadcasts returned %d messages, want 1", len(msgs))
	}

	got := msgs[0]
	if got.Type != MsgChat {
		t.Fatalf("msg.Type = %v, want MsgChat (%v)", got.Type, MsgChat)
	}

	var parsed map[string]string
	if err := json.Unmarshal(got.Payload, &parsed); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	if parsed["text"] != "hello mesh" {
		t.Fatalf("payload text = %q, want %q", parsed["text"], "hello mesh")
	}
}

// --- HMAC covers Payload ---

func TestHMAC_CoversPayload(t *testing.T) {
	g := newGossipWithSecret([]byte("test-secret-key"))

	msg := &Message{
		Type:      MsgChat,
		SeqNo:     1,
		From:      "node1",
		Timestamp: time.Now().UnixNano(),
		Payload:   json.RawMessage(`{"text":"original"}`),
	}
	g.signHMAC(msg)

	if !g.verifyHMAC(msg) {
		t.Fatal("verifyHMAC should pass for freshly signed message")
	}

	// Tamper with the payload — verification must fail.
	msg.Payload = json.RawMessage(`{"text":"tampered"}`)
	if g.verifyHMAC(msg) {
		t.Fatal("verifyHMAC should fail when Payload is tampered")
	}
}

// --- MemberState.String ---

func TestMemberStateString(t *testing.T) {
	tests := []struct {
		state MemberState
		want  string
	}{
		{StateAlive, "alive"},
		{StateSuspect, "suspect"},
		{StateDead, "dead"},
		{StateLeft, "left"},
		{MemberState(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("MemberState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}
