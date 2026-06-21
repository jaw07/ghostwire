package gossip

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

// TestMergeNilMemberNoPanic guards the nil-deref crash: a malformed gossip
// payload can decode to a nil *Member.
func TestMergeNilMemberNoPanic(t *testing.T) {
	ml := NewMemberList(&Member{NodeID: "self"})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Merge(nil) panicked: %v", r)
		}
	}()
	if ml.Merge(nil) {
		t.Error("Merge(nil) should return false")
	}
}

// TestMarkDeadIfSuspectRequiresSuspect verifies SWIM refutation: an Alive member
// (e.g. one that refuted during the suspicion window) is not killed.
func TestMarkDeadIfSuspectRequiresSuspect(t *testing.T) {
	ml := NewMemberList(&Member{NodeID: "self"})
	ml.Merge(&Member{NodeID: "peer", State: StateAlive, Incarnation: 1})

	if ml.MarkDeadIfSuspect("peer") {
		t.Error("alive member must not be confirmed dead")
	}
	if m := ml.Get("peer"); m == nil || m.State != StateAlive {
		t.Fatalf("peer should still be alive, got %v", m)
	}

	if !ml.MarkSuspect("peer") {
		t.Fatal("MarkSuspect should succeed on alive member")
	}
	if !ml.MarkDeadIfSuspect("peer") {
		t.Error("suspect member should be confirmed dead")
	}
}

// TestHMACCoversRoutingFields verifies the per-member HMAC authenticates the
// routing-relevant fields (PublicKey, Endpoints, MeshIP), so an on-path attacker
// cannot rewrite them in a validly-signed message.
func TestHMACCoversRoutingFields(t *testing.T) {
	g, err := New(&Config{MeshSecret: []byte("test-mesh-secret")}, &Member{NodeID: "self"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	msg := &Message{
		Type:      MsgBroadcast,
		From:      "self",
		SeqNo:     1,
		Timestamp: time.Now().UnixNano(),
		Members: []*Member{{
			NodeID:    "peer",
			PublicKey: "PUBKEY-A",
			Endpoints: []string{"1.2.3.4:8444"},
			MeshIP:    netip.MustParseAddr("10.0.0.2"),
			State:     StateAlive,
		}},
	}
	base := g.hmacMessage(msg)

	cases := []struct {
		name   string
		mutate func()
		undo   func()
	}{
		{"PublicKey", func() { msg.Members[0].PublicKey = "PUBKEY-EVIL" }, func() { msg.Members[0].PublicKey = "PUBKEY-A" }},
		{"Endpoints", func() { msg.Members[0].Endpoints = []string{"6.6.6.6:8444"} }, func() { msg.Members[0].Endpoints = []string{"1.2.3.4:8444"} }},
		{"MeshIP", func() { msg.Members[0].MeshIP = netip.MustParseAddr("10.0.0.99") }, func() { msg.Members[0].MeshIP = netip.MustParseAddr("10.0.0.2") }},
	}
	for _, tc := range cases {
		tc.mutate()
		if bytes.Equal(base, g.hmacMessage(msg)) {
			t.Errorf("HMAC must change when %s is tampered", tc.name)
		}
		tc.undo()
		if !bytes.Equal(base, g.hmacMessage(msg)) {
			t.Errorf("HMAC should match base after restoring %s", tc.name)
		}
	}
}
