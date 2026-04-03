package routing

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/ghostwire/ghostwire/internal/gossip"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(fmt.Sprintf("bad test addr %q: %v", s, err))
	}
	return a
}

// newTestMemberList builds a MemberList with the given self node and merges
// the supplied members into it.
func newTestMemberList(self *gossip.Member, others ...*gossip.Member) *gossip.MemberList {
	ml := gossip.NewMemberList(self)
	for _, m := range others {
		ml.Merge(m)
	}
	return ml
}

// ---------------------------------------------------------------------------
// RouteType
// ---------------------------------------------------------------------------

func TestRouteType_String(t *testing.T) {
	tests := []struct {
		rt   RouteType
		want string
	}{
		{RouteDirect, "direct"},
		{RouteRelay, "relay"},
		{RouteMultiHop, "multihop"},
		{RouteType(99), "unknown"},
	}
	for _, tc := range tests {
		if got := tc.rt.String(); got != tc.want {
			t.Errorf("RouteType(%d).String() = %q, want %q", tc.rt, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// NewTable
// ---------------------------------------------------------------------------

func TestNewTable(t *testing.T) {
	ip := mustAddr("10.0.0.1")
	tbl := NewTable("node-local", ip)
	if tbl == nil {
		t.Fatal("NewTable returned nil")
	}
	if tbl.localID != "node-local" {
		t.Errorf("localID = %q, want %q", tbl.localID, "node-local")
	}
	if tbl.localIP != ip {
		t.Errorf("localIP = %v, want %v", tbl.localIP, ip)
	}
	if tbl.maxHops != 3 {
		t.Errorf("maxHops = %d, want 3", tbl.maxHops)
	}
	if tbl.Size() != 0 {
		t.Errorf("Size() = %d, want 0 for new table", tbl.Size())
	}
}

// ---------------------------------------------------------------------------
// GetRoute / GetRouteByIP – empty table
// ---------------------------------------------------------------------------

func TestGetRoute_UnknownReturnsNil(t *testing.T) {
	tbl := NewTable("local", mustAddr("10.0.0.1"))
	if r := tbl.GetRoute("nonexistent"); r != nil {
		t.Errorf("GetRoute on empty table returned %+v, want nil", r)
	}
}

func TestGetRouteByIP_UnknownReturnsNil(t *testing.T) {
	tbl := NewTable("local", mustAddr("10.0.0.1"))
	if r := tbl.GetRouteByIP(mustAddr("10.0.0.99")); r != nil {
		t.Errorf("GetRouteByIP on empty table returned %+v, want nil", r)
	}
}

// ---------------------------------------------------------------------------
// UpdateFromGossip – direct and relay route creation
// ---------------------------------------------------------------------------

func TestUpdateFromGossip_DirectRoutes(t *testing.T) {
	localIP := mustAddr("10.0.0.1")
	tbl := NewTable("local", localIP)

	self := &gossip.Member{
		NodeID:    "local",
		MeshIP:    localIP,
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.1:51820"},
	}

	peer := &gossip.Member{
		NodeID:    "peer-1",
		MeshIP:    mustAddr("10.0.0.2"),
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.2:51820"},
		RTT:       5 * time.Millisecond,
		Transport: "wireguard",
	}

	ml := newTestMemberList(self, peer)
	tbl.UpdateFromGossip(ml)

	// Should have exactly one destination.
	if tbl.Size() != 1 {
		t.Fatalf("Size() = %d, want 1", tbl.Size())
	}

	route := tbl.GetRoute("peer-1")
	if route == nil {
		t.Fatal("GetRoute(peer-1) returned nil")
	}
	if route.Type != RouteDirect {
		t.Errorf("route.Type = %v, want RouteDirect", route.Type)
	}
	if route.Destination != "peer-1" {
		t.Errorf("route.Destination = %q, want %q", route.Destination, "peer-1")
	}
	if route.DestIP != mustAddr("10.0.0.2") {
		t.Errorf("route.DestIP = %v, want 10.0.0.2", route.DestIP)
	}
	if route.NextHop != "peer-1" {
		t.Errorf("route.NextHop = %q, want %q", route.NextHop, "peer-1")
	}

	// GetRouteByIP should find the same route.
	byIP := tbl.GetRouteByIP(mustAddr("10.0.0.2"))
	if byIP == nil {
		t.Fatal("GetRouteByIP returned nil for 10.0.0.2")
	}
	if byIP.Destination != "peer-1" {
		t.Errorf("byIP.Destination = %q, want peer-1", byIP.Destination)
	}
}

func TestUpdateFromGossip_RelayRoutes(t *testing.T) {
	localIP := mustAddr("10.0.0.1")
	tbl := NewTable("local", localIP)

	self := &gossip.Member{
		NodeID:    "local",
		MeshIP:    localIP,
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.1:51820"},
	}

	// Peer with no endpoints (can only be reached via relay).
	peerNoEP := &gossip.Member{
		NodeID: "peer-2",
		MeshIP: mustAddr("10.0.0.3"),
		State:  gossip.StateAlive,
		RTT:    10 * time.Millisecond,
	}

	relay := &gossip.Member{
		NodeID:    "relay-1",
		MeshIP:    mustAddr("10.0.0.100"),
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.100:51820"},
		Roles:     []string{"relay"},
		RTT:       3 * time.Millisecond,
		Transport: "wireguard",
	}

	ml := newTestMemberList(self, peerNoEP, relay)
	tbl.UpdateFromGossip(ml)

	// peer-2 should only have relay routes (no endpoints => no direct).
	route := tbl.GetRoute("peer-2")
	if route == nil {
		t.Fatal("GetRoute(peer-2) returned nil")
	}
	if route.Type != RouteRelay {
		t.Errorf("route.Type = %v, want RouteRelay", route.Type)
	}
	if route.NextHop != "relay-1" {
		t.Errorf("route.NextHop = %q, want relay-1", route.NextHop)
	}
}

func TestUpdateFromGossip_DirectPreferredOverRelay(t *testing.T) {
	localIP := mustAddr("10.0.0.1")
	tbl := NewTable("local", localIP)

	self := &gossip.Member{
		NodeID:    "local",
		MeshIP:    localIP,
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.1:51820"},
	}

	peer := &gossip.Member{
		NodeID:    "peer-1",
		MeshIP:    mustAddr("10.0.0.2"),
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.2:51820"},
		RTT:       5 * time.Millisecond,
		Transport: "wireguard",
	}

	relay := &gossip.Member{
		NodeID:    "relay-1",
		MeshIP:    mustAddr("10.0.0.100"),
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.100:51820"},
		Roles:     []string{"relay"},
		RTT:       2 * time.Millisecond,
		Transport: "wireguard",
	}

	ml := newTestMemberList(self, peer, relay)
	tbl.UpdateFromGossip(ml)

	// Best route for peer-1 should be direct (metric 1 < 2).
	best := tbl.GetRoute("peer-1")
	if best == nil {
		t.Fatal("GetRoute(peer-1) returned nil")
	}
	if best.Type != RouteDirect {
		t.Errorf("best route type = %v, want RouteDirect", best.Type)
	}

	// All routes should include both direct and relay.
	all := tbl.GetAllRoutes("peer-1")
	if len(all) < 2 {
		t.Fatalf("expected at least 2 routes for peer-1, got %d", len(all))
	}
}

// ---------------------------------------------------------------------------
// GetDirectPeers / GetRelayedPeers
// ---------------------------------------------------------------------------

func TestGetDirectPeers_and_GetRelayedPeers(t *testing.T) {
	localIP := mustAddr("10.0.0.1")
	tbl := NewTable("local", localIP)

	self := &gossip.Member{
		NodeID:    "local",
		MeshIP:    localIP,
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.1:51820"},
	}

	directPeer := &gossip.Member{
		NodeID:    "direct-peer",
		MeshIP:    mustAddr("10.0.0.2"),
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.2:51820"},
		RTT:       5 * time.Millisecond,
	}

	relayOnlyPeer := &gossip.Member{
		NodeID: "relay-only-peer",
		MeshIP: mustAddr("10.0.0.3"),
		State:  gossip.StateAlive,
		RTT:    10 * time.Millisecond,
	}

	relay := &gossip.Member{
		NodeID:    "relay-1",
		MeshIP:    mustAddr("10.0.0.100"),
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.100:51820"},
		Roles:     []string{"relay"},
		RTT:       2 * time.Millisecond,
	}

	ml := newTestMemberList(self, directPeer, relayOnlyPeer, relay)
	tbl.UpdateFromGossip(ml)

	direct := tbl.GetDirectPeers()
	relayed := tbl.GetRelayedPeers()

	// direct-peer and relay-1 have endpoints => direct routes.
	// relay-only-peer has no endpoints => best route is relay.
	directSet := make(map[string]bool)
	for _, id := range direct {
		directSet[id] = true
	}
	if !directSet["direct-peer"] {
		t.Errorf("direct-peer not in GetDirectPeers(); got %v", direct)
	}
	if !directSet["relay-1"] {
		t.Errorf("relay-1 not in GetDirectPeers(); got %v", direct)
	}

	relaySet := make(map[string]bool)
	for _, id := range relayed {
		relaySet[id] = true
	}
	if !relaySet["relay-only-peer"] {
		t.Errorf("relay-only-peer not in GetRelayedPeers(); got %v", relayed)
	}
}

// ---------------------------------------------------------------------------
// Size / All
// ---------------------------------------------------------------------------

func TestSize_and_All(t *testing.T) {
	localIP := mustAddr("10.0.0.1")
	tbl := NewTable("local", localIP)

	self := &gossip.Member{
		NodeID:    "local",
		MeshIP:    localIP,
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.1:51820"},
	}

	members := []*gossip.Member{
		{NodeID: "a", MeshIP: mustAddr("10.0.0.2"), State: gossip.StateAlive, Endpoints: []string{"1.2.3.4:51820"}, RTT: time.Millisecond},
		{NodeID: "b", MeshIP: mustAddr("10.0.0.3"), State: gossip.StateAlive, Endpoints: []string{"1.2.3.5:51820"}, RTT: time.Millisecond},
		{NodeID: "c", MeshIP: mustAddr("10.0.0.4"), State: gossip.StateAlive, Endpoints: []string{"1.2.3.6:51820"}, RTT: time.Millisecond},
	}

	ml := newTestMemberList(self, members...)
	tbl.UpdateFromGossip(ml)

	if tbl.Size() != 3 {
		t.Errorf("Size() = %d, want 3", tbl.Size())
	}

	all := tbl.All()
	if len(all) != 3 {
		t.Errorf("len(All()) = %d, want 3", len(all))
	}
	for _, id := range []string{"a", "b", "c"} {
		if _, ok := all[id]; !ok {
			t.Errorf("All() missing key %q", id)
		}
	}
}

// ---------------------------------------------------------------------------
// UpdateMetrics
// ---------------------------------------------------------------------------

func TestUpdateMetrics(t *testing.T) {
	localIP := mustAddr("10.0.0.1")
	tbl := NewTable("local", localIP)

	self := &gossip.Member{
		NodeID:    "local",
		MeshIP:    localIP,
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.1:51820"},
	}
	peer := &gossip.Member{
		NodeID:    "peer-1",
		MeshIP:    mustAddr("10.0.0.2"),
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.2:51820"},
		RTT:       50 * time.Millisecond,
	}

	ml := newTestMemberList(self, peer)
	tbl.UpdateFromGossip(ml)

	// Update metrics.
	tbl.UpdateMetrics("peer-1", 12*time.Millisecond)

	route := tbl.GetRoute("peer-1")
	if route == nil {
		t.Fatal("route nil after UpdateMetrics")
	}
	if route.RTT != 12*time.Millisecond {
		t.Errorf("RTT = %v, want 12ms", route.RTT)
	}
}

func TestUpdateMetrics_UnknownNode(t *testing.T) {
	tbl := NewTable("local", mustAddr("10.0.0.1"))
	// Should not panic.
	tbl.UpdateMetrics("no-such-node", 5*time.Millisecond)
}

// ---------------------------------------------------------------------------
// InvalidateRoute
// ---------------------------------------------------------------------------

func TestInvalidateRoute(t *testing.T) {
	localIP := mustAddr("10.0.0.1")
	tbl := NewTable("local", localIP)

	self := &gossip.Member{
		NodeID:    "local",
		MeshIP:    localIP,
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.1:51820"},
	}
	peer := &gossip.Member{
		NodeID:    "peer-1",
		MeshIP:    mustAddr("10.0.0.2"),
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.2:51820"},
		RTT:       5 * time.Millisecond,
	}
	relay := &gossip.Member{
		NodeID:    "relay-1",
		MeshIP:    mustAddr("10.0.0.100"),
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.100:51820"},
		Roles:     []string{"relay"},
		RTT:       3 * time.Millisecond,
	}

	ml := newTestMemberList(self, peer, relay)
	tbl.UpdateFromGossip(ml)

	// Peer should have both direct and relay routes.
	before := tbl.GetAllRoutes("peer-1")
	if len(before) < 2 {
		t.Fatalf("expected >=2 routes before invalidate, got %d", len(before))
	}

	// Invalidate direct route.
	tbl.InvalidateRoute("peer-1", RouteDirect)

	after := tbl.GetAllRoutes("peer-1")
	for _, r := range after {
		if r.Type == RouteDirect {
			t.Error("direct route still present after InvalidateRoute")
		}
	}

	// Best route should now be relay.
	best := tbl.GetRoute("peer-1")
	if best == nil {
		t.Fatal("no route after invalidation")
	}
	if best.Type != RouteRelay {
		t.Errorf("best route type = %v after invalidation, want RouteRelay", best.Type)
	}
}

func TestInvalidateRoute_SingleRoute_NoRemoval(t *testing.T) {
	localIP := mustAddr("10.0.0.1")
	tbl := NewTable("local", localIP)

	// Manually insert one route.
	tbl.mu.Lock()
	tbl.routes["peer-1"] = []*Route{
		{Destination: "peer-1", Type: RouteDirect},
	}
	tbl.mu.Unlock()

	tbl.InvalidateRoute("peer-1", RouteDirect)

	// With only one route, InvalidateRoute should not remove it.
	if r := tbl.GetRoute("peer-1"); r == nil {
		t.Error("single route was removed; InvalidateRoute should be a no-op for len<=1")
	}
}

// ---------------------------------------------------------------------------
// SetOnChange callback
// ---------------------------------------------------------------------------

func TestSetOnChange_FiresOnRouteChange(t *testing.T) {
	localIP := mustAddr("10.0.0.1")
	tbl := NewTable("local", localIP)

	var calledWith []string
	tbl.SetOnChange(func(nodeID string, routes []*Route) {
		calledWith = append(calledWith, nodeID)
	})

	self := &gossip.Member{
		NodeID:    "local",
		MeshIP:    localIP,
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.1:51820"},
	}
	peer := &gossip.Member{
		NodeID:    "peer-1",
		MeshIP:    mustAddr("10.0.0.2"),
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.2:51820"},
		RTT:       5 * time.Millisecond,
	}

	ml := newTestMemberList(self, peer)
	tbl.UpdateFromGossip(ml)

	if len(calledWith) == 0 {
		t.Error("onChange was not called on initial route creation")
	}
	found := false
	for _, id := range calledWith {
		if id == "peer-1" {
			found = true
		}
	}
	if !found {
		t.Errorf("onChange not called for peer-1; calls: %v", calledWith)
	}
}

func TestSetOnChange_FiresOnNodeRemoval(t *testing.T) {
	localIP := mustAddr("10.0.0.1")
	tbl := NewTable("local", localIP)

	self := &gossip.Member{
		NodeID:    "local",
		MeshIP:    localIP,
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.1:51820"},
	}
	peer := &gossip.Member{
		NodeID:    "peer-1",
		MeshIP:    mustAddr("10.0.0.2"),
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.2:51820"},
		RTT:       5 * time.Millisecond,
	}

	// First gossip with peer present.
	ml := newTestMemberList(self, peer)
	tbl.UpdateFromGossip(ml)

	// Now set callback and gossip without the peer (simulate it going dead and
	// being filtered out of AliveMembers).
	var removedNodes []string
	tbl.SetOnChange(func(nodeID string, routes []*Route) {
		if routes == nil {
			removedNodes = append(removedNodes, nodeID)
		}
	})

	mlEmpty := newTestMemberList(self) // no peers
	tbl.UpdateFromGossip(mlEmpty)

	if len(removedNodes) == 0 {
		t.Error("onChange was not called with nil routes for removed node")
	}
}

// ---------------------------------------------------------------------------
// routesEqual (unexported)
// ---------------------------------------------------------------------------

func TestRoutesEqual(t *testing.T) {
	a := []*Route{
		{Type: RouteDirect, NextHop: "x"},
		{Type: RouteRelay, NextHop: "y"},
	}
	b := []*Route{
		{Type: RouteDirect, NextHop: "x"},
		{Type: RouteRelay, NextHop: "y"},
	}
	if !routesEqual(a, b) {
		t.Error("routesEqual returned false for identical routes")
	}

	c := []*Route{
		{Type: RouteDirect, NextHop: "x"},
	}
	if routesEqual(a, c) {
		t.Error("routesEqual returned true for different-length slices")
	}

	d := []*Route{
		{Type: RouteDirect, NextHop: "x"},
		{Type: RouteRelay, NextHop: "z"}, // different NextHop
	}
	if routesEqual(a, d) {
		t.Error("routesEqual returned true for different NextHop")
	}

	if !routesEqual(nil, nil) {
		t.Error("routesEqual returned false for two nils")
	}
}

// ---------------------------------------------------------------------------
// RelayManager – NewRelayManager
// ---------------------------------------------------------------------------

func TestNewRelayManager(t *testing.T) {
	tbl := NewTable("local", mustAddr("10.0.0.1"))
	self := &gossip.Member{NodeID: "local", MeshIP: mustAddr("10.0.0.1"), State: gossip.StateAlive}
	ml := gossip.NewMemberList(self)

	rm := NewRelayManager(tbl, ml)
	if rm == nil {
		t.Fatal("NewRelayManager returned nil")
	}
	if rm.table != tbl {
		t.Error("table pointer mismatch")
	}
	if rm.members != ml {
		t.Error("members pointer mismatch")
	}
}

// ---------------------------------------------------------------------------
// RelayManager – SelectRelay
// ---------------------------------------------------------------------------

func TestSelectRelay_NoRelays(t *testing.T) {
	tbl := NewTable("local", mustAddr("10.0.0.1"))
	self := &gossip.Member{NodeID: "local", State: gossip.StateAlive}
	ml := gossip.NewMemberList(self)

	rm := NewRelayManager(tbl, ml)
	if got := rm.SelectRelay("dest"); got != nil {
		t.Errorf("SelectRelay with no relays returned %+v, want nil", got)
	}
}

func TestSelectRelay_LowestRTT(t *testing.T) {
	tbl := NewTable("local", mustAddr("10.0.0.1"))
	self := &gossip.Member{NodeID: "local", State: gossip.StateAlive}

	slow := &gossip.Member{
		NodeID:    "relay-slow",
		State:     gossip.StateAlive,
		Roles:     []string{"relay"},
		Endpoints: []string{"1.2.3.4:51820"},
		RTT:       100 * time.Millisecond,
	}
	fast := &gossip.Member{
		NodeID:    "relay-fast",
		State:     gossip.StateAlive,
		Roles:     []string{"relay"},
		Endpoints: []string{"1.2.3.5:51820"},
		RTT:       10 * time.Millisecond,
	}

	ml := newTestMemberList(self, slow, fast)
	rm := NewRelayManager(tbl, ml)

	got := rm.SelectRelay("dest")
	if got == nil {
		t.Fatal("SelectRelay returned nil")
	}
	if got.NodeID != "relay-fast" {
		t.Errorf("SelectRelay chose %q, want relay-fast (lowest RTT)", got.NodeID)
	}
}

func TestSelectRelay_PrefersConfigured(t *testing.T) {
	tbl := NewTable("local", mustAddr("10.0.0.1"))
	self := &gossip.Member{NodeID: "local", State: gossip.StateAlive}

	slow := &gossip.Member{
		NodeID:    "relay-slow",
		State:     gossip.StateAlive,
		Roles:     []string{"relay"},
		Endpoints: []string{"1.2.3.4:51820"},
		RTT:       100 * time.Millisecond,
	}
	fast := &gossip.Member{
		NodeID:    "relay-fast",
		State:     gossip.StateAlive,
		Roles:     []string{"relay"},
		Endpoints: []string{"1.2.3.5:51820"},
		RTT:       10 * time.Millisecond,
	}

	ml := newTestMemberList(self, slow, fast)
	rm := NewRelayManager(tbl, ml)

	// Prefer the slow relay explicitly.
	rm.SetPreferred("relay-slow")

	got := rm.SelectRelay("dest")
	if got == nil {
		t.Fatal("SelectRelay returned nil")
	}
	if got.NodeID != "relay-slow" {
		t.Errorf("SelectRelay chose %q, want relay-slow (preferred)", got.NodeID)
	}
}

func TestSelectRelay_PreferredNotAlive_FallsBack(t *testing.T) {
	tbl := NewTable("local", mustAddr("10.0.0.1"))
	self := &gossip.Member{NodeID: "local", State: gossip.StateAlive}

	fast := &gossip.Member{
		NodeID:    "relay-fast",
		State:     gossip.StateAlive,
		Roles:     []string{"relay"},
		Endpoints: []string{"1.2.3.5:51820"},
		RTT:       10 * time.Millisecond,
	}

	ml := newTestMemberList(self, fast)
	rm := NewRelayManager(tbl, ml)

	// Prefer a relay that doesn't exist.
	rm.SetPreferred("relay-gone")

	got := rm.SelectRelay("dest")
	if got == nil {
		t.Fatal("SelectRelay returned nil when preferred is missing")
	}
	if got.NodeID != "relay-fast" {
		t.Errorf("SelectRelay chose %q, want relay-fast (fallback)", got.NodeID)
	}
}

// ---------------------------------------------------------------------------
// RelayManager – SetPreferred
// ---------------------------------------------------------------------------

func TestSetPreferred(t *testing.T) {
	tbl := NewTable("local", mustAddr("10.0.0.1"))
	self := &gossip.Member{NodeID: "local", State: gossip.StateAlive}
	ml := gossip.NewMemberList(self)
	rm := NewRelayManager(tbl, ml)

	rm.SetPreferred("relay-x")

	rm.mu.RLock()
	got := rm.preferred
	rm.mu.RUnlock()
	if got != "relay-x" {
		t.Errorf("preferred = %q, want relay-x", got)
	}
}

// ---------------------------------------------------------------------------
// RelayManager – Failover
// ---------------------------------------------------------------------------

func TestFailover(t *testing.T) {
	tbl := NewTable("local", mustAddr("10.0.0.1"))
	self := &gossip.Member{NodeID: "local", State: gossip.StateAlive}

	relayA := &gossip.Member{
		NodeID: "relay-a",
		State:  gossip.StateAlive,
		Roles:  []string{"relay"},
		RTT:    50 * time.Millisecond,
	}
	relayB := &gossip.Member{
		NodeID: "relay-b",
		State:  gossip.StateAlive,
		Roles:  []string{"relay"},
		RTT:    20 * time.Millisecond,
	}

	ml := newTestMemberList(self, relayA, relayB)
	rm := NewRelayManager(tbl, ml)
	rm.SetPreferred("relay-a")

	// Failover away from relay-a.
	alt := rm.Failover("relay-a")
	if alt == nil {
		t.Fatal("Failover returned nil")
	}
	if alt.NodeID != "relay-b" {
		t.Errorf("Failover chose %q, want relay-b", alt.NodeID)
	}

	// Preferred should now be relay-b.
	rm.mu.RLock()
	pref := rm.preferred
	rm.mu.RUnlock()
	if pref != "relay-b" {
		t.Errorf("preferred after failover = %q, want relay-b", pref)
	}
}

func TestFailover_NoAlternate(t *testing.T) {
	tbl := NewTable("local", mustAddr("10.0.0.1"))
	self := &gossip.Member{NodeID: "local", State: gossip.StateAlive}

	only := &gossip.Member{
		NodeID: "relay-only",
		State:  gossip.StateAlive,
		Roles:  []string{"relay"},
		RTT:    10 * time.Millisecond,
	}

	ml := newTestMemberList(self, only)
	rm := NewRelayManager(tbl, ml)

	alt := rm.Failover("relay-only")
	if alt != nil {
		t.Errorf("Failover with no alternates returned %+v, want nil", alt)
	}
}

// ===========================================================================
// nat.go tests
// ===========================================================================

// ---------------------------------------------------------------------------
// NATType.String()
// ---------------------------------------------------------------------------

func TestNATType_String(t *testing.T) {
	tests := []struct {
		nt   NATType
		want string
	}{
		{NATNone, "none"},
		{NATFull, "full-cone"},
		{NATRestricted, "restricted"},
		{NATPortRestricted, "port-restricted"},
		{NATSymmetric, "symmetric"},
		{NATUnknown, "unknown"},
		{NATType(99), "unknown"}, // out of range
	}
	for _, tc := range tests {
		if got := tc.nt.String(); got != tc.want {
			t.Errorf("NATType(%d).String() = %q, want %q", tc.nt, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// NATType.CanHolePunch()
// ---------------------------------------------------------------------------

func TestNATType_CanHolePunch(t *testing.T) {
	canPunch := []NATType{NATNone, NATFull, NATRestricted, NATPortRestricted}
	for _, nt := range canPunch {
		if !nt.CanHolePunch() {
			t.Errorf("NATType(%d / %s).CanHolePunch() = false, want true", nt, nt)
		}
	}

	cantPunch := []NATType{NATSymmetric, NATUnknown}
	for _, nt := range cantPunch {
		if nt.CanHolePunch() {
			t.Errorf("NATType(%d / %s).CanHolePunch() = true, want false", nt, nt)
		}
	}
}

// ---------------------------------------------------------------------------
// parseSTUNResponse – XOR-MAPPED-ADDRESS
// ---------------------------------------------------------------------------

// buildSTUNResponse constructs a minimal valid STUN Binding Response with a
// XOR-MAPPED-ADDRESS attribute for the given IPv4 address and port.
func buildSTUNResponse(ip [4]byte, port uint16) []byte {
	// STUN header: 20 bytes
	// Type: 0x0101 (Binding Success Response)
	// Length: 12 (one XOR-MAPPED-ADDRESS attribute: 4 header + 8 value)
	// Magic cookie: 0x2112A442
	// Transaction ID: 12 bytes of zeros
	magicCookie := [4]byte{0x21, 0x12, 0xa4, 0x42}

	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], 0x0101)      // message type
	binary.BigEndian.PutUint16(header[2:4], 12)           // message length (attrs only)
	copy(header[4:8], magicCookie[:])                     // magic cookie
	// transaction ID is zeros (bytes 8-19)

	// XOR-MAPPED-ADDRESS attribute
	// Attribute type: 0x0020, length: 8
	attr := make([]byte, 4+8)
	binary.BigEndian.PutUint16(attr[0:2], 0x0020) // type
	binary.BigEndian.PutUint16(attr[2:4], 8)      // length

	attr[4] = 0x00 // reserved
	attr[5] = 0x01 // family: IPv4

	// XOR'd port: port ^ (magic_cookie >> 16) = port ^ 0x2112
	binary.BigEndian.PutUint16(attr[6:8], port^0x2112)

	// XOR'd IP: each byte XOR'd with magic cookie
	attr[8] = ip[0] ^ magicCookie[0]
	attr[9] = ip[1] ^ magicCookie[1]
	attr[10] = ip[2] ^ magicCookie[2]
	attr[11] = ip[3] ^ magicCookie[3]

	return append(header, attr...)
}

func TestParseSTUNResponse_XORMappedAddress(t *testing.T) {
	// Test with IP 203.0.113.42, port 12345.
	ip := [4]byte{203, 0, 113, 42}
	port := uint16(12345)

	data := buildSTUNResponse(ip, port)
	got, err := parseSTUNResponse(data)
	if err != nil {
		t.Fatalf("parseSTUNResponse error: %v", err)
	}

	want := "203.0.113.42:12345"
	if got != want {
		t.Errorf("parseSTUNResponse = %q, want %q", got, want)
	}
}

func TestParseSTUNResponse_AnotherAddress(t *testing.T) {
	// Test with IP 192.168.1.1, port 51820.
	ip := [4]byte{192, 168, 1, 1}
	port := uint16(51820)

	data := buildSTUNResponse(ip, port)
	got, err := parseSTUNResponse(data)
	if err != nil {
		t.Fatalf("parseSTUNResponse error: %v", err)
	}

	want := "192.168.1.1:51820"
	if got != want {
		t.Errorf("parseSTUNResponse = %q, want %q", got, want)
	}
}

func TestParseSTUNResponse_TooShort(t *testing.T) {
	_, err := parseSTUNResponse([]byte{0x00, 0x01})
	if err == nil {
		t.Error("expected error for short data, got nil")
	}
}

func TestParseSTUNResponse_NoMappedAddress(t *testing.T) {
	// Valid header but no attributes.
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], 0x0101)
	binary.BigEndian.PutUint16(header[2:4], 0) // zero-length body
	copy(header[4:8], []byte{0x21, 0x12, 0xa4, 0x42})

	_, err := parseSTUNResponse(header)
	if err == nil {
		t.Error("expected error for response with no mapped address, got nil")
	}
}

// ---------------------------------------------------------------------------
// parseSTUNResponse – MAPPED-ADDRESS fallback (0x0001)
// ---------------------------------------------------------------------------

func buildSTUNResponseMappedAddress(ip [4]byte, port uint16) []byte {
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], 0x0101)
	binary.BigEndian.PutUint16(header[2:4], 12) // one attr
	copy(header[4:8], []byte{0x21, 0x12, 0xa4, 0x42})

	attr := make([]byte, 4+8)
	binary.BigEndian.PutUint16(attr[0:2], 0x0001) // MAPPED-ADDRESS
	binary.BigEndian.PutUint16(attr[2:4], 8)

	attr[4] = 0x00
	attr[5] = 0x01 // IPv4
	binary.BigEndian.PutUint16(attr[6:8], port)
	copy(attr[8:12], ip[:])

	return append(header, attr...)
}

func TestParseSTUNResponse_MappedAddressFallback(t *testing.T) {
	ip := [4]byte{10, 20, 30, 40}
	port := uint16(9999)

	data := buildSTUNResponseMappedAddress(ip, port)
	got, err := parseSTUNResponse(data)
	if err != nil {
		t.Fatalf("parseSTUNResponse error: %v", err)
	}

	want := "10.20.30.40:9999"
	if got != want {
		t.Errorf("parseSTUNResponse = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// HolePunchRequest / HolePunchResponse – struct construction
// ---------------------------------------------------------------------------

func TestHolePunchRequest_Construction(t *testing.T) {
	req := HolePunchRequest{
		FromNodeID: "node-a",
		ToNodeID:   "node-b",
		FromAddr:   "1.2.3.4:51820",
		ToAddr:     "5.6.7.8:51820",
		Nonce:      []byte{0xDE, 0xAD},
		Timestamp:  1234567890,
	}
	if req.FromNodeID != "node-a" {
		t.Error("FromNodeID mismatch")
	}
	if req.ToNodeID != "node-b" {
		t.Error("ToNodeID mismatch")
	}
	if req.Timestamp != 1234567890 {
		t.Error("Timestamp mismatch")
	}
}

func TestHolePunchResponse_Construction(t *testing.T) {
	resp := HolePunchResponse{
		FromNodeID: "node-b",
		ToNodeID:   "node-a",
		Success:    true,
		Addr:       "5.6.7.8:51820",
		Nonce:      []byte{0xCA, 0xFE},
	}
	if !resp.Success {
		t.Error("Success should be true")
	}
	if resp.Addr != "5.6.7.8:51820" {
		t.Errorf("Addr = %q, want 5.6.7.8:51820", resp.Addr)
	}
}

// ---------------------------------------------------------------------------
// UpdateFromGossip – skips local node
// ---------------------------------------------------------------------------

func TestUpdateFromGossip_SkipsLocalNode(t *testing.T) {
	localIP := mustAddr("10.0.0.1")
	tbl := NewTable("local", localIP)

	self := &gossip.Member{
		NodeID:    "local",
		MeshIP:    localIP,
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.1:51820"},
	}

	ml := newTestMemberList(self)
	tbl.UpdateFromGossip(ml)

	// Local node should not appear in routes.
	if tbl.Size() != 0 {
		t.Errorf("Size() = %d, want 0 (local should be skipped)", tbl.Size())
	}
}

// ---------------------------------------------------------------------------
// GetAllRoutes – returns a copy
// ---------------------------------------------------------------------------

func TestGetAllRoutes_ReturnsCopy(t *testing.T) {
	localIP := mustAddr("10.0.0.1")
	tbl := NewTable("local", localIP)

	self := &gossip.Member{
		NodeID:    "local",
		MeshIP:    localIP,
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.1:51820"},
	}
	peer := &gossip.Member{
		NodeID:    "peer-1",
		MeshIP:    mustAddr("10.0.0.2"),
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.2:51820"},
		RTT:       5 * time.Millisecond,
	}
	relay := &gossip.Member{
		NodeID:    "relay-1",
		MeshIP:    mustAddr("10.0.0.100"),
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.100:51820"},
		Roles:     []string{"relay"},
		RTT:       2 * time.Millisecond,
	}

	ml := newTestMemberList(self, peer, relay)
	tbl.UpdateFromGossip(ml)

	routes1 := tbl.GetAllRoutes("peer-1")
	routes2 := tbl.GetAllRoutes("peer-1")

	// Mutating the returned slice should not affect future calls.
	if len(routes1) > 0 {
		routes1[0] = nil
	}
	if routes2[0] == nil {
		t.Error("GetAllRoutes did not return an independent copy")
	}
}

// ---------------------------------------------------------------------------
// Relay metric adjustment for high-RTT relays
// ---------------------------------------------------------------------------

func TestUpdateFromGossip_HighRTTRelayMetric(t *testing.T) {
	localIP := mustAddr("10.0.0.1")
	tbl := NewTable("local", localIP)

	self := &gossip.Member{
		NodeID:    "local",
		MeshIP:    localIP,
		State:     gossip.StateAlive,
		Endpoints: []string{"192.168.1.1:51820"},
	}

	// Peer with no direct endpoint.
	peer := &gossip.Member{
		NodeID: "peer-1",
		MeshIP: mustAddr("10.0.0.2"),
		State:  gossip.StateAlive,
		RTT:    5 * time.Millisecond,
	}

	slowRelay := &gossip.Member{
		NodeID:    "relay-slow",
		MeshIP:    mustAddr("10.0.0.200"),
		State:     gossip.StateAlive,
		Endpoints: []string{"9.9.9.9:51820"},
		Roles:     []string{"relay"},
		RTT:       200 * time.Millisecond, // > 100ms
	}

	fastRelay := &gossip.Member{
		NodeID:    "relay-fast",
		MeshIP:    mustAddr("10.0.0.201"),
		State:     gossip.StateAlive,
		Endpoints: []string{"8.8.8.8:51820"},
		Roles:     []string{"relay"},
		RTT:       10 * time.Millisecond,
	}

	ml := newTestMemberList(self, peer, slowRelay, fastRelay)
	tbl.UpdateFromGossip(ml)

	allRoutes := tbl.GetAllRoutes("peer-1")
	if len(allRoutes) < 2 {
		t.Fatalf("expected >=2 relay routes, got %d", len(allRoutes))
	}

	// Routes should be sorted: fast relay (metric 2) before slow relay (metric 3).
	sort.Slice(allRoutes, func(i, j int) bool {
		return allRoutes[i].Metric < allRoutes[j].Metric
	})

	if allRoutes[0].NextHop != "relay-fast" {
		t.Errorf("lowest metric route nextHop = %q, want relay-fast", allRoutes[0].NextHop)
	}
}
