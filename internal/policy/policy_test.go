package policy

import (
	"net/netip"
	"testing"
	"time"
)

// ─── Engine creation ────────────────────────────────────────────────────────

func TestNewEngine(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine returned error: %v", err)
	}
	if eng == nil {
		t.Fatal("NewEngine returned nil engine")
	}
	if eng.celEnv == nil {
		t.Fatal("CEL environment not initialised")
	}
	if eng.compiled == nil {
		t.Fatal("compiled map not initialised")
	}
}

// ─── LoadPolicies ───────────────────────────────────────────────────────────

func TestLoadPolicies_SortsByPriority(t *testing.T) {
	eng := mustEngine(t)

	ps := &PolicySet{
		Version: 1,
		Name:    "test",
		Rules: []*Rule{
			{Name: "low", Priority: 10, Effect: EffectAllow},
			{Name: "high", Priority: 100, Effect: EffectDeny},
			{Name: "mid", Priority: 50, Effect: EffectAllow},
		},
	}

	if err := eng.LoadPolicies(ps); err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}

	if ps.Rules[0].Name != "high" {
		t.Errorf("expected first rule 'high', got %q", ps.Rules[0].Name)
	}
	if ps.Rules[1].Name != "mid" {
		t.Errorf("expected second rule 'mid', got %q", ps.Rules[1].Name)
	}
	if ps.Rules[2].Name != "low" {
		t.Errorf("expected third rule 'low', got %q", ps.Rules[2].Name)
	}
}

func TestLoadPolicies_InvalidCELCondition(t *testing.T) {
	eng := mustEngine(t)

	ps := &PolicySet{
		Version: 1,
		Name:    "bad",
		Rules: []*Rule{
			{Name: "bad-cel", Priority: 10, Condition: "invalid +++ syntax", Effect: EffectDeny},
		},
	}

	if err := eng.LoadPolicies(ps); err == nil {
		t.Fatal("expected error for invalid CEL condition")
	}
}

func TestLoadPolicies_ValidCELCondition(t *testing.T) {
	eng := mustEngine(t)

	ps := &PolicySet{
		Version: 1,
		Name:    "cel",
		Rules: []*Rule{
			{
				Name:      "port-check",
				Priority:  10,
				Condition: "dest_port > 1024",
				Effect:    EffectAllow,
			},
		},
	}

	if err := eng.LoadPolicies(ps); err != nil {
		t.Fatalf("LoadPolicies with valid CEL: %v", err)
	}
	if ps.Rules[0].program == nil {
		t.Error("CEL program not compiled")
	}
}

// ─── Evaluate ───────────────────────────────────────────────────────────────

func TestEvaluate_DefaultDenyNoPolicies(t *testing.T) {
	eng := mustEngine(t)

	dec := eng.Evaluate(&Request{Protocol: "tcp", Direction: "egress"})
	if dec.Effect != EffectDeny {
		t.Errorf("expected deny with no policies, got %v", dec.Effect)
	}
	if dec.Reason != "no policies loaded" {
		t.Errorf("unexpected reason: %s", dec.Reason)
	}
}

func TestEvaluate_DefaultDenyEmptyRules(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, &PolicySet{Version: 1, Name: "empty", Rules: []*Rule{}})

	dec := eng.Evaluate(&Request{Protocol: "tcp", Direction: "egress"})
	if dec.Effect != EffectDeny {
		t.Errorf("expected deny with empty rules, got %v", dec.Effect)
	}
}

func TestEvaluate_AllowRuleMatchesRole(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, &PolicySet{
		Version: 1,
		Name:    "test",
		Rules: []*Rule{
			{
				Name:     "allow-admin",
				Priority: 10,
				Subjects: SubjectSpec{Roles: []string{"admin"}},
				Resources: ResourceSpec{
					Nodes:     []string{"*"},
					Protocols: []string{"*"},
				},
				Effect: EffectAllow,
			},
		},
	})

	dec := eng.Evaluate(&Request{
		SourceRoles: []string{"admin"},
		DestNodeID:  "node-1",
		Protocol:    "tcp",
		Direction:   "egress",
	})
	if dec.Effect != EffectAllow {
		t.Errorf("expected allow for admin role, got %v", dec.Effect)
	}
}

func TestEvaluate_DenyRuleBlocksNonMatching(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, &PolicySet{
		Version: 1,
		Name:    "test",
		Rules: []*Rule{
			{
				Name:     "allow-admin-only",
				Priority: 10,
				Subjects: SubjectSpec{Roles: []string{"admin"}},
				Resources: ResourceSpec{
					Nodes: []string{"*"},
				},
				Effect: EffectAllow,
			},
		},
	})

	dec := eng.Evaluate(&Request{
		SourceRoles: []string{"sensor"},
		DestNodeID:  "node-1",
		Protocol:    "tcp",
		Direction:   "egress",
	})
	if dec.Effect != EffectDeny {
		t.Errorf("expected deny for sensor role, got %v", dec.Effect)
	}
}

func TestEvaluate_WildcardMatchesAny(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, &PolicySet{
		Version: 1,
		Name:    "test",
		Rules: []*Rule{
			{
				Name:     "allow-all",
				Priority: 10,
				Subjects: SubjectSpec{Roles: []string{"*"}},
				Resources: ResourceSpec{
					Nodes:     []string{"*"},
					Protocols: []string{"*"},
				},
				Effect: EffectAllow,
			},
		},
	})

	dec := eng.Evaluate(&Request{
		SourceRoles: []string{"anything"},
		DestNodeID:  "any-node",
		Protocol:    "tcp",
		Direction:   "egress",
	})
	if dec.Effect != EffectAllow {
		t.Errorf("expected allow with wildcard, got %v", dec.Effect)
	}
}

func TestEvaluate_PriorityOrdering(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, &PolicySet{
		Version: 1,
		Name:    "priority",
		Rules: []*Rule{
			{
				Name:      "low-allow",
				Priority:  1,
				Subjects:  SubjectSpec{Roles: []string{"*"}},
				Resources: ResourceSpec{Nodes: []string{"*"}},
				Effect:    EffectAllow,
			},
			{
				Name:      "high-deny",
				Priority:  100,
				Subjects:  SubjectSpec{Roles: []string{"*"}},
				Resources: ResourceSpec{Nodes: []string{"*"}},
				Effect:    EffectDeny,
			},
		},
	})

	dec := eng.Evaluate(&Request{
		SourceRoles: []string{"operator"},
		DestNodeID:  "node-1",
	})
	if dec.Effect != EffectDeny {
		t.Errorf("expected higher priority deny to win, got %v", dec.Effect)
	}
	if dec.Rule == nil || dec.Rule.Name != "high-deny" {
		t.Errorf("expected to match 'high-deny' rule")
	}
}

func TestEvaluate_PortRangeMatching(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, &PolicySet{
		Version: 1,
		Name:    "ports",
		Rules: []*Rule{
			{
				Name:     "allow-high-ports",
				Priority: 10,
				Subjects: SubjectSpec{Roles: []string{"*"}},
				Resources: ResourceSpec{
					Nodes: []string{"*"},
					Ports: []PortRange{{Start: 8000, End: 9000}},
				},
				Effect: EffectAllow,
			},
		},
	})

	tests := []struct {
		port   uint16
		expect Effect
	}{
		{8080, EffectAllow},
		{8000, EffectAllow},
		{9000, EffectAllow},
		{7999, EffectDeny},
		{9001, EffectDeny},
		{443, EffectDeny},
	}

	for _, tt := range tests {
		dec := eng.Evaluate(&Request{
			SourceRoles: []string{"any"},
			DestNodeID:  "node-1",
			DestPort:    tt.port,
		})
		if dec.Effect != tt.expect {
			t.Errorf("port %d: expected %v, got %v", tt.port, tt.expect, dec.Effect)
		}
	}
}

func TestEvaluate_DirectionMatching(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, &PolicySet{
		Version: 1,
		Name:    "direction",
		Rules: []*Rule{
			{
				Name:     "egress-only",
				Priority: 10,
				Subjects: SubjectSpec{Roles: []string{"*"}},
				Resources: ResourceSpec{
					Nodes:     []string{"*"},
					Direction: "egress",
				},
				Effect: EffectAllow,
			},
		},
	})

	dec := eng.Evaluate(&Request{
		SourceRoles: []string{"any"},
		DestNodeID:  "node-1",
		Direction:   "egress",
	})
	if dec.Effect != EffectAllow {
		t.Errorf("egress should be allowed, got %v", dec.Effect)
	}

	dec = eng.Evaluate(&Request{
		SourceRoles: []string{"any"},
		DestNodeID:  "node-1",
		Direction:   "ingress",
	})
	if dec.Effect != EffectDeny {
		t.Errorf("ingress should be denied, got %v", dec.Effect)
	}
}

func TestEvaluate_DirectionBothMatchesAll(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, &PolicySet{
		Version: 1,
		Name:    "both",
		Rules: []*Rule{
			{
				Name:     "both-dir",
				Priority: 10,
				Subjects: SubjectSpec{Roles: []string{"*"}},
				Resources: ResourceSpec{
					Nodes:     []string{"*"},
					Direction: "both",
				},
				Effect: EffectAllow,
			},
		},
	})

	for _, dir := range []string{"ingress", "egress"} {
		dec := eng.Evaluate(&Request{
			SourceRoles: []string{"any"},
			DestNodeID:  "node-1",
			Direction:   dir,
		})
		if dec.Effect != EffectAllow {
			t.Errorf("direction 'both' should allow %s, got %v", dir, dec.Effect)
		}
	}
}

func TestEvaluate_CELCondition(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, &PolicySet{
		Version: 1,
		Name:    "cel-test",
		Rules: []*Rule{
			{
				Name:      "high-port-only",
				Priority:  10,
				Subjects:  SubjectSpec{Roles: []string{"*"}},
				Resources: ResourceSpec{Nodes: []string{"*"}},
				Condition: "dest_port > 1024",
				Effect:    EffectAllow,
			},
		},
	})

	dec := eng.Evaluate(&Request{
		SourceRoles: []string{"any"},
		DestNodeID:  "node-1",
		DestPort:    8080,
		Protocol:    "tcp",
		Direction:   "egress",
		Metadata:    map[string]string{},
	})
	if dec.Effect != EffectAllow {
		t.Errorf("port 8080 should match CEL condition, got %v", dec.Effect)
	}

	dec = eng.Evaluate(&Request{
		SourceRoles: []string{"any"},
		DestNodeID:  "node-1",
		DestPort:    80,
		Protocol:    "tcp",
		Direction:   "egress",
		Metadata:    map[string]string{},
	})
	if dec.Effect != EffectDeny {
		t.Errorf("port 80 should NOT match CEL condition, got %v", dec.Effect)
	}
}

func TestEvaluate_NetworkMatching(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, &PolicySet{
		Version: 1,
		Name:    "net",
		Rules: []*Rule{
			{
				Name:     "allow-10-net",
				Priority: 10,
				Subjects: SubjectSpec{Roles: []string{"*"}},
				Resources: ResourceSpec{
					Networks: []string{"10.0.0.0/8"},
				},
				Effect: EffectAllow,
			},
		},
	})

	dec := eng.Evaluate(&Request{
		SourceRoles: []string{"any"},
		DestIP:      netip.MustParseAddr("10.1.2.3"),
	})
	if dec.Effect != EffectAllow {
		t.Errorf("10.1.2.3 should be in 10.0.0.0/8, got %v", dec.Effect)
	}

	dec = eng.Evaluate(&Request{
		SourceRoles: []string{"any"},
		DestIP:      netip.MustParseAddr("192.168.1.1"),
	})
	if dec.Effect != EffectDeny {
		t.Errorf("192.168.1.1 should NOT be in 10.0.0.0/8, got %v", dec.Effect)
	}
}

// ─── PortRange.Contains ─────────────────────────────────────────────────────

func TestPortRange_Contains(t *testing.T) {
	tests := []struct {
		name string
		pr   PortRange
		port uint16
		want bool
	}{
		{"single port match", PortRange{Start: 443}, 443, true},
		{"single port no match", PortRange{Start: 443}, 80, false},
		{"range start", PortRange{Start: 8000, End: 9000}, 8000, true},
		{"range end", PortRange{Start: 8000, End: 9000}, 9000, true},
		{"range mid", PortRange{Start: 8000, End: 9000}, 8500, true},
		{"range below", PortRange{Start: 8000, End: 9000}, 7999, false},
		{"range above", PortRange{Start: 8000, End: 9000}, 9001, false},
		{"end zero acts as single", PortRange{Start: 22, End: 0}, 22, true},
		{"end zero other port", PortRange{Start: 22, End: 0}, 23, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pr.Contains(tt.port); got != tt.want {
				t.Errorf("PortRange{%d,%d}.Contains(%d) = %v, want %v",
					tt.pr.Start, tt.pr.End, tt.port, got, tt.want)
			}
		})
	}
}

// ─── DefaultPolicies ────────────────────────────────────────────────────────

func TestDefaultPolicies(t *testing.T) {
	ps := DefaultPolicies()
	if ps == nil {
		t.Fatal("DefaultPolicies returned nil")
	}
	if ps.Version != 1 {
		t.Errorf("expected version 1, got %d", ps.Version)
	}
	if ps.Name != "default" {
		t.Errorf("expected name 'default', got %q", ps.Name)
	}
	if len(ps.Rules) < 3 {
		t.Fatalf("expected at least 3 rules, got %d", len(ps.Rules))
	}

	ruleNames := make(map[string]bool)
	for _, r := range ps.Rules {
		ruleNames[r.Name] = true
	}

	expected := []string{"admin-full-access", "relay-forward", "operator-mesh-access", "sensor-egress-only", "default-deny"}
	for _, name := range expected {
		if !ruleNames[name] {
			t.Errorf("missing expected rule %q in DefaultPolicies", name)
		}
	}
}

func TestDefaultPolicies_CanBeLoaded(t *testing.T) {
	eng := mustEngine(t)
	ps := DefaultPolicies()
	if err := eng.LoadPolicies(ps); err != nil {
		t.Fatalf("LoadPolicies(DefaultPolicies()) failed: %v", err)
	}
}

// ─── subjectsMatch ──────────────────────────────────────────────────────────

func TestSubjectsMatch_EmptyMatchesAll(t *testing.T) {
	eng := mustEngine(t)
	spec := &SubjectSpec{}
	req := &Request{SourceRoles: []string{"any"}}
	if !eng.subjectsMatch(spec, req) {
		t.Error("empty subject spec should match everything")
	}
}

func TestSubjectsMatch_RoleMatch(t *testing.T) {
	eng := mustEngine(t)

	spec := &SubjectSpec{Roles: []string{"admin", "operator"}}

	if !eng.subjectsMatch(spec, &Request{SourceRoles: []string{"admin"}}) {
		t.Error("should match admin role")
	}
	if !eng.subjectsMatch(spec, &Request{SourceRoles: []string{"operator"}}) {
		t.Error("should match operator role")
	}
	if eng.subjectsMatch(spec, &Request{SourceRoles: []string{"sensor"}}) {
		t.Error("should not match sensor role")
	}
}

func TestSubjectsMatch_RoleWildcard(t *testing.T) {
	eng := mustEngine(t)
	spec := &SubjectSpec{Roles: []string{"*"}}

	if !eng.subjectsMatch(spec, &Request{SourceRoles: []string{"anything"}}) {
		t.Error("wildcard role should match any role")
	}
}

func TestSubjectsMatch_NodeIDMatch(t *testing.T) {
	eng := mustEngine(t)

	spec := &SubjectSpec{NodeIDs: []string{"node-1", "node-2"}}

	if !eng.subjectsMatch(spec, &Request{SourceNodeID: "node-1"}) {
		t.Error("should match node-1")
	}
	if eng.subjectsMatch(spec, &Request{SourceNodeID: "node-3"}) {
		t.Error("should not match node-3")
	}
}

func TestSubjectsMatch_NodeIDWildcard(t *testing.T) {
	eng := mustEngine(t)
	spec := &SubjectSpec{NodeIDs: []string{"*"}}

	if !eng.subjectsMatch(spec, &Request{SourceNodeID: "any-node"}) {
		t.Error("wildcard nodeID should match any node")
	}
}

func TestSubjectsMatch_CompartmentMatch(t *testing.T) {
	eng := mustEngine(t)

	spec := &SubjectSpec{Compartments: []string{"prod", "staging"}}

	if !eng.subjectsMatch(spec, &Request{SourceCompartment: "prod"}) {
		t.Error("should match prod compartment")
	}
	if eng.subjectsMatch(spec, &Request{SourceCompartment: "dev"}) {
		t.Error("should not match dev compartment")
	}
}

func TestSubjectsMatch_CompartmentWildcard(t *testing.T) {
	eng := mustEngine(t)
	spec := &SubjectSpec{Compartments: []string{"*"}}

	if !eng.subjectsMatch(spec, &Request{SourceCompartment: "anything"}) {
		t.Error("wildcard compartment should match any compartment")
	}
}

func TestSubjectsMatch_MultipleFieldsAND(t *testing.T) {
	eng := mustEngine(t)

	// Both roles AND nodeIDs must match (AND between categories)
	spec := &SubjectSpec{
		Roles:   []string{"admin"},
		NodeIDs: []string{"node-1"},
	}

	// Both match
	if !eng.subjectsMatch(spec, &Request{SourceRoles: []string{"admin"}, SourceNodeID: "node-1"}) {
		t.Error("both fields match, should return true")
	}
	// Role matches but node does not
	if eng.subjectsMatch(spec, &Request{SourceRoles: []string{"admin"}, SourceNodeID: "node-2"}) {
		t.Error("node mismatch should fail")
	}
	// Node matches but role does not
	if eng.subjectsMatch(spec, &Request{SourceRoles: []string{"sensor"}, SourceNodeID: "node-1"}) {
		t.Error("role mismatch should fail")
	}
}

// ─── resourcesMatch ─────────────────────────────────────────────────────────

func TestResourcesMatch_EmptyMatchesAll(t *testing.T) {
	eng := mustEngine(t)
	spec := &ResourceSpec{}
	req := &Request{DestNodeID: "any", DestPort: 443, Protocol: "tcp"}
	if !eng.resourcesMatch(spec, req) {
		t.Error("empty resource spec should match everything")
	}
}

func TestResourcesMatch_NodeMatch(t *testing.T) {
	eng := mustEngine(t)

	spec := &ResourceSpec{Nodes: []string{"node-a", "node-b"}}

	if !eng.resourcesMatch(spec, &Request{DestNodeID: "node-a"}) {
		t.Error("should match node-a")
	}
	if eng.resourcesMatch(spec, &Request{DestNodeID: "node-c"}) {
		t.Error("should not match node-c")
	}
}

func TestResourcesMatch_PortMatch(t *testing.T) {
	eng := mustEngine(t)

	spec := &ResourceSpec{
		Ports: []PortRange{
			{Start: 80},
			{Start: 443},
			{Start: 8000, End: 9000},
		},
	}

	if !eng.resourcesMatch(spec, &Request{DestPort: 80}) {
		t.Error("should match port 80")
	}
	if !eng.resourcesMatch(spec, &Request{DestPort: 8500}) {
		t.Error("should match port 8500 in range")
	}
	if eng.resourcesMatch(spec, &Request{DestPort: 22}) {
		t.Error("should not match port 22")
	}
}

func TestResourcesMatch_ProtocolMatch(t *testing.T) {
	eng := mustEngine(t)

	spec := &ResourceSpec{Protocols: []string{"tcp", "udp"}}

	if !eng.resourcesMatch(spec, &Request{Protocol: "tcp"}) {
		t.Error("should match tcp")
	}
	if eng.resourcesMatch(spec, &Request{Protocol: "icmp"}) {
		t.Error("should not match icmp")
	}
}

func TestResourcesMatch_ProtocolWildcard(t *testing.T) {
	eng := mustEngine(t)
	spec := &ResourceSpec{Protocols: []string{"*"}}

	if !eng.resourcesMatch(spec, &Request{Protocol: "icmp"}) {
		t.Error("wildcard should match icmp")
	}
}

// ─── Effect.String ──────────────────────────────────────────────────────────

func TestEffectString(t *testing.T) {
	if EffectAllow.String() != "allow" {
		t.Errorf("EffectAllow.String() = %q", EffectAllow.String())
	}
	if EffectDeny.String() != "deny" {
		t.Errorf("EffectDeny.String() = %q", EffectDeny.String())
	}
}

// ─── sortRules ──────────────────────────────────────────────────────────────

func TestSortRules(t *testing.T) {
	rules := []*Rule{
		{Name: "a", Priority: 1},
		{Name: "b", Priority: 100},
		{Name: "c", Priority: 50},
		{Name: "d", Priority: 50},
	}

	sortRules(rules)

	if rules[0].Name != "b" {
		t.Errorf("expected b first, got %s", rules[0].Name)
	}
	// c and d have same priority; the sort is not stable, so either order is fine
	if rules[0].Priority != 100 || rules[1].Priority != 50 || rules[2].Priority != 50 || rules[3].Priority != 1 {
		t.Errorf("priorities not in descending order: %d, %d, %d, %d",
			rules[0].Priority, rules[1].Priority, rules[2].Priority, rules[3].Priority)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
//  enforcer.go tests
// ═══════════════════════════════════════════════════════════════════════════

func TestNewEnforcer(t *testing.T) {
	eng := mustEngine(t)
	enf := NewEnforcer(eng, "local-node", []string{"admin"}, "prod")
	if enf == nil {
		t.Fatal("NewEnforcer returned nil")
	}
	if enf.localID != "local-node" {
		t.Errorf("localID = %q", enf.localID)
	}
	if enf.peerInfo == nil {
		t.Error("peerInfo map not initialised")
	}
}

// ─── Peer management ────────────────────────────────────────────────────────

func TestRegisterPeer_And_GetPeerByIP(t *testing.T) {
	eng := mustEngine(t)
	enf := NewEnforcer(eng, "local", []string{"admin"}, "prod")

	ip := netip.MustParseAddr("10.0.0.1")
	enf.RegisterPeer(&PeerInfo{
		NodeID:      "peer-1",
		Roles:       []string{"operator"},
		Compartment: "prod",
		MeshIP:      ip,
	})

	got := enf.GetPeerByIP(ip)
	if got == nil {
		t.Fatal("GetPeerByIP returned nil after RegisterPeer")
	}
	if got.NodeID != "peer-1" {
		t.Errorf("NodeID = %q, want peer-1", got.NodeID)
	}
	if got.LastUpdated.IsZero() {
		t.Error("LastUpdated should be set")
	}
}

func TestRemovePeer(t *testing.T) {
	eng := mustEngine(t)
	enf := NewEnforcer(eng, "local", []string{"admin"}, "prod")

	enf.RegisterPeer(&PeerInfo{
		NodeID: "peer-1",
		MeshIP: netip.MustParseAddr("10.0.0.1"),
	})

	enf.RemovePeer("peer-1")

	if got := enf.GetPeerByIP(netip.MustParseAddr("10.0.0.1")); got != nil {
		t.Error("peer should be removed")
	}
}

func TestGetPeerByIP_NotFound(t *testing.T) {
	eng := mustEngine(t)
	enf := NewEnforcer(eng, "local", []string{"admin"}, "prod")

	if got := enf.GetPeerByIP(netip.MustParseAddr("10.99.99.99")); got != nil {
		t.Error("should return nil for unknown IP")
	}
}

// ─── CheckConnection ────────────────────────────────────────────────────────

func TestCheckConnection_AdminAllowed(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, DefaultPolicies())

	enf := NewEnforcer(eng, "local", []string{"admin"}, "prod")
	enf.RegisterPeer(&PeerInfo{
		NodeID:      "admin-node",
		Roles:       []string{"admin"},
		Compartment: "prod",
		MeshIP:      netip.MustParseAddr("10.0.0.1"),
	})
	enf.RegisterPeer(&PeerInfo{
		NodeID:      "target",
		Roles:       []string{"operator"},
		Compartment: "prod",
		MeshIP:      netip.MustParseAddr("10.0.0.2"),
	})

	dec := enf.CheckConnection("admin-node", "target", 443, "tcp")
	if dec.Effect != EffectAllow {
		t.Errorf("admin should have full access, got %v (%s)", dec.Effect, dec.Reason)
	}
}

func TestCheckConnection_OperatorToOperator(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, DefaultPolicies())

	enf := NewEnforcer(eng, "local", []string{"operator"}, "prod")
	enf.RegisterPeer(&PeerInfo{
		NodeID:      "op-1",
		Roles:       []string{"operator"},
		Compartment: "prod",
		MeshIP:      netip.MustParseAddr("10.0.0.10"),
	})
	enf.RegisterPeer(&PeerInfo{
		NodeID:      "op-2",
		Roles:       []string{"operator"},
		Compartment: "prod",
		MeshIP:      netip.MustParseAddr("10.0.0.11"),
	})

	dec := enf.CheckConnection("op-1", "op-2", 8080, "tcp")
	if dec.Effect != EffectAllow {
		t.Errorf("operator-to-operator should be allowed, got %v (%s)", dec.Effect, dec.Reason)
	}
}

func TestCheckConnection_SensorToCollector(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, DefaultPolicies())

	enf := NewEnforcer(eng, "local", nil, "prod")
	enf.RegisterPeer(&PeerInfo{
		NodeID:      "sensor-1",
		Roles:       []string{"sensor"},
		Compartment: "prod",
		MeshIP:      netip.MustParseAddr("10.0.0.20"),
	})
	enf.RegisterPeer(&PeerInfo{
		NodeID:      "collector-1",
		Roles:       []string{"collector"},
		Compartment: "prod",
		MeshIP:      netip.MustParseAddr("10.0.0.30"),
	})

	dec := enf.CheckConnection("sensor-1", "collector-1", 9090, "tcp")
	if dec.Effect != EffectAllow {
		t.Errorf("sensor-to-collector should be allowed, got %v (%s)", dec.Effect, dec.Reason)
	}
}

func TestCheckConnection_SensorToOperatorDenied(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, DefaultPolicies())

	enf := NewEnforcer(eng, "local", nil, "prod")
	enf.RegisterPeer(&PeerInfo{
		NodeID:      "sensor-1",
		Roles:       []string{"sensor"},
		Compartment: "prod",
		MeshIP:      netip.MustParseAddr("10.0.0.20"),
	})
	enf.RegisterPeer(&PeerInfo{
		NodeID:      "op-1",
		Roles:       []string{"operator"},
		Compartment: "prod",
		MeshIP:      netip.MustParseAddr("10.0.0.10"),
	})

	dec := enf.CheckConnection("sensor-1", "op-1", 8080, "tcp")
	if dec.Effect != EffectDeny {
		t.Errorf("sensor-to-operator should be denied, got %v (%s)", dec.Effect, dec.Reason)
	}
}

func TestCheckConnection_DefaultDenyUnknownRole(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, DefaultPolicies())

	enf := NewEnforcer(eng, "local", nil, "prod")
	enf.RegisterPeer(&PeerInfo{
		NodeID:      "unknown-1",
		Roles:       []string{"unknown"},
		Compartment: "prod",
		MeshIP:      netip.MustParseAddr("10.0.0.50"),
	})
	enf.RegisterPeer(&PeerInfo{
		NodeID:      "unknown-2",
		Roles:       []string{"unknown"},
		Compartment: "prod",
		MeshIP:      netip.MustParseAddr("10.0.0.51"),
	})

	dec := enf.CheckConnection("unknown-1", "unknown-2", 80, "tcp")
	if dec.Effect != EffectDeny {
		t.Errorf("unknown role should be default-denied, got %v (%s)", dec.Effect, dec.Reason)
	}
}

// ─── Stats ──────────────────────────────────────────────────────────────────

func TestStats_And_ResetStats(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, &PolicySet{
		Version: 1,
		Name:    "stats-test",
		Rules: []*Rule{
			{
				Name:      "allow-all",
				Priority:  10,
				Subjects:  SubjectSpec{Roles: []string{"*"}},
				Resources: ResourceSpec{Nodes: []string{"*"}},
				Effect:    EffectAllow,
			},
		},
	})

	enf := NewEnforcer(eng, "local", []string{"admin"}, "prod")

	// Build a minimal valid IPv4 TCP packet: egress from local
	pkt := makeIPv4Packet(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 6, 12345, 443)
	enf.CheckPacket(pkt, "egress")
	enf.CheckPacket(pkt, "egress")

	stats := enf.Stats()
	if stats.Evaluated != 2 {
		t.Errorf("evaluated = %d, want 2", stats.Evaluated)
	}
	if stats.Allowed != 2 {
		t.Errorf("allowed = %d, want 2", stats.Allowed)
	}
	if stats.Denied != 0 {
		t.Errorf("denied = %d, want 0", stats.Denied)
	}

	enf.ResetStats()
	stats = enf.Stats()
	if stats.Evaluated != 0 || stats.Allowed != 0 || stats.Denied != 0 {
		t.Error("stats not reset to zero")
	}
}

func TestStats_DeniedCounted(t *testing.T) {
	eng := mustEngine(t)
	// No policies loaded -> default deny
	enf := NewEnforcer(eng, "local", []string{"admin"}, "prod")

	pkt := makeIPv4Packet(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 6, 12345, 443)
	enf.CheckPacket(pkt, "egress")

	stats := enf.Stats()
	if stats.Denied != 1 {
		t.Errorf("denied = %d, want 1", stats.Denied)
	}
	if stats.Evaluated != 1 {
		t.Errorf("evaluated = %d, want 1", stats.Evaluated)
	}
}

func TestCheckPacket_TooShort(t *testing.T) {
	eng := mustEngine(t)
	enf := NewEnforcer(eng, "local", []string{"admin"}, "prod")

	verdict := enf.CheckPacket([]byte{0x45, 0x00}, "egress")
	if verdict != VerdictDrop {
		t.Errorf("short packet should be dropped, got %v", verdict)
	}
	stats := enf.Stats()
	if stats.Denied != 1 {
		t.Errorf("short packet should count as denied")
	}
}

func TestCheckPacket_IPv6Dropped(t *testing.T) {
	eng := mustEngine(t)
	enf := NewEnforcer(eng, "local", []string{"admin"}, "prod")

	// 20 bytes with IPv6 version nibble
	pkt := make([]byte, 20)
	pkt[0] = 0x60 // version 6
	verdict := enf.CheckPacket(pkt, "egress")
	if verdict != VerdictDrop {
		t.Errorf("IPv6 should be dropped, got %v", verdict)
	}
}

// ─── ConnectionTracker ──────────────────────────────────────────────────────

func TestConnectionTracker_TrackAndIsTracked(t *testing.T) {
	ct := NewConnectionTracker(5 * time.Minute)

	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")

	ct.Track(src, dst, 12345, 443, "tcp", 100)

	// IsTracked checks the reverse direction
	if !ct.IsTracked(dst, src, 443, 12345, "tcp") {
		t.Error("reverse connection should be tracked")
	}

	// Forward direction key won't match reverse lookup
	if ct.IsTracked(src, dst, 12345, 443, "tcp") {
		t.Error("forward direction should not be tracked via IsTracked (it checks reverse)")
	}
}

func TestConnectionTracker_NotTracked(t *testing.T) {
	ct := NewConnectionTracker(5 * time.Minute)

	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")

	if ct.IsTracked(src, dst, 12345, 443, "tcp") {
		t.Error("untracked connection should return false")
	}
}

func TestConnectionTracker_ExpiredTTL(t *testing.T) {
	ct := NewConnectionTracker(1 * time.Millisecond)

	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")

	ct.Track(src, dst, 12345, 443, "tcp", 100)

	time.Sleep(5 * time.Millisecond)

	if ct.IsTracked(dst, src, 443, 12345, "tcp") {
		t.Error("expired connection should not be tracked")
	}
}

func TestConnectionTracker_UpdatesExistingConn(t *testing.T) {
	ct := NewConnectionTracker(5 * time.Minute)

	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")

	ct.Track(src, dst, 12345, 443, "tcp", 100)
	ct.Track(src, dst, 12345, 443, "tcp", 200)

	ct.mu.RLock()
	key := connKey(src, dst, 12345, 443, "tcp")
	conn := ct.conns[key]
	ct.mu.RUnlock()

	if conn == nil {
		t.Fatal("connection not found")
	}
	if conn.packets != 2 {
		t.Errorf("packets = %d, want 2", conn.packets)
	}
	if conn.bytes != 300 {
		t.Errorf("bytes = %d, want 300", conn.bytes)
	}
}

// ─── SetOnDeny callback ─────────────────────────────────────────────────────

func TestSetOnDeny_CallbackInvoked(t *testing.T) {
	eng := mustEngine(t)
	// No policies = default deny
	enf := NewEnforcer(eng, "local", []string{"admin"}, "prod")

	var called bool
	enf.SetOnDeny(func(req *Request, dec *Decision) {
		called = true
	})

	pkt := makeIPv4Packet(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 6, 12345, 443)
	enf.CheckPacket(pkt, "egress")

	if !called {
		t.Error("onDeny callback should have been invoked")
	}
}

// ─── protocolToString ───────────────────────────────────────────────────────

func TestProtocolToString(t *testing.T) {
	tests := []struct {
		proto uint8
		want  string
	}{
		{1, "icmp"},
		{6, "tcp"},
		{17, "udp"},
		{47, "gre"},
		{50, "esp"},
		{255, "unknown"},
	}
	for _, tt := range tests {
		if got := protocolToString(tt.proto); got != tt.want {
			t.Errorf("protocolToString(%d) = %q, want %q", tt.proto, got, tt.want)
		}
	}
}

// ─── Full scenario: DefaultPolicies through engine ──────────────────────────

func TestFullScenario_DefaultPolicies(t *testing.T) {
	eng := mustEngine(t)
	mustLoad(t, eng, DefaultPolicies())

	enf := NewEnforcer(eng, "mesh-node", nil, "default")

	// Register peers with various roles
	peers := []PeerInfo{
		{NodeID: "admin-1", Roles: []string{"admin"}, Compartment: "ops", MeshIP: netip.MustParseAddr("10.0.0.1")},
		{NodeID: "relay-1", Roles: []string{"relay"}, Compartment: "infra", MeshIP: netip.MustParseAddr("10.0.0.2")},
		{NodeID: "op-1", Roles: []string{"operator"}, Compartment: "field", MeshIP: netip.MustParseAddr("10.0.0.3")},
		{NodeID: "op-2", Roles: []string{"operator"}, Compartment: "field", MeshIP: netip.MustParseAddr("10.0.0.4")},
		{NodeID: "sensor-1", Roles: []string{"sensor"}, Compartment: "edge", MeshIP: netip.MustParseAddr("10.0.0.5")},
		{NodeID: "collector-1", Roles: []string{"collector"}, Compartment: "core", MeshIP: netip.MustParseAddr("10.0.0.6")},
		{NodeID: "rogue-1", Roles: []string{"rogue"}, Compartment: "unknown", MeshIP: netip.MustParseAddr("10.0.0.99")},
	}
	for i := range peers {
		enf.RegisterPeer(&peers[i])
	}

	tests := []struct {
		name   string
		src    string
		dst    string
		port   uint16
		proto  string
		expect Effect
	}{
		{"admin to anyone", "admin-1", "rogue-1", 443, "tcp", EffectAllow},
		{"relay to anyone", "relay-1", "op-1", 8080, "tcp", EffectAllow},
		{"operator to operator", "op-1", "op-2", 8080, "tcp", EffectAllow},
		{"operator to relay", "op-1", "relay-1", 8080, "udp", EffectAllow},
		{"operator to admin", "op-1", "admin-1", 443, "tcp", EffectAllow},
		{"sensor to collector", "sensor-1", "collector-1", 9090, "tcp", EffectAllow},
		{"sensor to admin", "sensor-1", "admin-1", 9090, "udp", EffectAllow},
		{"sensor to operator denied", "sensor-1", "op-1", 9090, "tcp", EffectDeny},
		{"sensor to rogue denied", "sensor-1", "rogue-1", 9090, "tcp", EffectDeny},
		{"rogue to anyone denied", "rogue-1", "op-1", 80, "tcp", EffectDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := enf.CheckConnection(tt.src, tt.dst, tt.port, tt.proto)
			if dec.Effect != tt.expect {
				t.Errorf("got %v (%s), want %v", dec.Effect, dec.Reason, tt.expect)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════

func mustEngine(t *testing.T) *Engine {
	t.Helper()
	eng, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

func mustLoad(t *testing.T, eng *Engine, ps *PolicySet) {
	t.Helper()
	if err := eng.LoadPolicies(ps); err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
}

// makeIPv4Packet constructs a minimal IPv4/TCP or UDP packet for testing.
func makeIPv4Packet(srcIP, dstIP netip.Addr, proto uint8, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 40) // 20 byte IP header + 20 byte payload
	pkt[0] = 0x45           // version 4, IHL 5 (20 bytes)
	pkt[9] = proto          // protocol

	src := srcIP.As4()
	dst := dstIP.As4()
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])

	// TCP/UDP header: src port, dst port
	pkt[20] = byte(srcPort >> 8)
	pkt[21] = byte(srcPort)
	pkt[22] = byte(dstPort >> 8)
	pkt[23] = byte(dstPort)

	return pkt
}
