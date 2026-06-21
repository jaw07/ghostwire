// Package gossip implements a SWIM-based protocol for decentralized peer discovery and state sync.
package gossip

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// MemberState represents the state of a member in the cluster
type MemberState uint8

const (
	StateAlive MemberState = iota
	StateSuspect
	StateDead
	StateLeft
)

func (s MemberState) String() string {
	switch s {
	case StateAlive:
		return "alive"
	case StateSuspect:
		return "suspect"
	case StateDead:
		return "dead"
	case StateLeft:
		return "left"
	default:
		return "unknown"
	}
}

// Member represents a node in the mesh
type Member struct {
	// NodeID is the unique identifier for this node
	NodeID string

	// MeshIP is the node's IP within the mesh
	MeshIP netip.Addr

	// Endpoints are the external addresses where this node can be reached
	Endpoints []string

	// Roles are the roles assigned to this node
	Roles []string

	// PublicKey is the node's WireGuard public key (base64)
	PublicKey string

	// State is the current membership state
	State MemberState

	// Incarnation is a logical clock to resolve state conflicts
	Incarnation uint64

	// LastSeen is when we last heard from this node
	LastSeen time.Time

	// RTT is the round-trip time to this node
	RTT time.Duration

	// Transport is the preferred transport for this node
	Transport string

	// Metadata is arbitrary key-value data about the node
	Metadata map[string]string
}

// Clone creates a deep copy of the member
func (m *Member) Clone() *Member {
	clone := &Member{
		NodeID:      m.NodeID,
		MeshIP:      m.MeshIP,
		PublicKey:   m.PublicKey,
		State:       m.State,
		Incarnation: m.Incarnation,
		LastSeen:    m.LastSeen,
		RTT:         m.RTT,
		Transport:   m.Transport,
	}

	clone.Endpoints = make([]string, len(m.Endpoints))
	copy(clone.Endpoints, m.Endpoints)

	clone.Roles = make([]string, len(m.Roles))
	copy(clone.Roles, m.Roles)

	if m.Metadata != nil {
		clone.Metadata = make(map[string]string, len(m.Metadata))
		for k, v := range m.Metadata {
			clone.Metadata[k] = v
		}
	}

	return clone
}

// HasRole checks if the member has the given role
func (m *Member) HasRole(role string) bool {
	for _, r := range m.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// IsRelay returns true if this member can act as a relay
func (m *Member) IsRelay() bool {
	return m.HasRole("relay") || m.HasRole("admin")
}

// MemberList manages the list of known members
type MemberList struct {
	mu      sync.RWMutex
	members map[string]*Member
	self    *Member

	// Callbacks for member state changes
	onJoin   func(*Member)
	onLeave  func(*Member)
	onUpdate func(*Member)
}

// NewMemberList creates a new member list
func NewMemberList(self *Member) *MemberList {
	return &MemberList{
		members: make(map[string]*Member),
		self:    self,
	}
}

// SetCallbacks sets the callbacks for member events
func (ml *MemberList) SetCallbacks(onJoin, onLeave, onUpdate func(*Member)) {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	ml.onJoin = onJoin
	ml.onLeave = onLeave
	ml.onUpdate = onUpdate
}

// Self returns the local member
func (ml *MemberList) Self() *Member {
	ml.mu.RLock()
	defer ml.mu.RUnlock()
	return ml.self.Clone()
}

// UpdateSelf updates the local member info
func (ml *MemberList) UpdateSelf(fn func(*Member)) {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	fn(ml.self)
	ml.self.Incarnation++
}

// Get returns a member by node ID
func (ml *MemberList) Get(nodeID string) *Member {
	ml.mu.RLock()
	defer ml.mu.RUnlock()

	if m, ok := ml.members[nodeID]; ok {
		return m.Clone()
	}
	return nil
}

// Merge updates the member list with new member info
// Returns true if the member was new or updated
func (ml *MemberList) Merge(m *Member) bool {
	// A malformed gossip payload (e.g. JSON "members":[null]) decodes to a nil
	// member; reject it rather than dereferencing it and crashing the goroutine.
	if m == nil {
		return false
	}

	ml.mu.Lock()
	defer ml.mu.Unlock()

	// Don't overwrite ourselves
	if m.NodeID == ml.self.NodeID {
		return false
	}

	existing, exists := ml.members[m.NodeID]

	// New member. Callbacks run in goroutines, so hand them a Clone — never the
	// caller's m (mutated as the receive loop ranges the message) nor a pointer
	// into the mutex-guarded map.
	if !exists {
		ml.members[m.NodeID] = m.Clone()
		if ml.onJoin != nil {
			go ml.onJoin(m.Clone())
		}
		return true
	}

	// Existing member - check incarnation
	if m.Incarnation > existing.Incarnation {
		// Newer info, update everything
		ml.members[m.NodeID] = m.Clone()
		if ml.onUpdate != nil {
			go ml.onUpdate(m.Clone())
		}
		return true
	}

	if m.Incarnation == existing.Incarnation {
		// Same incarnation - state precedence: dead > suspect > alive
		if m.State > existing.State {
			existing.State = m.State
			existing.LastSeen = m.LastSeen
			if m.State == StateDead && ml.onLeave != nil {
				go ml.onLeave(existing.Clone())
			}
			return true
		}
	}

	return false
}

// MarkSuspect marks a member as suspect
func (ml *MemberList) MarkSuspect(nodeID string) bool {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	m, exists := ml.members[nodeID]
	if !exists || m.State != StateAlive {
		return false
	}

	m.State = StateSuspect
	return true
}

// MarkDead marks a member as dead
func (ml *MemberList) MarkDead(nodeID string) bool {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	m, exists := ml.members[nodeID]
	if !exists || m.State == StateDead {
		return false
	}

	m.State = StateDead
	if ml.onLeave != nil {
		go ml.onLeave(m.Clone())
	}
	return true
}

// MarkDeadIfSuspect atomically confirms death only if the member is still
// suspect. If it refuted (gossiped a higher incarnation back to Alive) during
// the suspicion window, it is spared — preventing a recovered node from being
// killed cluster-wide (SWIM refutation). This is the correct call from the
// suspicion-timeout path; MarkDead remains available for unconditional kills.
func (ml *MemberList) MarkDeadIfSuspect(nodeID string) bool {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	m, exists := ml.members[nodeID]
	if !exists || m.State != StateSuspect {
		return false
	}

	m.State = StateDead
	if ml.onLeave != nil {
		go ml.onLeave(m.Clone())
	}
	return true
}

// MarkAlive marks a member as alive
func (ml *MemberList) MarkAlive(nodeID string) bool {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	m, exists := ml.members[nodeID]
	if !exists {
		return false
	}

	if m.State == StateSuspect {
		m.State = StateAlive
		m.LastSeen = time.Now()
		return true
	}
	return false
}

// Remove removes a member from the list
func (ml *MemberList) Remove(nodeID string) {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	delete(ml.members, nodeID)
}

// Members returns all members matching the filter
func (ml *MemberList) Members(filter func(*Member) bool) []*Member {
	ml.mu.RLock()
	defer ml.mu.RUnlock()

	var result []*Member
	for _, m := range ml.members {
		if filter == nil || filter(m) {
			result = append(result, m.Clone())
		}
	}
	return result
}

// AliveMembers returns all alive members
func (ml *MemberList) AliveMembers() []*Member {
	return ml.Members(func(m *Member) bool {
		return m.State == StateAlive
	})
}

// RelayMembers returns all alive relay members
func (ml *MemberList) RelayMembers() []*Member {
	return ml.Members(func(m *Member) bool {
		return m.State == StateAlive && m.IsRelay()
	})
}

// RandomMember returns a random alive member
func (ml *MemberList) RandomMember() *Member {
	alive := ml.AliveMembers()
	if len(alive) == 0 {
		return nil
	}

	var idx uint32
	binary.Read(rand.Reader, binary.BigEndian, &idx)
	return alive[int(idx)%len(alive)]
}

// RandomMembers returns n random alive members (excluding self)
func (ml *MemberList) RandomMembers(n int, exclude ...string) []*Member {
	alive := ml.AliveMembers()

	// Build exclusion set
	excludeSet := make(map[string]bool)
	for _, id := range exclude {
		excludeSet[id] = true
	}

	// Filter out excluded
	var filtered []*Member
	for _, m := range alive {
		if !excludeSet[m.NodeID] {
			filtered = append(filtered, m)
		}
	}

	// Shuffle using Fisher-Yates
	for i := len(filtered) - 1; i > 0; i-- {
		var j uint32
		binary.Read(rand.Reader, binary.BigEndian, &j)
		j = j % uint32(i+1)
		filtered[i], filtered[j] = filtered[j], filtered[i]
	}

	if n > len(filtered) {
		n = len(filtered)
	}
	return filtered[:n]
}

// Count returns the number of members in each state
func (ml *MemberList) Count() map[MemberState]int {
	ml.mu.RLock()
	defer ml.mu.RUnlock()

	counts := make(map[MemberState]int)
	for _, m := range ml.members {
		counts[m.State]++
	}
	return counts
}

// Size returns the total number of known members
func (ml *MemberList) Size() int {
	ml.mu.RLock()
	defer ml.mu.RUnlock()
	return len(ml.members)
}
