// Package routing implements mesh routing table and path selection.
package routing

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/ghostwire/ghostwire/internal/gossip"
)

// RouteType indicates how to reach a destination
type RouteType uint8

const (
	RouteDirect   RouteType = iota // Direct WireGuard connection
	RouteRelay                     // Via a relay node
	RouteMultiHop                  // Through multiple relays
)

func (r RouteType) String() string {
	switch r {
	case RouteDirect:
		return "direct"
	case RouteRelay:
		return "relay"
	case RouteMultiHop:
		return "multihop"
	default:
		return "unknown"
	}
}

// Route represents a path to a destination node
type Route struct {
	// Destination is the target node ID
	Destination string

	// DestIP is the mesh IP of the destination
	DestIP netip.Addr

	// Type indicates the route type
	Type RouteType

	// NextHop is the node ID of the next hop (self for direct routes)
	NextHop string

	// Path is the full path for multi-hop routes
	Path []string

	// Metric is the route cost (lower is better)
	Metric int

	// RTT is the estimated round-trip time
	RTT time.Duration

	// LastUpdated is when this route was last validated
	LastUpdated time.Time

	// Transport is the preferred transport for this route
	Transport string
}

// Table manages routes to mesh nodes
type Table struct {
	mu       sync.RWMutex
	routes   map[string][]*Route // nodeID -> routes (multiple paths)
	localID  string
	localIP  netip.Addr
	maxHops  int
	onChange func(nodeID string, routes []*Route)
}

// NewTable creates a new routing table
func NewTable(localID string, localIP netip.Addr) *Table {
	return &Table{
		routes:  make(map[string][]*Route),
		localID: localID,
		localIP: localIP,
		maxHops: 3,
	}
}

// SetOnChange sets a callback for route changes
func (t *Table) SetOnChange(fn func(nodeID string, routes []*Route)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onChange = fn
}

// UpdateFromGossip updates routes based on gossip member list
func (t *Table) UpdateFromGossip(members *gossip.MemberList) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Get all alive members
	alive := members.AliveMembers()
	relays := members.RelayMembers()

	// Build route map
	newRoutes := make(map[string][]*Route)

	for _, m := range alive {
		if m.NodeID == t.localID {
			continue
		}

		var routes []*Route

		// Direct route if we have endpoints
		if len(m.Endpoints) > 0 {
			routes = append(routes, &Route{
				Destination: m.NodeID,
				DestIP:      m.MeshIP,
				Type:        RouteDirect,
				NextHop:     m.NodeID,
				Path:        []string{m.NodeID},
				Metric:      1,
				RTT:         m.RTT,
				LastUpdated: time.Now(),
				Transport:   m.Transport,
			})
		}

		// Relay routes through each relay
		for _, relay := range relays {
			if relay.NodeID == m.NodeID || relay.NodeID == t.localID {
				continue
			}

			// Calculate metric: 2 (relay) + RTT-based adjustment
			metric := 2
			if relay.RTT > 100*time.Millisecond {
				metric++
			}

			routes = append(routes, &Route{
				Destination: m.NodeID,
				DestIP:      m.MeshIP,
				Type:        RouteRelay,
				NextHop:     relay.NodeID,
				Path:        []string{relay.NodeID, m.NodeID},
				Metric:      metric,
				RTT:         relay.RTT + m.RTT, // Estimated
				LastUpdated: time.Now(),
				Transport:   relay.Transport,
			})
		}

		// Sort routes by metric
		sort.Slice(routes, func(i, j int) bool {
			if routes[i].Metric != routes[j].Metric {
				return routes[i].Metric < routes[j].Metric
			}
			return routes[i].RTT < routes[j].RTT
		})

		newRoutes[m.NodeID] = routes
	}

	// Detect changes and notify
	for nodeID, routes := range newRoutes {
		old := t.routes[nodeID]
		if !routesEqual(old, routes) && t.onChange != nil {
			t.onChange(nodeID, routes)
		}
	}

	// Check for removed nodes
	for nodeID := range t.routes {
		if _, exists := newRoutes[nodeID]; !exists && t.onChange != nil {
			t.onChange(nodeID, nil)
		}
	}

	t.routes = newRoutes
}

// cloneRoute returns a copy of a route so callers never hold a pointer into the
// mutex-guarded table (UpdateMetrics mutates route fields under the lock).
func cloneRoute(r *Route) *Route {
	if r == nil {
		return nil
	}
	c := *r
	if r.Path != nil {
		c.Path = make([]string, len(r.Path))
		copy(c.Path, r.Path)
	}
	return &c
}

// GetRoute returns the best route to a destination
func (t *Table) GetRoute(nodeID string) *Route {
	t.mu.RLock()
	defer t.mu.RUnlock()

	routes := t.routes[nodeID]
	if len(routes) == 0 {
		return nil
	}
	return cloneRoute(routes[0])
}

// GetRouteByIP returns the best route to a mesh IP
func (t *Table) GetRouteByIP(ip netip.Addr) *Route {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, routes := range t.routes {
		if len(routes) > 0 && routes[0].DestIP == ip {
			return cloneRoute(routes[0])
		}
	}
	return nil
}

// GetAllRoutes returns all routes to a destination
func (t *Table) GetAllRoutes(nodeID string) []*Route {
	t.mu.RLock()
	defer t.mu.RUnlock()

	routes := t.routes[nodeID]
	result := make([]*Route, len(routes))
	for i, r := range routes {
		result[i] = cloneRoute(r)
	}
	return result
}

// GetDirectPeers returns nodes we can reach directly
func (t *Table) GetDirectPeers() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var peers []string
	for nodeID, routes := range t.routes {
		if len(routes) > 0 && routes[0].Type == RouteDirect {
			peers = append(peers, nodeID)
		}
	}
	return peers
}

// GetRelayedPeers returns nodes we reach via relay
func (t *Table) GetRelayedPeers() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var peers []string
	for nodeID, routes := range t.routes {
		if len(routes) > 0 && routes[0].Type == RouteRelay {
			peers = append(peers, nodeID)
		}
	}
	return peers
}

// Size returns the number of reachable destinations
func (t *Table) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.routes)
}

// All returns all current routes
func (t *Table) All() map[string]*Route {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make(map[string]*Route)
	for nodeID, routes := range t.routes {
		if len(routes) > 0 {
			result[nodeID] = cloneRoute(routes[0])
		}
	}
	return result
}

// UpdateMetrics updates RTT metrics for a route
func (t *Table) UpdateMetrics(nodeID string, rtt time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	routes := t.routes[nodeID]
	for _, r := range routes {
		if r.Type == RouteDirect {
			r.RTT = rtt
			r.LastUpdated = time.Now()
		}
	}
}

// InvalidateRoute marks a route as failed, promoting alternates
func (t *Table) InvalidateRoute(nodeID string, routeType RouteType) {
	t.mu.Lock()
	defer t.mu.Unlock()

	routes := t.routes[nodeID]
	if len(routes) <= 1 {
		return
	}

	// Remove the failed route type and re-sort
	var filtered []*Route
	for _, r := range routes {
		if r.Type != routeType {
			filtered = append(filtered, r)
		}
	}

	if len(filtered) > 0 {
		t.routes[nodeID] = filtered
	}
}

// routesEqual checks if two route slices are equivalent
func routesEqual(a, b []*Route) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type != b[i].Type || a[i].NextHop != b[i].NextHop {
			return false
		}
	}
	return true
}

// RelayManager handles relay node selection and failover
type RelayManager struct {
	table     *Table
	members   *gossip.MemberList
	preferred string
	mu        sync.RWMutex
}

// NewRelayManager creates a relay manager
func NewRelayManager(table *Table, members *gossip.MemberList) *RelayManager {
	return &RelayManager{
		table:   table,
		members: members,
	}
}

// SelectRelay chooses the best relay for a destination
func (rm *RelayManager) SelectRelay(destNodeID string) *gossip.Member {
	rm.mu.RLock()
	preferred := rm.preferred
	rm.mu.RUnlock()

	relays := rm.members.RelayMembers()
	if len(relays) == 0 {
		return nil
	}

	// Prefer the configured relay if available
	if preferred != "" {
		for _, r := range relays {
			if r.NodeID == preferred && r.State == gossip.StateAlive {
				return r
			}
		}
	}

	// Select by lowest RTT
	var best *gossip.Member
	for _, r := range relays {
		if best == nil || r.RTT < best.RTT {
			best = r
		}
	}

	return best
}

// SetPreferred sets the preferred relay node
func (rm *RelayManager) SetPreferred(nodeID string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.preferred = nodeID
}

// Failover switches to an alternate relay
func (rm *RelayManager) Failover(failedRelayID string) *gossip.Member {
	relays := rm.members.RelayMembers()

	var best *gossip.Member
	for _, r := range relays {
		if r.NodeID == failedRelayID {
			continue
		}
		if best == nil || r.RTT < best.RTT {
			best = r
		}
	}

	if best != nil {
		rm.SetPreferred(best.NodeID)
	}

	return best
}
