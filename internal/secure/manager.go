package secure

import (
	"fmt"
	"runtime"
	"sync"
)

const (
	// DefaultMaxLocked is the default mlock limit (64KB)
	DefaultMaxLocked = 64 * 1024

	// DefaultCompartmentSize is the default max size per compartment
	DefaultCompartmentSize = 16 * 1024
)

// Manager manages multiple isolated compartments
type Manager struct {
	mu           sync.RWMutex
	compartments map[string]*Compartment
	totalLocked  int
	maxLocked    int
	closed       bool
}

// ManagerConfig configures the manager
type ManagerConfig struct {
	MaxLocked int // Maximum bytes to mlock (0 = auto-detect)
}

// NewManager creates a new compartment manager
func NewManager(cfg *ManagerConfig) *Manager {
	maxLocked := DefaultMaxLocked
	if cfg != nil && cfg.MaxLocked > 0 {
		maxLocked = cfg.MaxLocked
	} else {
		// Try to detect system limit
		if detected := getMemlockLimit(); detected > 0 {
			maxLocked = detected
		}
	}

	m := &Manager{
		compartments: make(map[string]*Compartment),
		maxLocked:    maxLocked,
	}

	// Pre-create standard compartments
	m.initStandardCompartments()

	return m
}

// initStandardCompartments creates the predefined compartments
func (m *Manager) initStandardCompartments() {
	// CA keys compartment (small, only admin nodes)
	m.compartments[CompartmentCA] = NewCompartment(CompartmentCA, 4*1024)

	// Node keys compartment
	m.compartments[CompartmentNode] = NewCompartment(CompartmentNode, 8*1024)

	// Session keys compartment (ephemeral, may need more space)
	m.compartments[CompartmentSession] = NewCompartment(CompartmentSession, 32*1024)

	// Tokens compartment
	m.compartments[CompartmentTokens] = NewCompartment(CompartmentTokens, 8*1024)

	// Mesh secrets compartment
	m.compartments[CompartmentSecrets] = NewCompartment(CompartmentSecrets, 4*1024)
}

// GetCompartment returns a compartment by name
func (m *Manager) GetCompartment(name string) (*Compartment, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.compartments[name]
	return c, ok
}

// CreateCompartment creates a new custom compartment
func (m *Manager) CreateCompartment(name string, maxSize int) (*Compartment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, fmt.Errorf("manager is closed")
	}

	if _, exists := m.compartments[name]; exists {
		return nil, fmt.Errorf("compartment %q already exists", name)
	}

	c := NewCompartment(name, maxSize)
	m.compartments[name] = c
	return c, nil
}

// Allocate creates a region in a compartment
func (m *Manager) Allocate(compartment, id string, size int, purpose string) (*Region, error) {
	c, ok := m.GetCompartment(compartment)
	if !ok {
		return nil, fmt.Errorf("compartment %q not found", compartment)
	}
	return c.Allocate(id, size, purpose)
}

// Get retrieves a region from a compartment
func (m *Manager) Get(compartment, id string) (*Region, error) {
	c, ok := m.GetCompartment(compartment)
	if !ok {
		return nil, fmt.Errorf("compartment %q not found", compartment)
	}

	region, ok := c.Get(id)
	if !ok {
		return nil, fmt.Errorf("region %q not found in compartment %q", id, compartment)
	}
	return region, nil
}

// Release frees a region from a compartment
func (m *Manager) Release(compartment, id string) error {
	c, ok := m.GetCompartment(compartment)
	if !ok {
		return fmt.Errorf("compartment %q not found", compartment)
	}
	return c.Release(id)
}

// Stats returns manager statistics
func (m *Manager) Stats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	compartmentStats := make([]CompartmentStats, 0, len(m.compartments))
	totalRegions := 0
	totalSize := 0
	totalLocked := 0

	for _, c := range m.compartments {
		stats := c.Stats()
		compartmentStats = append(compartmentStats, stats)
		totalRegions += stats.RegionCount
		totalSize += stats.TotalSize
		totalLocked += stats.LockedSize
	}

	return ManagerStats{
		CompartmentCount: len(m.compartments),
		TotalRegions:     totalRegions,
		TotalSize:        totalSize,
		TotalLocked:      totalLocked,
		MaxLocked:        m.maxLocked,
		Compartments:     compartmentStats,
	}
}

// ManagerStats contains manager statistics
type ManagerStats struct {
	CompartmentCount int
	TotalRegions     int
	TotalSize        int
	TotalLocked      int
	MaxLocked        int
	Compartments     []CompartmentStats
}

// WipeCompartment wipes all regions in a compartment
func (m *Manager) WipeCompartment(name string) error {
	c, ok := m.GetCompartment(name)
	if !ok {
		return fmt.Errorf("compartment %q not found", name)
	}
	c.Wipe()
	return nil
}

// WipeAll wipes all regions in all compartments
func (m *Manager) WipeAll() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, c := range m.compartments {
		c.Wipe()
	}
}

// Close wipes and releases all compartments
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return
	}

	for name, c := range m.compartments {
		c.Close()
		delete(m.compartments, name)
	}
	m.closed = true
}

// global manager instance
var (
	globalManager     *Manager
	globalManagerOnce sync.Once
)

// Global returns the global manager instance
func Global() *Manager {
	globalManagerOnce.Do(func() {
		globalManager = NewManager(nil)
	})
	return globalManager
}

// InitGlobal initializes the global manager with custom config
func InitGlobal(cfg *ManagerConfig) *Manager {
	globalManagerOnce.Do(func() {
		globalManager = NewManager(cfg)
	})
	return globalManager
}

// wipeBytes securely zeros a byte slice
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
