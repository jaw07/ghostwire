package secure

import (
	"fmt"
	"sync"
	"time"
)

// Predefined compartment names
const (
	CompartmentCA      = "ca_keys"      // CA private key (admin only)
	CompartmentNode    = "node_keys"    // Node private keys
	CompartmentSession = "session_keys" // Ephemeral session keys
	CompartmentTokens  = "tokens"       // Active tokens
	CompartmentSecrets = "mesh_secrets" // Shared mesh secrets
)

// Region represents an isolated memory region for sensitive data
type Region struct {
	mu          sync.Mutex
	data        []byte
	locked      bool
	purpose     string
	created     time.Time
	lastAccess  time.Time
	accessCount uint64
	wiped       bool
}

// NewRegion creates a new secure memory region
func NewRegion(size int, purpose string) (*Region, error) {
	r := &Region{
		data:    make([]byte, size),
		purpose: purpose,
		created: time.Now(),
	}

	// Try to lock memory
	if err := r.mlock(); err != nil {
		// Non-fatal, continue without lock
	}

	return r, nil
}

// Write copies data into the region
func (r *Region) Write(data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.wiped {
		return fmt.Errorf("region has been wiped")
	}

	if len(data) > len(r.data) {
		return fmt.Errorf("data exceeds region size: %d > %d", len(data), len(r.data))
	}

	// Zero existing data first
	wipeBytes(r.data)

	copy(r.data, data)
	r.lastAccess = time.Now()
	r.accessCount++
	return nil
}

// Read returns a copy of the data
func (r *Region) Read() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.wiped {
		return nil, fmt.Errorf("region has been wiped")
	}

	result := make([]byte, len(r.data))
	copy(result, r.data)
	r.lastAccess = time.Now()
	r.accessCount++
	return result, nil
}

// Size returns the region size
func (r *Region) Size() int {
	return len(r.data)
}

// Purpose returns the region's purpose
func (r *Region) Purpose() string {
	return r.purpose
}

// Stats returns region statistics
func (r *Region) Stats() RegionStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return RegionStats{
		Size:        len(r.data),
		Purpose:     r.purpose,
		Locked:      r.locked,
		Created:     r.created,
		LastAccess:  r.lastAccess,
		AccessCount: r.accessCount,
		Wiped:       r.wiped,
	}
}

// RegionStats contains region statistics
type RegionStats struct {
	Size        int
	Purpose     string
	Locked      bool
	Created     time.Time
	LastAccess  time.Time
	AccessCount uint64
	Wiped       bool
}

// Wipe securely zeros the region
func (r *Region) Wipe() {
	r.mu.Lock()
	defer r.mu.Unlock()

	wipeBytes(r.data)
	r.wiped = true
}

// Close wipes and unlocks the region
func (r *Region) Close() {
	r.Wipe()
	r.munlock()
}

// Compartment groups related secure regions
type Compartment struct {
	mu        sync.RWMutex
	name      string
	regions   map[string]*Region
	maxSize   int
	totalSize int
	created   time.Time
}

// NewCompartment creates a new compartment
func NewCompartment(name string, maxSize int) *Compartment {
	return &Compartment{
		name:    name,
		regions: make(map[string]*Region),
		maxSize: maxSize,
		created: time.Now(),
	}
}

// Name returns the compartment name
func (c *Compartment) Name() string {
	return c.name
}

// Allocate creates a new region in the compartment
func (c *Compartment) Allocate(id string, size int, purpose string) (*Region, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.regions[id]; exists {
		return nil, fmt.Errorf("region %q already exists", id)
	}

	if c.maxSize > 0 && c.totalSize+size > c.maxSize {
		return nil, fmt.Errorf("compartment size limit exceeded: %d + %d > %d", c.totalSize, size, c.maxSize)
	}

	region, err := NewRegion(size, purpose)
	if err != nil {
		return nil, err
	}

	c.regions[id] = region
	c.totalSize += size
	return region, nil
}

// Get retrieves a region by ID
func (c *Compartment) Get(id string) (*Region, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	region, ok := c.regions[id]
	return region, ok
}

// Release wipes and removes a region
func (c *Compartment) Release(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	region, ok := c.regions[id]
	if !ok {
		return fmt.Errorf("region %q not found", id)
	}

	region.Close()
	c.totalSize -= region.Size()
	delete(c.regions, id)
	return nil
}

// Stats returns compartment statistics
func (c *Compartment) Stats() CompartmentStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	regionStats := make([]RegionStats, 0, len(c.regions))
	lockedSize := 0
	for _, r := range c.regions {
		stats := r.Stats()
		regionStats = append(regionStats, stats)
		if stats.Locked {
			lockedSize += stats.Size
		}
	}

	return CompartmentStats{
		Name:        c.name,
		RegionCount: len(c.regions),
		TotalSize:   c.totalSize,
		MaxSize:     c.maxSize,
		LockedSize:  lockedSize,
		Created:     c.created,
		Regions:     regionStats,
	}
}

// CompartmentStats contains compartment statistics
type CompartmentStats struct {
	Name        string
	RegionCount int
	TotalSize   int
	MaxSize     int
	LockedSize  int
	Created     time.Time
	Regions     []RegionStats
}

// Wipe securely zeros all regions in the compartment
func (c *Compartment) Wipe() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, region := range c.regions {
		region.Wipe()
	}
}

// Close wipes and releases all regions
func (c *Compartment) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for id, region := range c.regions {
		region.Close()
		delete(c.regions, id)
	}
	c.totalSize = 0
}
