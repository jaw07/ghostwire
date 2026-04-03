package canary

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

const (
	// DefaultCheckInterval is how often to check dead switches
	DefaultCheckInterval = 1 * time.Minute
)

// Handler processes canary alerts
type Handler interface {
	OnAlert(alert *Alert)
}

// HandlerFunc is an adapter for alert handler functions
type HandlerFunc func(*Alert)

func (f HandlerFunc) OnAlert(alert *Alert) {
	f(alert)
}

// Monitor manages canaries and checks for triggers
type Monitor struct {
	mu            sync.RWMutex
	canaries      map[string]*Canary
	handlers      []Handler
	checkInterval time.Duration
	nodeID        string
	privateKey    ed25519.PrivateKey
	shutdown      chan struct{}
	wg            sync.WaitGroup
}

// MonitorConfig configures the monitor
type MonitorConfig struct {
	NodeID        string
	PrivateKey    ed25519.PrivateKey
	CheckInterval time.Duration
}

// NewMonitor creates a new canary monitor
func NewMonitor(cfg *MonitorConfig) *Monitor {
	checkInterval := cfg.CheckInterval
	if checkInterval <= 0 {
		checkInterval = DefaultCheckInterval
	}

	return &Monitor{
		canaries:      make(map[string]*Canary),
		handlers:      make([]Handler, 0),
		checkInterval: checkInterval,
		nodeID:        cfg.NodeID,
		privateKey:    cfg.PrivateKey,
		shutdown:      make(chan struct{}),
	}
}

// AddHandler registers an alert handler
func (m *Monitor) AddHandler(h Handler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, h)
}

// AddHandlerFunc registers an alert handler function
func (m *Monitor) AddHandlerFunc(f func(*Alert)) {
	m.AddHandler(HandlerFunc(f))
}

// Register adds a canary to the monitor
func (m *Monitor) Register(c *Canary) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := c.IDString()
	if _, exists := m.canaries[id]; exists {
		return fmt.Errorf("canary %s already registered", c.ShortID())
	}

	m.canaries[id] = c
	return nil
}

// Unregister removes a canary from the monitor
func (m *Monitor) Unregister(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.canaries[id]; !exists {
		return fmt.Errorf("canary %s not found", id[:8])
	}

	delete(m.canaries, id)
	return nil
}

// Get retrieves a canary by ID
func (m *Monitor) Get(id string) (*Canary, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.canaries[id]
	return c, ok
}

// GetByShortID finds a canary by ID prefix
func (m *Monitor) GetByShortID(prefix string) (*Canary, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for id, c := range m.canaries {
		if len(id) >= len(prefix) && id[:len(prefix)] == prefix {
			return c, true
		}
	}
	return nil, false
}

// List returns all registered canaries
func (m *Monitor) List() []*Canary {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Canary, 0, len(m.canaries))
	for _, c := range m.canaries {
		result = append(result, c)
	}
	return result
}

// ListByType returns canaries of a specific type
func (m *Monitor) ListByType(t Type) []*Canary {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Canary, 0)
	for _, c := range m.canaries {
		if c.Type == t {
			result = append(result, c)
		}
	}
	return result
}

// CheckIn records a check-in for a dead switch canary
func (m *Monitor) CheckIn(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.canaries[id]
	if !ok {
		return fmt.Errorf("canary %s not found", id[:8])
	}

	if c.Type != TypeDeadSwitch {
		return fmt.Errorf("canary %s is not a dead switch", c.ShortID())
	}

	c.CheckIn()
	return nil
}

// CheckInByShortID records a check-in using an ID prefix
func (m *Monitor) CheckInByShortID(prefix string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, c := range m.canaries {
		if len(id) >= len(prefix) && id[:len(prefix)] == prefix {
			if c.Type != TypeDeadSwitch {
				return fmt.Errorf("canary %s is not a dead switch", c.ShortID())
			}
			c.CheckIn()
			return nil
		}
	}
	return fmt.Errorf("canary with prefix %s not found", prefix)
}

// TriggerTripwire manually triggers a tripwire canary
func (m *Monitor) TriggerTripwire(id string, source string) error {
	m.mu.Lock()
	c, ok := m.canaries[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("canary %s not found", id[:8])
	}

	if c.Type != TypeTripwire {
		m.mu.Unlock()
		return fmt.Errorf("canary %s is not a tripwire", c.ShortID())
	}

	c.Trigger()
	m.mu.Unlock()

	// Create and dispatch alert
	alert := NewAlert(c)
	alert.Details.AccessSource = source
	m.dispatchAlert(alert)

	return nil
}

// TriggerHoneypot manually triggers a honeypot canary
func (m *Monitor) TriggerHoneypot(id string, attemptType, attemptData string) error {
	m.mu.Lock()
	c, ok := m.canaries[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("canary %s not found", id[:8])
	}

	if c.Type != TypeHoneypot {
		m.mu.Unlock()
		return fmt.Errorf("canary %s is not a honeypot", c.ShortID())
	}

	c.Trigger()
	m.mu.Unlock()

	// Create and dispatch alert
	alert := NewAlert(c)
	alert.Details.AttemptType = attemptType
	alert.Details.AttemptData = attemptData
	m.dispatchAlert(alert)

	return nil
}

// CheckHoneypot checks if a value matches any honeypot
func (m *Monitor) CheckHoneypot(value string) (*Canary, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, c := range m.canaries {
		if c.Type == TypeHoneypot && c.Context == value {
			return c, true
		}
	}
	return nil, false
}

// Start begins the monitoring loop
func (m *Monitor) Start() {
	m.wg.Add(1)
	go m.monitorLoop()
}

// Stop stops the monitoring loop
func (m *Monitor) Stop() {
	close(m.shutdown)
	m.wg.Wait()
}

// monitorLoop checks dead switch canaries periodically
func (m *Monitor) monitorLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.checkDeadSwitches()
		case <-m.shutdown:
			return
		}
	}
}

// checkDeadSwitches checks all dead switch canaries
func (m *Monitor) checkDeadSwitches() {
	m.mu.Lock()
	var alerts []*Alert

	for _, c := range m.canaries {
		if c.Type != TypeDeadSwitch {
			continue
		}
		if c.IsTriggered() {
			continue
		}

		if c.IsDue() {
			if c.RecordMiss() {
				c.Trigger()
				alerts = append(alerts, NewAlert(c))
			}
		}
	}
	m.mu.Unlock()

	// Dispatch alerts outside of lock
	for _, alert := range alerts {
		m.dispatchAlert(alert)
	}
}

// dispatchAlert sends an alert to all handlers
func (m *Monitor) dispatchAlert(alert *Alert) {
	m.mu.RLock()
	handlers := make([]Handler, len(m.handlers))
	copy(handlers, m.handlers)
	m.mu.RUnlock()

	for _, h := range handlers {
		h.OnAlert(alert)
	}
}

// CreateDeadSwitch is a convenience method to create and register a dead switch
func (m *Monitor) CreateDeadSwitch(description string, interval time.Duration, threshold int) (*Canary, error) {
	c, err := NewDeadSwitch(m.nodeID, description, interval, threshold)
	if err != nil {
		return nil, err
	}
	if err := m.Register(c); err != nil {
		return nil, err
	}
	return c, nil
}

// CreateTripwire is a convenience method to create and register a tripwire
func (m *Monitor) CreateTripwire(description, path string) (*Canary, error) {
	c, err := NewTripwire(m.nodeID, description, path)
	if err != nil {
		return nil, err
	}
	if err := m.Register(c); err != nil {
		return nil, err
	}
	return c, nil
}

// CreateHoneypot is a convenience method to create and register a honeypot
func (m *Monitor) CreateHoneypot(description, value string) (*Canary, error) {
	c, err := NewHoneypot(m.nodeID, description, value)
	if err != nil {
		return nil, err
	}
	if err := m.Register(c); err != nil {
		return nil, err
	}
	return c, nil
}

// Stats returns monitor statistics
type Stats struct {
	TotalCanaries   int
	DeadSwitches    int
	Tripwires       int
	Honeypots       int
	TriggeredCount  int
	OverdueCount    int
}

// Stats returns current monitor statistics
func (m *Monitor) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var stats Stats
	stats.TotalCanaries = len(m.canaries)

	for _, c := range m.canaries {
		switch c.Type {
		case TypeDeadSwitch:
			stats.DeadSwitches++
			if c.IsDue() {
				stats.OverdueCount++
			}
		case TypeTripwire:
			stats.Tripwires++
		case TypeHoneypot:
			stats.Honeypots++
		}
		if c.IsTriggered() {
			stats.TriggeredCount++
		}
	}

	return stats
}

// ParseID parses a canary ID from hex string
func ParseID(s string) ([CanaryIDLength]byte, error) {
	var id [CanaryIDLength]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, err
	}
	if len(b) != CanaryIDLength {
		return id, fmt.Errorf("invalid ID length: %d", len(b))
	}
	copy(id[:], b)
	return id, nil
}
