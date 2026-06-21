package canary

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

const (
	// CanaryPrefix is the prefix for canary token strings
	CanaryPrefix = "gw_canary_"

	// CanaryIDLength is the length of canary IDs in bytes
	CanaryIDLength = 16
)

// Type distinguishes between canary modes
type Type uint8

const (
	// TypeDeadSwitch must check in periodically, alerts on missed check-ins
	TypeDeadSwitch Type = iota

	// TypeTripwire alerts immediately when accessed
	TypeTripwire

	// TypeHoneypot is a fake credential that alerts on use
	TypeHoneypot
)

func (t Type) String() string {
	switch t {
	case TypeDeadSwitch:
		return "dead_switch"
	case TypeTripwire:
		return "tripwire"
	case TypeHoneypot:
		return "honeypot"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// Canary represents a canary token
type Canary struct {
	mu              sync.Mutex
	ID              [CanaryIDLength]byte
	Type            Type
	NodeID          string
	Description     string
	Created         time.Time
	CheckInInterval time.Duration // For dead switch
	LastCheckIn     time.Time
	MissedCount     int
	Threshold       int               // Alert after this many misses
	Context         string            // Path for tripwire, value for honeypot
	Metadata        map[string]string // Additional context
	Triggered       bool
	TriggeredAt     time.Time
}

// NewDeadSwitch creates a dead man's switch canary
func NewDeadSwitch(nodeID, description string, interval time.Duration, threshold int) (*Canary, error) {
	var id [CanaryIDLength]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("generate ID: %w", err)
	}

	if threshold <= 0 {
		threshold = 3 // Default: alert after 3 missed check-ins
	}
	if interval <= 0 {
		interval = 6 * time.Hour // Default: 6 hour check-in interval
	}

	return &Canary{
		ID:              id,
		Type:            TypeDeadSwitch,
		NodeID:          nodeID,
		Description:     description,
		Created:         time.Now(),
		CheckInInterval: interval,
		LastCheckIn:     time.Now(),
		Threshold:       threshold,
		Metadata:        make(map[string]string),
	}, nil
}

// NewTripwire creates a tripwire canary for path monitoring
func NewTripwire(nodeID, description, path string) (*Canary, error) {
	var id [CanaryIDLength]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("generate ID: %w", err)
	}

	return &Canary{
		ID:          id,
		Type:        TypeTripwire,
		NodeID:      nodeID,
		Description: description,
		Created:     time.Now(),
		Context:     path,
		Metadata:    make(map[string]string),
	}, nil
}

// NewHoneypot creates a honeypot canary (fake credential)
func NewHoneypot(nodeID, description, value string) (*Canary, error) {
	var id [CanaryIDLength]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("generate ID: %w", err)
	}

	return &Canary{
		ID:          id,
		Type:        TypeHoneypot,
		NodeID:      nodeID,
		Description: description,
		Created:     time.Now(),
		Context:     value,
		Metadata:    make(map[string]string),
	}, nil
}

// IDString returns the hex-encoded ID
func (c *Canary) IDString() string {
	return hex.EncodeToString(c.ID[:])
}

// ShortID returns a truncated ID for logging
func (c *Canary) ShortID() string {
	return hex.EncodeToString(c.ID[:4])
}

// CheckIn records a check-in for dead switch canaries
func (c *Canary) CheckIn() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.LastCheckIn = time.Now()
	c.MissedCount = 0
}

// IsDue returns true if a check-in is overdue
func (c *Canary) IsDue() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Type != TypeDeadSwitch {
		return false
	}
	return time.Since(c.LastCheckIn) > c.CheckInInterval
}

// RecordMiss recomputes the missed count and returns true if the threshold is
// reached. Misses are derived from elapsed time / CheckInInterval rather than
// incremented per call, so Threshold means "N missed check-in windows"
// regardless of how often the monitor polls (incrementing per poll tripped the
// switch after Threshold ticks instead of Threshold intervals).
func (c *Canary) RecordMiss() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.CheckInInterval <= 0 {
		return false
	}
	c.MissedCount = int(time.Since(c.LastCheckIn) / c.CheckInInterval)
	return c.MissedCount >= c.Threshold
}

// Trigger marks the canary as triggered
func (c *Canary) Trigger() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.Triggered {
		c.Triggered = true
		c.TriggeredAt = time.Now()
	}
}

// IsTriggered returns whether the canary has been triggered
func (c *Canary) IsTriggered() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Triggered
}

// Hash returns a hash of the canary for safe logging
func (c *Canary) Hash() string {
	h := sha256.Sum256(c.ID[:])
	return hex.EncodeToString(h[:8])
}

// SignedCanary wraps a canary with its signature
type SignedCanary struct {
	Canary    *Canary
	Signature []byte
}

// Sign creates a signed canary
func Sign(c *Canary, privateKey ed25519.PrivateKey) (*SignedCanary, error) {
	data := c.signatureData()
	sig := ed25519.Sign(privateKey, data)
	return &SignedCanary{
		Canary:    c,
		Signature: sig,
	}, nil
}

// Verify checks the canary signature
func Verify(sc *SignedCanary, publicKey ed25519.PublicKey) bool {
	data := sc.Canary.signatureData()
	return ed25519.Verify(publicKey, data, sc.Signature)
}

// signatureData returns the data to sign
func (c *Canary) signatureData() []byte {
	// Include all immutable fields. The variable-length strings are
	// length-prefixed so adjacent fields can't be shifted across the boundary
	// to forge a different canary with the same signing input.
	data := make([]byte, 0, 128)
	data = append(data, c.ID[:]...)
	data = append(data, byte(c.Type))
	data = appendLenPrefixed(data, []byte(c.NodeID))
	data = appendLenPrefixed(data, []byte(c.Description))
	data = appendLenPrefixed(data, []byte(c.Context))
	return data
}

func appendLenPrefixed(dst, field []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(field)))
	dst = append(dst, l[:]...)
	return append(dst, field...)
}

// Alert contains information about a triggered canary
type Alert struct {
	CanaryID    string
	CanaryType  Type
	NodeID      string
	Description string
	Timestamp   time.Time
	Details     AlertDetails
}

// AlertDetails contains type-specific alert information
type AlertDetails struct {
	// Dead switch
	MissedCount int
	LastCheckIn time.Time

	// Tripwire
	AccessPath   string
	AccessSource string
	AccessTime   time.Time

	// Honeypot
	AttemptType string // "auth", "api", "file"
	AttemptData string
}

// NewAlert creates an alert from a triggered canary
func NewAlert(c *Canary) *Alert {
	// Snapshot the mutable fields under the lock (they race with
	// CheckIn/RecordMiss/Trigger). IDString locks internally, so read it
	// outside the critical section to avoid re-entrant locking.
	c.mu.Lock()
	missedCount := c.MissedCount
	lastCheckIn := c.LastCheckIn
	c.mu.Unlock()

	alert := &Alert{
		CanaryID:    c.IDString(),
		CanaryType:  c.Type,
		NodeID:      c.NodeID,
		Description: c.Description,
		Timestamp:   time.Now(),
	}

	switch c.Type {
	case TypeDeadSwitch:
		alert.Details.MissedCount = missedCount
		alert.Details.LastCheckIn = lastCheckIn
	case TypeTripwire:
		alert.Details.AccessPath = c.Context
		alert.Details.AccessTime = time.Now()
	case TypeHoneypot:
		alert.Details.AttemptType = "unknown"
	}

	return alert
}
