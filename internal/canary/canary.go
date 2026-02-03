package canary

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	c.LastCheckIn = time.Now()
	c.MissedCount = 0
}

// IsDue returns true if a check-in is overdue
func (c *Canary) IsDue() bool {
	if c.Type != TypeDeadSwitch {
		return false
	}
	return time.Since(c.LastCheckIn) > c.CheckInInterval
}

// RecordMiss increments the missed count and returns true if threshold exceeded
func (c *Canary) RecordMiss() bool {
	c.MissedCount++
	return c.MissedCount >= c.Threshold
}

// Trigger marks the canary as triggered
func (c *Canary) Trigger() {
	if !c.Triggered {
		c.Triggered = true
		c.TriggeredAt = time.Now()
	}
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
	// Include all immutable fields
	data := make([]byte, 0, 128)
	data = append(data, c.ID[:]...)
	data = append(data, byte(c.Type))
	data = append(data, []byte(c.NodeID)...)
	data = append(data, []byte(c.Description)...)
	data = append(data, []byte(c.Context)...)
	return data
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
	alert := &Alert{
		CanaryID:    c.IDString(),
		CanaryType:  c.Type,
		NodeID:      c.NodeID,
		Description: c.Description,
		Timestamp:   time.Now(),
	}

	switch c.Type {
	case TypeDeadSwitch:
		alert.Details.MissedCount = c.MissedCount
		alert.Details.LastCheckIn = c.LastCheckIn
	case TypeTripwire:
		alert.Details.AccessPath = c.Context
		alert.Details.AccessTime = time.Now()
	case TypeHoneypot:
		alert.Details.AttemptType = "unknown"
	}

	return alert
}
