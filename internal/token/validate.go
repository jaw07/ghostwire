package token

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Validator verifies enrollment tokens
type Validator struct {
	publicKey    ed25519.PublicKey
	meshID       [32]byte
	usageTracker *UsageTracker
	clockSkew    time.Duration // Allowed clock skew between nodes
}

// NewValidator creates a token validator
func NewValidator(publicKey ed25519.PublicKey, meshID [32]byte) *Validator {
	return &Validator{
		publicKey:    publicKey,
		meshID:       meshID,
		usageTracker: NewUsageTracker(),
		clockSkew:    60 * time.Second, // Allow 1 minute clock skew
	}
}

// SetClockSkew sets the allowed clock skew for time validation
func (v *Validator) SetClockSkew(d time.Duration) {
	v.clockSkew = d
}

// SetUsageTracker sets a custom usage tracker (for persistence)
func (v *Validator) SetUsageTracker(tracker *UsageTracker) {
	v.usageTracker = tracker
}

// Validate verifies a token string and returns the parsed token if valid
func (v *Validator) Validate(tokenStr string) (*Token, error) {
	// Parse token string
	payloadBytes, signature, err := ParseTokenString(tokenStr)
	if err != nil {
		return nil, err
	}

	// Verify signature using constant-time comparison
	if !ed25519.Verify(v.publicKey, payloadBytes, signature) {
		return nil, ErrInvalidSignature
	}

	// Decode payload
	payload, err := DecodePayload(payloadBytes)
	if err != nil {
		return nil, err
	}

	// Check version
	if payload.Version != TokenVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidTokenFormat, payload.Version)
	}

	// Verify mesh ID using constant-time comparison
	if subtle.ConstantTimeCompare(payload.MeshID[:], v.meshID[:]) != 1 {
		return nil, ErrMeshIDMismatch
	}

	// Check time validity with clock skew allowance
	now := time.Now()
	notBefore := time.Unix(payload.NotBefore, 0).Add(-v.clockSkew)
	notAfter := time.Unix(payload.NotAfter, 0).Add(v.clockSkew)

	if now.Before(notBefore) {
		return nil, ErrTokenNotYetValid
	}
	if now.After(notAfter) {
		return nil, ErrTokenExpired
	}

	// Check usage limits
	if payload.MaxUses > 0 {
		if !v.usageTracker.IncrementAndCheck(payload.TokenID, int(payload.MaxUses)) {
			return nil, ErrTokenUsageExceeded
		}
	}

	// Build Token struct
	token := &Token{
		ID:            payload.TokenID,
		Version:       int(payload.Version),
		AllowedRoles:  payload.Roles,
		Compartment:   payload.Compartment,
		SuggestedName: payload.SuggestedName,
		NotBefore:     time.Unix(payload.NotBefore, 0),
		NotAfter:      time.Unix(payload.NotAfter, 0),
		MaxUses:       int(payload.MaxUses),
		MeshID:        payload.MeshID,
		signature:     signature,
	}

	return token, nil
}

// ValidateWithoutUsage validates a token without incrementing usage count
// Useful for checking token validity before actually using it
func (v *Validator) ValidateWithoutUsage(tokenStr string) (*Token, error) {
	// Parse token string
	payloadBytes, signature, err := ParseTokenString(tokenStr)
	if err != nil {
		return nil, err
	}

	// Verify signature
	if !ed25519.Verify(v.publicKey, payloadBytes, signature) {
		return nil, ErrInvalidSignature
	}

	// Decode payload
	payload, err := DecodePayload(payloadBytes)
	if err != nil {
		return nil, err
	}

	// Check version
	if payload.Version != TokenVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidTokenFormat, payload.Version)
	}

	// Verify mesh ID
	if subtle.ConstantTimeCompare(payload.MeshID[:], v.meshID[:]) != 1 {
		return nil, ErrMeshIDMismatch
	}

	// Check time validity
	now := time.Now()
	notBefore := time.Unix(payload.NotBefore, 0).Add(-v.clockSkew)
	notAfter := time.Unix(payload.NotAfter, 0).Add(v.clockSkew)

	if now.Before(notBefore) {
		return nil, ErrTokenNotYetValid
	}
	if now.After(notAfter) {
		return nil, ErrTokenExpired
	}

	// Don't check/increment usage

	token := &Token{
		ID:            payload.TokenID,
		Version:       int(payload.Version),
		AllowedRoles:  payload.Roles,
		Compartment:   payload.Compartment,
		SuggestedName: payload.SuggestedName,
		NotBefore:     time.Unix(payload.NotBefore, 0),
		NotAfter:      time.Unix(payload.NotAfter, 0),
		MaxUses:       int(payload.MaxUses),
		MeshID:        payload.MeshID,
		signature:     signature,
	}

	return token, nil
}

// GetUsageCount returns the current usage count for a token
func (v *Validator) GetUsageCount(tokenID [TokenIDLength]byte) int {
	return v.usageTracker.GetCount(tokenID)
}

// UsageTracker tracks token usage to enforce limits
type UsageTracker struct {
	mu    sync.Mutex
	uses  map[[TokenIDLength]byte]int
}

// NewUsageTracker creates a new usage tracker
func NewUsageTracker() *UsageTracker {
	return &UsageTracker{
		uses: make(map[[TokenIDLength]byte]int),
	}
}

// IncrementAndCheck atomically increments usage and checks if within limit
// Returns true if the usage is allowed, false if limit exceeded
func (t *UsageTracker) IncrementAndCheck(tokenID [TokenIDLength]byte, maxUses int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	current := t.uses[tokenID]
	if current >= maxUses {
		return false
	}
	t.uses[tokenID] = current + 1
	return true
}

// GetCount returns the current usage count for a token
func (t *UsageTracker) GetCount(tokenID [TokenIDLength]byte) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.uses[tokenID]
}

// Reset clears all usage tracking (for testing)
func (t *UsageTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.uses = make(map[[TokenIDLength]byte]int)
}

// LoadState loads usage state from a map (for persistence)
func (t *UsageTracker) LoadState(state map[string]int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.uses = make(map[[TokenIDLength]byte]int)
	for idHex, count := range state {
		var id [TokenIDLength]byte
		// Parse hex string using encoding/hex
		decoded, err := hex.DecodeString(idHex)
		if err != nil || len(decoded) != TokenIDLength {
			continue // Skip invalid entries
		}
		copy(id[:], decoded)
		t.uses[id] = count
	}
}

// SaveState exports usage state to a map (for persistence)
func (t *UsageTracker) SaveState() map[string]int {
	t.mu.Lock()
	defer t.mu.Unlock()

	state := make(map[string]int)
	for id, count := range t.uses {
		state[fmt.Sprintf("%x", id)] = count
	}
	return state
}
