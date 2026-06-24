package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"
)

// cryptoRandRead reads random bytes (can be mocked for testing)
var cryptoRandRead = func(b []byte) (int, error) {
	return io.ReadFull(rand.Reader, b)
}

const (
	// DefaultMaxClockSkew is the maximum allowed clock difference
	DefaultMaxClockSkew = 5 * time.Minute

	// DefaultMaxAge is the maximum age of an attestation claim
	DefaultMaxAge = 24 * time.Hour
)

// Verifier validates attestation claims
type Verifier struct {
	mu            sync.RWMutex
	trustedHashes map[string]string      // binary hash -> version string
	consumed      map[[16]byte]time.Time // nonces already used (replay defense)
	tpmPolicies   map[string]*TPMPolicy  // nodeID -> trusted TPM attestation policy
	maxClockSkew  time.Duration
	maxAge        time.Duration
	requireConfig bool // Require config hash
}

// VerifierConfig configures the verifier
type VerifierConfig struct {
	MaxClockSkew  time.Duration
	MaxAge        time.Duration
	RequireConfig bool
}

// NewVerifier creates a new attestation verifier
func NewVerifier(cfg *VerifierConfig) *Verifier {
	v := &Verifier{
		trustedHashes: make(map[string]string),
		consumed:      make(map[[16]byte]time.Time),
		tpmPolicies:   make(map[string]*TPMPolicy),
		maxClockSkew:  DefaultMaxClockSkew,
		maxAge:        DefaultMaxAge,
	}

	if cfg != nil {
		if cfg.MaxClockSkew > 0 {
			v.maxClockSkew = cfg.MaxClockSkew
		}
		if cfg.MaxAge > 0 {
			v.maxAge = cfg.MaxAge
		}
		v.requireConfig = cfg.RequireConfig
	}

	return v
}

// AddTrustedHash adds a trusted binary hash
func (v *Verifier) AddTrustedHash(hash, version string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.trustedHashes[hash] = version
}

// AddTrustedHashBytes adds a trusted binary hash from bytes
func (v *Verifier) AddTrustedHashBytes(hash [32]byte, version string) {
	v.AddTrustedHash(hex.EncodeToString(hash[:]), version)
}

// RemoveTrustedHash removes a trusted binary hash
func (v *Verifier) RemoveTrustedHash(hash string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.trustedHashes, hash)
}

// ListTrustedHashes returns all trusted hashes
func (v *Verifier) ListTrustedHashes() map[string]string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	result := make(map[string]string, len(v.trustedHashes))
	for k, version := range v.trustedHashes {
		result[k] = version
	}
	return result
}

// IsTrusted checks if a binary hash is trusted
func (v *Verifier) IsTrusted(hash string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	version, ok := v.trustedHashes[hash]
	return version, ok
}

// Verify validates an attestation claim
func (v *Verifier) Verify(claim *Claim, publicKey ed25519.PublicKey, expectedNonce [16]byte) *Result {
	result := &Result{
		Valid:      true,
		NodeID:     claim.NodeID,
		Timestamp:  claim.Timestamp,
		SystemInfo: claim.SystemInfo,
	}

	// 1. Verify signature
	if !claim.Verify(publicKey) {
		result.AddIssue("invalid signature")
		return result
	}

	// 2. Verify nonce matches
	if claim.Nonce != expectedNonce {
		result.AddIssue("nonce mismatch")
		return result
	}

	// 2b. Replay defense: a (signed, matching) nonce may be accepted only once.
	// Without this, a captured valid claim replays freely within maxAge.
	v.mu.Lock()
	now2 := time.Now()
	for n, used := range v.consumed {
		if now2.Sub(used) > v.maxAge {
			delete(v.consumed, n)
		}
	}
	if _, used := v.consumed[claim.Nonce]; used {
		v.mu.Unlock()
		result.AddIssue("nonce already used (replay)")
		return result
	}
	v.consumed[claim.Nonce] = now2
	v.mu.Unlock()

	// 3. Verify timestamp is fresh
	now := time.Now().UTC()
	if claim.Timestamp.After(now.Add(v.maxClockSkew)) {
		result.AddIssue(fmt.Sprintf("timestamp in future: %v", claim.Timestamp))
	}
	if claim.Timestamp.Before(now.Add(-v.maxAge)) {
		result.AddIssue(fmt.Sprintf("timestamp too old: %v", claim.Timestamp))
	}

	// 4. Verify binary hash is trusted
	binaryHashHex := claim.BinaryHashHex()
	version, trusted := v.IsTrusted(binaryHashHex)
	if !trusted {
		result.AddIssue(fmt.Sprintf("untrusted binary hash: %s", binaryHashHex[:16]))
	} else {
		result.BinaryVersion = version
	}

	// 5. Verify config hash is present if required
	if v.requireConfig {
		var zeroHash [32]byte
		if claim.ConfigHash == zeroHash {
			result.AddIssue("config hash required but not provided")
		}
	}

	// 6. Type-specific verification
	switch claim.Type {
	case TypeSoftware:
		// Software attestation only verifies binary hash (done above)
	case TypeTPM:
		if len(claim.TPMQuote) == 0 {
			result.AddIssue("TPM quote missing for TPM attestation")
		} else if err := v.verifyTPMQuote(claim); err != nil {
			// Fail closed: any error (no registered policy, bad signature, stale
			// nonce, or PCR mismatch) rejects the claim. An unverified quote must
			// never inherit the trust of hardware attestation.
			result.AddIssue("TPM quote verification failed: " + err.Error())
		}
	case TypeSGX:
		result.AddIssue("SGX attestation not implemented")
	}

	return result
}

// VerifySimple does basic verification without trusted hash checking
func (v *Verifier) VerifySimple(claim *Claim, publicKey ed25519.PublicKey) *Result {
	result := &Result{
		Valid:      true,
		NodeID:     claim.NodeID,
		Timestamp:  claim.Timestamp,
		SystemInfo: claim.SystemInfo,
	}

	// Verify signature only
	if !claim.Verify(publicKey) {
		result.AddIssue("invalid signature")
	}

	return result
}

// Challenge generates a random nonce for attestation
func Challenge() ([16]byte, error) {
	var nonce [16]byte
	if _, err := cryptoRandRead(nonce[:]); err != nil {
		return nonce, err
	}
	return nonce, nil
}
