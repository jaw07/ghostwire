// Package keys provides cryptographic key generation and management for GHOSTWIRE.
// It handles Ed25519 keys for certificate signing and their conversion to X25519
// for WireGuard compatibility.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrInvalidSeedLength is returned when a seed has incorrect length
	ErrInvalidSeedLength = errors.New("seed must be exactly 32 bytes")
	// ErrInvalidKeyLength is returned when a key has incorrect length
	ErrInvalidKeyLength = errors.New("invalid key length")
)

// KeyPair holds both Ed25519 (for signing/certificates) and X25519 (for WireGuard) keys.
// Both key types are derived from the same seed, ensuring a single identity.
type KeyPair struct {
	// Ed25519 keys for certificate signing
	Ed25519PrivateKey ed25519.PrivateKey
	Ed25519PublicKey  ed25519.PublicKey

	// X25519 keys for WireGuard
	X25519PrivateKey [32]byte
	X25519PublicKey  [32]byte

	// Original seed (for secure storage/recovery)
	seed [32]byte
}

// Generate creates a new cryptographically secure keypair.
// The keypair includes both Ed25519 (for certificates) and X25519 (for WireGuard) keys,
// derived from the same random seed.
func Generate() (*KeyPair, error) {
	var seed [32]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}
	return FromSeed(seed[:])
}

// FromSeed recreates a keypair from a 32-byte seed.
// This allows recovery of keys from secure storage.
func FromSeed(seed []byte) (*KeyPair, error) {
	if len(seed) != 32 {
		return nil, ErrInvalidSeedLength
	}

	kp := &KeyPair{}
	copy(kp.seed[:], seed)

	// Generate Ed25519 keypair from seed
	kp.Ed25519PrivateKey = ed25519.NewKeyFromSeed(seed)
	kp.Ed25519PublicKey = kp.Ed25519PrivateKey.Public().(ed25519.PublicKey)

	// Derive X25519 keys from the same seed
	x25519Priv, x25519Pub, err := Ed25519SeedToX25519(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to derive X25519 keys: %w", err)
	}
	kp.X25519PrivateKey = x25519Priv
	kp.X25519PublicKey = x25519Pub

	return kp, nil
}

// Seed returns a copy of the keypair's seed.
// The seed should be stored securely and can be used to recreate the keypair.
func (kp *KeyPair) Seed() []byte {
	seedCopy := make([]byte, 32)
	copy(seedCopy, kp.seed[:])
	return seedCopy
}

// WireGuardPrivateKeyBase64 returns the WireGuard private key in base64 format,
// suitable for use in WireGuard configuration.
func (kp *KeyPair) WireGuardPrivateKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.X25519PrivateKey[:])
}

// WireGuardPublicKeyBase64 returns the WireGuard public key in base64 format,
// suitable for sharing with peers.
func (kp *KeyPair) WireGuardPublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.X25519PublicKey[:])
}

// Wipe securely zeros all key material in memory.
// Call this when the keypair is no longer needed.
func (kp *KeyPair) Wipe() {
	WipeBytes(kp.seed[:])
	WipeBytes(kp.Ed25519PrivateKey)
	WipeBytes(kp.Ed25519PublicKey)
	WipeBytes(kp.X25519PrivateKey[:])
	WipeBytes(kp.X25519PublicKey[:])
}

// ParseWireGuardPublicKey parses a base64-encoded WireGuard public key.
func ParseWireGuardPublicKey(encoded string) ([32]byte, error) {
	var key [32]byte
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return key, fmt.Errorf("invalid base64: %w", err)
	}
	if len(decoded) != 32 {
		return key, ErrInvalidKeyLength
	}
	copy(key[:], decoded)
	return key, nil
}

// ParseWireGuardPrivateKey parses a base64-encoded WireGuard private key.
func ParseWireGuardPrivateKey(encoded string) ([32]byte, error) {
	return ParseWireGuardPublicKey(encoded) // Same format
}
