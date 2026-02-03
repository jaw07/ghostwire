// Package token implements enrollment token generation and validation for GHOSTWIRE.
// Tokens are cryptographically signed, time-limited, and role-scoped credentials
// used to enroll new nodes into the mesh.
package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// TokenPrefix identifies GHOSTWIRE enrollment tokens
	TokenPrefix = "gw_enroll_"

	// TokenVersion is the current token format version
	TokenVersion = 1

	// DefaultExpiry is the default token expiration time
	DefaultExpiry = 1 * time.Hour

	// DefaultMaxUses is the default maximum number of token uses
	DefaultMaxUses = 1

	// TokenIDLength is the length of the random token ID
	TokenIDLength = 16
)

var (
	// ErrInvalidTokenFormat indicates the token string format is invalid
	ErrInvalidTokenFormat = errors.New("invalid token format")

	// ErrTokenExpired indicates the token has expired
	ErrTokenExpired = errors.New("token has expired")

	// ErrTokenNotYetValid indicates the token is not yet valid
	ErrTokenNotYetValid = errors.New("token is not yet valid")

	// ErrTokenUsageExceeded indicates the token has been used too many times
	ErrTokenUsageExceeded = errors.New("token usage limit exceeded")

	// ErrInvalidSignature indicates the token signature is invalid
	ErrInvalidSignature = errors.New("invalid token signature")

	// ErrMeshIDMismatch indicates the token is for a different mesh
	ErrMeshIDMismatch = errors.New("token mesh ID does not match")
)

// Token represents a parsed enrollment token
type Token struct {
	// Unique identifier for tracking and revocation
	ID [TokenIDLength]byte

	// Version of the token format
	Version int

	// Allowed roles for the enrolling node
	AllowedRoles []string

	// Optional compartment restriction
	Compartment string

	// Optional suggested node name
	SuggestedName string

	// Temporal constraints
	NotBefore time.Time
	NotAfter  time.Time

	// Usage constraints
	MaxUses int

	// Mesh identifier
	MeshID [32]byte

	// Raw signature for verification
	signature []byte
}

// TokenPayload is the serialized token data (before signing)
type TokenPayload struct {
	Version       byte
	TokenID       [TokenIDLength]byte
	MeshID        [32]byte
	NotBefore     int64 // Unix timestamp
	NotAfter      int64 // Unix timestamp
	MaxUses       uint16
	RolesCount    uint8
	Roles         []string
	Compartment   string
	SuggestedName string
}

// Encode serializes the token payload for signing
func (p *TokenPayload) Encode() []byte {
	var buf []byte

	// Fixed-size fields
	buf = append(buf, p.Version)
	buf = append(buf, p.TokenID[:]...)
	buf = append(buf, p.MeshID[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(p.NotBefore))
	buf = binary.BigEndian.AppendUint64(buf, uint64(p.NotAfter))
	buf = binary.BigEndian.AppendUint16(buf, p.MaxUses)

	// Roles
	buf = append(buf, byte(len(p.Roles)))
	for _, role := range p.Roles {
		buf = append(buf, byte(len(role)))
		buf = append(buf, []byte(role)...)
	}

	// Compartment (length-prefixed)
	buf = append(buf, byte(len(p.Compartment)))
	buf = append(buf, []byte(p.Compartment)...)

	// Suggested name (length-prefixed)
	buf = append(buf, byte(len(p.SuggestedName)))
	buf = append(buf, []byte(p.SuggestedName)...)

	return buf
}

// Decode deserializes a token payload
func DecodePayload(data []byte) (*TokenPayload, error) {
	if len(data) < 1+TokenIDLength+32+8+8+2+1 {
		return nil, ErrInvalidTokenFormat
	}

	p := &TokenPayload{}
	offset := 0

	p.Version = data[offset]
	offset++

	copy(p.TokenID[:], data[offset:offset+TokenIDLength])
	offset += TokenIDLength

	copy(p.MeshID[:], data[offset:offset+32])
	offset += 32

	p.NotBefore = int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	p.NotAfter = int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	p.MaxUses = binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// Roles
	rolesCount := int(data[offset])
	offset++

	p.Roles = make([]string, rolesCount)
	for i := 0; i < rolesCount; i++ {
		if offset >= len(data) {
			return nil, ErrInvalidTokenFormat
		}
		roleLen := int(data[offset])
		offset++
		if offset+roleLen > len(data) {
			return nil, ErrInvalidTokenFormat
		}
		p.Roles[i] = string(data[offset : offset+roleLen])
		offset += roleLen
	}

	// Compartment
	if offset >= len(data) {
		return nil, ErrInvalidTokenFormat
	}
	compLen := int(data[offset])
	offset++
	if offset+compLen > len(data) {
		return nil, ErrInvalidTokenFormat
	}
	p.Compartment = string(data[offset : offset+compLen])
	offset += compLen

	// Suggested name
	if offset >= len(data) {
		return nil, ErrInvalidTokenFormat
	}
	nameLen := int(data[offset])
	offset++
	if offset+nameLen > len(data) {
		return nil, ErrInvalidTokenFormat
	}
	p.SuggestedName = string(data[offset : offset+nameLen])

	return p, nil
}

// IDString returns the token ID as a hex string
func (t *Token) IDString() string {
	return fmt.Sprintf("%x", t.ID[:])
}

// IsExpired returns true if the token has expired
func (t *Token) IsExpired() bool {
	return time.Now().After(t.NotAfter)
}

// IsValid returns true if the token is currently valid (time-wise)
func (t *Token) IsValid() bool {
	now := time.Now()
	return now.After(t.NotBefore) && now.Before(t.NotAfter)
}

// TimeUntilExpiry returns the duration until the token expires
func (t *Token) TimeUntilExpiry() time.Duration {
	return time.Until(t.NotAfter)
}

// HasRole checks if the token allows a specific role
func (t *Token) HasRole(role string) bool {
	for _, r := range t.AllowedRoles {
		if r == role {
			return true
		}
	}
	return false
}

// ComputeTokenHash returns a hash of the token for logging (without revealing the full token)
func (t *Token) ComputeTokenHash() string {
	h := sha256.Sum256(t.ID[:])
	return fmt.Sprintf("%x", h[:8])
}

// FormatToken creates the final token string from payload and signature
func FormatToken(payloadBytes, signature []byte) string {
	// Combine payload and signature
	combined := append(payloadBytes, signature...)

	// Base64 URL encode
	encoded := base64.RawURLEncoding.EncodeToString(combined)

	return TokenPrefix + encoded
}

// ParseTokenString parses a token string into its components
func ParseTokenString(tokenStr string) (payloadBytes, signature []byte, err error) {
	if !strings.HasPrefix(tokenStr, TokenPrefix) {
		return nil, nil, ErrInvalidTokenFormat
	}

	encoded := strings.TrimPrefix(tokenStr, TokenPrefix)
	combined, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid base64", ErrInvalidTokenFormat)
	}

	// Signature is the last 64 bytes (Ed25519 signature size)
	if len(combined) < ed25519.SignatureSize+1 {
		return nil, nil, fmt.Errorf("%w: too short", ErrInvalidTokenFormat)
	}

	sigStart := len(combined) - ed25519.SignatureSize
	payloadBytes = combined[:sigStart]
	signature = combined[sigStart:]

	return payloadBytes, signature, nil
}

// GenerateTokenID creates a random token ID
func GenerateTokenID() ([TokenIDLength]byte, error) {
	var id [TokenIDLength]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	return id, nil
}
