package token

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

// GeneratorOptions configures token generation
type GeneratorOptions struct {
	// Allowed roles for nodes using this token
	Roles []string

	// Token expiration duration
	Expiry time.Duration

	// Maximum number of uses (0 = unlimited)
	MaxUses int

	// Optional compartment restriction
	Compartment string

	// Optional suggested node name
	SuggestedName string
}

// DefaultGeneratorOptions returns sensible defaults for token generation
func DefaultGeneratorOptions() *GeneratorOptions {
	return &GeneratorOptions{
		Roles:   []string{"operator"},
		Expiry:  DefaultExpiry,
		MaxUses: DefaultMaxUses,
	}
}

// Generator creates enrollment tokens
type Generator struct {
	privateKey ed25519.PrivateKey
	meshID     [32]byte
}

// NewGenerator creates a token generator with the given signing key and mesh ID
func NewGenerator(privateKey ed25519.PrivateKey, meshID [32]byte) *Generator {
	return &Generator{
		privateKey: privateKey,
		meshID:     meshID,
	}
}

// Generate creates a new enrollment token
func (g *Generator) Generate(opts *GeneratorOptions) (string, *Token, error) {
	if opts == nil {
		opts = DefaultGeneratorOptions()
	}

	// Apply defaults
	if len(opts.Roles) == 0 {
		opts.Roles = []string{"operator"}
	}
	if opts.Expiry == 0 {
		opts.Expiry = DefaultExpiry
	}
	if opts.MaxUses == 0 {
		opts.MaxUses = DefaultMaxUses
	}

	// Generate random token ID
	tokenID, err := GenerateTokenID()
	if err != nil {
		return "", nil, fmt.Errorf("generate token ID: %w", err)
	}

	now := time.Now()
	payload := &TokenPayload{
		Version:       TokenVersion,
		TokenID:       tokenID,
		MeshID:        g.meshID,
		NotBefore:     now.Unix(),
		NotAfter:      now.Add(opts.Expiry).Unix(),
		MaxUses:       uint16(opts.MaxUses),
		Roles:         opts.Roles,
		Compartment:   opts.Compartment,
		SuggestedName: opts.SuggestedName,
	}

	// Serialize payload
	payloadBytes := payload.Encode()

	// Sign with admin key
	signature := ed25519.Sign(g.privateKey, payloadBytes)

	// Create token string
	tokenStr := FormatToken(payloadBytes, signature)

	// Create Token struct
	token := &Token{
		ID:            tokenID,
		Version:       TokenVersion,
		AllowedRoles:  opts.Roles,
		Compartment:   opts.Compartment,
		SuggestedName: opts.SuggestedName,
		NotBefore:     now,
		NotAfter:      now.Add(opts.Expiry),
		MaxUses:       opts.MaxUses,
		MeshID:        g.meshID,
		signature:     signature,
	}

	return tokenStr, token, nil
}

// GenerateWithDefaults creates a token with default options
func (g *Generator) GenerateWithDefaults() (string, *Token, error) {
	return g.Generate(nil)
}

// GenerateForRole creates a token for a specific role
func (g *Generator) GenerateForRole(role string, expiry time.Duration) (string, *Token, error) {
	return g.Generate(&GeneratorOptions{
		Roles:  []string{role},
		Expiry: expiry,
	})
}

// GenerateMultiUse creates a token that can be used multiple times
func (g *Generator) GenerateMultiUse(roles []string, expiry time.Duration, maxUses int) (string, *Token, error) {
	return g.Generate(&GeneratorOptions{
		Roles:   roles,
		Expiry:  expiry,
		MaxUses: maxUses,
	})
}
