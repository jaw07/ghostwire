package token

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestGenerateAndValidateToken(t *testing.T) {
	// Generate keypair for testing
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	meshID := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	generator := NewGenerator(privKey, meshID)
	validator := NewValidator(pubKey, meshID)

	// Generate token
	tokenStr, token, err := generator.Generate(&GeneratorOptions{
		Roles:         []string{"operator", "relay"},
		Expiry:        1 * time.Hour,
		MaxUses:       5,
		Compartment:   "alpha",
		SuggestedName: "new-node",
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if tokenStr == "" {
		t.Error("Token string should not be empty")
	}

	if !hasPrefix(tokenStr, TokenPrefix) {
		t.Errorf("Token should start with %s", TokenPrefix)
	}

	if token.Version != TokenVersion {
		t.Errorf("Token version should be %d, got %d", TokenVersion, token.Version)
	}

	if len(token.AllowedRoles) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(token.AllowedRoles))
	}

	if token.Compartment != "alpha" {
		t.Errorf("Compartment should be alpha, got %s", token.Compartment)
	}

	// Validate token
	validated, err := validator.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if validated.ID != token.ID {
		t.Error("Token IDs should match")
	}

	if !validated.HasRole("operator") {
		t.Error("Validated token should have operator role")
	}

	if !validated.HasRole("relay") {
		t.Error("Validated token should have relay role")
	}

	if validated.HasRole("admin") {
		t.Error("Validated token should not have admin role")
	}

	if validated.SuggestedName != "new-node" {
		t.Errorf("Suggested name should be new-node, got %s", validated.SuggestedName)
	}
}

func TestTokenExpiry(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	meshID := [32]byte{1, 2, 3}

	generator := NewGenerator(privKey, meshID)
	validator := NewValidator(pubKey, meshID)

	// Generate token that expires immediately
	tokenStr, _, err := generator.Generate(&GeneratorOptions{
		Roles:  []string{"operator"},
		Expiry: -1 * time.Hour, // Already expired
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	_, err = validator.Validate(tokenStr)
	if err != ErrTokenExpired {
		t.Errorf("Expected ErrTokenExpired, got %v", err)
	}
}

func TestTokenUsageLimits(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	meshID := [32]byte{1, 2, 3}

	generator := NewGenerator(privKey, meshID)
	validator := NewValidator(pubKey, meshID)

	// Generate token with max 2 uses
	tokenStr, _, err := generator.Generate(&GeneratorOptions{
		Roles:   []string{"operator"},
		Expiry:  1 * time.Hour,
		MaxUses: 2,
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// First use should succeed
	_, err = validator.Validate(tokenStr)
	if err != nil {
		t.Fatalf("First validation failed: %v", err)
	}

	// Second use should succeed
	_, err = validator.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Second validation failed: %v", err)
	}

	// Third use should fail
	_, err = validator.Validate(tokenStr)
	if err != ErrTokenUsageExceeded {
		t.Errorf("Expected ErrTokenUsageExceeded, got %v", err)
	}
}

func TestTokenMeshIDMismatch(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	meshID1 := [32]byte{1, 2, 3}
	meshID2 := [32]byte{4, 5, 6}

	generator := NewGenerator(privKey, meshID1)
	validator := NewValidator(pubKey, meshID2) // Different mesh ID

	tokenStr, _, err := generator.Generate(nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	_, err = validator.Validate(tokenStr)
	if err != ErrMeshIDMismatch {
		t.Errorf("Expected ErrMeshIDMismatch, got %v", err)
	}
}

func TestTokenInvalidSignature(t *testing.T) {
	_, privKey1, _ := ed25519.GenerateKey(nil)
	pubKey2, _, _ := ed25519.GenerateKey(nil)
	meshID := [32]byte{1, 2, 3}

	generator := NewGenerator(privKey1, meshID)
	validator := NewValidator(pubKey2, meshID) // Different key

	tokenStr, _, err := generator.Generate(nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	_, err = validator.Validate(tokenStr)
	if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got %v", err)
	}
}

func TestTokenInvalidFormat(t *testing.T) {
	pubKey, _, _ := ed25519.GenerateKey(nil)
	meshID := [32]byte{1, 2, 3}

	validator := NewValidator(pubKey, meshID)

	// Test various invalid formats
	invalidTokens := []string{
		"",
		"not_a_token",
		"gw_enroll_",                          // Empty payload
		"gw_enroll_invalid_base64!@#$",        // Invalid base64
		"gw_enroll_dG9vX3Nob3J0",              // Too short
		"wrong_prefix_" + "dGVzdA",            // Wrong prefix
	}

	for _, invalidToken := range invalidTokens {
		_, err := validator.Validate(invalidToken)
		if err == nil {
			t.Errorf("Validation should fail for: %s", invalidToken)
		}
	}
}

func TestValidateWithoutUsage(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	meshID := [32]byte{1, 2, 3}

	generator := NewGenerator(privKey, meshID)
	validator := NewValidator(pubKey, meshID)

	// Generate token with max 1 use
	tokenStr, _, err := generator.Generate(&GeneratorOptions{
		Roles:   []string{"operator"},
		Expiry:  1 * time.Hour,
		MaxUses: 1,
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// ValidateWithoutUsage should not count toward limit
	for i := 0; i < 5; i++ {
		_, err = validator.ValidateWithoutUsage(tokenStr)
		if err != nil {
			t.Fatalf("ValidateWithoutUsage failed on iteration %d: %v", i, err)
		}
	}

	// Now do actual validation - should succeed once
	_, err = validator.Validate(tokenStr)
	if err != nil {
		t.Fatalf("First Validate should succeed: %v", err)
	}

	// Second actual validation should fail
	_, err = validator.Validate(tokenStr)
	if err != ErrTokenUsageExceeded {
		t.Errorf("Expected ErrTokenUsageExceeded, got %v", err)
	}
}

func TestUsageTracker(t *testing.T) {
	tracker := NewUsageTracker()

	tokenID := [TokenIDLength]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	maxUses := 3

	// Should succeed for first 3 uses
	for i := 0; i < maxUses; i++ {
		if !tracker.IncrementAndCheck(tokenID, maxUses) {
			t.Errorf("Use %d should succeed", i+1)
		}
	}

	// Should fail for 4th use
	if tracker.IncrementAndCheck(tokenID, maxUses) {
		t.Error("4th use should fail")
	}

	// Check count
	if tracker.GetCount(tokenID) != 3 {
		t.Errorf("Expected count 3, got %d", tracker.GetCount(tokenID))
	}

	// Test save/load state
	state := tracker.SaveState()
	if len(state) != 1 {
		t.Errorf("Expected 1 entry in state, got %d", len(state))
	}

	newTracker := NewUsageTracker()
	newTracker.LoadState(state)

	// Should still be at limit
	if newTracker.IncrementAndCheck(tokenID, maxUses) {
		t.Error("Should still be at limit after loading state")
	}
}

func TestTokenIDString(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(nil)
	meshID := [32]byte{1, 2, 3}

	generator := NewGenerator(privKey, meshID)

	_, token, err := generator.Generate(nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	idStr := token.IDString()
	if len(idStr) != TokenIDLength*2 { // Hex encoding doubles length
		t.Errorf("ID string should be %d chars, got %d", TokenIDLength*2, len(idStr))
	}
}

func TestTokenTimeUntilExpiry(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(nil)
	meshID := [32]byte{1, 2, 3}

	generator := NewGenerator(privKey, meshID)

	_, token, err := generator.Generate(&GeneratorOptions{
		Roles:  []string{"operator"},
		Expiry: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	remaining := token.TimeUntilExpiry()
	if remaining < 59*time.Minute || remaining > 61*time.Minute {
		t.Errorf("Time until expiry should be ~1 hour, got %v", remaining)
	}

	if token.IsExpired() {
		t.Error("Token should not be expired")
	}

	if !token.IsValid() {
		t.Error("Token should be valid")
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
