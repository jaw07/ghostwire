package attestation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

func TestGatherSystemInfo(t *testing.T) {
	info := GatherSystemInfo()

	if info.OS == "" {
		t.Error("OS should not be empty")
	}
	if info.Arch == "" {
		t.Error("Arch should not be empty")
	}
	if info.GoVersion == "" {
		t.Error("GoVersion should not be empty")
	}
	if info.NumCPU == 0 {
		t.Error("NumCPU should not be 0")
	}
}

func TestSystemInfoHash(t *testing.T) {
	info1 := SystemInfo{
		OS:       "linux",
		Arch:     "amd64",
		Hostname: "test",
	}
	info2 := SystemInfo{
		OS:       "linux",
		Arch:     "amd64",
		Hostname: "test",
	}
	info3 := SystemInfo{
		OS:       "darwin",
		Arch:     "amd64",
		Hostname: "test",
	}

	hash1 := info1.Hash()
	hash2 := info2.Hash()
	hash3 := info3.Hash()

	if hash1 != hash2 {
		t.Error("Same info should produce same hash")
	}
	if hash1 == hash3 {
		t.Error("Different info should produce different hash")
	}
}

func TestNewClaim(t *testing.T) {
	var nonce [16]byte
	copy(nonce[:], "test-nonce-12345")

	claim, err := NewClaim("node-1", nonce)
	if err != nil {
		t.Fatalf("NewClaim error: %v", err)
	}

	if claim.Type != TypeSoftware {
		t.Errorf("Type = %v, want %v", claim.Type, TypeSoftware)
	}
	if claim.NodeID != "node-1" {
		t.Errorf("NodeID = %q, want %q", claim.NodeID, "node-1")
	}
	if claim.Nonce != nonce {
		t.Error("Nonce mismatch")
	}
	if claim.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}

func TestClaimSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	var nonce [16]byte
	copy(nonce[:], "test-nonce-12345")

	claim, err := NewClaim("node-1", nonce)
	if err != nil {
		t.Fatalf("NewClaim error: %v", err)
	}

	// Sign
	if err := claim.Sign(priv); err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	// Verify
	if !claim.Verify(pub) {
		t.Error("Verify should succeed")
	}

	// Modify and verify should fail
	claim.NodeID = "modified"
	if claim.Verify(pub) {
		t.Error("Verify should fail after modification")
	}
}

func TestClaimConfigHash(t *testing.T) {
	var nonce [16]byte
	claim, _ := NewClaim("node-1", nonce)

	configData := []byte("test config data")
	hash := ComputeConfigHash(configData)
	claim.SetConfigHash(hash)

	expected := sha256.Sum256(configData)
	if claim.ConfigHash != expected {
		t.Error("ConfigHash mismatch")
	}
}

func TestVerifier(t *testing.T) {
	v := NewVerifier(&VerifierConfig{
		MaxClockSkew: 5 * time.Minute,
		MaxAge:       1 * time.Hour,
	})

	// Add trusted hash
	testHash := sha256.Sum256([]byte("test binary"))
	v.AddTrustedHashBytes(testHash, "v1.0.0")

	// Check trusted
	hashHex := v.ListTrustedHashes()
	var hashKey string
	for k := range hashHex {
		hashKey = k
		break
	}
	version, ok := v.IsTrusted(hashKey)
	if ok {
		t.Logf("Found version: %s", version)
	}

	// List trusted
	hashes := v.ListTrustedHashes()
	if len(hashes) != 1 {
		t.Errorf("ListTrustedHashes len = %d, want 1", len(hashes))
	}

	// Remove trusted
	v.RemoveTrustedHash("invalid")
	hashes = v.ListTrustedHashes()
	if len(hashes) != 1 {
		t.Error("Remove invalid hash should not affect list")
	}
}

func TestVerifierVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	v := NewVerifier(&VerifierConfig{
		MaxClockSkew: 5 * time.Minute,
		MaxAge:       1 * time.Hour,
	})

	nonce, err := Challenge()
	if err != nil {
		t.Fatalf("Challenge error: %v", err)
	}

	claim, err := NewClaim("node-1", nonce)
	if err != nil {
		t.Fatalf("NewClaim error: %v", err)
	}

	// Add claim's binary hash as trusted
	v.AddTrustedHashBytes(claim.BinaryHash, "v1.0.0")

	// Sign claim
	claim.Sign(priv)

	// Verify
	result := v.Verify(claim, pub, nonce)
	if !result.Valid {
		t.Errorf("Verify failed: %v", result.Issues)
	}
	if result.BinaryVersion != "v1.0.0" {
		t.Errorf("BinaryVersion = %q, want %q", result.BinaryVersion, "v1.0.0")
	}
}

func TestVerifierTPMFailsClosed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	v := NewVerifier(&VerifierConfig{MaxClockSkew: 5 * time.Minute, MaxAge: time.Hour})

	nonce, _ := Challenge()
	claim, _ := NewClaim("node-1", nonce)
	claim.Type = TypeTPM
	// A non-empty quote must NOT be accepted just for being present: without a
	// verification path it cannot be trusted.
	claim.TPMQuote = []byte("not-a-real-quote")
	v.AddTrustedHashBytes(claim.BinaryHash, "v1.0.0")
	claim.Sign(priv)

	result := v.Verify(claim, pub, nonce)
	if result.Valid {
		t.Error("TPM claim with no registered policy should be rejected (fail closed)")
	}
	found := false
	for _, iss := range result.Issues {
		if strings.Contains(iss, "TPM quote verification failed") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'verification failed' issue, got %v", result.Issues)
	}
}

func TestVerifierNonceMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	v := NewVerifier(nil)

	var nonce1, nonce2 [16]byte
	copy(nonce1[:], "nonce-1")
	copy(nonce2[:], "nonce-2")

	claim, _ := NewClaim("node-1", nonce1)
	v.AddTrustedHashBytes(claim.BinaryHash, "v1.0.0")
	claim.Sign(priv)

	// Verify with wrong nonce
	result := v.Verify(claim, pub, nonce2)
	if result.Valid {
		t.Error("Should fail with nonce mismatch")
	}

	found := false
	for _, issue := range result.Issues {
		if issue == "nonce mismatch" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected 'nonce mismatch' in issues: %v", result.Issues)
	}
}

func TestVerifierUntrustedHash(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	v := NewVerifier(nil)
	// Don't add any trusted hashes

	nonce, _ := Challenge()
	claim, _ := NewClaim("node-1", nonce)
	claim.Sign(priv)

	result := v.Verify(claim, pub, nonce)
	if result.Valid {
		t.Error("Should fail with untrusted hash")
	}

	found := false
	for _, issue := range result.Issues {
		if len(issue) > 20 && issue[:20] == "untrusted binary has" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected untrusted hash issue: %v", result.Issues)
	}
}

func TestVerifierExpiredTimestamp(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	v := NewVerifier(&VerifierConfig{
		MaxAge: 1 * time.Hour,
	})

	nonce, _ := Challenge()
	claim, _ := NewClaim("node-1", nonce)
	v.AddTrustedHashBytes(claim.BinaryHash, "v1.0.0")

	// Set old timestamp
	claim.Timestamp = time.Now().Add(-2 * time.Hour)
	claim.Sign(priv)

	result := v.Verify(claim, pub, nonce)
	if result.Valid {
		t.Error("Should fail with old timestamp")
	}
}

func TestVerifySimple(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	v := NewVerifier(nil)

	nonce, _ := Challenge()
	claim, _ := NewClaim("node-1", nonce)
	claim.Sign(priv)

	// Simple verify only checks signature
	result := v.VerifySimple(claim, pub)
	if !result.Valid {
		t.Errorf("VerifySimple should pass: %v", result.Issues)
	}
}

func TestChallenge(t *testing.T) {
	nonce1, err := Challenge()
	if err != nil {
		t.Fatalf("Challenge error: %v", err)
	}

	nonce2, err := Challenge()
	if err != nil {
		t.Fatalf("Challenge error: %v", err)
	}

	// Should be different
	if nonce1 == nonce2 {
		t.Error("Nonces should be different")
	}

	// Should not be all zeros
	var zero [16]byte
	if nonce1 == zero {
		t.Error("Nonce should not be zero")
	}
}

func TestTypeString(t *testing.T) {
	tests := []struct {
		t        Type
		expected string
	}{
		{TypeSoftware, "software"},
		{TypeTPM, "tpm"},
		{TypeSGX, "sgx"},
		{Type(99), "unknown(99)"},
	}

	for _, tt := range tests {
		if got := tt.t.String(); got != tt.expected {
			t.Errorf("Type(%d).String() = %q, want %q", tt.t, got, tt.expected)
		}
	}
}

func TestResultAddIssue(t *testing.T) {
	result := &Result{Valid: true}

	result.AddIssue("test issue")

	if result.Valid {
		t.Error("Valid should be false after AddIssue")
	}
	if len(result.Issues) != 1 {
		t.Errorf("Issues len = %d, want 1", len(result.Issues))
	}
	if result.Issues[0] != "test issue" {
		t.Errorf("Issues[0] = %q, want %q", result.Issues[0], "test issue")
	}
}
