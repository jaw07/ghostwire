package pqc

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestPQCKeyExchangeIntegration(t *testing.T) {
	// Simulate Alice and Bob performing hybrid key exchange

	// Alice generates a keypair
	aliceKP, err := Generate()
	if err != nil {
		t.Fatalf("Alice Generate error: %v", err)
	}
	t.Logf("Alice generated keypair (X25519 pub: %x...)", aliceKP.X25519Public[:8])

	// Bob generates a keypair
	bobKP, err := Generate()
	if err != nil {
		t.Fatalf("Bob Generate error: %v", err)
	}
	t.Logf("Bob generated keypair (X25519 pub: %x...)", bobKP.X25519Public[:8])

	// Alice gets Bob's public key
	bobPub := bobKP.Public()

	// Alice encapsulates a secret for Bob
	aliceShared, encap, err := Encapsulate(bobPub)
	if err != nil {
		t.Fatalf("Alice Encapsulate error: %v", err)
	}
	aliceHash := sha256.Sum256(aliceShared.Combined[:])
	t.Logf("Alice encapsulated secret (shared key hash: %x...)", aliceHash[:8])
	t.Logf("Encapsulation size: X25519=%d bytes, Kyber=%d bytes", len(encap.X25519Ephemeral), len(encap.KyberCiphertext))

	// Bob decapsulates to get the same shared secret
	bobShared, err := bobKP.Decapsulate(encap)
	if err != nil {
		t.Fatalf("Bob Decapsulate error: %v", err)
	}
	bobHash := sha256.Sum256(bobShared.Combined[:])
	t.Logf("Bob decapsulated secret (shared key hash: %x...)", bobHash[:8])

	// Verify both parties have the same shared secret
	if !bytes.Equal(aliceShared.Combined[:], bobShared.Combined[:]) {
		t.Error("Alice and Bob have different shared secrets!")
		t.Logf("Alice: %x", aliceShared.Combined[:])
		t.Logf("Bob:   %x", bobShared.Combined[:])
	} else {
		t.Log("SUCCESS: Alice and Bob derived the same 64-byte shared secret")
	}

	// Basic entropy check
	allZero := true
	allSame := true
	firstByte := aliceShared.Combined[0]
	for _, b := range aliceShared.Combined {
		if b != 0 {
			allZero = false
		}
		if b != firstByte {
			allSame = false
		}
	}
	if allZero {
		t.Error("Shared secret is all zeros")
	}
	if allSame {
		t.Error("Shared secret has all same bytes")
	}

	// Test multiple exchanges produce different secrets
	shared2, _, err := Encapsulate(bobPub)
	if err != nil {
		t.Fatalf("Second Encapsulate error: %v", err)
	}
	if bytes.Equal(aliceShared.Combined[:], shared2.Combined[:]) {
		t.Error("Two encapsulations produced the same shared secret")
	}

	// Test wipe functionality
	aliceKP.Wipe()
	allZero = true
	for _, b := range aliceKP.X25519Private {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("Wipe did not zero X25519 private key")
	}

	t.Log("PQC key exchange integration test passed")
}

func TestPQCFromSeed(t *testing.T) {
	// Test deterministic key generation from seed
	seed := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	kp1, err := FromX25519Seed(seed)
	if err != nil {
		t.Fatalf("FromX25519Seed error: %v", err)
	}

	kp2, err := FromX25519Seed(seed)
	if err != nil {
		t.Fatalf("FromX25519Seed error: %v", err)
	}

	// X25519 keys should match
	if !bytes.Equal(kp1.X25519Public[:], kp2.X25519Public[:]) {
		t.Error("Same seed produced different X25519 public keys")
	}

	// Kyber keys will differ (random generation) but that's expected
	t.Logf("X25519 keys match for same seed")

	// Different seed should produce different keys
	seed2 := [32]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
		16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	kp3, err := FromX25519Seed(seed2)
	if err != nil {
		t.Fatalf("FromX25519Seed error: %v", err)
	}

	if bytes.Equal(kp1.X25519Public[:], kp3.X25519Public[:]) {
		t.Error("Different seeds produced same X25519 public key")
	}

	t.Log("PQC seed-based generation test passed")
}
