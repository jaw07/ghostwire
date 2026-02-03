package keys

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestGenerate(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer kp.Wipe()

	// Verify Ed25519 key lengths
	if len(kp.Ed25519PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("Ed25519 private key has wrong length: %d", len(kp.Ed25519PrivateKey))
	}
	if len(kp.Ed25519PublicKey) != ed25519.PublicKeySize {
		t.Errorf("Ed25519 public key has wrong length: %d", len(kp.Ed25519PublicKey))
	}

	// Verify X25519 keys are non-zero
	var zeroKey [32]byte
	if kp.X25519PrivateKey == zeroKey {
		t.Error("X25519 private key is all zeros")
	}
	if kp.X25519PublicKey == zeroKey {
		t.Error("X25519 public key is all zeros")
	}

	// Verify seed recovery produces same keys
	seed := kp.Seed()
	kp2, err := FromSeed(seed)
	if err != nil {
		t.Fatalf("FromSeed failed: %v", err)
	}
	defer kp2.Wipe()

	if !bytes.Equal(kp.Ed25519PrivateKey, kp2.Ed25519PrivateKey) {
		t.Error("Recovered Ed25519 private key doesn't match")
	}
	if !bytes.Equal(kp.Ed25519PublicKey, kp2.Ed25519PublicKey) {
		t.Error("Recovered Ed25519 public key doesn't match")
	}
	if kp.X25519PrivateKey != kp2.X25519PrivateKey {
		t.Error("Recovered X25519 private key doesn't match")
	}
	if kp.X25519PublicKey != kp2.X25519PublicKey {
		t.Error("Recovered X25519 public key doesn't match")
	}
}

func TestFromSeedInvalidLength(t *testing.T) {
	_, err := FromSeed([]byte("too short"))
	if err != ErrInvalidSeedLength {
		t.Errorf("Expected ErrInvalidSeedLength, got %v", err)
	}

	_, err = FromSeed(make([]byte, 64))
	if err != ErrInvalidSeedLength {
		t.Errorf("Expected ErrInvalidSeedLength, got %v", err)
	}
}

func TestEd25519PublicKeyToX25519(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer kp.Wipe()

	// Convert Ed25519 public key to X25519
	derived, err := Ed25519PublicKeyToX25519(kp.Ed25519PublicKey)
	if err != nil {
		t.Fatalf("Ed25519PublicKeyToX25519 failed: %v", err)
	}

	// Should match the X25519 public key derived from seed
	if derived != kp.X25519PublicKey {
		t.Error("Derived X25519 public key doesn't match")
	}
}

func TestVerifyKeyPairConsistency(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer kp.Wipe()

	// Valid keypair should pass
	err = VerifyKeyPairConsistency(kp.Ed25519PublicKey, kp.X25519PublicKey)
	if err != nil {
		t.Errorf("Valid keypair failed consistency check: %v", err)
	}

	// Mismatched keypair should fail
	kp2, _ := Generate()
	defer kp2.Wipe()
	err = VerifyKeyPairConsistency(kp.Ed25519PublicKey, kp2.X25519PublicKey)
	if err == nil {
		t.Error("Mismatched keypair should fail consistency check")
	}
}

func TestWireGuardKeyEncoding(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer kp.Wipe()

	// Encode and decode private key
	privB64 := kp.WireGuardPrivateKeyBase64()
	decoded, err := ParseWireGuardPrivateKey(privB64)
	if err != nil {
		t.Fatalf("ParseWireGuardPrivateKey failed: %v", err)
	}
	if decoded != kp.X25519PrivateKey {
		t.Error("Decoded private key doesn't match")
	}

	// Encode and decode public key
	pubB64 := kp.WireGuardPublicKeyBase64()
	decoded, err = ParseWireGuardPublicKey(pubB64)
	if err != nil {
		t.Fatalf("ParseWireGuardPublicKey failed: %v", err)
	}
	if decoded != kp.X25519PublicKey {
		t.Error("Decoded public key doesn't match")
	}
}

func TestWipe(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Store copies to compare after wipe
	origSeed := make([]byte, 32)
	copy(origSeed, kp.seed[:])

	kp.Wipe()

	// Check that seed was wiped
	var zeroSeed [32]byte
	if kp.seed != zeroSeed {
		t.Error("Seed was not wiped")
	}
}

func TestSecureBuffer(t *testing.T) {
	sb := NewSecureBuffer(32)
	defer sb.Close()

	data := []byte("secret-key-material-here-1234567")
	if err := sb.Write(data); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Read should return the same data
	read := sb.Read()
	if !bytes.Equal(read, data) {
		t.Error("Read data doesn't match written data")
	}

	// Wipe should zero the buffer
	sb.Wipe()
	for _, b := range sb.Bytes() {
		if b != 0 {
			t.Error("Buffer not properly wiped")
			break
		}
	}
}

func TestSecureString(t *testing.T) {
	secret := "my-secret-passphrase"
	ss := NewSecureString(secret)
	defer ss.Close()

	if ss.String() != secret {
		t.Error("SecureString value doesn't match")
	}

	ss.Wipe()
	for _, b := range ss.buf.Bytes() {
		if b != 0 {
			t.Error("SecureString not properly wiped")
			break
		}
	}
}
