package pqc

import (
	"bytes"
	"testing"
)

func TestGenerate(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	if kp.Scheme != SchemeX25519Kyber768 {
		t.Errorf("Scheme = %v, want %v", kp.Scheme, SchemeX25519Kyber768)
	}

	// X25519 keys should be set
	var zeroKey [X25519KeySize]byte
	if kp.X25519Private == zeroKey {
		t.Error("X25519Private should not be zero")
	}
	if kp.X25519Public == zeroKey {
		t.Error("X25519Public should not be zero")
	}

	// Kyber keys should be set
	if len(kp.KyberPrivate) != KyberPrivateKeySize {
		t.Errorf("KyberPrivate size = %d, want %d", len(kp.KyberPrivate), KyberPrivateKeySize)
	}
	if len(kp.KyberPublic) != KyberPublicKeySize {
		t.Errorf("KyberPublic size = %d, want %d", len(kp.KyberPublic), KyberPublicKeySize)
	}
}

func TestFromX25519Seed(t *testing.T) {
	// Create original keypair
	original, err := Generate()
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	// Create from seed
	derived, err := FromX25519Seed(original.X25519Private)
	if err != nil {
		t.Fatalf("FromX25519Seed error: %v", err)
	}

	// X25519 keys should match
	if derived.X25519Private != original.X25519Private {
		t.Error("X25519Private should match")
	}
	if derived.X25519Public != original.X25519Public {
		t.Error("X25519Public should match")
	}

	// Kyber keys will be different (freshly generated)
	if bytes.Equal(derived.KyberPrivate, original.KyberPrivate) {
		t.Error("KyberPrivate should be different (newly generated)")
	}
}

func TestPublicKey(t *testing.T) {
	kp, _ := Generate()

	pub := kp.Public()
	if pub.Scheme != kp.Scheme {
		t.Error("Scheme mismatch")
	}
	if pub.X25519Public != kp.X25519Public {
		t.Error("X25519Public mismatch")
	}
	if !bytes.Equal(pub.KyberPublic, kp.KyberPublic) {
		t.Error("KyberPublic mismatch")
	}
}

func TestEncapsulateDecapsulate(t *testing.T) {
	// Generate recipient keypair
	recipient, err := Generate()
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	// Encapsulate to recipient's public key
	senderSS, enc, err := Encapsulate(recipient.Public())
	if err != nil {
		t.Fatalf("Encapsulate error: %v", err)
	}

	// Check encapsulation sizes
	if len(enc.KyberCiphertext) != KyberCiphertextSize {
		t.Errorf("KyberCiphertext size = %d, want %d", len(enc.KyberCiphertext), KyberCiphertextSize)
	}

	var zeroKey [X25519KeySize]byte
	if enc.X25519Ephemeral == zeroKey {
		t.Error("X25519Ephemeral should not be zero")
	}

	// Decapsulate
	recipientSS, err := recipient.Decapsulate(enc)
	if err != nil {
		t.Fatalf("Decapsulate error: %v", err)
	}

	// Shared secrets should match
	if senderSS.Combined != recipientSS.Combined {
		t.Error("Combined shared secrets should match")
	}
	if senderSS.X25519SS != recipientSS.X25519SS {
		t.Error("X25519 shared secrets should match")
	}
	if senderSS.KyberSS != recipientSS.KyberSS {
		t.Error("Kyber shared secrets should match")
	}
}

func TestEncapsulateDecapsulateMultiple(t *testing.T) {
	// Test multiple encapsulations to same recipient
	recipient, _ := Generate()

	secrets := make([][SharedSecretSize]byte, 5)
	for i := 0; i < 5; i++ {
		ss, enc, err := Encapsulate(recipient.Public())
		if err != nil {
			t.Fatalf("Encapsulate %d error: %v", i, err)
		}

		decSS, err := recipient.Decapsulate(enc)
		if err != nil {
			t.Fatalf("Decapsulate %d error: %v", i, err)
		}

		if ss.Combined != decSS.Combined {
			t.Errorf("Round %d: shared secrets don't match", i)
		}

		secrets[i] = ss.Combined
	}

	// All shared secrets should be different
	for i := 0; i < len(secrets); i++ {
		for j := i + 1; j < len(secrets); j++ {
			if secrets[i] == secrets[j] {
				t.Errorf("Shared secrets %d and %d should be different", i, j)
			}
		}
	}
}

func TestWrongRecipient(t *testing.T) {
	// Generate two keypairs
	alice, _ := Generate()
	bob, _ := Generate()

	// Encapsulate to Alice
	aliceSS, enc, err := Encapsulate(alice.Public())
	if err != nil {
		t.Fatalf("Encapsulate error: %v", err)
	}

	// Bob tries to decapsulate (should get different secret)
	bobSS, err := bob.Decapsulate(enc)
	if err != nil {
		t.Fatalf("Decapsulate error: %v", err)
	}

	// Shared secrets should NOT match
	if aliceSS.Combined == bobSS.Combined {
		t.Error("Wrong recipient should get different shared secret")
	}

	// Alice can decapsulate correctly
	aliceDecSS, err := alice.Decapsulate(enc)
	if err != nil {
		t.Fatalf("Alice Decapsulate error: %v", err)
	}

	if aliceSS.Combined != aliceDecSS.Combined {
		t.Error("Correct recipient should get matching shared secret")
	}
}

func TestWipe(t *testing.T) {
	kp, _ := Generate()

	// Store original private keys
	origX25519 := kp.X25519Private
	origKyber := make([]byte, len(kp.KyberPrivate))
	copy(origKyber, kp.KyberPrivate)

	// Wipe
	kp.Wipe()

	// X25519 private should be zero
	var zeroKey [X25519KeySize]byte
	if kp.X25519Private != zeroKey {
		t.Error("X25519Private should be wiped to zero")
	}

	// Kyber private should be zero
	for i, b := range kp.KyberPrivate {
		if b != 0 {
			t.Errorf("KyberPrivate[%d] = %d, should be 0", i, b)
			break
		}
	}

	// Original values should have been non-zero
	if origX25519 == zeroKey {
		t.Error("Original X25519Private was already zero")
	}
	allZero := true
	for _, b := range origKyber {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Original KyberPrivate was already zero")
	}
}

func TestSharedSecretBytes(t *testing.T) {
	alice, _ := Generate()
	ss, _, _ := Encapsulate(alice.Public())

	bytes := ss.Bytes()
	if len(bytes) != SharedSecretSize {
		t.Errorf("Bytes() len = %d, want %d", len(bytes), SharedSecretSize)
	}

	// Should be same as Combined
	for i := 0; i < SharedSecretSize; i++ {
		if bytes[i] != ss.Combined[i] {
			t.Error("Bytes() should return Combined")
			break
		}
	}
}

func TestEncapsulationSize(t *testing.T) {
	alice, _ := Generate()
	_, enc, _ := Encapsulate(alice.Public())

	expectedSize := X25519KeySize + KyberCiphertextSize
	if enc.Size() != expectedSize {
		t.Errorf("Encapsulation.Size() = %d, want %d", enc.Size(), expectedSize)
	}
}

func TestSchemeString(t *testing.T) {
	tests := []struct {
		s        Scheme
		expected string
	}{
		{SchemeX25519Kyber768, "X25519-Kyber768"},
		{Scheme(99), "unknown(99)"},
	}

	for _, tt := range tests {
		if got := tt.s.String(); got != tt.expected {
			t.Errorf("Scheme(%d).String() = %q, want %q", tt.s, got, tt.expected)
		}
	}
}

func BenchmarkGenerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		kp, _ := Generate()
		kp.Wipe()
	}
}

func BenchmarkEncapsulate(b *testing.B) {
	recipient, _ := Generate()
	pub := recipient.Public()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encapsulate(pub)
	}
}

func BenchmarkDecapsulate(b *testing.B) {
	recipient, _ := Generate()
	_, enc, _ := Encapsulate(recipient.Public())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recipient.Decapsulate(enc)
	}
}

func BenchmarkFullExchange(b *testing.B) {
	recipient, _ := Generate()
	pub := recipient.Public()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, enc, _ := Encapsulate(pub)
		recipient.Decapsulate(enc)
	}
}
