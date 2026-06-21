package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestVerifyRejectsReplay(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := Challenge()
	if err != nil {
		t.Fatal(err)
	}
	claim, err := NewClaim("node-1", nonce) // hashes the test binary
	if err != nil {
		t.Fatal(err)
	}
	if err := claim.Sign(priv); err != nil {
		t.Fatal(err)
	}

	v := NewVerifier(nil)
	v.AddTrustedHashBytes(claim.BinaryHash, "test")

	if r := v.Verify(claim, pub, nonce); !r.Valid {
		t.Fatalf("first verify should pass: %v", r.Issues)
	}
	// Same valid claim again -> must be rejected as a replay.
	if r := v.Verify(claim, pub, nonce); r.Valid {
		t.Error("replayed claim (reused nonce) should be rejected")
	}
}
