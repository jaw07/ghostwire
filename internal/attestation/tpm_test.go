package attestation

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
	"time"

	tpm2 "github.com/google/go-tpm/legacy/tpm2"
)

// pcrFixture returns a deterministic PCR set and the digest the TPM would sign
// for it (SHA-256 over the concatenated values in ascending index order).
func pcrFixture() (sel tpm2.PCRSelection, expected map[int][]byte, digest []byte) {
	pcr0 := bytes.Repeat([]byte{0x01}, 32)
	pcr1 := bytes.Repeat([]byte{0x02}, 32)
	pcr7 := bytes.Repeat([]byte{0x07}, 32)
	expected = map[int][]byte{0: pcr0, 1: pcr1, 7: pcr7}
	sel = tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{0, 1, 7}}
	concat := append(append(append([]byte{}, pcr0...), pcr1...), pcr7...)
	d := sha256.Sum256(concat)
	return sel, expected, d[:]
}

// buildQuote marshals a TPMS_ATTEST quote binding the given nonce and PCR digest.
func buildQuote(t *testing.T, nonce [16]byte, sel tpm2.PCRSelection, pcrDigest []byte) []byte {
	t.Helper()
	ad := tpm2.AttestationData{
		Magic:     tpmGeneratedValue,
		Type:      tpm2.TagAttestQuote,
		ExtraData: nonce[:],
		AttestedQuoteInfo: &tpm2.QuoteInfo{
			PCRSelection: sel,
			PCRDigest:    pcrDigest,
		},
	}
	b, err := ad.Encode()
	if err != nil {
		t.Fatalf("encode attestation: %v", err)
	}
	return b
}

func signECDSA(t *testing.T, priv *ecdsa.PrivateKey, quote []byte) []byte {
	t.Helper()
	d := sha256.Sum256(quote)
	r, s, err := ecdsa.Sign(rand.Reader, priv, d[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	sig := tpm2.Signature{Alg: tpm2.AlgECDSA, ECC: &tpm2.SignatureECC{HashAlg: tpm2.AlgSHA256, R: r, S: s}}
	b, err := sig.Encode()
	if err != nil {
		t.Fatalf("encode sig: %v", err)
	}
	return b
}

func signRSA(t *testing.T, priv *rsa.PrivateKey, quote []byte) []byte {
	t.Helper()
	d := sha256.Sum256(quote)
	raw, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, d[:])
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}
	sig := tpm2.Signature{Alg: tpm2.AlgRSASSA, RSA: &tpm2.SignatureRSA{HashAlg: tpm2.AlgSHA256, Signature: raw}}
	b, err := sig.Encode()
	if err != nil {
		t.Fatalf("encode sig: %v", err)
	}
	return b
}

// signedTPMClaim assembles a node-signed TPM claim for the given quote/sig.
func signedTPMClaim(t *testing.T, nonce [16]byte, quote, sig []byte) (*Claim, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("node key: %v", err)
	}
	claim, err := NewTPMClaim("node-1", nonce, quote, sig)
	if err != nil {
		t.Fatalf("NewTPMClaim: %v", err)
	}
	if err := claim.Sign(priv); err != nil {
		t.Fatalf("sign claim: %v", err)
	}
	return claim, pub
}

func newTPMVerifier(t *testing.T, claim *Claim, akPub crypto.PublicKey, expected map[int][]byte) *Verifier {
	t.Helper()
	v := NewVerifier(&VerifierConfig{MaxClockSkew: 5 * time.Minute, MaxAge: time.Hour})
	v.AddTrustedHashBytes(claim.BinaryHash, "v1.0.0")
	v.SetTPMPolicy("node-1", &TPMPolicy{
		AKPublic:     akPub,
		ExpectedPCRs: expected,
		PCRBank:      crypto.SHA256,
	})
	return v
}

func TestVerifyTPMQuoteECDSA(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nonce, _ := Challenge()
	sel, expected, digest := pcrFixture()
	quote := buildQuote(t, nonce, sel, digest)
	sig := signECDSA(t, priv, quote)

	claim, nodePub := signedTPMClaim(t, nonce, quote, sig)
	v := newTPMVerifier(t, claim, &priv.PublicKey, expected)

	result := v.Verify(claim, nodePub, nonce)
	if !result.Valid {
		t.Fatalf("expected valid TPM claim, got issues: %v", result.Issues)
	}
}

func TestVerifyTPMQuoteRSA(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	nonce, _ := Challenge()
	sel, expected, digest := pcrFixture()
	quote := buildQuote(t, nonce, sel, digest)
	sig := signRSA(t, priv, quote)

	claim, nodePub := signedTPMClaim(t, nonce, quote, sig)
	v := newTPMVerifier(t, claim, &priv.PublicKey, expected)

	result := v.Verify(claim, nodePub, nonce)
	if !result.Valid {
		t.Fatalf("expected valid TPM claim, got issues: %v", result.Issues)
	}
}

func TestVerifyTPMNoPolicyFailsClosed(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nonce, _ := Challenge()
	sel, _, digest := pcrFixture()
	quote := buildQuote(t, nonce, sel, digest)
	sig := signECDSA(t, priv, quote)
	claim, nodePub := signedTPMClaim(t, nonce, quote, sig)

	// Verifier with the binary trusted but NO TPM policy registered.
	v := NewVerifier(&VerifierConfig{MaxClockSkew: 5 * time.Minute, MaxAge: time.Hour})
	v.AddTrustedHashBytes(claim.BinaryHash, "v1.0.0")

	result := v.Verify(claim, nodePub, nonce)
	if result.Valid {
		t.Fatal("unconfigured TPM claim must fail closed")
	}
}

func TestVerifyTPMTamperedPCR(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nonce, _ := Challenge()
	sel, expected, digest := pcrFixture()
	quote := buildQuote(t, nonce, sel, digest)
	sig := signECDSA(t, priv, quote)
	claim, nodePub := signedTPMClaim(t, nonce, quote, sig)

	// Policy expects a different PCR0 value than the quote attests.
	tampered := map[int][]byte{
		0: bytes.Repeat([]byte{0xee}, 32),
		1: expected[1],
		7: expected[7],
	}
	v := newTPMVerifier(t, claim, &priv.PublicKey, tampered)

	result := v.Verify(claim, nodePub, nonce)
	if result.Valid {
		t.Fatal("PCR mismatch must reject the claim")
	}
}

func TestVerifyTPMWrongAK(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nonce, _ := Challenge()
	sel, expected, digest := pcrFixture()
	quote := buildQuote(t, nonce, sel, digest)
	sig := signECDSA(t, priv, quote)
	claim, nodePub := signedTPMClaim(t, nonce, quote, sig)

	// Trust the attacker's AK instead of the signer's: signature must fail.
	v := newTPMVerifier(t, claim, &attacker.PublicKey, expected)

	result := v.Verify(claim, nodePub, nonce)
	if result.Valid {
		t.Fatal("quote signed by an untrusted AK must be rejected")
	}
}

func TestVerifyTPMQuoteNonceUnbound(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nonce, _ := Challenge()
	sel, expected, digest := pcrFixture()

	// Quote binds a DIFFERENT nonce than the claim's challenge nonce.
	var otherNonce [16]byte
	otherNonce[0] = nonce[0] ^ 0xff
	quote := buildQuote(t, otherNonce, sel, digest)
	sig := signECDSA(t, priv, quote)
	claim, nodePub := signedTPMClaim(t, nonce, quote, sig)
	v := newTPMVerifier(t, claim, &priv.PublicKey, expected)

	result := v.Verify(claim, nodePub, nonce)
	if result.Valid {
		t.Fatal("quote not bound to the challenge nonce must be rejected")
	}
}

func TestVerifyTPMMissingSignature(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nonce, _ := Challenge()
	sel, expected, digest := pcrFixture()
	quote := buildQuote(t, nonce, sel, digest)
	claim, nodePub := signedTPMClaim(t, nonce, quote, nil) // no signature
	v := newTPMVerifier(t, claim, &priv.PublicKey, expected)

	result := v.Verify(claim, nodePub, nonce)
	if result.Valid {
		t.Fatal("TPM claim without a signature must be rejected")
	}
}
