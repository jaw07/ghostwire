package keys

import (
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"

	"filippo.io/edwards25519"
)

// Ed25519SeedToX25519 derives X25519 private and public keys from an Ed25519 seed.
//
// This uses the mathematical relationship between Ed25519 (twisted Edwards curve)
// and X25519 (Montgomery curve). Both curves are birationally equivalent, allowing
// key conversion.
//
// The conversion process:
// 1. Hash the Ed25519 seed with SHA-512
// 2. Apply X25519 clamping to the first 32 bytes (private key)
// 3. Derive the public key via scalar multiplication
//
// DESIGN NOTE (intentional shared key): the resulting X25519/WireGuard scalar is
// the same secret as the Ed25519 signing scalar. This is deliberate and load-
// bearing: a node's CA-signed Ed25519 certificate authenticates its WireGuard
// identity precisely because the WireGuard public key is the birational image of
// the certificate's Ed25519 public key (see Ed25519PublicKeyToX25519 and
// pki/verify.go's derivedWG check). Deriving the WireGuard key independently
// (e.g. via a separate HKDF) would sever that binding and break peer
// authentication. Using one Ed25519/X25519 key pair for both signatures and
// Diffie-Hellman is a well-analyzed, accepted construction (it is what age and
// several Ed25519-identity mesh VPNs do); the standard ScalarBaseMult/clamping
// path below preserves its security properties.
func Ed25519SeedToX25519(seed []byte) (privateKey [32]byte, publicKey [32]byte, err error) {
	if len(seed) != 32 {
		return privateKey, publicKey, ErrInvalidSeedLength
	}

	// SHA-512 hash of seed, first 32 bytes become the scalar
	h := sha512.Sum512(seed)

	// Apply X25519 clamping per RFC 7748
	h[0] &= 248  // Clear bottom 3 bits
	h[31] &= 127 // Clear top bit
	h[31] |= 64  // Set second-to-top bit

	copy(privateKey[:], h[:32])

	// Derive public key: publicKey = privateKey * basepoint
	// Using edwards25519 library for the scalar multiplication
	scalar, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		return privateKey, publicKey, fmt.Errorf("invalid scalar: %w", err)
	}

	// Multiply by basepoint and convert to Montgomery form
	point := edwards25519.NewGeneratorPoint().ScalarBaseMult(scalar)
	copy(publicKey[:], point.BytesMontgomery())

	// Wipe the SHA-512 intermediate from memory
	WipeBytes(h[:])

	return privateKey, publicKey, nil
}

// Ed25519PublicKeyToX25519 converts an Ed25519 public key to X25519 format.
//
// This uses the birational map between the twisted Edwards curve and Montgomery curve:
// u = (1 + y) / (1 - y)
//
// This allows verifying that a WireGuard public key corresponds to a certificate's
// Ed25519 public key.
func Ed25519PublicKeyToX25519(edPub ed25519.PublicKey) ([32]byte, error) {
	var x25519Pub [32]byte

	if len(edPub) != ed25519.PublicKeySize {
		return x25519Pub, ErrInvalidKeyLength
	}

	// Parse the Ed25519 public key as an Edwards point
	point, err := edwards25519.NewIdentityPoint().SetBytes(edPub)
	if err != nil {
		return x25519Pub, fmt.Errorf("invalid Ed25519 public key: %w", err)
	}

	// Convert to Montgomery form (X25519)
	copy(x25519Pub[:], point.BytesMontgomery())

	return x25519Pub, nil
}

// VerifyKeyPairConsistency checks that an Ed25519 public key correctly
// corresponds to an X25519 public key. Used to verify certificate authenticity.
func VerifyKeyPairConsistency(edPub ed25519.PublicKey, x25519Pub [32]byte) error {
	derived, err := Ed25519PublicKeyToX25519(edPub)
	if err != nil {
		return err
	}

	if derived != x25519Pub {
		return fmt.Errorf("X25519 public key does not match Ed25519 public key")
	}

	return nil
}
