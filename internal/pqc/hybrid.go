package pqc

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// kdfLabel domain-separates the hybrid KEM output derivation.
const kdfLabel = "ghostwire-pqc-hybrid-v1"

// deriveCombined binds the combined shared secret to the full handshake
// transcript so that an active attacker cannot substitute KEM material
// without changing the derived key. The transcript covers the scheme tag,
// the X25519 ephemeral, the Kyber ciphertext, and both recipient public
// keys. HKDF-SHA512 is used instead of a bare hash for proper key
// derivation. The X25519 and Kyber shared secrets are the keying material.
func deriveCombined(scheme Scheme, ephemeral [X25519KeySize]byte, ciphertext []byte,
	recipientX25519 [X25519KeySize]byte, recipientKyber []byte,
	x25519SS [X25519KeySize]byte, kyberSS [KyberSharedSecretSize]byte) ([SharedSecretSize]byte, error) {

	transcript := make([]byte, 0, len(kdfLabel)+1+X25519KeySize+len(ciphertext)+X25519KeySize+len(recipientKyber))
	transcript = append(transcript, kdfLabel...)
	transcript = append(transcript, byte(scheme))
	transcript = append(transcript, ephemeral[:]...)
	transcript = append(transcript, ciphertext...)
	transcript = append(transcript, recipientX25519[:]...)
	transcript = append(transcript, recipientKyber...)

	ikm := make([]byte, 0, X25519KeySize+KyberSharedSecretSize)
	ikm = append(ikm, x25519SS[:]...)
	ikm = append(ikm, kyberSS[:]...)

	var out [SharedSecretSize]byte
	r := hkdf.New(sha512.New, ikm, nil, transcript)
	_, err := io.ReadFull(r, out[:])

	for i := range ikm {
		ikm[i] = 0
	}
	if err != nil {
		return out, fmt.Errorf("derive combined secret: %w", err)
	}
	return out, nil
}

// Scheme identifies the hybrid PQC scheme
type Scheme uint8

const (
	// SchemeX25519Kyber768 combines X25519 with Kyber-768
	SchemeX25519Kyber768 Scheme = iota
)

func (s Scheme) String() string {
	switch s {
	case SchemeX25519Kyber768:
		return "X25519-Kyber768"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

const (
	// X25519KeySize is the size of X25519 keys
	X25519KeySize = 32

	// SharedSecretSize is the size of the combined shared secret
	SharedSecretSize = 64

	// KyberPublicKeySize is the size of Kyber-768 public keys (1184 bytes)
	KyberPublicKeySize = 1184

	// KyberPrivateKeySize is the size of Kyber-768 private keys (2400 bytes)
	KyberPrivateKeySize = 2400

	// KyberCiphertextSize is the size of Kyber-768 ciphertexts (1088 bytes)
	KyberCiphertextSize = 1088

	// KyberSharedSecretSize is the size of Kyber-768 shared secrets
	KyberSharedSecretSize = 32

	// KyberSeedSize is the seed size for encapsulation
	KyberSeedSize = 32
)

// KeyPair contains both classical and post-quantum keys
type KeyPair struct {
	Scheme Scheme

	// Classical X25519
	X25519Private [X25519KeySize]byte
	X25519Public  [X25519KeySize]byte

	// Post-quantum Kyber-768
	KyberPrivate []byte
	KyberPublic  []byte
}

// Generate creates a new hybrid keypair
func Generate() (*KeyPair, error) {
	kp := &KeyPair{
		Scheme: SchemeX25519Kyber768,
	}

	// Generate X25519 keypair
	if _, err := rand.Read(kp.X25519Private[:]); err != nil {
		return nil, fmt.Errorf("generate X25519 private key: %w", err)
	}
	curve25519.ScalarBaseMult(&kp.X25519Public, &kp.X25519Private)

	// Generate Kyber-768 keypair
	pub, priv, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Kyber keypair: %w", err)
	}

	kp.KyberPublic = make([]byte, KyberPublicKeySize)
	kp.KyberPrivate = make([]byte, KyberPrivateKeySize)
	pub.Pack(kp.KyberPublic)
	priv.Pack(kp.KyberPrivate)

	return kp, nil
}

// FromX25519Seed creates a keypair from an existing X25519 private key
func FromX25519Seed(x25519Private [X25519KeySize]byte) (*KeyPair, error) {
	kp := &KeyPair{
		Scheme:        SchemeX25519Kyber768,
		X25519Private: x25519Private,
	}

	// Derive X25519 public key
	curve25519.ScalarBaseMult(&kp.X25519Public, &kp.X25519Private)

	// Generate new Kyber keypair (cannot derive from X25519)
	pub, priv, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Kyber keypair: %w", err)
	}

	kp.KyberPublic = make([]byte, KyberPublicKeySize)
	kp.KyberPrivate = make([]byte, KyberPrivateKeySize)
	pub.Pack(kp.KyberPublic)
	priv.Pack(kp.KyberPrivate)

	return kp, nil
}

// PublicKey returns the combined public key material
type PublicKey struct {
	Scheme       Scheme
	X25519Public [X25519KeySize]byte
	KyberPublic  []byte
}

// Public extracts the public key from a keypair
func (kp *KeyPair) Public() *PublicKey {
	return &PublicKey{
		Scheme:       kp.Scheme,
		X25519Public: kp.X25519Public,
		KyberPublic:  kp.KyberPublic,
	}
}

// SharedSecret is the result of a hybrid key exchange
type SharedSecret struct {
	Combined [SharedSecretSize]byte      // HKDF-SHA512 over transcript || X25519_SS || Kyber_SS
	X25519SS [X25519KeySize]byte         // Classical shared secret
	KyberSS  [KyberSharedSecretSize]byte // Post-quantum shared secret
}

// Validate checks that a PublicKey carries well-formed key material. It must
// be called on any public key received from an untrusted peer before use:
// the underlying circl Unpack/EncapsulateTo routines panic on wrong-length
// input, so a malformed key would otherwise be a remote DoS.
func (pk *PublicKey) Validate() error {
	if pk.Scheme != SchemeX25519Kyber768 {
		return fmt.Errorf("unsupported scheme: %v", pk.Scheme)
	}
	if len(pk.KyberPublic) != KyberPublicKeySize {
		return fmt.Errorf("invalid Kyber public key size: got %d, want %d", len(pk.KyberPublic), KyberPublicKeySize)
	}
	return nil
}

// Bytes returns the combined shared secret
func (ss *SharedSecret) Bytes() []byte {
	return ss.Combined[:]
}

// Encapsulation contains the ciphertexts for key exchange
type Encapsulation struct {
	X25519Ephemeral [X25519KeySize]byte
	KyberCiphertext []byte
}

// Size returns the total size of the encapsulation
func (e *Encapsulation) Size() int {
	return X25519KeySize + len(e.KyberCiphertext)
}

// Encapsulate performs key encapsulation to a recipient's public key
// Returns the shared secret and the encapsulation to send
func Encapsulate(recipient *PublicKey) (*SharedSecret, *Encapsulation, error) {
	// Validate untrusted input before handing it to circl, which panics on
	// wrong-length keys (see PublicKey.Validate).
	if err := recipient.Validate(); err != nil {
		return nil, nil, err
	}

	ss := &SharedSecret{}
	enc := &Encapsulation{}

	// X25519: Generate ephemeral keypair and compute shared secret
	var ephemeralPrivate [X25519KeySize]byte
	if _, err := rand.Read(ephemeralPrivate[:]); err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	curve25519.ScalarBaseMult(&enc.X25519Ephemeral, &ephemeralPrivate)

	// X25519 ECDH
	x25519SS, err := curve25519.X25519(ephemeralPrivate[:], recipient.X25519Public[:])
	if err != nil {
		return nil, nil, fmt.Errorf("X25519 key exchange: %w", err)
	}
	copy(ss.X25519SS[:], x25519SS)

	// Kyber: Encapsulate
	var kyberPub kyber768.PublicKey
	kyberPub.Unpack(recipient.KyberPublic)

	// Allocate buffers for ciphertext and shared secret
	enc.KyberCiphertext = make([]byte, KyberCiphertextSize)
	var kyberSSBytes [KyberSharedSecretSize]byte

	// Generate random seed for encapsulation
	var seed [KyberSeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, nil, fmt.Errorf("generate encapsulation seed: %w", err)
	}

	kyberPub.EncapsulateTo(enc.KyberCiphertext, kyberSSBytes[:], seed[:])
	copy(ss.KyberSS[:], kyberSSBytes[:])

	// Combine shared secrets, bound to the full handshake transcript.
	combined, err := deriveCombined(recipient.Scheme, enc.X25519Ephemeral, enc.KyberCiphertext,
		recipient.X25519Public, recipient.KyberPublic, ss.X25519SS, ss.KyberSS)
	if err != nil {
		return nil, nil, err
	}
	ss.Combined = combined

	// Wipe ephemeral private key and seed
	for i := range ephemeralPrivate {
		ephemeralPrivate[i] = 0
	}
	for i := range seed {
		seed[i] = 0
	}

	return ss, enc, nil
}

// Decapsulate recovers the shared secret from an encapsulation
func (kp *KeyPair) Decapsulate(enc *Encapsulation) (*SharedSecret, error) {
	if kp.Scheme != SchemeX25519Kyber768 {
		return nil, fmt.Errorf("unsupported scheme: %v", kp.Scheme)
	}
	// Validate untrusted ciphertext length before circl DecapsulateTo, which
	// panics on a wrong-length ciphertext.
	if len(enc.KyberCiphertext) != KyberCiphertextSize {
		return nil, fmt.Errorf("invalid Kyber ciphertext size: got %d, want %d", len(enc.KyberCiphertext), KyberCiphertextSize)
	}
	if len(kp.KyberPrivate) != KyberPrivateKeySize {
		return nil, fmt.Errorf("invalid Kyber private key size: got %d, want %d", len(kp.KyberPrivate), KyberPrivateKeySize)
	}

	ss := &SharedSecret{}

	// X25519 ECDH with sender's ephemeral public key
	x25519SS, err := curve25519.X25519(kp.X25519Private[:], enc.X25519Ephemeral[:])
	if err != nil {
		return nil, fmt.Errorf("X25519 key exchange: %w", err)
	}
	copy(ss.X25519SS[:], x25519SS)

	// Kyber: Decapsulate
	var kyberPriv kyber768.PrivateKey
	kyberPriv.Unpack(kp.KyberPrivate)

	var kyberSSBytes [KyberSharedSecretSize]byte
	kyberPriv.DecapsulateTo(kyberSSBytes[:], enc.KyberCiphertext)
	copy(ss.KyberSS[:], kyberSSBytes[:])

	// Recompute the same transcript-bound secret as the sender. The recipient
	// public material is this keypair's own public keys.
	combined, err := deriveCombined(kp.Scheme, enc.X25519Ephemeral, enc.KyberCiphertext,
		kp.X25519Public, kp.KyberPublic, ss.X25519SS, ss.KyberSS)
	if err != nil {
		return nil, err
	}
	ss.Combined = combined

	return ss, nil
}

// Wipe securely zeros all private key material
func (kp *KeyPair) Wipe() {
	for i := range kp.X25519Private {
		kp.X25519Private[i] = 0
	}
	for i := range kp.KyberPrivate {
		kp.KyberPrivate[i] = 0
	}
}
