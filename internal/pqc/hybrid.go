package pqc

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/curve25519"
)

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
	Combined [SharedSecretSize]byte         // SHA-512(X25519_SS || Kyber_SS)
	X25519SS [X25519KeySize]byte            // Classical shared secret
	KyberSS  [KyberSharedSecretSize]byte    // Post-quantum shared secret
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
	if recipient.Scheme != SchemeX25519Kyber768 {
		return nil, nil, fmt.Errorf("unsupported scheme: %v", recipient.Scheme)
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

	// Combine shared secrets: SHA-512(X25519_SS || Kyber_SS)
	combined := sha512.New()
	combined.Write(ss.X25519SS[:])
	combined.Write(ss.KyberSS[:])
	copy(ss.Combined[:], combined.Sum(nil))

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

	// Combine shared secrets: SHA-512(X25519_SS || Kyber_SS)
	combined := sha512.New()
	combined.Write(ss.X25519SS[:])
	combined.Write(ss.KyberSS[:])
	copy(ss.Combined[:], combined.Sum(nil))

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
