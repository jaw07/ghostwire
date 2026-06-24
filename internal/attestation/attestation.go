package attestation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// OID for attestation X.509 extension
var OIDGhostwireAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 10}

// Type indicates the attestation method
type Type uint8

const (
	// TypeSoftware is binary hash attestation
	TypeSoftware Type = iota

	// TypeTPM is TPM-based attestation
	TypeTPM

	// TypeSGX is Intel SGX attestation (future)
	TypeSGX
)

func (t Type) String() string {
	switch t {
	case TypeSoftware:
		return "software"
	case TypeTPM:
		return "tpm"
	case TypeSGX:
		return "sgx"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// Claim represents a node's attestation
type Claim struct {
	Type       Type
	NodeID     string
	Timestamp  time.Time
	BinaryHash [32]byte
	ConfigHash [32]byte
	SystemInfo SystemInfo
	Nonce      [16]byte // Challenge nonce for freshness
	TPMQuote   []byte   // Optional TPM quote (TPMS_ATTEST), present for TypeTPM
	TPMSig     []byte   // AK signature over TPMQuote (TPMT_SIGNATURE), present for TypeTPM
	Signature  []byte   // Signed by node key
}

// SystemInfo captures system characteristics
type SystemInfo struct {
	OS        string
	Arch      string
	GoVersion string
	NumCPU    int
	Hostname  string
	BootID    string // Unique per boot on Linux
}

// GatherSystemInfo collects current system information
func GatherSystemInfo() SystemInfo {
	hostname, _ := os.Hostname()
	bootID := getBootID()

	return SystemInfo{
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		GoVersion: runtime.Version(),
		NumCPU:    runtime.NumCPU(),
		Hostname:  hostname,
		BootID:    bootID,
	}
}

// getBootID returns the system boot ID if available
func getBootID() string {
	// Linux: /proc/sys/kernel/random/boot_id
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if err == nil && len(data) >= 36 {
			return string(data[:36]) // UUID format
		}
	}
	// Other platforms: empty
	return ""
}

// Hash returns a hash of the system info for comparison
func (s *SystemInfo) Hash() [32]byte {
	data := fmt.Sprintf("%s:%s:%s:%d:%s:%s",
		s.OS, s.Arch, s.GoVersion, s.NumCPU, s.Hostname, s.BootID)
	return sha256.Sum256([]byte(data))
}

// NewClaim creates a new attestation claim
func NewClaim(nodeID string, nonce [16]byte) (*Claim, error) {
	binaryHash, err := ComputeBinaryHash()
	if err != nil {
		return nil, fmt.Errorf("compute binary hash: %w", err)
	}

	return &Claim{
		Type:       TypeSoftware,
		NodeID:     nodeID,
		Timestamp:  time.Now().UTC(),
		BinaryHash: binaryHash,
		SystemInfo: GatherSystemInfo(),
		Nonce:      nonce,
	}, nil
}

// NewTPMClaim creates a TPM-backed attestation claim. quote is the marshaled
// TPMS_ATTEST structure returned by the node's TPM (via go-tpm tpm2.Quote, with
// the challenge nonce supplied as the qualifying data) and sig is the
// accompanying TPMT_SIGNATURE produced by the Attestation Key over that quote.
//
// Producing these bytes requires access to the node's TPM hardware; the
// verification side (Verifier.Verify against a registered TPMPolicy) is
// hardware-free and fully exercised by the package tests.
func NewTPMClaim(nodeID string, nonce [16]byte, quote, sig []byte) (*Claim, error) {
	c, err := NewClaim(nodeID, nonce)
	if err != nil {
		return nil, err
	}
	c.Type = TypeTPM
	c.TPMQuote = quote
	c.TPMSig = sig
	return c, nil
}

// SetConfigHash sets the config hash (excluding secrets)
func (c *Claim) SetConfigHash(hash [32]byte) {
	c.ConfigHash = hash
}

// Sign signs the claim with the node's private key
func (c *Claim) Sign(privateKey ed25519.PrivateKey) error {
	data := c.signatureData()
	c.Signature = ed25519.Sign(privateKey, data)
	return nil
}

// Verify checks the claim signature
func (c *Claim) Verify(publicKey ed25519.PublicKey) bool {
	data := c.signatureData()
	return ed25519.Verify(publicKey, data, c.Signature)
}

// signatureData returns the data to sign
func (c *Claim) signatureData() []byte {
	data := make([]byte, 0, 256)
	data = append(data, byte(c.Type))
	// Length-prefix the variable-length NodeID so it can't shift the boundary
	// with the following fixed-size fields (signing-input ambiguity).
	var nl [2]byte
	binary.BigEndian.PutUint16(nl[:], uint16(len(c.NodeID)))
	data = append(data, nl[:]...)
	data = append(data, []byte(c.NodeID)...)
	data = append(data, c.BinaryHash[:]...)
	data = append(data, c.ConfigHash[:]...)
	data = append(data, c.Nonce[:]...)

	// Include timestamp as unix seconds
	ts := c.Timestamp.Unix()
	data = append(data, byte(ts>>56), byte(ts>>48), byte(ts>>40), byte(ts>>32),
		byte(ts>>24), byte(ts>>16), byte(ts>>8), byte(ts))

	// Include system info hash
	sysHash := c.SystemInfo.Hash()
	data = append(data, sysHash[:]...)

	return data
}

// BinaryHashHex returns the binary hash as hex string
func (c *Claim) BinaryHashHex() string {
	return hex.EncodeToString(c.BinaryHash[:])
}

// ComputeBinaryHash computes the SHA-256 hash of the running binary
func ComputeBinaryHash() ([32]byte, error) {
	var hash [32]byte

	exePath, err := os.Executable()
	if err != nil {
		return hash, fmt.Errorf("get executable path: %w", err)
	}

	// Resolve symlinks
	exePath, err = evalSymlinks(exePath)
	if err != nil {
		return hash, fmt.Errorf("resolve symlinks: %w", err)
	}

	data, err := os.ReadFile(exePath)
	if err != nil {
		return hash, fmt.Errorf("read executable: %w", err)
	}

	hash = sha256.Sum256(data)
	return hash, nil
}

// evalSymlinks fully resolves symbolic links in a path (multi-hop, relative
// links included) so the hashed binary is the real target, not an intermediate
// or relative link.
func evalSymlinks(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}

// ComputeConfigHash computes a hash of config data (should exclude secrets)
func ComputeConfigHash(configData []byte) [32]byte {
	return sha256.Sum256(configData)
}

// Result is the outcome of attestation verification
type Result struct {
	Valid         bool
	NodeID        string
	BinaryVersion string // Looked up from trusted hashes
	Timestamp     time.Time
	Issues        []string
	SystemInfo    SystemInfo
}

// AddIssue adds an issue to the result
func (r *Result) AddIssue(issue string) {
	r.Issues = append(r.Issues, issue)
	r.Valid = false
}
