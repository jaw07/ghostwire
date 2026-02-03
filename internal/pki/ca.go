package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/ghostwire/ghostwire/internal/keys"
)

// CertificateAuthority manages the mesh PKI
type CertificateAuthority struct {
	// Root CA certificate and key
	RootCert *x509.Certificate
	rootKey  ed25519.PrivateKey

	// Mesh identifier (SHA-256 of root CA public key)
	MeshID [32]byte

	// Mesh name
	MeshName string

	// Whether this CA can sign certificates (has private key)
	canSign bool
}

// CAConfig holds configuration for creating a new CA
type CAConfig struct {
	MeshName     string
	Organization string
	Validity     time.Duration
}

// DefaultCAConfig returns sensible defaults for CA configuration
func DefaultCAConfig(meshName string) *CAConfig {
	return &CAConfig{
		MeshName:     meshName,
		Organization: "GHOSTWIRE Mesh: " + meshName,
		Validity:     2 * 365 * 24 * time.Hour, // 2 years
	}
}

// NewCertificateAuthority creates a new root CA for the mesh
func NewCertificateAuthority(cfg *CAConfig) (*CertificateAuthority, *keys.KeyPair, error) {
	// Generate CA keypair
	kp, err := keys.Generate()
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA keypair: %w", err)
	}

	// Generate serial number
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "GHOSTWIRE Root CA",
			Organization: []string{cfg.Organization},
		},
		NotBefore:             now,
		NotAfter:              now.Add(cfg.Validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}

	// Self-sign the CA certificate
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template, // Self-signed
		kp.Ed25519PublicKey,
		kp.Ed25519PrivateKey,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	// Compute mesh ID from CA public key
	meshID := sha256.Sum256(kp.Ed25519PublicKey)

	ca := &CertificateAuthority{
		RootCert: cert,
		rootKey:  kp.Ed25519PrivateKey,
		MeshID:   meshID,
		MeshName: cfg.MeshName,
		canSign:  true,
	}

	return ca, kp, nil
}

// LoadCertificateAuthority loads a CA from PEM-encoded certificate and optionally key
func LoadCertificateAuthority(certPEM, keyPEM []byte) (*CertificateAuthority, error) {
	// Parse certificate
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	ca := &CertificateAuthority{
		RootCert: cert,
		canSign:  false,
	}

	// Extract mesh ID from public key
	edPub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("CA certificate must use Ed25519 key")
	}
	ca.MeshID = sha256.Sum256(edPub)

	// Parse private key if provided
	if len(keyPEM) > 0 {
		block, _ = pem.Decode(keyPEM)
		if block == nil {
			return nil, fmt.Errorf("invalid key PEM")
		}

		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}

		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key must be Ed25519")
		}

		ca.rootKey = edKey
		ca.canSign = true
	}

	return ca, nil
}

// NodeCertRequest contains information for creating a node certificate
type NodeCertRequest struct {
	NodeID          string
	Roles           []string
	AllowedNetworks []AllowedNetwork
	Compartment     string
	PublicKey       ed25519.PublicKey
	WireGuardPubKey [32]byte
	MeshIP          net.IP
	Validity        time.Duration
}

// IssueCertificate creates a signed node certificate
func (ca *CertificateAuthority) IssueCertificate(req *NodeCertRequest) (*x509.Certificate, []byte, error) {
	if !ca.canSign {
		return nil, nil, fmt.Errorf("CA cannot sign certificates (no private key)")
	}

	// Validate roles
	for _, role := range req.Roles {
		if !IsValidRole(role) {
			return nil, nil, fmt.Errorf("invalid role: %s", role)
		}
	}

	// Default validity to 24 hours
	validity := req.Validity
	if validity == 0 {
		validity = 24 * time.Hour
	}

	// Generate serial number
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	// Build GHOSTWIRE extensions
	gwExt := &GhostwireExtensions{
		NodeID:          req.NodeID,
		Roles:           req.Roles,
		AllowedNetworks: req.AllowedNetworks,
		MeshID:          ca.MeshID,
		Compartment:     req.Compartment,
		WireGuardPubKey: req.WireGuardPubKey,
	}

	extensions, err := gwExt.BuildExtensions()
	if err != nil {
		return nil, nil, fmt.Errorf("build extensions: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   req.NodeID,
			Organization: ca.RootCert.Subject.Organization,
		},
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions:       extensions,
	}

	// Add mesh IP if provided
	if req.MeshIP != nil {
		template.IPAddresses = []net.IP{req.MeshIP}
	}

	// Sign with CA key
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		ca.RootCert,
		req.PublicKey,
		ca.rootKey,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("sign certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}

	return cert, certDER, nil
}

// CertificateToPEM encodes a certificate as PEM
func CertificateToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// PrivateKeyToPEM encodes an Ed25519 private key as PEM
func PrivateKeyToPEM(key ed25519.PrivateKey) ([]byte, error) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8,
	}), nil
}

func generateSerialNumber() (*big.Int, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	return serialNumber, nil
}

// CanSign returns whether this CA can sign certificates
func (ca *CertificateAuthority) CanSign() bool {
	return ca.canSign
}

// RootKey returns the CA's private key (for token signing)
// Returns nil if the CA was loaded without a private key
func (ca *CertificateAuthority) RootKey() ed25519.PrivateKey {
	return ca.rootKey
}

// Wipe securely erases the CA private key from memory
func (ca *CertificateAuthority) Wipe() {
	if ca.rootKey != nil {
		keys.WipeBytes(ca.rootKey)
		ca.rootKey = nil
	}
	ca.canSign = false
}
