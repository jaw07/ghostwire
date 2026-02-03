package pki

import (
	"net/netip"
	"testing"
	"time"

	"github.com/ghostwire/ghostwire/internal/keys"
)

func TestNewCertificateAuthority(t *testing.T) {
	cfg := DefaultCAConfig("test-mesh")
	ca, kp, err := NewCertificateAuthority(cfg)
	if err != nil {
		t.Fatalf("NewCertificateAuthority failed: %v", err)
	}
	defer kp.Wipe()
	defer ca.Wipe()

	if !ca.CanSign() {
		t.Error("CA should be able to sign")
	}

	if ca.RootCert == nil {
		t.Error("CA should have root certificate")
	}

	if ca.RootCert.Subject.CommonName != "GHOSTWIRE Root CA" {
		t.Errorf("Unexpected CA common name: %s", ca.RootCert.Subject.CommonName)
	}

	if !ca.RootCert.IsCA {
		t.Error("Root certificate should be a CA")
	}

	// Verify mesh ID is derived from public key
	var zeroID [32]byte
	if ca.MeshID == zeroID {
		t.Error("Mesh ID should not be zero")
	}
}

func TestIssueCertificate(t *testing.T) {
	// Create CA
	cfg := DefaultCAConfig("test-mesh")
	ca, caKp, err := NewCertificateAuthority(cfg)
	if err != nil {
		t.Fatalf("NewCertificateAuthority failed: %v", err)
	}
	defer caKp.Wipe()
	defer ca.Wipe()

	// Create node keypair
	nodeKp, err := keys.Generate()
	if err != nil {
		t.Fatalf("Generate node keypair failed: %v", err)
	}
	defer nodeKp.Wipe()

	// Issue certificate
	req := &NodeCertRequest{
		NodeID:          "test-node-1",
		Roles:           []string{RoleOperator},
		PublicKey:       nodeKp.Ed25519PublicKey,
		WireGuardPubKey: nodeKp.X25519PublicKey,
		Validity:        24 * time.Hour,
	}

	cert, _, err := ca.IssueCertificate(req)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	if cert.Subject.CommonName != "test-node-1" {
		t.Errorf("Unexpected cert common name: %s", cert.Subject.CommonName)
	}

	// Parse extensions
	gwExt, err := ParseExtensions(cert.Extensions)
	if err != nil {
		t.Fatalf("ParseExtensions failed: %v", err)
	}

	if gwExt.NodeID != "test-node-1" {
		t.Errorf("Unexpected node ID: %s", gwExt.NodeID)
	}

	if len(gwExt.Roles) != 1 || gwExt.Roles[0] != RoleOperator {
		t.Errorf("Unexpected roles: %v", gwExt.Roles)
	}

	if gwExt.MeshID != ca.MeshID {
		t.Error("Mesh ID mismatch")
	}

	if gwExt.WireGuardPubKey != nodeKp.X25519PublicKey {
		t.Error("WireGuard public key mismatch")
	}
}

func TestIssueCertificateWithAllowedNetworks(t *testing.T) {
	cfg := DefaultCAConfig("test-mesh")
	ca, caKp, err := NewCertificateAuthority(cfg)
	if err != nil {
		t.Fatalf("NewCertificateAuthority failed: %v", err)
	}
	defer caKp.Wipe()
	defer ca.Wipe()

	nodeKp, err := keys.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer nodeKp.Wipe()

	networks := []AllowedNetwork{
		{Prefix: netip.MustParsePrefix("10.0.0.0/24"), Direction: DirectionBidirectional},
		{Prefix: netip.MustParsePrefix("192.168.1.0/24"), Direction: DirectionEgressOnly},
	}

	req := &NodeCertRequest{
		NodeID:          "test-node-2",
		Roles:           []string{RoleSensor},
		AllowedNetworks: networks,
		Compartment:     "field-team-alpha",
		PublicKey:       nodeKp.Ed25519PublicKey,
		WireGuardPubKey: nodeKp.X25519PublicKey,
	}

	cert, _, err := ca.IssueCertificate(req)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	gwExt, err := ParseExtensions(cert.Extensions)
	if err != nil {
		t.Fatalf("ParseExtensions failed: %v", err)
	}

	if len(gwExt.AllowedNetworks) != 2 {
		t.Fatalf("Expected 2 allowed networks, got %d", len(gwExt.AllowedNetworks))
	}

	if gwExt.AllowedNetworks[0].Prefix.String() != "10.0.0.0/24" {
		t.Errorf("Unexpected first network: %s", gwExt.AllowedNetworks[0].Prefix)
	}

	if gwExt.AllowedNetworks[1].Direction != DirectionEgressOnly {
		t.Errorf("Unexpected second network direction: %v", gwExt.AllowedNetworks[1].Direction)
	}

	if gwExt.Compartment != "field-team-alpha" {
		t.Errorf("Unexpected compartment: %s", gwExt.Compartment)
	}
}

func TestVerifyCertificate(t *testing.T) {
	// Create CA
	cfg := DefaultCAConfig("test-mesh")
	ca, caKp, err := NewCertificateAuthority(cfg)
	if err != nil {
		t.Fatalf("NewCertificateAuthority failed: %v", err)
	}
	defer caKp.Wipe()
	defer ca.Wipe()

	// Create and issue node certificate
	nodeKp, err := keys.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer nodeKp.Wipe()

	req := &NodeCertRequest{
		NodeID:          "verified-node",
		Roles:           []string{RoleOperator, RoleRelay},
		PublicKey:       nodeKp.Ed25519PublicKey,
		WireGuardPubKey: nodeKp.X25519PublicKey,
	}

	cert, _, err := ca.IssueCertificate(req)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	// Create verifier
	verifier := NewVerifier(ca.RootCert, ca.MeshID)

	// Verify the certificate
	peer, err := verifier.VerifyCertificate(cert)
	if err != nil {
		t.Fatalf("VerifyCertificate failed: %v", err)
	}

	if peer.NodeID != "verified-node" {
		t.Errorf("Unexpected node ID: %s", peer.NodeID)
	}

	if !peer.HasRole(RoleOperator) {
		t.Error("Peer should have operator role")
	}

	if !peer.IsRelay() {
		t.Error("Peer should be able to relay")
	}

	if peer.IsAdmin() {
		t.Error("Peer should not be admin")
	}
}

func TestVerifyCertificateWithWireGuard(t *testing.T) {
	cfg := DefaultCAConfig("test-mesh")
	ca, caKp, err := NewCertificateAuthority(cfg)
	if err != nil {
		t.Fatalf("NewCertificateAuthority failed: %v", err)
	}
	defer caKp.Wipe()
	defer ca.Wipe()

	nodeKp, err := keys.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer nodeKp.Wipe()

	req := &NodeCertRequest{
		NodeID:          "wg-node",
		Roles:           []string{RoleOperator},
		PublicKey:       nodeKp.Ed25519PublicKey,
		WireGuardPubKey: nodeKp.X25519PublicKey,
	}

	cert, _, err := ca.IssueCertificate(req)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	verifier := NewVerifier(ca.RootCert, ca.MeshID)

	// Verify with correct WireGuard key
	peer, err := verifier.VerifyCertificateWithWireGuard(cert, nodeKp.X25519PublicKey)
	if err != nil {
		t.Fatalf("VerifyCertificateWithWireGuard failed: %v", err)
	}

	if peer.WireGuardPubKey != nodeKp.X25519PublicKey {
		t.Error("WireGuard public key mismatch")
	}

	// Verify with wrong WireGuard key should fail
	wrongKp, _ := keys.Generate()
	defer wrongKp.Wipe()

	_, err = verifier.VerifyCertificateWithWireGuard(cert, wrongKp.X25519PublicKey)
	if err == nil {
		t.Error("Verification should fail with wrong WireGuard key")
	}
}

func TestVerifyExpiredCertificate(t *testing.T) {
	cfg := DefaultCAConfig("test-mesh")
	ca, caKp, err := NewCertificateAuthority(cfg)
	if err != nil {
		t.Fatalf("NewCertificateAuthority failed: %v", err)
	}
	defer caKp.Wipe()
	defer ca.Wipe()

	nodeKp, err := keys.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer nodeKp.Wipe()

	// Issue certificate with very short validity (already expired)
	req := &NodeCertRequest{
		NodeID:          "expired-node",
		Roles:           []string{RoleOperator},
		PublicKey:       nodeKp.Ed25519PublicKey,
		WireGuardPubKey: nodeKp.X25519PublicKey,
		Validity:        -1 * time.Hour, // Already expired
	}

	cert, _, err := ca.IssueCertificate(req)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	verifier := NewVerifier(ca.RootCert, ca.MeshID)

	_, err = verifier.VerifyCertificate(cert)
	if err != ErrCertExpired {
		t.Errorf("Expected ErrCertExpired, got: %v", err)
	}
}

func TestVerifyMeshIDMismatch(t *testing.T) {
	// Create two different CAs
	ca1, caKp1, _ := NewCertificateAuthority(DefaultCAConfig("mesh-1"))
	defer caKp1.Wipe()
	defer ca1.Wipe()

	ca2, caKp2, _ := NewCertificateAuthority(DefaultCAConfig("mesh-2"))
	defer caKp2.Wipe()
	defer ca2.Wipe()

	// Issue certificate with CA1
	nodeKp, _ := keys.Generate()
	defer nodeKp.Wipe()

	req := &NodeCertRequest{
		NodeID:          "cross-mesh-node",
		Roles:           []string{RoleOperator},
		PublicKey:       nodeKp.Ed25519PublicKey,
		WireGuardPubKey: nodeKp.X25519PublicKey,
	}

	cert, _, _ := ca1.IssueCertificate(req)

	// Try to verify with CA2's mesh ID (should fail mesh ID check, but also chain check)
	verifier := NewVerifier(ca2.RootCert, ca2.MeshID)

	_, err := verifier.VerifyCertificate(cert)
	if err == nil {
		t.Error("Verification should fail for certificate from different mesh")
	}
}

func TestIsValidRole(t *testing.T) {
	tests := []struct {
		role  string
		valid bool
	}{
		{RoleAdmin, true},
		{RoleRelay, true},
		{RoleOperator, true},
		{RoleSensor, true},
		{RoleEndpoint, true},
		{"invalid", false},
		{"", false},
		{"ADMIN", false}, // Case-sensitive
	}

	for _, tt := range tests {
		if got := IsValidRole(tt.role); got != tt.valid {
			t.Errorf("IsValidRole(%q) = %v, want %v", tt.role, got, tt.valid)
		}
	}
}

func TestCertificatePEM(t *testing.T) {
	cfg := DefaultCAConfig("test-mesh")
	ca, caKp, err := NewCertificateAuthority(cfg)
	if err != nil {
		t.Fatalf("NewCertificateAuthority failed: %v", err)
	}
	defer caKp.Wipe()
	defer ca.Wipe()

	// Encode to PEM
	pem := CertificateToPEM(ca.RootCert)
	if len(pem) == 0 {
		t.Error("PEM encoding returned empty result")
	}

	// Decode from PEM
	parsed, err := ParseCertificatePEM(pem)
	if err != nil {
		t.Fatalf("ParseCertificatePEM failed: %v", err)
	}

	if parsed.Subject.CommonName != ca.RootCert.Subject.CommonName {
		t.Error("Parsed certificate doesn't match original")
	}
}
