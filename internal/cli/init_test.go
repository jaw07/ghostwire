package cli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/ghostwire/ghostwire/internal/config"
)

// TestInitializeMeshRoundTrip exercises the full mesh bootstrap: generate CA +
// admin cert + config, persist encrypted, reload, and verify the PKI is
// internally consistent (CA signs the admin cert, mesh ID = SHA-256(CA pubkey)).
func TestInitializeMeshRoundTrip(t *testing.T) {
	dir := t.TempDir()
	const pass = "correct horse battery staple"

	err := initializeMesh(
		"test-mesh", dir, "10.42.0.0/16", "admin-1",
		"vpn.example.com", ":8443", "gw.example.com:443", pass,
	)
	if err != nil {
		t.Fatalf("initializeMesh: %v", err)
	}

	loader := config.NewLoader(dir)
	if !loader.AdminConfigExists() {
		t.Fatal("admin config should exist after init")
	}

	// Wrong passphrase must fail to decrypt.
	if _, err := loader.LoadAdminConfig("wrong passphrase"); err == nil {
		t.Error("LoadAdminConfig with wrong passphrase should fail")
	}

	cfg, err := loader.LoadAdminConfig(pass)
	if err != nil {
		t.Fatalf("LoadAdminConfig: %v", err)
	}

	// Config field checks.
	checks := map[string]struct{ got, want string }{
		"MeshName":            {cfg.MeshName, "test-mesh"},
		"NodeID":              {cfg.NodeID, "admin-1"},
		"MeshSubnet":          {cfg.MeshSubnet, "10.42.0.0/16"},
		"AssignedIP":          {cfg.AssignedIP, "10.42.0.1"},
		"ServerName":          {cfg.Transport.HTTPS.ServerName, "vpn.example.com"},
		"ListenAddr":          {cfg.Transport.HTTPS.ListenAddr, ":8443"},
		"AdvertiseEndpoint":   {cfg.Transport.HTTPS.AdvertiseEndpoint, "gw.example.com:443"},
		"TransportListenAddr": {cfg.Transport.HTTPS.TransportListenAddr, ":8444"},
	}
	for name, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", name, c.got, c.want)
		}
	}
	if cfg.CAPrivateKey == "" || cfg.NodeCertificate == "" || cfg.CACertChain == "" {
		t.Fatal("CA key / node cert / CA chain must all be populated")
	}
	if cfg.MeshSecret == "" {
		t.Error("mesh secret should be set")
	}

	// Parse CA + admin certs.
	caCert := parseCertPEM(t, cfg.CACertChain)
	adminCert := parseCertPEM(t, cfg.NodeCertificate)

	// The CA must have actually signed the admin certificate.
	if err := adminCert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("admin cert not signed by CA: %v", err)
	}

	// Mesh ID must equal SHA-256 of the CA's Ed25519 public key.
	caPub, ok := caCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("CA key is not Ed25519")
	}
	wantMeshID := sha256.Sum256(caPub)
	if cfg.MeshID != hex.EncodeToString(wantMeshID[:]) {
		t.Errorf("MeshID = %s, want %s", cfg.MeshID, hex.EncodeToString(wantMeshID[:]))
	}

	// Admin IP must be allocated and NextIP advanced past it.
	if cfg.IPAllocator.Allocated["admin-1"] != "10.42.0.1" {
		t.Errorf("admin IP allocation = %q, want 10.42.0.1", cfg.IPAllocator.Allocated["admin-1"])
	}
	if cfg.IPAllocator.NextIP == "" || cfg.IPAllocator.NextIP == "10.42.0.1" {
		t.Errorf("NextIP should have advanced past the admin IP, got %q", cfg.IPAllocator.NextIP)
	}
}

func TestInitializeMeshRejectsBadSubnet(t *testing.T) {
	if err := initializeMesh("m", t.TempDir(), "not-a-cidr", "n", "", ":8443", "", "pass"); err == nil {
		t.Error("initializeMesh should reject an invalid subnet")
	}
}

func parseCertPEM(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}
