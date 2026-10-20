package cli

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/ghostwire/ghostwire/internal/pki"
)

// connState builds a tls.ConnectionState carrying the given DER chain.
func connState(t *testing.T, raw [][]byte) tls.ConnectionState {
	t.Helper()
	var certs []*x509.Certificate
	for _, der := range raw {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse cert: %v", err)
		}
		certs = append(certs, c)
	}
	return tls.ConnectionState{PeerCertificates: certs}
}

func TestPinnedMeshCAVerifier(t *testing.T) {
	ca, _, err := pki.NewCertificateAuthority(pki.DefaultCAConfig("pin-test"))
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	signed, err := generateTLSCertWithCA("admin.local", ca.RootCert, ca.RootKey())
	if err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	// generateTLSCertWithCA already appends the CA cert to the chain.
	chain := signed.Certificate
	if len(chain) != 2 {
		t.Fatalf("expected leaf+CA chain, got %d certs", len(chain))
	}
	leafOnly := chain[:1:1]

	t.Run("accepts CA-signed chain for matching mesh ID", func(t *testing.T) {
		if err := pinnedMeshCAVerifier(ca.MeshID)(connState(t, chain)); err != nil {
			t.Fatalf("expected success, got: %v", err)
		}
	})

	t.Run("rejects chain when mesh ID differs", func(t *testing.T) {
		wrong := sha256.Sum256([]byte("another mesh"))
		err := pinnedMeshCAVerifier(wrong)(connState(t, chain))
		if err == nil || !strings.Contains(err.Error(), "mesh ID mismatch") {
			t.Fatalf("expected mesh ID mismatch, got: %v", err)
		}
	})

	t.Run("rejects leaf without CA in chain", func(t *testing.T) {
		err := pinnedMeshCAVerifier(ca.MeshID)(connState(t, leafOnly))
		if err == nil || !strings.Contains(err.Error(), "mesh ID mismatch") {
			t.Fatalf("expected error for chain missing CA, got: %v", err)
		}
	})

	t.Run("rejects self-signed cert", func(t *testing.T) {
		self, err := generateTLSCert("admin.local")
		if err != nil {
			t.Fatalf("self-sign: %v", err)
		}
		if err := pinnedMeshCAVerifier(ca.MeshID)(connState(t, self.Certificate)); err == nil {
			t.Fatal("expected error for self-signed cert")
		}
	})

	t.Run("rejects leaf signed by a different CA even if mesh CA is presented", func(t *testing.T) {
		other, _, err := pki.NewCertificateAuthority(pki.DefaultCAConfig("other"))
		if err != nil {
			t.Fatalf("other CA: %v", err)
		}
		otherLeaf, err := generateTLSCertWithCA("admin.local", other.RootCert, other.RootKey())
		if err != nil {
			t.Fatalf("sign with other CA: %v", err)
		}
		// Present: leaf signed by other CA, other CA, and the real mesh CA.
		mixed := append(otherLeaf.Certificate[:len(otherLeaf.Certificate):len(otherLeaf.Certificate)], ca.RootCert.Raw)
		err = pinnedMeshCAVerifier(ca.MeshID)(connState(t, mixed))
		if err == nil || !strings.Contains(err.Error(), "does not chain") {
			t.Fatalf("expected chain failure, got: %v", err)
		}
	})

	t.Run("rejects empty chain", func(t *testing.T) {
		if err := pinnedMeshCAVerifier(ca.MeshID)(connState(t, nil)); err == nil {
			t.Fatal("expected error for empty chain")
		}
	})
}
