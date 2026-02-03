package tunnel

import (
	"net/netip"
	"testing"
)

func TestKeyToHex(t *testing.T) {
	key := []byte{0x00, 0x01, 0x02, 0x0f, 0x10, 0xab, 0xff}
	expected := "0001020f10abff"

	result := keyToHex(key)
	if result != expected {
		t.Errorf("keyToHex() = %s, want %s", result, expected)
	}
}

func TestDerivePublicKey(t *testing.T) {
	// Known test vector for Curve25519
	privateKey := make([]byte, 32)
	for i := range privateKey {
		privateKey[i] = byte(i)
	}

	publicKey := derivePublicKey(privateKey)
	if len(publicKey) != 32 {
		t.Errorf("derivePublicKey() returned %d bytes, want 32", len(publicKey))
	}

	// Verify it's not all zeros
	allZero := true
	for _, b := range publicKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("derivePublicKey() returned all zeros")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.InterfaceName != "gw0" {
		t.Errorf("InterfaceName = %s, want gw0", cfg.InterfaceName)
	}
	if cfg.MTU != 1420 {
		t.Errorf("MTU = %d, want 1420", cfg.MTU)
	}
	if cfg.ListenPort != 0 {
		t.Errorf("ListenPort = %d, want 0", cfg.ListenPort)
	}
}

func TestPeerNewAndStatus(t *testing.T) {
	var pubKey [32]byte
	for i := range pubKey {
		pubKey[i] = byte(i)
	}

	meshIP := netip.MustParseAddr("10.100.0.5")

	cfg := &PeerConfig{
		NodeID:              "test-node",
		PublicKey:           pubKey,
		MeshIP:              meshIP,
		PersistentKeepalive: 25,
		Roles:               []string{"operator"},
	}

	peer := NewPeer(cfg)

	if peer.NodeID != "test-node" {
		t.Errorf("NodeID = %s, want test-node", peer.NodeID)
	}
	if peer.PublicKey != pubKey {
		t.Error("PublicKey mismatch")
	}
	if peer.MeshIP != meshIP {
		t.Errorf("MeshIP = %s, want %s", peer.MeshIP, meshIP)
	}
	if peer.PersistentKeepalive != 25 {
		t.Errorf("PersistentKeepalive = %d, want 25", peer.PersistentKeepalive)
	}
	if !peer.HasRole("operator") {
		t.Error("HasRole(operator) = false, want true")
	}
	if peer.HasRole("admin") {
		t.Error("HasRole(admin) = true, want false")
	}
	if peer.IsConnected() {
		t.Error("IsConnected() = true, want false (no handshake)")
	}

	status := peer.Status()
	if status.NodeID != "test-node" {
		t.Errorf("Status().NodeID = %s, want test-node", status.NodeID)
	}
	if status.Connected {
		t.Error("Status().Connected = true, want false")
	}
}
