package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEncryptDecryptConfig(t *testing.T) {
	encryptor := NewEncryptor()
	passphrase := "test-passphrase-12345"

	config := &MeshConfig{
		Version:    1,
		MeshName:   "test-mesh",
		MeshID:     "abc123",
		NodeID:     "node-1",
		Roles:      []string{"operator"},
		MeshSubnet: "10.100.0.0/16",
		AssignedIP: "10.100.0.5",
		Transport: TransportConfig{
			Active: "https-mimic",
			HTTPS: HTTPSTransportConfig{
				ServerName:  "example.com",
				Fingerprint: "chrome",
			},
		},
		Peers: []PeerConfig{
			{
				NodeID:    "relay-1",
				PublicKey: "base64-key-here",
				Endpoints: []string{"relay.example.com:443"},
				Roles:     []string{"relay"},
			},
		},
	}

	// Encrypt
	encrypted, err := encryptor.EncryptConfig(config, passphrase)
	if err != nil {
		t.Fatalf("EncryptConfig failed: %v", err)
	}

	if len(encrypted) == 0 {
		t.Error("Encrypted data is empty")
	}

	// Encrypted data should not contain plaintext
	if containsString(encrypted, "test-mesh") {
		t.Error("Encrypted data contains plaintext mesh name")
	}

	// Decrypt
	decrypted, err := encryptor.DecryptConfig(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptConfig failed: %v", err)
	}

	// Verify decrypted matches original
	if decrypted.MeshName != config.MeshName {
		t.Errorf("Mesh name mismatch: got %s, want %s", decrypted.MeshName, config.MeshName)
	}
	if decrypted.NodeID != config.NodeID {
		t.Errorf("Node ID mismatch: got %s, want %s", decrypted.NodeID, config.NodeID)
	}
	if len(decrypted.Peers) != 1 {
		t.Errorf("Peers count mismatch: got %d, want 1", len(decrypted.Peers))
	}
	if decrypted.Peers[0].NodeID != "relay-1" {
		t.Errorf("Peer node ID mismatch: got %s, want relay-1", decrypted.Peers[0].NodeID)
	}
}

func TestDecryptWithWrongPassphrase(t *testing.T) {
	encryptor := NewEncryptor()

	config := DefaultConfig()
	config.MeshName = "test-mesh"

	encrypted, err := encryptor.EncryptConfig(config, "correct-passphrase")
	if err != nil {
		t.Fatalf("EncryptConfig failed: %v", err)
	}

	_, err = encryptor.DecryptConfig(encrypted, "wrong-passphrase")
	if err == nil {
		t.Error("Decryption should fail with wrong passphrase")
	}
}

func TestEncryptDecryptAdminConfig(t *testing.T) {
	encryptor := NewEncryptor()
	passphrase := "admin-passphrase"

	config := &AdminConfig{
		MeshConfig: MeshConfig{
			Version:  1,
			MeshName: "admin-mesh",
			NodeID:   "admin-node",
			Roles:    []string{"admin"},
		},
		CAPrivateKey: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
		IPAllocator: IPAllocatorState{
			Subnet:    "10.100.0.0/16",
			Allocated: map[string]string{"node-1": "10.100.0.2"},
			NextIP:    "10.100.0.3",
		},
	}

	encrypted, err := encryptor.EncryptAdminConfig(config, passphrase)
	if err != nil {
		t.Fatalf("EncryptAdminConfig failed: %v", err)
	}

	decrypted, err := encryptor.DecryptAdminConfig(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptAdminConfig failed: %v", err)
	}

	if decrypted.CAPrivateKey != config.CAPrivateKey {
		t.Error("CA private key mismatch")
	}
	if decrypted.IPAllocator.NextIP != "10.100.0.3" {
		t.Error("IP allocator state mismatch")
	}
}

func TestLoaderSaveLoad(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "ghostwire-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	loader := NewLoader(tmpDir)
	passphrase := "test-passphrase"

	config := DefaultConfig()
	config.MeshName = "loader-test-mesh"
	config.NodeID = "loader-test-node"

	// Save config
	if err := loader.SaveConfig(config, passphrase); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	// Verify file exists
	if !loader.ConfigExists() {
		t.Error("Config file should exist after save")
	}

	// Load config
	loaded, err := loader.LoadConfig(passphrase)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded.MeshName != config.MeshName {
		t.Errorf("Loaded mesh name mismatch: got %s, want %s", loaded.MeshName, config.MeshName)
	}
}

func TestLoaderWipeConfig(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ghostwire-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	loader := NewLoader(tmpDir)
	passphrase := "test-passphrase"

	config := DefaultConfig()
	config.MeshName = "wipe-test"

	if err := loader.SaveConfig(config, passphrase); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	if !loader.ConfigExists() {
		t.Fatal("Config should exist before wipe")
	}

	if err := loader.WipeConfig(); err != nil {
		t.Fatalf("WipeConfig failed: %v", err)
	}

	if loader.ConfigExists() {
		t.Error("Config should not exist after wipe")
	}
}

func TestSecureDelete(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ghostwire-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "test-secret.txt")
	testData := []byte("this is secret data that should be wiped")

	if err := os.WriteFile(testFile, testData, 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	if err := SecureDelete(testFile); err != nil {
		t.Fatalf("SecureDelete failed: %v", err)
	}

	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("File should not exist after secure delete")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Version != 1 {
		t.Errorf("Default version should be 1, got %d", config.Version)
	}

	if config.Transport.Active != "https-mimic" {
		t.Errorf("Default transport should be https-mimic, got %s", config.Transport.Active)
	}

	if config.CertRenewalThreshold != 6*time.Hour {
		t.Errorf("Default cert renewal threshold should be 6h, got %v", config.CertRenewalThreshold)
	}
}

func containsString(data []byte, s string) bool {
	return len(data) > 0 && len(s) > 0 &&
		string(data) == s ||
		len(data) >= len(s) && containsBytes(data, []byte(s))
}

func containsBytes(data, pattern []byte) bool {
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
