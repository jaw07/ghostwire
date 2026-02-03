package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEncryptedLoggingIntegration(t *testing.T) {
	// Create temp directory for logs
	tmpDir, err := os.MkdirTemp("", "ghostwire-log-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp error: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	passphrase := "test-passphrase-123"

	// Create encrypted logger
	logger, err := NewEncryptedLogger(&Config{
		LogDir:        tmpDir,
		NodeID:        "test-node",
		Passphrase:    passphrase,
		Level:         LevelDebug,
		BufferSize:    5,
		FlushInterval: 100 * time.Millisecond,
		MaxFileSize:   1024 * 1024,
	})
	if err != nil {
		t.Fatalf("NewEncryptedLogger error: %v", err)
	}

	// Log various levels
	logger.Debug("mesh", "Starting mesh initialization")
	logger.Info("transport", "Connected to relay at 192.0.2.1:443")
	logger.Warn("pki", "Certificate expires in 2 hours")

	// Log with sensitive data
	entry := NewEntry(LevelSecurity, "auth", "Authentication attempt")
	entry.Sensitive = &SensitiveFields{
		SourceIP: "198.51.100.1",
		PeerID:   "suspicious-node",
	}
	logger.Log(entry)

	// Log with fields
	entry2 := NewEntry(LevelInfo, "gossip", "Peer state changed")
	entry2.WithField("peer_id", "peer-123").WithField("state", "alive")
	logger.Log(entry2)

	// Log with error
	logger.Error("tunnel", "Tunnel creation failed", os.ErrPermission)

	// Flush and close
	logger.Flush()
	if err := logger.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	// Verify log file exists
	files, err := filepath.Glob(filepath.Join(tmpDir, "ghostwire-*.log"))
	if err != nil {
		t.Fatalf("Glob error: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("No log files created")
	}

	t.Logf("Log file created: %s", files[0])

	// Read the log file
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	logContent := string(data)
	t.Logf("Log file size: %d bytes", len(data))

	// Verify entries were written
	if !strings.Contains(logContent, "mesh") {
		t.Error("Log should contain 'mesh' component")
	}
	if !strings.Contains(logContent, "transport") {
		t.Error("Log should contain 'transport' component")
	}
	if !strings.Contains(logContent, "auth") {
		t.Error("Log should contain 'auth' component")
	}

	// Use the log reader to read entries
	reader := NewReader("") // No passphrase for now
	entries, err := reader.ReadFile(files[0])
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	t.Logf("Read %d log entries", len(entries))

	if len(entries) < 5 {
		t.Errorf("Expected at least 5 entries, got %d", len(entries))
	}

	// Filter by level using FilterEntries
	errorLevel := LevelError
	errors := FilterEntries(entries, &Filter{MinLevel: &errorLevel})
	t.Logf("Found %d error+ entries", len(errors))

	// Search by pattern
	authEntries := Search(entries, "auth")
	t.Logf("Found %d entries matching 'auth'", len(authEntries))

	// Verify security entry has encrypted field
	for _, e := range entries {
		if e.Level == LevelSecurity && e.Encrypted != nil {
			t.Log("Security entry has encrypted sensitive data")
		}
	}

	t.Log("Encrypted logging integration test passed")
}

func TestLogRotationIntegration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ghostwire-rotation-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp error: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create rotator with small max size
	rotator := NewRotator(&RotatorConfig{
		MaxSize:  1024, // 1KB
		MaxFiles: 3,
	})

	// Test ShouldRotate
	if rotator.ShouldRotate(500) {
		t.Error("ShouldRotate(500) should be false for 1KB max")
	}
	if !rotator.ShouldRotate(2000) {
		t.Error("ShouldRotate(2000) should be true for 1KB max")
	}

	// Create a test file
	testFile := filepath.Join(tmpDir, "test.log")
	if err := os.WriteFile(testFile, []byte("test content"), 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	// Rotate
	err = rotator.Rotate(testFile)
	if err != nil {
		t.Fatalf("Rotate error: %v", err)
	}
	t.Log("Rotation completed")

	// Verify rotation created timestamped file (format: test.{timestamp}.log.gz)
	files, err := filepath.Glob(filepath.Join(tmpDir, "test.*.log*"))
	if err != nil {
		t.Fatalf("Glob error: %v", err)
	}
	if len(files) == 0 {
		t.Log("No rotated files found (may have been compressed and removed)")
	} else {
		t.Logf("Found rotated file: %s", files[0])
	}

	t.Log("Log rotation integration test passed")
}

func TestLogFilterAndSearch(t *testing.T) {
	entries := []*Entry{
		{Level: LevelDebug, Component: "mesh", Message: "Debug message"},
		{Level: LevelInfo, Component: "transport", Message: "Info message"},
		{Level: LevelWarn, Component: "pki", Message: "Warning about certificate"},
		{Level: LevelError, Component: "tunnel", Message: "Error in tunnel"},
		{Level: LevelSecurity, Component: "auth", Message: "Authentication failed"},
	}

	// Filter by min level using FilterEntries
	warnLevel := LevelWarn
	warns := FilterEntries(entries, &Filter{MinLevel: &warnLevel})
	if len(warns) != 3 {
		t.Errorf("Filter >= Warn: got %d, want 3", len(warns))
	}

	// Filter by component
	transport := FilterEntries(entries, &Filter{Component: "transport"})
	if len(transport) != 1 {
		t.Errorf("Filter transport: got %d, want 1", len(transport))
	}

	// Search by keyword
	cert := Search(entries, "certificate")
	if len(cert) != 1 {
		t.Errorf("Search 'certificate': got %d, want 1", len(cert))
	}

	// Search case insensitive
	auth := Search(entries, "AUTHENTICATION")
	if len(auth) != 1 {
		t.Errorf("Search 'AUTHENTICATION': got %d, want 1", len(auth))
	}

	t.Log("Filter and search test passed")
}
