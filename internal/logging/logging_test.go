package logging

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLogLevels(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarn, "WARN"},
		{LevelError, "ERROR"},
		{LevelSecurity, "SECURITY"},
	}

	for _, tt := range tests {
		if got := tt.level.String(); got != tt.expected {
			t.Errorf("Level(%d).String() = %q, want %q", tt.level, got, tt.expected)
		}
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected Level
		wantErr  bool
	}{
		{"DEBUG", LevelDebug, false},
		{"debug", LevelDebug, false},
		{"INFO", LevelInfo, false},
		{"WARN", LevelWarn, false},
		{"ERROR", LevelError, false},
		{"SECURITY", LevelSecurity, false},
		{"invalid", LevelInfo, true},
	}

	for _, tt := range tests {
		got, err := ParseLevel(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.expected {
			t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestNewEntry(t *testing.T) {
	entry := NewEntry(LevelInfo, "test", "test message")
	if entry.Level != LevelInfo {
		t.Errorf("entry.Level = %v, want %v", entry.Level, LevelInfo)
	}
	if entry.Component != "test" {
		t.Errorf("entry.Component = %q, want %q", entry.Component, "test")
	}
	if entry.Message != "test message" {
		t.Errorf("entry.Message = %q, want %q", entry.Message, "test message")
	}
	if entry.Timestamp.IsZero() {
		t.Error("entry.Timestamp should not be zero")
	}
}

func TestEntryChaining(t *testing.T) {
	entry := NewEntry(LevelInfo, "test", "msg").
		WithNodeID("node-1").
		WithField("key", "value").
		WithSourceIP("192.168.1.1").
		WithPeerID("peer-1")

	if entry.NodeID != "node-1" {
		t.Errorf("NodeID = %q, want %q", entry.NodeID, "node-1")
	}
	if entry.Fields["key"] != "value" {
		t.Errorf("Fields[key] = %v, want %q", entry.Fields["key"], "value")
	}
	if entry.Sensitive == nil {
		t.Fatal("Sensitive should not be nil")
	}
	if entry.Sensitive.SourceIP != "192.168.1.1" {
		t.Errorf("Sensitive.SourceIP = %q, want %q", entry.Sensitive.SourceIP, "192.168.1.1")
	}
	if entry.Sensitive.PeerID != "peer-1" {
		t.Errorf("Sensitive.PeerID = %q, want %q", entry.Sensitive.PeerID, "peer-1")
	}
}

func TestEntryClone(t *testing.T) {
	original := NewEntry(LevelInfo, "test", "msg").
		WithField("key", "value").
		WithSourceIP("192.168.1.1")

	clone := original.Clone()

	// Modify original
	original.Fields["key"] = "modified"
	original.Sensitive.SourceIP = "10.0.0.1"

	// Clone should be unchanged
	if clone.Fields["key"] != "value" {
		t.Error("clone.Fields was modified when original changed")
	}
	if clone.Sensitive.SourceIP != "192.168.1.1" {
		t.Error("clone.Sensitive was modified when original changed")
	}
}

func TestLevelMarshalJSON(t *testing.T) {
	level := LevelInfo
	data, err := json.Marshal(level)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	if string(data) != `"INFO"` {
		t.Errorf("Marshal = %s, want %q", data, `"INFO"`)
	}
}

func TestLevelUnmarshalJSON(t *testing.T) {
	var level Level

	// String format
	if err := json.Unmarshal([]byte(`"WARN"`), &level); err != nil {
		t.Fatalf("Unmarshal string error: %v", err)
	}
	if level != LevelWarn {
		t.Errorf("Unmarshal string = %v, want %v", level, LevelWarn)
	}

	// Integer format
	if err := json.Unmarshal([]byte(`3`), &level); err != nil {
		t.Fatalf("Unmarshal int error: %v", err)
	}
	if level != LevelError {
		t.Errorf("Unmarshal int = %v, want %v", level, LevelError)
	}
}

func TestEncryptedLoggerBasic(t *testing.T) {
	dir := t.TempDir()
	passphrase := "test-passphrase"

	cfg := &Config{
		LogDir:        dir,
		NodeID:        "test-node",
		Passphrase:    passphrase,
		Level:         LevelDebug,
		BufferSize:    1,
		FlushInterval: time.Hour, // Don't auto-flush
	}

	logger, err := NewEncryptedLogger(cfg)
	if err != nil {
		t.Fatalf("NewEncryptedLogger error: %v", err)
	}

	// Log some entries
	logger.Info("test", "test message 1")
	logger.Log(NewEntry(LevelWarn, "test", "test message 2").WithSourceIP("192.168.1.1"))

	// Flush and close
	if err := logger.Flush(); err != nil {
		t.Fatalf("Flush error: %v", err)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	// Read back
	files, err := ListLogFiles(dir)
	if err != nil {
		t.Fatalf("ListLogFiles error: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("No log files found")
	}

	reader := NewReader(passphrase)
	entries, err := reader.ReadFile(files[0].Path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}

	// Check first entry
	if entries[0].Message != "test message 1" {
		t.Errorf("entries[0].Message = %q, want %q", entries[0].Message, "test message 1")
	}

	// Check second entry with decrypted sensitive data
	if entries[1].Sensitive == nil {
		t.Fatal("entries[1].Sensitive should not be nil after decryption")
	}
	if entries[1].Sensitive.SourceIP != "192.168.1.1" {
		t.Errorf("entries[1].Sensitive.SourceIP = %q, want %q", entries[1].Sensitive.SourceIP, "192.168.1.1")
	}
}

func TestFilter(t *testing.T) {
	entries := []*Entry{
		{Level: LevelDebug, Component: "a", Message: "debug msg"},
		{Level: LevelInfo, Component: "b", Message: "info msg"},
		{Level: LevelWarn, Component: "a", Message: "warn msg"},
		{Level: LevelError, Component: "b", Message: "error msg"},
	}

	// Filter by level
	warnLevel := LevelWarn
	filtered := FilterEntries(entries, &Filter{Level: &warnLevel})
	if len(filtered) != 1 || filtered[0].Level != LevelWarn {
		t.Errorf("Filter by level failed")
	}

	// Filter by min level
	filtered = FilterEntries(entries, &Filter{MinLevel: &warnLevel})
	if len(filtered) != 2 {
		t.Errorf("Filter by min level: got %d entries, want 2", len(filtered))
	}

	// Filter by component
	filtered = FilterEntries(entries, &Filter{Component: "a"})
	if len(filtered) != 2 {
		t.Errorf("Filter by component: got %d entries, want 2", len(filtered))
	}

	// Filter by message
	filtered = FilterEntries(entries, &Filter{MessageLike: "info"})
	if len(filtered) != 1 {
		t.Errorf("Filter by message: got %d entries, want 1", len(filtered))
	}
}

func TestSearch(t *testing.T) {
	entries := []*Entry{
		{Component: "auth", Message: "user logged in"},
		{Component: "network", Message: "connection established"},
		{Component: "auth", Message: "user logged out"},
	}

	// Search for "logged"
	results := Search(entries, "logged")
	if len(results) != 2 {
		t.Errorf("Search 'logged': got %d results, want 2", len(results))
	}

	// Search for "network" (in component)
	results = Search(entries, "network")
	if len(results) != 1 {
		t.Errorf("Search 'network': got %d results, want 1", len(results))
	}

	// Case insensitive
	results = Search(entries, "USER")
	if len(results) != 2 {
		t.Errorf("Search 'USER' (case insensitive): got %d results, want 2", len(results))
	}
}

func TestFormatEntry(t *testing.T) {
	entry := &Entry{
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Level:     LevelInfo,
		Component: "test",
		Message:   "hello world",
	}

	formatted := FormatEntry(entry, false)
	expected := "2024-01-15 10:30:00 [INFO] test: hello world"
	if formatted != expected {
		t.Errorf("FormatEntry = %q, want %q", formatted, expected)
	}
}

func TestRotator(t *testing.T) {
	dir := t.TempDir()

	// Create a test log file
	logPath := filepath.Join(dir, "test.log")
	if err := os.WriteFile(logPath, []byte("test content\n"), 0644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	rotator := NewRotator(&RotatorConfig{
		MaxSize:  100,
		Compress: false,
		MaxFiles: 2,
	})

	// Should rotate (file exists)
	if err := rotator.Rotate(logPath); err != nil {
		t.Fatalf("Rotate error: %v", err)
	}

	// Original file should be gone
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Error("Original file should be renamed")
	}

	// Should have rotated file
	matches, _ := filepath.Glob(filepath.Join(dir, "test.*.log"))
	if len(matches) != 1 {
		t.Errorf("Expected 1 rotated file, got %d", len(matches))
	}
}

func TestExportJSON(t *testing.T) {
	entries := []*Entry{
		NewEntry(LevelInfo, "test", "message 1"),
		NewEntry(LevelWarn, "test", "message 2"),
	}

	var buf bytes.Buffer
	if err := ExportJSON(entries, &buf); err != nil {
		t.Fatalf("ExportJSON error: %v", err)
	}

	// Should be valid JSON array
	var parsed []*Entry
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if len(parsed) != 2 {
		t.Errorf("len(parsed) = %d, want 2", len(parsed))
	}
}
