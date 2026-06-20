package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestPIDRoundTripWithExe(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	if err := m.WritePID(); err != nil {
		t.Fatalf("WritePID: %v", err)
	}

	pid, exe, err := m.readPIDInfo()
	if err != nil {
		t.Fatalf("readPIDInfo: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("pid = %d, want %d", pid, os.Getpid())
	}
	// The executable path should have been recorded (non-empty on supported OSes).
	if exe == "" {
		t.Log("warning: executable path empty (os.Executable unsupported here)")
	}

	// ReadPID must remain compatible.
	if p, err := m.ReadPID(); err != nil || p != pid {
		t.Errorf("ReadPID() = %d, %v; want %d, nil", p, err, pid)
	}
}

func TestReadPIDInfoLegacyFormat(t *testing.T) {
	// A legacy PID file with just the number (no exe line) must still parse.
	dir := t.TempDir()
	m := NewManager(dir)
	if err := os.WriteFile(m.PIDFile(), []byte(strconv.Itoa(4242)), 0600); err != nil {
		t.Fatal(err)
	}
	pid, exe, err := m.readPIDInfo()
	if err != nil {
		t.Fatalf("readPIDInfo legacy: %v", err)
	}
	if pid != 4242 || exe != "" {
		t.Errorf("got pid=%d exe=%q, want 4242 and empty exe", pid, exe)
	}
}

func TestIsRunningStalePID(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)
	// A PID that is almost certainly not alive.
	if err := os.WriteFile(m.PIDFile(), []byte("999999\n/nonexistent/ghostwire\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if running, _ := m.IsRunning(); running {
		t.Error("IsRunning should report false for a dead PID")
	}
	// Stale PID file should have been cleaned up.
	if _, err := os.Stat(filepath.Join(dir, PIDFileName)); !os.IsNotExist(err) {
		t.Error("stale PID file should have been removed")
	}
}
