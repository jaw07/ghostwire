// Package daemon provides daemon management utilities for GHOSTWIRE.
package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const (
	// PIDFileName is the name of the PID file
	PIDFileName = "ghostwire.pid"
)

// Manager handles daemon lifecycle operations
type Manager struct {
	configDir string
}

// NewManager creates a new daemon manager
func NewManager(configDir string) *Manager {
	return &Manager{configDir: configDir}
}

// PIDFile returns the path to the PID file
func (m *Manager) PIDFile() string {
	return filepath.Join(m.configDir, PIDFileName)
}

// WritePID writes the current process ID and executable path to the PID file.
// The executable path lets IsRunning detect PID reuse by an unrelated process.
func (m *Manager) WritePID() error {
	exe, _ := os.Executable() // best effort; empty is tolerated on read
	content := fmt.Sprintf("%d\n%s\n", os.Getpid(), exe)
	return os.WriteFile(m.PIDFile(), []byte(content), 0600)
}

// ReadPID reads the PID from the PID file.
func (m *Manager) ReadPID() (int, error) {
	pid, _, err := m.readPIDInfo()
	return pid, err
}

// readPIDInfo reads the PID and recorded executable path from the PID file.
// The executable path may be empty (older PID files or unknown executable).
func (m *Manager) readPIDInfo() (int, string, error) {
	data, err := os.ReadFile(m.PIDFile())
	if err != nil {
		return 0, "", err
	}
	lines := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)
	pid, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil {
		return 0, "", err
	}
	exe := ""
	if len(lines) > 1 {
		exe = strings.TrimSpace(lines[1])
	}
	return pid, exe, nil
}

// processExePath returns the executable path of a live process where the OS
// exposes it (Linux /proc). The bool is false when it cannot be determined.
func processExePath(pid int) (string, bool) {
	if runtime.GOOS == "linux" {
		p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil {
			return "", false
		}
		return p, true
	}
	return "", false
}

// RemovePID removes the PID file
func (m *Manager) RemovePID() error {
	return os.Remove(m.PIDFile())
}

// IsRunning checks if a daemon is running
func (m *Manager) IsRunning() (bool, int) {
	pid, exe, err := m.readPIDInfo()
	if err != nil {
		return false, 0
	}

	// Check if process exists
	process, err := os.FindProcess(pid)
	if err != nil {
		return false, 0
	}

	// Send signal 0 to check if process exists
	err = process.Signal(syscall.Signal(0))
	if err != nil {
		// Process doesn't exist, clean up stale PID file
		m.RemovePID()
		return false, 0
	}

	// Guard against PID reuse: if we recorded the daemon's executable and can
	// read the live process's executable (Linux), a mismatch means the PID was
	// recycled by an unrelated process. Treat the daemon as not running rather
	// than risk signaling (and later SIGKILLing) the wrong process.
	if exe != "" {
		if live, ok := processExePath(pid); ok && live != exe {
			m.RemovePID()
			return false, 0
		}
	}

	return true, pid
}

// Stop sends a termination signal to the daemon
func (m *Manager) Stop() error {
	running, pid := m.IsRunning()
	if !running {
		return fmt.Errorf("daemon is not running")
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process: %w", err)
	}

	// Send SIGTERM for graceful shutdown
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("send signal: %w", err)
	}

	return nil
}

// ForceStop sends a kill signal to the daemon
func (m *Manager) ForceStop() error {
	running, pid := m.IsRunning()
	if !running {
		return fmt.Errorf("daemon is not running")
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process: %w", err)
	}

	// Send SIGKILL for immediate termination
	if err := process.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("send signal: %w", err)
	}

	m.RemovePID()
	return nil
}
