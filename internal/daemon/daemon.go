// Package daemon provides daemon management utilities for GHOSTWIRE.
package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

// WritePID writes the current process ID to the PID file
func (m *Manager) WritePID() error {
	pid := os.Getpid()
	return os.WriteFile(m.PIDFile(), []byte(strconv.Itoa(pid)), 0600)
}

// ReadPID reads the PID from the PID file
func (m *Manager) ReadPID() (int, error) {
	data, err := os.ReadFile(m.PIDFile())
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(string(data))
}

// RemovePID removes the PID file
func (m *Manager) RemovePID() error {
	return os.Remove(m.PIDFile())
}

// IsRunning checks if a daemon is running
func (m *Manager) IsRunning() (bool, int) {
	pid, err := m.ReadPID()
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
