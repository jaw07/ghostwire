package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ghostwire/ghostwire/internal/keys"
)

const (
	// DefaultConfigDir is the default configuration directory
	DefaultConfigDir = ".config/gw"

	// DefaultConfigFile is the default encrypted config filename
	DefaultConfigFile = "config.enc"

	// AdminConfigFile is the admin config filename
	AdminConfigFile = "admin.enc"
)

// Loader handles loading and saving configuration files
type Loader struct {
	encryptor *Encryptor
	configDir string
}

// NewLoader creates a new config loader
func NewLoader(configDir string) *Loader {
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			configDir = DefaultConfigDir
		} else {
			configDir = filepath.Join(home, DefaultConfigDir)
		}
	}

	return &Loader{
		encryptor: NewEncryptor(),
		configDir: configDir,
	}
}

// ConfigDir returns the configuration directory path
func (l *Loader) ConfigDir() string {
	return l.configDir
}

// ConfigPath returns the full path to the config file
func (l *Loader) ConfigPath() string {
	return filepath.Join(l.configDir, DefaultConfigFile)
}

// AdminConfigPath returns the full path to the admin config file
func (l *Loader) AdminConfigPath() string {
	return filepath.Join(l.configDir, AdminConfigFile)
}

// EnsureConfigDir creates the config directory if it doesn't exist
func (l *Loader) EnsureConfigDir() error {
	return os.MkdirAll(l.configDir, 0700)
}

// LoadConfig loads and decrypts the mesh configuration
func (l *Loader) LoadConfig(passphrase string) (*MeshConfig, error) {
	return l.LoadConfigFrom(l.ConfigPath(), passphrase)
}

// LoadConfigFrom loads and decrypts a mesh configuration from a specific path
func (l *Loader) LoadConfigFrom(path, passphrase string) (*MeshConfig, error) {
	encrypted, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	config, err := l.encryptor.DecryptConfig(encrypted, passphrase)
	if err != nil {
		return nil, fmt.Errorf("decrypt config: %w", err)
	}

	return config, nil
}

// SaveConfig encrypts and saves the mesh configuration
func (l *Loader) SaveConfig(config *MeshConfig, passphrase string) error {
	return l.SaveConfigTo(l.ConfigPath(), config, passphrase)
}

// SaveConfigTo encrypts and saves a mesh configuration to a specific path
func (l *Loader) SaveConfigTo(path string, config *MeshConfig, passphrase string) error {
	if err := l.EnsureConfigDir(); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	encrypted, err := l.encryptor.EncryptConfig(config, passphrase)
	if err != nil {
		return fmt.Errorf("encrypt config: %w", err)
	}

	// Write with restrictive permissions (owner read/write only)
	if err := os.WriteFile(path, encrypted, 0600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

// LoadAdminConfig loads and decrypts the admin configuration
func (l *Loader) LoadAdminConfig(passphrase string) (*AdminConfig, error) {
	return l.LoadAdminConfigFrom(l.AdminConfigPath(), passphrase)
}

// LoadAdminConfigFrom loads and decrypts an admin configuration from a specific path
func (l *Loader) LoadAdminConfigFrom(path, passphrase string) (*AdminConfig, error) {
	encrypted, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read admin config file: %w", err)
	}

	config, err := l.encryptor.DecryptAdminConfig(encrypted, passphrase)
	if err != nil {
		return nil, fmt.Errorf("decrypt admin config: %w", err)
	}

	return config, nil
}

// SaveAdminConfig encrypts and saves the admin configuration
func (l *Loader) SaveAdminConfig(config *AdminConfig, passphrase string) error {
	return l.SaveAdminConfigTo(l.AdminConfigPath(), config, passphrase)
}

// SaveAdminConfigTo encrypts and saves an admin configuration to a specific path
func (l *Loader) SaveAdminConfigTo(path string, config *AdminConfig, passphrase string) error {
	if err := l.EnsureConfigDir(); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	encrypted, err := l.encryptor.EncryptAdminConfig(config, passphrase)
	if err != nil {
		return fmt.Errorf("encrypt admin config: %w", err)
	}

	if err := os.WriteFile(path, encrypted, 0600); err != nil {
		return fmt.Errorf("write admin config file: %w", err)
	}

	return nil
}

// ConfigExists checks if the config file exists
func (l *Loader) ConfigExists() bool {
	_, err := os.Stat(l.ConfigPath())
	return err == nil
}

// AdminConfigExists checks if the admin config file exists
func (l *Loader) AdminConfigExists() bool {
	_, err := os.Stat(l.AdminConfigPath())
	return err == nil
}

// SecureDelete securely deletes a file by overwriting before deletion.
// Note: On copy-on-write filesystems (APFS, Btrfs), the original data blocks
// may be retained in journal or snapshot history. This is a best-effort wipe.
func SecureDelete(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil // Already gone
	}
	if err != nil {
		return err
	}

	size := info.Size()
	buf := make([]byte, 4096)

	// Open file for writing
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	// Pass 1: Overwrite with random bytes
	for written := int64(0); written < size; {
		n := size - written
		if n > int64(len(buf)) {
			n = int64(len(buf))
		}
		rand.Read(buf[:n])
		if _, err := f.Write(buf[:n]); err != nil {
			f.Close()
			return err
		}
		written += n
	}
	f.Sync()

	// Pass 2: Overwrite with zeros
	f.Seek(0, 0)
	keys.WipeBytes(buf) // Zero the buffer
	for written := int64(0); written < size; {
		n := size - written
		if n > int64(len(buf)) {
			n = int64(len(buf))
		}
		if _, err := f.Write(buf[:n]); err != nil {
			f.Close()
			return err
		}
		written += n
	}

	// Sync to disk
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()

	// Rename to random name before deletion to prevent directory entry recovery
	dir := filepath.Dir(path)
	var randomName [8]byte
	rand.Read(randomName[:])
	tmpPath := filepath.Join(dir, "."+hex.EncodeToString(randomName[:])+".tmp")
	if err := os.Rename(path, tmpPath); err != nil {
		// Rename failed, fall back to removing original path
		return os.Remove(path)
	}

	return os.Remove(tmpPath)
}

// WipeConfig securely deletes the config file
func (l *Loader) WipeConfig() error {
	return SecureDelete(l.ConfigPath())
}

// WipeAdminConfig securely deletes the admin config file
func (l *Loader) WipeAdminConfig() error {
	return SecureDelete(l.AdminConfigPath())
}

// WipeAll securely deletes all config files and the config directory
func (l *Loader) WipeAll() error {
	// Wipe individual files
	files, _ := os.ReadDir(l.configDir)
	for _, f := range files {
		path := filepath.Join(l.configDir, f.Name())
		if err := SecureDelete(path); err != nil {
			// Continue wiping other files
			keys.WipeBytes([]byte(err.Error()))
		}
	}

	// Remove directory
	return os.RemoveAll(l.configDir)
}
