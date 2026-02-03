package config

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

const (
	// DefaultScryptWorkFactor is the scrypt work factor (2^18 = 262144 iterations)
	// Takes ~1 second on modern hardware, resistant to brute force
	DefaultScryptWorkFactor = 18

	// MaxScryptWorkFactor prevents DoS from maliciously crafted files
	MaxScryptWorkFactor = 20
)

// Encryptor handles config encryption and decryption
type Encryptor struct {
	workFactor int
}

// NewEncryptor creates a new config encryptor with default settings
func NewEncryptor() *Encryptor {
	return &Encryptor{
		workFactor: DefaultScryptWorkFactor,
	}
}

// EncryptConfig encrypts a mesh configuration with a passphrase
func (e *Encryptor) EncryptConfig(config *MeshConfig, passphrase string) ([]byte, error) {
	// Serialize config to YAML
	configBytes, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}

	return e.encryptBytes(configBytes, passphrase)
}

// EncryptAdminConfig encrypts an admin configuration with a passphrase
func (e *Encryptor) EncryptAdminConfig(config *AdminConfig, passphrase string) ([]byte, error) {
	configBytes, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("marshal admin config: %w", err)
	}

	return e.encryptBytes(configBytes, passphrase)
}

// encryptBytes encrypts arbitrary bytes with a passphrase using age
func (e *Encryptor) encryptBytes(plaintext []byte, passphrase string) ([]byte, error) {
	// Create scrypt recipient from passphrase
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, fmt.Errorf("create recipient: %w", err)
	}
	recipient.SetWorkFactor(e.workFactor)

	// Encrypt
	var buf bytes.Buffer
	writer, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, fmt.Errorf("create encryptor: %w", err)
	}

	if _, err := writer.Write(plaintext); err != nil {
		return nil, fmt.Errorf("write plaintext: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close encryptor: %w", err)
	}

	return buf.Bytes(), nil
}

// DecryptConfig decrypts a mesh configuration with a passphrase
func (e *Encryptor) DecryptConfig(encrypted []byte, passphrase string) (*MeshConfig, error) {
	decrypted, err := e.decryptBytes(encrypted, passphrase)
	if err != nil {
		return nil, err
	}

	var config MeshConfig
	if err := yaml.Unmarshal(decrypted, &config); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &config, nil
}

// DecryptAdminConfig decrypts an admin configuration with a passphrase
func (e *Encryptor) DecryptAdminConfig(encrypted []byte, passphrase string) (*AdminConfig, error) {
	decrypted, err := e.decryptBytes(encrypted, passphrase)
	if err != nil {
		return nil, err
	}

	var config AdminConfig
	if err := yaml.Unmarshal(decrypted, &config); err != nil {
		return nil, fmt.Errorf("unmarshal admin config: %w", err)
	}

	return &config, nil
}

// decryptBytes decrypts arbitrary bytes with a passphrase using age
func (e *Encryptor) decryptBytes(encrypted []byte, passphrase string) ([]byte, error) {
	// Create scrypt identity from passphrase
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("create identity: %w", err)
	}
	identity.SetMaxWorkFactor(MaxScryptWorkFactor)

	// Decrypt
	reader, err := age.Decrypt(bytes.NewReader(encrypted), identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	decrypted, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read decrypted: %w", err)
	}

	return decrypted, nil
}

// EncryptBytes encrypts arbitrary bytes (for tokens, etc.)
func (e *Encryptor) EncryptBytes(plaintext []byte, passphrase string) ([]byte, error) {
	return e.encryptBytes(plaintext, passphrase)
}

// DecryptBytes decrypts arbitrary bytes
func (e *Encryptor) DecryptBytes(encrypted []byte, passphrase string) ([]byte, error) {
	return e.decryptBytes(encrypted, passphrase)
}
