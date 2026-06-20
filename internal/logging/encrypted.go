package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"filippo.io/age"
)

const (
	// DefaultBufferSize is the number of entries to buffer before flushing
	DefaultBufferSize = 100

	// DefaultFlushInterval is how often to flush buffered entries
	DefaultFlushInterval = 5 * time.Second

	// ScryptWorkFactor for log encryption (lower than config for performance)
	ScryptWorkFactor = 14
)

// EncryptedLogger writes encrypted structured logs
type EncryptedLogger struct {
	mu            sync.Mutex
	output        io.Writer
	file          *os.File
	logDir        string
	nodeID        string
	passphrase    string
	level         Level
	buffer        []*Entry
	bufferSize    int
	flushInterval time.Duration
	shutdown      chan struct{}
	wg            sync.WaitGroup
	rotator       *Rotator
	closeOnce     sync.Once
}

// Config for the encrypted logger
type Config struct {
	LogDir        string
	NodeID        string
	Passphrase    string
	Level         Level
	BufferSize    int
	FlushInterval time.Duration
	MaxFileSize   int64
	MaxAge        time.Duration
	MaxFiles      int
}

// DefaultConfig returns a default logger configuration
func DefaultConfig() *Config {
	return &Config{
		LogDir:        filepath.Join(os.Getenv("HOME"), ".config", "gw", "logs"),
		Level:         LevelInfo,
		BufferSize:    DefaultBufferSize,
		FlushInterval: DefaultFlushInterval,
		MaxFileSize:   10 * 1024 * 1024, // 10MB
		MaxAge:        7 * 24 * time.Hour,
		MaxFiles:      10,
	}
}

// NewEncryptedLogger creates a new encrypted logger
func NewEncryptedLogger(cfg *Config) (*EncryptedLogger, error) {
	if cfg.LogDir == "" {
		cfg.LogDir = DefaultConfig().LogDir
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = DefaultBufferSize
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = DefaultFlushInterval
	}

	// Create log directory
	if err := os.MkdirAll(cfg.LogDir, 0700); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	l := &EncryptedLogger{
		logDir:        cfg.LogDir,
		nodeID:        cfg.NodeID,
		passphrase:    cfg.Passphrase,
		level:         cfg.Level,
		buffer:        make([]*Entry, 0, cfg.BufferSize),
		bufferSize:    cfg.BufferSize,
		flushInterval: cfg.FlushInterval,
		shutdown:      make(chan struct{}),
	}

	// Initialize rotator
	l.rotator = NewRotator(&RotatorConfig{
		MaxSize:  cfg.MaxFileSize,
		MaxAge:   cfg.MaxAge,
		MaxFiles: cfg.MaxFiles,
	})

	// Open current log file
	if err := l.openLogFile(); err != nil {
		return nil, err
	}

	// Start background flusher
	l.wg.Add(1)
	go l.flushLoop()

	return l, nil
}

// openLogFile opens or creates the current log file
func (l *EncryptedLogger) openLogFile() error {
	filename := l.currentLogFilename()
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	l.file = f
	l.output = f
	return nil
}

// currentLogFilename returns the filename for today's log
func (l *EncryptedLogger) currentLogFilename() string {
	date := time.Now().UTC().Format("2006-01-02")
	return filepath.Join(l.logDir, fmt.Sprintf("ghostwire-%s.log", date))
}

// Log writes an entry at the specified level
func (l *EncryptedLogger) Log(entry *Entry) {
	if entry.Level < l.level {
		return
	}

	entry.NodeID = l.nodeID

	l.mu.Lock()
	l.buffer = append(l.buffer, entry)
	shouldFlush := len(l.buffer) >= l.bufferSize
	l.mu.Unlock()

	if shouldFlush {
		l.Flush()
	}
}

// Debug logs at debug level
func (l *EncryptedLogger) Debug(component, message string) {
	l.Log(NewEntry(LevelDebug, component, message))
}

// Info logs at info level
func (l *EncryptedLogger) Info(component, message string) {
	l.Log(NewEntry(LevelInfo, component, message))
}

// Warn logs at warn level
func (l *EncryptedLogger) Warn(component, message string) {
	l.Log(NewEntry(LevelWarn, component, message))
}

// Error logs at error level
func (l *EncryptedLogger) Error(component, message string, err error) {
	l.Log(NewEntry(LevelError, component, message).WithError(err))
}

// Security logs security-relevant events
func (l *EncryptedLogger) Security(component, message string) {
	l.Log(NewEntry(LevelSecurity, component, message))
}

// Flush writes all buffered entries to disk
func (l *EncryptedLogger) Flush() error {
	l.mu.Lock()
	if len(l.buffer) == 0 {
		l.mu.Unlock()
		return nil
	}
	entries := l.buffer
	l.buffer = make([]*Entry, 0, l.bufferSize)

	// Check if rotation is needed while still holding the lock, so the
	// l.file access here can't race with Close() setting l.file = nil.
	if l.rotator != nil && l.file != nil {
		if info, err := l.file.Stat(); err == nil && l.rotator.ShouldRotate(info.Size()) {
			l.file.Close()
			l.rotator.Rotate(l.currentLogFilename())
			l.openLogFile()
		}
	}
	l.mu.Unlock()

	// Write entries (writeEntry takes l.mu internally, so the lock must be
	// released here).
	for _, entry := range entries {
		if err := l.writeEntry(entry); err != nil {
			return err
		}
	}

	// Sync under the lock with a nil check: a concurrent Close() may have
	// closed and nilled the file while we were writing.
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	return l.file.Sync()
}

// writeEntry writes a single entry, encrypting sensitive fields
func (l *EncryptedLogger) writeEntry(entry *Entry) error {
	// Encrypt sensitive fields if present and passphrase set
	if entry.Sensitive != nil && l.passphrase != "" {
		encrypted, err := l.encryptSensitive(entry.Sensitive)
		if err != nil {
			return fmt.Errorf("encrypt sensitive fields: %w", err)
		}
		entry.Encrypted = encrypted
	}

	// Marshal to JSON
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}

	// Write with newline
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = fmt.Fprintf(l.output, "%s\n", data)
	return err
}

// encryptSensitive encrypts the sensitive fields using age
func (l *EncryptedLogger) encryptSensitive(s *SensitiveFields) ([]byte, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	recipient, err := age.NewScryptRecipient(l.passphrase)
	if err != nil {
		return nil, err
	}
	recipient.SetWorkFactor(ScryptWorkFactor)

	var buf bytes.Buffer
	writer, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, err
	}

	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// flushLoop periodically flushes the buffer
func (l *EncryptedLogger) flushLoop() {
	defer l.wg.Done()
	ticker := time.NewTicker(l.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.Flush()
		case <-l.shutdown:
			l.Flush()
			return
		}
	}
}

// Close shuts down the logger
func (l *EncryptedLogger) Close() error {
	var closeErr error
	l.closeOnce.Do(func() {
		close(l.shutdown)
		l.wg.Wait()

		l.mu.Lock()
		defer l.mu.Unlock()

		if l.file != nil {
			closeErr = l.file.Close()
			l.file = nil
		}
	})
	return closeErr
}

// SetLevel changes the minimum log level
func (l *EncryptedLogger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetOutput redirects output (for testing)
func (l *EncryptedLogger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
}
