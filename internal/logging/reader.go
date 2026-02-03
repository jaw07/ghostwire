package logging

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"filippo.io/age"
)

// Reader reads and decrypts log files
type Reader struct {
	passphrase string
}

// NewReader creates a new log reader
func NewReader(passphrase string) *Reader {
	return &Reader{passphrase: passphrase}
}

// ReadFile reads all entries from a log file
func (r *Reader) ReadFile(path string) ([]*Entry, error) {
	var reader io.Reader

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	// Handle gzip compressed files
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("create gzip reader: %w", err)
		}
		defer gz.Close()
		reader = gz
	} else {
		reader = f
	}

	return r.readEntries(reader)
}

// readEntries reads entries from a reader
func (r *Reader) readEntries(reader io.Reader) ([]*Entry, error) {
	var entries []*Entry
	scanner := bufio.NewScanner(reader)

	// Increase buffer size for large entries
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		entry, err := r.parseEntry(line)
		if err != nil {
			// Skip malformed entries
			continue
		}
		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return entries, fmt.Errorf("scan: %w", err)
	}

	return entries, nil
}

// parseEntry parses and optionally decrypts an entry
func (r *Reader) parseEntry(line []byte) (*Entry, error) {
	var entry Entry
	if err := json.Unmarshal(line, &entry); err != nil {
		return nil, err
	}

	// Decrypt sensitive fields if present
	if len(entry.Encrypted) > 0 && r.passphrase != "" {
		sensitive, err := r.decryptSensitive(entry.Encrypted)
		if err != nil {
			// Store error but don't fail
			entry.Sensitive = &SensitiveFields{
				ErrorDetails: fmt.Sprintf("decryption failed: %v", err),
			}
		} else {
			entry.Sensitive = sensitive
		}
	}

	return &entry, nil
}

// decryptSensitive decrypts the sensitive fields
func (r *Reader) decryptSensitive(encrypted []byte) (*SensitiveFields, error) {
	identity, err := age.NewScryptIdentity(r.passphrase)
	if err != nil {
		return nil, err
	}
	identity.SetMaxWorkFactor(20)

	reader, err := age.Decrypt(bytes.NewReader(encrypted), identity)
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	var sensitive SensitiveFields
	if err := json.Unmarshal(data, &sensitive); err != nil {
		return nil, err
	}

	return &sensitive, nil
}

// Filter specifies criteria for filtering log entries
type Filter struct {
	Level       *Level
	MinLevel    *Level
	Component   string
	NodeID      string
	StartTime   *time.Time
	EndTime     *time.Time
	MessageLike string
	HasSensitive bool
}

// FilterEntries applies filters to entries
func FilterEntries(entries []*Entry, filter *Filter) []*Entry {
	if filter == nil {
		return entries
	}

	result := make([]*Entry, 0, len(entries))
	for _, e := range entries {
		if matchesFilter(e, filter) {
			result = append(result, e)
		}
	}
	return result
}

// matchesFilter checks if an entry matches the filter
func matchesFilter(e *Entry, f *Filter) bool {
	if f.Level != nil && e.Level != *f.Level {
		return false
	}
	if f.MinLevel != nil && e.Level < *f.MinLevel {
		return false
	}
	if f.Component != "" && e.Component != f.Component {
		return false
	}
	if f.NodeID != "" && e.NodeID != f.NodeID {
		return false
	}
	if f.StartTime != nil && e.Timestamp.Before(*f.StartTime) {
		return false
	}
	if f.EndTime != nil && e.Timestamp.After(*f.EndTime) {
		return false
	}
	if f.MessageLike != "" && !strings.Contains(e.Message, f.MessageLike) {
		return false
	}
	if f.HasSensitive && e.Sensitive == nil && len(e.Encrypted) == 0 {
		return false
	}
	return true
}

// Search searches entries for a pattern
func Search(entries []*Entry, pattern string) []*Entry {
	if pattern == "" {
		return entries
	}

	pattern = strings.ToLower(pattern)
	result := make([]*Entry, 0)

	for _, e := range entries {
		if matchesPattern(e, pattern) {
			result = append(result, e)
		}
	}
	return result
}

// matchesPattern checks if an entry contains the pattern
func matchesPattern(e *Entry, pattern string) bool {
	// Check message
	if strings.Contains(strings.ToLower(e.Message), pattern) {
		return true
	}
	// Check component
	if strings.Contains(strings.ToLower(e.Component), pattern) {
		return true
	}
	// Check node ID
	if strings.Contains(strings.ToLower(e.NodeID), pattern) {
		return true
	}
	// Check fields
	for k, v := range e.Fields {
		if strings.Contains(strings.ToLower(k), pattern) {
			return true
		}
		if str, ok := v.(string); ok && strings.Contains(strings.ToLower(str), pattern) {
			return true
		}
	}
	// Check decrypted sensitive fields
	if e.Sensitive != nil {
		if strings.Contains(strings.ToLower(e.Sensitive.SourceIP), pattern) ||
			strings.Contains(strings.ToLower(e.Sensitive.DestIP), pattern) ||
			strings.Contains(strings.ToLower(e.Sensitive.PeerID), pattern) ||
			strings.Contains(strings.ToLower(e.Sensitive.ErrorDetails), pattern) {
			return true
		}
	}
	return false
}

// FormatEntry formats an entry for display
func FormatEntry(e *Entry, verbose bool) string {
	var buf strings.Builder

	// Timestamp and level
	buf.WriteString(e.Timestamp.Format("2006-01-02 15:04:05"))
	buf.WriteString(" [")
	buf.WriteString(e.Level.String())
	buf.WriteString("] ")

	// Component
	if e.Component != "" {
		buf.WriteString(e.Component)
		buf.WriteString(": ")
	}

	// Message
	buf.WriteString(e.Message)

	// Fields (if verbose)
	if verbose && len(e.Fields) > 0 {
		buf.WriteString(" {")
		first := true
		for k, v := range e.Fields {
			if !first {
				buf.WriteString(", ")
			}
			buf.WriteString(k)
			buf.WriteString("=")
			buf.WriteString(fmt.Sprintf("%v", v))
			first = false
		}
		buf.WriteString("}")
	}

	// Sensitive fields (if decrypted and verbose)
	if verbose && e.Sensitive != nil {
		buf.WriteString(" [SENSITIVE: ")
		if e.Sensitive.SourceIP != "" {
			buf.WriteString("src=")
			buf.WriteString(e.Sensitive.SourceIP)
			buf.WriteString(" ")
		}
		if e.Sensitive.PeerID != "" {
			buf.WriteString("peer=")
			buf.WriteString(e.Sensitive.PeerID)
			buf.WriteString(" ")
		}
		if e.Sensitive.ErrorDetails != "" {
			buf.WriteString("err=")
			buf.WriteString(e.Sensitive.ErrorDetails)
		}
		buf.WriteString("]")
	}

	return buf.String()
}

// ExportJSON exports entries to JSON format
func ExportJSON(entries []*Entry, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(entries)
}

// ExportJSONL exports entries as JSON lines
func ExportJSONL(entries []*Entry, w io.Writer) error {
	for _, e := range entries {
		data, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
		if _, err := w.Write([]byte("\n")); err != nil {
			return err
		}
	}
	return nil
}
