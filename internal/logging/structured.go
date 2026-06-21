package logging

import (
	"encoding/json"
	"fmt"
	"time"
)

// Level represents log severity
type Level uint8

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelSecurity // Security-relevant events (auth, access control)
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelSecurity:
		return "SECURITY"
	default:
		return fmt.Sprintf("LEVEL(%d)", l)
	}
}

// ParseLevel converts a string to a Level
func ParseLevel(s string) (Level, error) {
	switch s {
	case "DEBUG", "debug":
		return LevelDebug, nil
	case "INFO", "info":
		return LevelInfo, nil
	case "WARN", "warn", "WARNING", "warning":
		return LevelWarn, nil
	case "ERROR", "error":
		return LevelError, nil
	case "SECURITY", "security":
		return LevelSecurity, nil
	default:
		return LevelInfo, fmt.Errorf("unknown log level: %s", s)
	}
}

// Entry is a single log entry
type Entry struct {
	Timestamp time.Time        `json:"ts"`
	Level     Level            `json:"level"`
	Component string           `json:"component"`
	NodeID    string           `json:"node_id,omitempty"`
	Message   string           `json:"msg"`
	Fields    map[string]any   `json:"fields,omitempty"`
	Sensitive *SensitiveFields `json:"-"` // Never serialized directly
	Encrypted []byte           `json:"encrypted,omitempty"`
}

// SensitiveFields contains data that must be encrypted
type SensitiveFields struct {
	SourceIP     string            `json:"src_ip,omitempty"`
	DestIP       string            `json:"dst_ip,omitempty"`
	PeerID       string            `json:"peer_id,omitempty"`
	TokenID      string            `json:"token_id,omitempty"`
	CertSerial   string            `json:"cert_serial,omitempty"`
	ErrorDetails string            `json:"error,omitempty"`
	Custom       map[string]string `json:"custom,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for Level
func (l Level) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.String())
}

// UnmarshalJSON implements custom JSON unmarshaling for Level
func (l *Level) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		// Try as integer
		var i uint8
		if err := json.Unmarshal(data, &i); err != nil {
			return err
		}
		*l = Level(i)
		return nil
	}
	level, err := ParseLevel(s)
	if err != nil {
		return err
	}
	*l = level
	return nil
}

// NewEntry creates a new log entry
func NewEntry(level Level, component, message string) *Entry {
	return &Entry{
		Timestamp: time.Now().UTC(),
		Level:     level,
		Component: component,
		Message:   message,
	}
}

// WithNodeID sets the node ID
func (e *Entry) WithNodeID(nodeID string) *Entry {
	e.NodeID = nodeID
	return e
}

// WithField adds a field to the entry
func (e *Entry) WithField(key string, value any) *Entry {
	if e.Fields == nil {
		e.Fields = make(map[string]any)
	}
	e.Fields[key] = value
	return e
}

// WithFields adds multiple fields to the entry
func (e *Entry) WithFields(fields map[string]any) *Entry {
	if e.Fields == nil {
		e.Fields = make(map[string]any)
	}
	for k, v := range fields {
		e.Fields[k] = v
	}
	return e
}

// WithSensitive adds sensitive fields that will be encrypted
func (e *Entry) WithSensitive(s *SensitiveFields) *Entry {
	e.Sensitive = s
	return e
}

// WithSourceIP adds a source IP to sensitive fields
func (e *Entry) WithSourceIP(ip string) *Entry {
	if e.Sensitive == nil {
		e.Sensitive = &SensitiveFields{}
	}
	e.Sensitive.SourceIP = ip
	return e
}

// WithPeerID adds a peer ID to sensitive fields
func (e *Entry) WithPeerID(peerID string) *Entry {
	if e.Sensitive == nil {
		e.Sensitive = &SensitiveFields{}
	}
	e.Sensitive.PeerID = peerID
	return e
}

// WithError adds error details to sensitive fields
func (e *Entry) WithError(err error) *Entry {
	if err == nil {
		return e
	}
	if e.Sensitive == nil {
		e.Sensitive = &SensitiveFields{}
	}
	e.Sensitive.ErrorDetails = err.Error()
	return e
}

// Clone creates a copy of the entry
func (e *Entry) Clone() *Entry {
	clone := &Entry{
		Timestamp: e.Timestamp,
		Level:     e.Level,
		Component: e.Component,
		NodeID:    e.NodeID,
		Message:   e.Message,
	}
	if e.Fields != nil {
		clone.Fields = make(map[string]any)
		for k, v := range e.Fields {
			clone.Fields[k] = v
		}
	}
	if e.Sensitive != nil {
		clone.Sensitive = &SensitiveFields{
			SourceIP:     e.Sensitive.SourceIP,
			DestIP:       e.Sensitive.DestIP,
			PeerID:       e.Sensitive.PeerID,
			TokenID:      e.Sensitive.TokenID,
			CertSerial:   e.Sensitive.CertSerial,
			ErrorDetails: e.Sensitive.ErrorDetails,
		}
		if e.Sensitive.Custom != nil {
			clone.Sensitive.Custom = make(map[string]string)
			for k, v := range e.Sensitive.Custom {
				clone.Sensitive.Custom[k] = v
			}
		}
	}
	return clone
}
