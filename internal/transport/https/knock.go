package https

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	// KnockPathPrefix is the API path prefix for knock requests
	KnockPathPrefix = "/api/v1/telemetry/"

	// KnockHeaderRequestID is the knock request ID header
	KnockHeaderRequestID = "X-Request-ID"

	// KnockHeaderClientToken is the knock client token header
	KnockHeaderClientToken = "X-Client-Token"

	// KnockHeaderTimestamp is the timestamp header
	KnockHeaderTimestamp = "X-Timestamp"

	// KnockMaterialLength is the total length of derived knock material
	KnockMaterialLength = 64
)

// KnockGenerator creates knock sequences for authentication
type KnockGenerator struct {
	meshSecret []byte
	window     time.Duration
}

// NewKnockGenerator creates a new knock generator
func NewKnockGenerator(meshSecret []byte, window time.Duration) *KnockGenerator {
	return &KnockGenerator{
		meshSecret: meshSecret,
		window:     window,
	}
}

// KnockSequence represents a complete knock authentication request
type KnockSequence struct {
	Path      string
	Headers   map[string]string
	Body      []byte
	Timestamp int64
}

// Generate creates a knock sequence for the given public key
func (kg *KnockGenerator) Generate(clientPubKey []byte) *KnockSequence {
	timestamp := time.Now().Unix()
	window := timestamp / int64(kg.window.Seconds())

	// Derive knock material using HKDF
	knockMaterial := kg.deriveKnockMaterial(clientPubKey, window)

	// Split material into components
	pathKnock := knockMaterial[:16]
	requestID := knockMaterial[16:32]
	clientToken := knockMaterial[32:48]
	// Reserved: knockMaterial[48:64]

	return &KnockSequence{
		Path: fmt.Sprintf("%s%s", KnockPathPrefix, hex.EncodeToString(pathKnock)),
		Headers: map[string]string{
			KnockHeaderRequestID:   hex.EncodeToString(requestID),
			KnockHeaderClientToken: hex.EncodeToString(clientToken),
			KnockHeaderTimestamp:   fmt.Sprintf("%d", timestamp*1000), // Milliseconds
			"Content-Type":         "application/json",
			"Accept":               "application/json",
		},
		Body:      kg.generateDecoyBody(knockMaterial[48:64]),
		Timestamp: timestamp,
	}
}

// deriveKnockMaterial derives the knock material using HKDF
func (kg *KnockGenerator) deriveKnockMaterial(clientPubKey []byte, window int64) []byte {
	// Create info with public key and timestamp window
	info := make([]byte, len(clientPubKey)+8)
	copy(info, clientPubKey)
	binary.BigEndian.PutUint64(info[len(clientPubKey):], uint64(window))

	// Derive using HKDF
	reader := hkdf.New(sha256.New, kg.meshSecret, []byte("ghostwire-knock-v1"), info)

	material := make([]byte, KnockMaterialLength)
	io.ReadFull(reader, material)

	return material
}

// generateDecoyBody creates a plausible JSON body for the knock request
func (kg *KnockGenerator) generateDecoyBody(seed []byte) []byte {
	// Generate deterministic but varying "telemetry" data
	h := sha256.Sum256(seed)
	sessionID := hex.EncodeToString(h[:8])
	eventCount := int(h[8])%100 + 1

	return []byte(fmt.Sprintf(
		`{"session_id":"%s","event_count":%d,"client_time":%d}`,
		sessionID, eventCount, time.Now().UnixMilli(),
	))
}

// KnockValidator validates knock sequences
type KnockValidator struct {
	meshSecret   []byte
	window       time.Duration
	clockSkew    time.Duration
	knownClients map[string][]byte // pubKeyHex -> pubKey
}

// NewKnockValidator creates a new knock validator
func NewKnockValidator(meshSecret []byte, window time.Duration) *KnockValidator {
	return &KnockValidator{
		meshSecret:   meshSecret,
		window:       window,
		clockSkew:    60 * time.Second,
		knownClients: make(map[string][]byte),
	}
}

// AddKnownClient adds a client public key for validation
func (kv *KnockValidator) AddKnownClient(pubKey []byte) {
	kv.knownClients[hex.EncodeToString(pubKey)] = pubKey
}

// RemoveKnownClient removes a client public key
func (kv *KnockValidator) RemoveKnownClient(pubKey []byte) {
	delete(kv.knownClients, hex.EncodeToString(pubKey))
}

// Validate checks if a request contains a valid knock sequence
// Returns the client public key if valid, nil otherwise
func (kv *KnockValidator) Validate(req *http.Request) []byte {
	// Extract knock components from request
	pathKnock := extractPathKnock(req.URL.Path)
	if pathKnock == nil {
		return nil
	}

	requestID, err := hex.DecodeString(req.Header.Get(KnockHeaderRequestID))
	if err != nil || len(requestID) != 16 {
		return nil
	}

	clientToken, err := hex.DecodeString(req.Header.Get(KnockHeaderClientToken))
	if err != nil || len(clientToken) != 16 {
		return nil
	}

	// Combine knock parts
	presentedKnock := make([]byte, 48)
	copy(presentedKnock[0:16], pathKnock)
	copy(presentedKnock[16:32], requestID)
	copy(presentedKnock[32:48], clientToken)

	// Get current and adjacent time windows
	now := time.Now().Unix()
	currentWindow := now / int64(kv.window.Seconds())

	// Try current and adjacent windows (for clock skew)
	for _, windowOffset := range []int64{0, -1, 1} {
		window := currentWindow + windowOffset

		// Try each known client
		for _, clientPubKey := range kv.knownClients {
			expectedKnock := kv.computeExpectedKnock(clientPubKey, window)

			// Constant-time comparison to prevent timing attacks
			if hmac.Equal(presentedKnock, expectedKnock[:48]) {
				return clientPubKey
			}
		}
	}

	return nil
}

// computeExpectedKnock computes the expected knock for a client and window
func (kv *KnockValidator) computeExpectedKnock(clientPubKey []byte, window int64) []byte {
	info := make([]byte, len(clientPubKey)+8)
	copy(info, clientPubKey)
	binary.BigEndian.PutUint64(info[len(clientPubKey):], uint64(window))

	reader := hkdf.New(sha256.New, kv.meshSecret, []byte("ghostwire-knock-v1"), info)

	material := make([]byte, KnockMaterialLength)
	io.ReadFull(reader, material)

	return material
}

// extractPathKnock extracts the knock from the URL path
func extractPathKnock(path string) []byte {
	if len(path) <= len(KnockPathPrefix) {
		return nil
	}

	knockHex := path[len(KnockPathPrefix):]
	if len(knockHex) != 32 { // 16 bytes = 32 hex chars
		return nil
	}

	knock, err := hex.DecodeString(knockHex)
	if err != nil {
		return nil
	}

	return knock
}
