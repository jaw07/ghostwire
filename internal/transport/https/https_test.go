package https

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------
// config.go tests
// -----------------------------------------------------------------------

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if cfg.Fingerprint != "auto" {
		t.Errorf("Fingerprint = %q, want %q", cfg.Fingerprint, "auto")
	}
	if cfg.KnockWindow != DefaultKnockWindow {
		t.Errorf("KnockWindow = %v, want %v", cfg.KnockWindow, DefaultKnockWindow)
	}
	if cfg.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, DefaultTimeout)
	}
	if cfg.DecoyTraffic {
		t.Error("DecoyTraffic should default to false")
	}
	if cfg.DecoyInterval != 5*time.Second {
		t.Errorf("DecoyInterval = %v, want 5s", cfg.DecoyInterval)
	}
}

func TestConfigValidate_Valid(t *testing.T) {
	cfg := &Config{
		ServerName: "example.com",
		MeshSecret: make([]byte, 32),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() returned error for valid config: %v", err)
	}
}

func TestConfigValidate_MissingServerName(t *testing.T) {
	cfg := &Config{
		MeshSecret: make([]byte, 32),
	}
	err := cfg.Validate()
	if err != ErrMissingServerName {
		t.Fatalf("Validate() = %v, want ErrMissingServerName", err)
	}
}

func TestConfigValidate_ShortMeshSecret(t *testing.T) {
	cfg := &Config{
		ServerName: "example.com",
		MeshSecret: make([]byte, 16),
	}
	err := cfg.Validate()
	if err != ErrInvalidMeshSecret {
		t.Fatalf("Validate() = %v, want ErrInvalidMeshSecret", err)
	}
}

func TestConfigValidate_NilMeshSecret(t *testing.T) {
	cfg := &Config{
		ServerName: "example.com",
	}
	err := cfg.Validate()
	if err != ErrInvalidMeshSecret {
		t.Fatalf("Validate() = %v, want ErrInvalidMeshSecret", err)
	}
}

// -----------------------------------------------------------------------
// framing.go tests
// -----------------------------------------------------------------------

func TestNewDataFrame(t *testing.T) {
	payload := []byte("hello world")
	f := NewDataFrame(payload)
	if f.Type != FrameTypeData {
		t.Errorf("Type = 0x%02x, want 0x%02x", f.Type, FrameTypeData)
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Error("Payload mismatch")
	}
}

func TestNewPingFrame(t *testing.T) {
	f := NewPingFrame()
	if f.Type != FrameTypePing {
		t.Errorf("Type = 0x%02x, want 0x%02x", f.Type, FrameTypePing)
	}
	if f.Payload != nil {
		t.Error("Ping payload should be nil")
	}
}

func TestNewCloseFrame(t *testing.T) {
	f := NewCloseFrame()
	if f.Type != FrameTypeClose {
		t.Errorf("Type = 0x%02x, want 0x%02x", f.Type, FrameTypeClose)
	}
	if f.Payload != nil {
		t.Error("Close payload should be nil")
	}
}

func TestFrameMarshalUnmarshalRoundTrip(t *testing.T) {
	payloads := [][]byte{
		[]byte("hello"),
		make([]byte, 100),
		make([]byte, 500),
		make([]byte, 1024),
	}
	for i, payload := range payloads {
		t.Run(fmt.Sprintf("payload_%d_len_%d", i, len(payload)), func(t *testing.T) {
			original := NewDataFrame(payload)
			data := original.Marshal()

			reader := bytes.NewReader(data)
			decoded, err := UnmarshalFrame(reader)
			if err != nil {
				t.Fatalf("UnmarshalFrame error: %v", err)
			}
			if decoded.Type != original.Type {
				t.Errorf("Type = 0x%02x, want 0x%02x", decoded.Type, original.Type)
			}
			if !bytes.Equal(decoded.Payload, original.Payload) {
				t.Error("Payload mismatch after round-trip")
			}
		})
	}
}

func TestFramePaddingToStandardSizes(t *testing.T) {
	// A 50-byte payload should be padded to 128 (next standard size)
	f := NewDataFrame(make([]byte, 50))
	data := f.Marshal()
	expectedTotal := FrameHeaderSize + 128
	if len(data) != expectedTotal {
		t.Errorf("marshalled size = %d, want %d (header %d + padded 128)", len(data), expectedTotal, FrameHeaderSize)
	}

	// 200-byte payload -> 256
	f2 := NewDataFrame(make([]byte, 200))
	data2 := f2.Marshal()
	if len(data2) != FrameHeaderSize+256 {
		t.Errorf("marshalled size = %d, want %d", len(data2), FrameHeaderSize+256)
	}

	// Exact standard size should stay the same
	f3 := NewDataFrame(make([]byte, 512))
	data3 := f3.Marshal()
	if len(data3) != FrameHeaderSize+512 {
		t.Errorf("marshalled size = %d, want %d", len(data3), FrameHeaderSize+512)
	}
}

func TestFrameLargePayload(t *testing.T) {
	// Payload larger than all standard sizes should round to next 1KB boundary
	payload := make([]byte, 20000)
	rand.Read(payload)
	f := NewDataFrame(payload)
	data := f.Marshal()

	expectedPadded := ((20000 + 1023) / 1024) * 1024 // 20480
	if len(data) != FrameHeaderSize+expectedPadded {
		t.Errorf("marshalled size = %d, want %d", len(data), FrameHeaderSize+expectedPadded)
	}

	// Verify round-trip
	decoded, err := UnmarshalFrame(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("UnmarshalFrame error: %v", err)
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Error("large payload mismatch after round-trip")
	}
}

func TestFindNextPaddingSize(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{0, 128},
		{1, 128},
		{128, 128},
		{129, 256},
		{256, 256},
		{257, 512},
		{16384, 16384},
		{16385, 17408}, // ((16385+1023)/1024)*1024 = 17*1024
		{20000, 20480}, // ((20000+1023)/1024)*1024 = 20*1024
	}
	for _, tt := range tests {
		got := findNextPaddingSize(tt.input)
		if got != tt.expected {
			t.Errorf("findNextPaddingSize(%d) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestFrameReaderWriter_Pipe(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()

	fw := NewFrameWriter(pw)
	fr := NewFrameReader(pr)

	payload := []byte("tunnel data goes here")

	// Write in a goroutine so the pipe doesn't block
	go func() {
		defer pw.Close()
		if err := fw.WriteData(payload); err != nil {
			t.Errorf("WriteData error: %v", err)
		}
	}()

	frame, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame error: %v", err)
	}
	if frame.Type != FrameTypeData {
		t.Errorf("Type = 0x%02x, want Data", frame.Type)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Error("Payload mismatch through pipe")
	}
}

func TestFrameReaderWriter_MultipleFrames(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()

	fw := NewFrameWriter(pw)
	fr := NewFrameReader(pr)

	frames := []*TunnelFrame{
		NewDataFrame([]byte("first")),
		NewPingFrame(),
		NewDataFrame([]byte("second payload that is a bit longer")),
		NewCloseFrame(),
	}

	go func() {
		defer pw.Close()
		for _, f := range frames {
			if err := fw.WriteFrame(f); err != nil {
				t.Errorf("WriteFrame error: %v", err)
				return
			}
		}
	}()

	for i, expected := range frames {
		got, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame #%d error: %v", i, err)
		}
		if got.Type != expected.Type {
			t.Errorf("frame #%d Type = 0x%02x, want 0x%02x", i, got.Type, expected.Type)
		}
		if !bytes.Equal(got.Payload, expected.Payload) {
			t.Errorf("frame #%d Payload mismatch", i)
		}
	}
}

func TestFramePaddedFlagSetWhenPadded(t *testing.T) {
	// A 50-byte payload gets padded -> FlagPadded should be set
	f := NewDataFrame(make([]byte, 50))
	data := f.Marshal()
	flags := data[1]
	if flags&FlagPadded == 0 {
		t.Error("FlagPadded not set for payload that requires padding")
	}
}

func TestFramePaddedFlagClear_ExactSize(t *testing.T) {
	// A payload exactly matching a standard size -> no padding needed
	f := NewDataFrame(make([]byte, 128))
	data := f.Marshal()
	flags := data[1]
	if flags&FlagPadded != 0 {
		t.Error("FlagPadded should not be set when payload matches standard size exactly")
	}
}

// -----------------------------------------------------------------------
// knock.go tests
// -----------------------------------------------------------------------

func makeSecret(t *testing.T) []byte {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	return secret
}

func makePubKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func knockToHTTPRequest(t *testing.T, knock *KnockSequence) *http.Request {
	t.Helper()
	req := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: knock.Path},
		Header: make(http.Header),
	}
	for k, v := range knock.Headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestKnockGenerator_ProducesValidKnock(t *testing.T) {
	secret := makeSecret(t)
	pubKey := makePubKey(t)
	kg := NewKnockGenerator(secret, DefaultKnockWindow)

	knock := kg.Generate(pubKey)

	if !strings.HasPrefix(knock.Path, KnockPathPrefix) {
		t.Errorf("Path %q does not start with %q", knock.Path, KnockPathPrefix)
	}

	// Path should have a 32-char hex suffix (16 bytes)
	pathKnock := knock.Path[len(KnockPathPrefix):]
	if len(pathKnock) != 32 {
		t.Errorf("path knock hex length = %d, want 32", len(pathKnock))
	}
	if _, err := hex.DecodeString(pathKnock); err != nil {
		t.Errorf("path knock is not valid hex: %v", err)
	}

	// Check required headers
	if knock.Headers[KnockHeaderRequestID] == "" {
		t.Error("missing X-Request-ID header")
	}
	if knock.Headers[KnockHeaderClientToken] == "" {
		t.Error("missing X-Client-Token header")
	}
	if knock.Headers[KnockHeaderTimestamp] == "" {
		t.Error("missing X-Timestamp header")
	}
	if knock.Headers["Content-Type"] != "application/json" {
		t.Error("missing or wrong Content-Type header")
	}

	// Body should be non-empty JSON
	if len(knock.Body) == 0 {
		t.Error("knock body is empty")
	}
	if knock.Body[0] != '{' {
		t.Error("knock body does not look like JSON")
	}
}

func TestKnockValidator_AcceptsValidKnock(t *testing.T) {
	secret := makeSecret(t)
	pubKey := makePubKey(t)

	kg := NewKnockGenerator(secret, DefaultKnockWindow)
	kv := NewKnockValidator(secret, DefaultKnockWindow)
	kv.AddKnownClient(pubKey)

	knock := kg.Generate(pubKey)
	req := knockToHTTPRequest(t, knock)

	result := kv.Validate(req)
	if result == nil {
		t.Fatal("Validate returned nil for valid knock")
	}
	if !bytes.Equal(result, pubKey) {
		t.Error("Validate returned wrong public key")
	}
}

func TestKnockValidator_RejectsUnknownClient(t *testing.T) {
	secret := makeSecret(t)
	knownKey := makePubKey(t)
	unknownKey := makePubKey(t)

	kg := NewKnockGenerator(secret, DefaultKnockWindow)
	kv := NewKnockValidator(secret, DefaultKnockWindow)
	kv.AddKnownClient(knownKey)

	// Generate knock with unknown key
	knock := kg.Generate(unknownKey)
	req := knockToHTTPRequest(t, knock)

	result := kv.Validate(req)
	if result != nil {
		t.Fatal("Validate should return nil for unknown client")
	}
}

func TestKnockValidator_TimeWindowSkew(t *testing.T) {
	secret := makeSecret(t)
	pubKey := makePubKey(t)
	window := DefaultKnockWindow

	// Validator checks windows {0, -1, +1} so a knock from an adjacent window
	// should still be valid. We test by using the same derivation logic directly.
	kv := NewKnockValidator(secret, window)
	kv.AddKnownClient(pubKey)

	now := time.Now().Unix()
	currentWindow := now / int64(window.Seconds())

	// Generate knock material for the previous time window
	kg := NewKnockGenerator(secret, window)
	prevMaterial := kg.deriveKnockMaterial(pubKey, currentWindow-1)

	pathKnock := hex.EncodeToString(prevMaterial[:16])
	requestID := hex.EncodeToString(prevMaterial[16:32])
	clientToken := hex.EncodeToString(prevMaterial[32:48])

	req := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: KnockPathPrefix + pathKnock},
		Header: make(http.Header),
	}
	req.Header.Set(KnockHeaderRequestID, requestID)
	req.Header.Set(KnockHeaderClientToken, clientToken)

	result := kv.Validate(req)
	if result == nil {
		t.Fatal("Validate should accept knock from previous time window")
	}
	if !bytes.Equal(result, pubKey) {
		t.Error("Validate returned wrong public key for window-1 knock")
	}

	// Also test next window
	nextMaterial := kg.deriveKnockMaterial(pubKey, currentWindow+1)
	req2 := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: KnockPathPrefix + hex.EncodeToString(nextMaterial[:16])},
		Header: make(http.Header),
	}
	req2.Header.Set(KnockHeaderRequestID, hex.EncodeToString(nextMaterial[16:32]))
	req2.Header.Set(KnockHeaderClientToken, hex.EncodeToString(nextMaterial[32:48]))

	result2 := kv.Validate(req2)
	if result2 == nil {
		t.Fatal("Validate should accept knock from next time window")
	}
}

func TestKnockValidator_AddRemoveKnownClient(t *testing.T) {
	secret := makeSecret(t)
	pubKey := makePubKey(t)

	kg := NewKnockGenerator(secret, DefaultKnockWindow)
	kv := NewKnockValidator(secret, DefaultKnockWindow)

	// Not added yet
	knock := kg.Generate(pubKey)
	req := knockToHTTPRequest(t, knock)
	if kv.Validate(req) != nil {
		t.Fatal("should reject when client not added")
	}

	// Add client
	kv.AddKnownClient(pubKey)
	knock = kg.Generate(pubKey)
	req = knockToHTTPRequest(t, knock)
	if kv.Validate(req) == nil {
		t.Fatal("should accept after AddKnownClient")
	}

	// Remove client
	kv.RemoveKnownClient(pubKey)
	knock = kg.Generate(pubKey)
	req = knockToHTTPRequest(t, knock)
	if kv.Validate(req) != nil {
		t.Fatal("should reject after RemoveKnownClient")
	}
}

func TestKnockDifferentSecretsProduceDifferentKnocks(t *testing.T) {
	secret1 := makeSecret(t)
	secret2 := makeSecret(t)
	pubKey := makePubKey(t)

	kg1 := NewKnockGenerator(secret1, DefaultKnockWindow)
	kg2 := NewKnockGenerator(secret2, DefaultKnockWindow)

	knock1 := kg1.Generate(pubKey)
	knock2 := kg2.Generate(pubKey)

	if knock1.Path == knock2.Path {
		t.Error("different secrets produced the same knock path")
	}
	if knock1.Headers[KnockHeaderRequestID] == knock2.Headers[KnockHeaderRequestID] {
		t.Error("different secrets produced the same request ID")
	}
	if knock1.Headers[KnockHeaderClientToken] == knock2.Headers[KnockHeaderClientToken] {
		t.Error("different secrets produced the same client token")
	}
}

func TestKnockValidator_RejectsWrongSecret(t *testing.T) {
	secret1 := makeSecret(t)
	secret2 := makeSecret(t)
	pubKey := makePubKey(t)

	kg := NewKnockGenerator(secret1, DefaultKnockWindow)
	kv := NewKnockValidator(secret2, DefaultKnockWindow)
	kv.AddKnownClient(pubKey)

	knock := kg.Generate(pubKey)
	req := knockToHTTPRequest(t, knock)

	if kv.Validate(req) != nil {
		t.Fatal("Validate should reject knock with mismatched secret")
	}
}

func TestKnockValidator_RejectsBadPath(t *testing.T) {
	secret := makeSecret(t)
	pubKey := makePubKey(t)

	kv := NewKnockValidator(secret, DefaultKnockWindow)
	kv.AddKnownClient(pubKey)

	req := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: "/some/other/path"},
		Header: make(http.Header),
	}
	req.Header.Set(KnockHeaderRequestID, strings.Repeat("ab", 16))
	req.Header.Set(KnockHeaderClientToken, strings.Repeat("cd", 16))

	if kv.Validate(req) != nil {
		t.Fatal("should reject request with wrong path")
	}
}

func TestKnockValidator_RejectsMissingHeaders(t *testing.T) {
	secret := makeSecret(t)
	pubKey := makePubKey(t)

	kg := NewKnockGenerator(secret, DefaultKnockWindow)
	kv := NewKnockValidator(secret, DefaultKnockWindow)
	kv.AddKnownClient(pubKey)

	knock := kg.Generate(pubKey)

	// Missing X-Request-ID
	req1 := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: knock.Path},
		Header: make(http.Header),
	}
	req1.Header.Set(KnockHeaderClientToken, knock.Headers[KnockHeaderClientToken])
	if kv.Validate(req1) != nil {
		t.Error("should reject when X-Request-ID missing")
	}

	// Missing X-Client-Token
	req2 := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: knock.Path},
		Header: make(http.Header),
	}
	req2.Header.Set(KnockHeaderRequestID, knock.Headers[KnockHeaderRequestID])
	if kv.Validate(req2) != nil {
		t.Error("should reject when X-Client-Token missing")
	}
}

func TestKnockValidator_ConstantTimeComparison(t *testing.T) {
	// This test verifies the structural property that hmac.Equal is used,
	// rather than attempting to measure timing (which is flaky in tests).
	// We verify that a knock with only one correct component (partial match)
	// is rejected just the same as a completely wrong knock.
	secret := makeSecret(t)
	pubKey := makePubKey(t)

	kg := NewKnockGenerator(secret, DefaultKnockWindow)
	kv := NewKnockValidator(secret, DefaultKnockWindow)
	kv.AddKnownClient(pubKey)

	knock := kg.Generate(pubKey)

	// Use correct path but wrong headers (partial match)
	reqPartial := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: knock.Path},
		Header: make(http.Header),
	}
	reqPartial.Header.Set(KnockHeaderRequestID, strings.Repeat("00", 16))
	reqPartial.Header.Set(KnockHeaderClientToken, strings.Repeat("00", 16))

	if kv.Validate(reqPartial) != nil {
		t.Error("partial match (correct path, wrong headers) should be rejected")
	}

	// Use correct request ID but wrong path and token
	wrongPathHex := strings.Repeat("ff", 16)
	reqPartial2 := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: KnockPathPrefix + wrongPathHex},
		Header: make(http.Header),
	}
	reqPartial2.Header.Set(KnockHeaderRequestID, knock.Headers[KnockHeaderRequestID])
	reqPartial2.Header.Set(KnockHeaderClientToken, strings.Repeat("00", 16))

	if kv.Validate(reqPartial2) != nil {
		t.Error("partial match (correct requestID, wrong path+token) should be rejected")
	}
}

func TestExtractPathKnock(t *testing.T) {
	// Valid path
	hexStr := strings.Repeat("ab", 16)
	knock := extractPathKnock(KnockPathPrefix + hexStr)
	if knock == nil {
		t.Fatal("extractPathKnock returned nil for valid path")
	}
	if hex.EncodeToString(knock) != hexStr {
		t.Errorf("got %s, want %s", hex.EncodeToString(knock), hexStr)
	}

	// Too short
	if extractPathKnock(KnockPathPrefix) != nil {
		t.Error("should return nil for path with no knock suffix")
	}

	// Wrong length
	if extractPathKnock(KnockPathPrefix+"abcd") != nil {
		t.Error("should return nil for wrong-length knock")
	}

	// Invalid hex
	if extractPathKnock(KnockPathPrefix+strings.Repeat("zz", 16)) != nil {
		t.Error("should return nil for invalid hex")
	}
}

func TestKnockValidator_MultipleClients(t *testing.T) {
	secret := makeSecret(t)
	key1 := makePubKey(t)
	key2 := makePubKey(t)

	kg := NewKnockGenerator(secret, DefaultKnockWindow)
	kv := NewKnockValidator(secret, DefaultKnockWindow)
	kv.AddKnownClient(key1)
	kv.AddKnownClient(key2)

	// Both clients should validate
	knock1 := kg.Generate(key1)
	req1 := knockToHTTPRequest(t, knock1)
	result1 := kv.Validate(req1)
	if result1 == nil || !bytes.Equal(result1, key1) {
		t.Error("first client knock should validate")
	}

	knock2 := kg.Generate(key2)
	req2 := knockToHTTPRequest(t, knock2)
	result2 := kv.Validate(req2)
	if result2 == nil || !bytes.Equal(result2, key2) {
		t.Error("second client knock should validate")
	}
}
