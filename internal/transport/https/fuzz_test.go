package https

import (
	"bytes"
	"testing"
)

func FuzzUnmarshalFrame(f *testing.F) {
	// Seed corpus: valid frame, minimal input, oversized length
	f.Add([]byte{0x01, 0x00, 0x00, 0x04, 'T', 'E', 'S', 'T'})
	f.Add([]byte{0x02, 0x00, 0x00, 0x00})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		// Must never panic regardless of input.
		UnmarshalFrame(r)
	})
}

func FuzzParseHTTPRequest(f *testing.F) {
	f.Add([]byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("POST /api/v1/telemetry/abc HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}"))
	f.Add([]byte("\r\n\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic regardless of input.
		parseHTTPRequest(data)
	})
}

func FuzzExtractPathKnock(f *testing.F) {
	f.Add("/api/v1/telemetry/deadbeefdeadbeefdeadbeefdeadbeef")
	f.Add("/api/v1/telemetry/")
	f.Add("")

	f.Fuzz(func(t *testing.T, path string) {
		// Must never panic regardless of input.
		extractPathKnock(path)
	})
}
