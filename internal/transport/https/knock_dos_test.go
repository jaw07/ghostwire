package https

import (
	"net/http"
	"testing"
	"time"
)

// TestParseHTTPRequestRejectsMalformedURL guards against the remote-DoS where a
// malformed request target made url.Parse return a nil URL with no error, which
// then panicked knock validation (req.URL.Path) and crashed the daemon.
func TestParseHTTPRequestRejectsMalformedURL(t *testing.T) {
	for _, target := range []string{"%", "%zz", "/a%2", "%g%"} {
		data := []byte("POST " + target + " HTTP/1.1\r\nHost: x\r\n\r\n")
		req, err := parseHTTPRequest(data)
		if err == nil {
			t.Errorf("target %q: expected a parse error, got req=%+v", target, req)
		}
	}
}

// TestKnockValidateNilURLNoPanic verifies the defensive guard: validation must
// return nil (reject) rather than panic when the request or its URL is nil.
func TestKnockValidateNilURLNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Validate panicked: %v", r)
		}
	}()
	kv := NewKnockValidator([]byte("test-mesh-secret"), 30*time.Second)
	if got := kv.Validate(&http.Request{Header: make(http.Header)}); got != nil {
		t.Errorf("nil-URL request: got %v, want nil", got)
	}
	if got := kv.Validate(nil); got != nil {
		t.Errorf("nil request: got %v, want nil", got)
	}
}
