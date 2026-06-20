package gui

import (
	"net/http"
	"testing"
)

func TestCheckLocalOrigin(t *testing.T) {
	cases := []struct {
		name   string
		origin string
		want   bool
	}{
		{"no origin (non-browser)", "", true},
		{"loopback v4", "http://127.0.0.1:9999", true},
		{"localhost", "http://localhost:9999", true},
		{"loopback v6", "http://[::1]:9999", true},
		{"external host", "http://evil.example.com", false},
		{"lan ip", "http://192.168.1.50", false},
		{"malformed", "://not a url", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{}}
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if got := checkLocalOrigin(r); got != tc.want {
				t.Errorf("checkLocalOrigin(%q) = %v, want %v", tc.origin, got, tc.want)
			}
		})
	}
}
