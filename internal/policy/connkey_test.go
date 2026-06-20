package policy

import (
	"net/netip"
	"testing"
)

// TestConnKeyDistinctPorts guards against the old string(rune(port)) encoding,
// which collided/garbled ports above 127. Distinct ports must yield distinct
// keys, and the port must be rendered as decimal digits.
func TestConnKeyDistinctPorts(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")

	seen := map[string]uint16{}
	for _, port := range []uint16{0, 53, 80, 128, 443, 8080, 14550, 65535} {
		k := connKey(src, dst, port, port, "tcp")
		if other, dup := seen[k]; dup {
			t.Fatalf("port %d and %d produced the same connKey %q", port, other, k)
		}
		seen[k] = port
	}

	// Sanity: key contains the decimal port, not a control rune.
	k := connKey(src, dst, 443, 8080, "tcp")
	want := "10.0.0.1:443->10.0.0.2:8080/tcp"
	if k != want {
		t.Errorf("connKey = %q, want %q", k, want)
	}
}
