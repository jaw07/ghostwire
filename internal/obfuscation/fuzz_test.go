package obfuscation

import (
	"bytes"
	"testing"
)

func FuzzPadUnpad(f *testing.F) {
	f.Add([]byte("hello world"))
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg := DefaultPaddingConfig()
		cfg.Mode = "mimic"
		p := NewPadder(cfg)

		padded := p.Pad(data)
		unpadded, err := p.Unpad(padded)
		if err != nil {
			t.Fatalf("Unpad returned error: %v", err)
		}
		if !bytes.Equal(unpadded, data) {
			t.Fatalf("roundtrip failed: got %v, want %v", unpadded, data)
		}
	})
}
