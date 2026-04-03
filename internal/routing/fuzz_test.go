package routing

import (
	"testing"
)

func FuzzParseSTUNResponse(f *testing.F) {
	// Seed: valid STUN response with XOR-MAPPED-ADDRESS (IPv4)
	validSTUN := make([]byte, 32)
	// Header: Binding Success Response
	validSTUN[0] = 0x01
	validSTUN[1] = 0x01
	// Message length = 12
	validSTUN[2] = 0x00
	validSTUN[3] = 0x0C
	// Magic cookie
	validSTUN[4] = 0x21
	validSTUN[5] = 0x12
	validSTUN[6] = 0xa4
	validSTUN[7] = 0x42
	// Transaction ID (12 bytes, indices 8-19)
	// Attribute: XOR-MAPPED-ADDRESS (0x0020), length 8
	validSTUN[20] = 0x00
	validSTUN[21] = 0x20
	validSTUN[22] = 0x00
	validSTUN[23] = 0x08
	// Reserved + Family (IPv4 = 0x01)
	validSTUN[24] = 0x00
	validSTUN[25] = 0x01
	// XOR port
	validSTUN[26] = 0x21
	validSTUN[27] = 0x12
	// XOR IP (192.168.1.1 XOR 0x2112a442)
	validSTUN[28] = 192 ^ 0x21
	validSTUN[29] = 168 ^ 0x12
	validSTUN[30] = 1 ^ 0xa4
	validSTUN[31] = 1 ^ 0x42

	f.Add(validSTUN)
	f.Add([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic regardless of input.
		parseSTUNResponse(data)
	})
}
