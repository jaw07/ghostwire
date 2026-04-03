// Package mavlink implements a minimal MAVLink packet parser for drone protocol support.
// It supports MAVLink v1 (magic=0xFE) and v2 (magic=0xFD) packet formats.
package mavlink

import (
	"errors"
	"fmt"
)

// Magic bytes identifying MAVLink packet versions.
const (
	MagicV1 = 0xFE
	MagicV2 = 0xFD
)

// Header sizes (not including payload or CRC).
const (
	// HeaderSizeV1 is the fixed header size for MAVLink v1:
	// magic(1) + len(1) + seq(1) + sysid(1) + compid(1) + msgid(1) = 6 bytes
	HeaderSizeV1 = 6

	// HeaderSizeV2 is the fixed header size for MAVLink v2:
	// magic(1) + len(1) + incompat(1) + compat(1) + seq(1) + sysid(1) + compid(1) + msgid(3) = 10 bytes
	HeaderSizeV2 = 10
)

// CRCSize is the size of the MAVLink CRC field in bytes.
const CRCSize = 2

// PacketInfo holds the parsed header fields of a MAVLink packet.
type PacketInfo struct {
	// Version is 1 or 2, corresponding to MAVLink v1 or v2.
	Version int

	// SystemID identifies the originating system (drone, GCS, etc.).
	SystemID uint8

	// ComponentID identifies the originating component within the system.
	ComponentID uint8

	// MessageID is the MAVLink message type identifier.
	// v1 supports 8-bit IDs; v2 supports 24-bit IDs.
	MessageID uint32

	// PayloadLen is the number of payload bytes following the header.
	PayloadLen uint8

	// Sequence is the packet sequence number used for loss detection.
	Sequence uint8
}

// Sentinel errors returned by Parse.
var (
	ErrTooShort = errors.New("mavlink: packet too short")
	ErrBadMagic = errors.New("mavlink: unknown magic byte")
)

// Parse extracts header fields from a MAVLink v1 or v2 packet.
// It returns an error if data is too short to contain a complete header
// or if the first byte is not a recognised magic value.
func Parse(data []byte) (*PacketInfo, error) {
	if len(data) == 0 {
		return nil, ErrTooShort
	}

	switch data[0] {
	case MagicV1:
		return parseV1(data)
	case MagicV2:
		return parseV2(data)
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrBadMagic, data[0])
	}
}

// parseV1 parses a MAVLink v1 packet.
// Wire layout: magic(1) len(1) seq(1) sysid(1) compid(1) msgid(1) payload(len) crc(2)
func parseV1(data []byte) (*PacketInfo, error) {
	if len(data) < HeaderSizeV1 {
		return nil, ErrTooShort
	}

	payloadLen := data[1]
	minLen := HeaderSizeV1 + int(payloadLen) + CRCSize
	if len(data) < minLen {
		return nil, ErrTooShort
	}

	return &PacketInfo{
		Version:     1,
		PayloadLen:  payloadLen,
		Sequence:    data[2],
		SystemID:    data[3],
		ComponentID: data[4],
		MessageID:   uint32(data[5]),
	}, nil
}

// parseV2 parses a MAVLink v2 packet.
// Wire layout: magic(1) len(1) incompat(1) compat(1) seq(1) sysid(1) compid(1) msgid(3,LE) payload(len) crc(2)
func parseV2(data []byte) (*PacketInfo, error) {
	if len(data) < HeaderSizeV2 {
		return nil, ErrTooShort
	}

	payloadLen := data[1]
	minLen := HeaderSizeV2 + int(payloadLen) + CRCSize
	if len(data) < minLen {
		return nil, ErrTooShort
	}

	// Message ID is 3 bytes little-endian starting at byte 7.
	msgID := uint32(data[7]) | uint32(data[8])<<8 | uint32(data[9])<<16

	return &PacketInfo{
		Version:     2,
		PayloadLen:  payloadLen,
		Sequence:    data[4],
		SystemID:    data[5],
		ComponentID: data[6],
		MessageID:   msgID,
	}, nil
}

// IsMAVLink reports whether data begins with a recognised MAVLink magic byte.
// Returns false for nil or empty slices.
func IsMAVLink(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	return data[0] == MagicV1 || data[0] == MagicV2
}

// PacketSize returns the total expected packet size in bytes for the packet
// described by data. It returns 0 if data is too short to determine the size
// or if the magic byte is not recognised.
func PacketSize(data []byte) int {
	if len(data) == 0 {
		return 0
	}

	switch data[0] {
	case MagicV1:
		if len(data) < 2 {
			return 0
		}
		return HeaderSizeV1 + int(data[1]) + CRCSize

	case MagicV2:
		if len(data) < 2 {
			return 0
		}
		return HeaderSizeV2 + int(data[1]) + CRCSize

	default:
		return 0
	}
}

// SystemIDString returns a human-readable label for a MAVLink system ID.
//
//   - ID 0        → "unknown"
//   - IDs 1-199   → "drone-N"
//   - IDs 200-254 → "gcs-N"
//   - ID 255      → "gcs-default"
func SystemIDString(id uint8) string {
	switch {
	case id == 0:
		return "unknown"
	case id <= 199:
		return fmt.Sprintf("drone-%d", id)
	case id <= 254:
		return fmt.Sprintf("gcs-%d", id)
	default: // 255
		return "gcs-default"
	}
}

// commonMessageNames maps well-known MAVLink message IDs to their names.
var commonMessageNames = map[uint32]string{
	0:   "HEARTBEAT",
	1:   "SYS_STATUS",
	24:  "GPS_RAW_INT",
	30:  "ATTITUDE",
	33:  "GLOBAL_POSITION_INT",
	76:  "COMMAND_LONG",
	253: "STATUSTEXT",
}

// MessageIDString returns the name of a MAVLink message ID, or a numeric
// representation if the ID is not in the common set.
func MessageIDString(id uint32) string {
	if name, ok := commonMessageNames[id]; ok {
		return name
	}
	return fmt.Sprintf("MSG_%d", id)
}
