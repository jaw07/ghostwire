package mavlink

import (
	"errors"
	"testing"
)

// buildV1Packet constructs a minimal MAVLink v1 packet with a zero-filled payload.
// Layout: magic(1) len(1) seq(1) sysid(1) compid(1) msgid(1) payload(len) crc(2)
func buildV1Packet(payloadLen uint8, seq, sysid, compid, msgid uint8) []byte {
	frame := make([]byte, HeaderSizeV1+int(payloadLen)+CRCSize)
	frame[0] = MagicV1
	frame[1] = payloadLen
	frame[2] = seq
	frame[3] = sysid
	frame[4] = compid
	frame[5] = msgid
	// payload bytes are zero-filled
	// crc bytes are zero-filled (we only test header parsing)
	return frame
}

// buildV2Packet constructs a minimal MAVLink v2 packet with a zero-filled payload.
// Layout: magic(1) len(1) incompat(1) compat(1) seq(1) sysid(1) compid(1) msgid(3,LE) payload(len) crc(2)
func buildV2Packet(payloadLen uint8, seq, sysid, compid uint8, msgid uint32) []byte {
	frame := make([]byte, HeaderSizeV2+int(payloadLen)+CRCSize)
	frame[0] = MagicV2
	frame[1] = payloadLen
	frame[2] = 0 // incompat flags
	frame[3] = 0 // compat flags
	frame[4] = seq
	frame[5] = sysid
	frame[6] = compid
	frame[7] = uint8(msgid)
	frame[8] = uint8(msgid >> 8)
	frame[9] = uint8(msgid >> 16)
	// payload bytes are zero-filled
	// crc bytes are zero-filled
	return frame
}

// ---------------------------------------------------------------------------
// TestParseV1
// ---------------------------------------------------------------------------

func TestParseV1(t *testing.T) {
	const (
		payloadLen uint8 = 9
		seq        uint8 = 42
		sysid      uint8 = 1
		compid     uint8 = 1
		msgid      uint8 = 0 // HEARTBEAT
	)

	frame := buildV1Packet(payloadLen, seq, sysid, compid, msgid)

	info, err := Parse(frame)
	if err != nil {
		t.Fatalf("Parse returned unexpected error: %v", err)
	}

	if info.Version != 1 {
		t.Errorf("Version = %d, want 1", info.Version)
	}
	if info.Sequence != seq {
		t.Errorf("Sequence = %d, want %d", info.Sequence, seq)
	}
	if info.SystemID != sysid {
		t.Errorf("SystemID = %d, want %d", info.SystemID, sysid)
	}
	if info.ComponentID != compid {
		t.Errorf("ComponentID = %d, want %d", info.ComponentID, compid)
	}
	if info.MessageID != uint32(msgid) {
		t.Errorf("MessageID = %d, want %d", info.MessageID, msgid)
	}
	if info.PayloadLen != payloadLen {
		t.Errorf("PayloadLen = %d, want %d", info.PayloadLen, payloadLen)
	}
}

// ---------------------------------------------------------------------------
// TestParseV2
// ---------------------------------------------------------------------------

func TestParseV2(t *testing.T) {
	const (
		payloadLen uint8  = 9
		seq        uint8  = 7
		sysid      uint8  = 2
		compid     uint8  = 1
		msgid      uint32 = 0 // HEARTBEAT
	)

	frame := buildV2Packet(payloadLen, seq, sysid, compid, msgid)

	info, err := Parse(frame)
	if err != nil {
		t.Fatalf("Parse returned unexpected error: %v", err)
	}

	if info.Version != 2 {
		t.Errorf("Version = %d, want 2", info.Version)
	}
	if info.Sequence != seq {
		t.Errorf("Sequence = %d, want %d", info.Sequence, seq)
	}
	if info.SystemID != sysid {
		t.Errorf("SystemID = %d, want %d", info.SystemID, sysid)
	}
	if info.ComponentID != compid {
		t.Errorf("ComponentID = %d, want %d", info.ComponentID, compid)
	}
	if info.MessageID != msgid {
		t.Errorf("MessageID = %d, want %d", info.MessageID, msgid)
	}
	if info.PayloadLen != payloadLen {
		t.Errorf("PayloadLen = %d, want %d", info.PayloadLen, payloadLen)
	}
}

// ---------------------------------------------------------------------------
// TestParseTooShort
// ---------------------------------------------------------------------------

func TestParseTooShort(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"v1 header truncated", []byte{MagicV1, 0x09}},           // only 2 bytes
		{"v1 payload truncated", buildV1Packet(9, 1, 1, 1, 0)[:7]}, // strip payload+CRC
		{"v2 header truncated", []byte{MagicV2, 0x09, 0x00}},     // only 3 bytes
		{"v2 payload truncated", buildV2Packet(9, 1, 1, 1, 0)[:11]}, // strip payload+CRC
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.data)
			if err == nil {
				t.Fatal("expected error for short packet, got nil")
			}
			if !errors.Is(err, ErrTooShort) {
				t.Errorf("expected ErrTooShort, got: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestParseBadMagic
// ---------------------------------------------------------------------------

func TestParseBadMagic(t *testing.T) {
	bad := []byte{0xAB, 0x09, 0x00, 0x01, 0x01, 0x00}

	_, err := Parse(bad)
	if err == nil {
		t.Fatal("expected error for unknown magic byte, got nil")
	}
	if !errors.Is(err, ErrBadMagic) {
		t.Errorf("expected ErrBadMagic, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestIsMAVLink
// ---------------------------------------------------------------------------

func TestIsMAVLink(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"nil slice", nil, false},
		{"empty slice", []byte{}, false},
		{"v1 magic", []byte{MagicV1, 0x00}, true},
		{"v2 magic", []byte{MagicV2, 0x00}, true},
		{"wrong magic 0x00", []byte{0x00}, false},
		{"wrong magic 0xFF", []byte{0xFF}, false},
		{"wrong magic 0xAB", []byte{0xAB, 0x01, 0x02}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsMAVLink(tc.data)
			if got != tc.want {
				t.Errorf("IsMAVLink(%x) = %v, want %v", tc.data, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestPacketSize
// ---------------------------------------------------------------------------

func TestPacketSize(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want int
	}{
		{"nil", nil, 0},
		{"empty", []byte{}, 0},
		{"bad magic", []byte{0xAB}, 0},
		{"v1 too short for len byte", []byte{MagicV1}, 0},
		{"v1 payload 9", buildV1Packet(9, 0, 1, 1, 0), HeaderSizeV1 + 9 + CRCSize},
		{"v1 payload 0", buildV1Packet(0, 0, 1, 1, 0), HeaderSizeV1 + 0 + CRCSize},
		{"v2 payload 9", buildV2Packet(9, 0, 1, 1, 0), HeaderSizeV2 + 9 + CRCSize},
		{"v2 payload 0", buildV2Packet(0, 0, 1, 1, 0), HeaderSizeV2 + 0 + CRCSize},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PacketSize(tc.data)
			if got != tc.want {
				t.Errorf("PacketSize = %d, want %d", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestSystemIDString
// ---------------------------------------------------------------------------

func TestSystemIDString(t *testing.T) {
	cases := []struct {
		id   uint8
		want string
	}{
		{0, "unknown"},
		{1, "drone-1"},
		{100, "drone-100"},
		{199, "drone-199"},
		{200, "gcs-200"},
		{254, "gcs-254"},
		{255, "gcs-default"},
	}

	for _, tc := range cases {
		got := SystemIDString(tc.id)
		if got != tc.want {
			t.Errorf("SystemIDString(%d) = %q, want %q", tc.id, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// TestMessageIDString
// ---------------------------------------------------------------------------

func TestMessageIDString(t *testing.T) {
	cases := []struct {
		id   uint32
		want string
	}{
		{0, "HEARTBEAT"},
		{1, "SYS_STATUS"},
		{24, "GPS_RAW_INT"},
		{30, "ATTITUDE"},
		{33, "GLOBAL_POSITION_INT"},
		{76, "COMMAND_LONG"},
		{253, "STATUSTEXT"},
		{999, "MSG_999"},
		{100, "MSG_100"},
	}

	for _, tc := range cases {
		got := MessageIDString(tc.id)
		if got != tc.want {
			t.Errorf("MessageIDString(%d) = %q, want %q", tc.id, got, tc.want)
		}
	}
}
