package https

import (
	"encoding/binary"
	"io"
)

// Frame types for the tunnel protocol
const (
	FrameTypeData   byte = 0x01 // WireGuard packet
	FrameTypePing   byte = 0x02 // Keepalive
	FrameTypeConfig byte = 0x03 // Configuration update
	FrameTypeClose  byte = 0x04 // Graceful close
)

// Frame header size: type(1) + flags(1) + length(2) = 4 bytes
const FrameHeaderSize = 4

// Maximum frame payload size (64KB - header)
const MaxFrameSize = 65536 - FrameHeaderSize

// Standard padding sizes to normalize packet sizes
var PaddingSizes = []int{128, 256, 512, 1024, 2048, 4096, 8192, 16384}

// TunnelFrame represents a framed WireGuard packet
type TunnelFrame struct {
	Type    byte
	Flags   byte
	Payload []byte
}

// FrameFlags
const (
	FlagPadded     byte = 0x01 // Frame contains padding
	FlagCompressed byte = 0x02 // Payload is compressed (reserved)
	FlagPriority   byte = 0x04 // High priority frame
)

// Marshal serializes a tunnel frame to bytes
func (f *TunnelFrame) Marshal() []byte {
	payloadLen := len(f.Payload)

	// Calculate padding to reach standard size
	paddedLen := findNextPaddingSize(payloadLen)
	paddingLen := paddedLen - payloadLen

	totalLen := FrameHeaderSize + paddedLen
	buf := make([]byte, totalLen)

	buf[0] = f.Type
	buf[1] = f.Flags
	if paddingLen > 0 {
		buf[1] |= FlagPadded
	}
	binary.BigEndian.PutUint16(buf[2:4], uint16(payloadLen))

	copy(buf[FrameHeaderSize:], f.Payload)

	// Fill padding with zeros (or could use random data)
	// The actual payload length is in the header, so padding is implicit

	return buf
}

// MarshalTo writes the frame to a writer
func (f *TunnelFrame) MarshalTo(w io.Writer) error {
	data := f.Marshal()
	_, err := w.Write(data)
	return err
}

// UnmarshalFrame reads a tunnel frame from a reader
func UnmarshalFrame(r io.Reader) (*TunnelFrame, error) {
	header := make([]byte, FrameHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	frameType := header[0]
	flags := header[1]
	payloadLen := binary.BigEndian.Uint16(header[2:4])

	if payloadLen > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}

	// Calculate total frame size including padding
	readLen := int(payloadLen)
	if flags&FlagPadded != 0 {
		readLen = findNextPaddingSize(int(payloadLen))
	}

	// Read the full padded payload
	buf := make([]byte, readLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return &TunnelFrame{
		Type:    frameType,
		Flags:   flags,
		Payload: buf[:payloadLen], // Trim padding
	}, nil
}

// findNextPaddingSize finds the next standard padding size >= length
func findNextPaddingSize(length int) int {
	for _, size := range PaddingSizes {
		if size >= length {
			return size
		}
	}
	// If larger than all standard sizes, round up to next 1KB boundary
	return ((length + 1023) / 1024) * 1024
}

// NewDataFrame creates a frame containing WireGuard data
func NewDataFrame(data []byte) *TunnelFrame {
	return &TunnelFrame{
		Type:    FrameTypeData,
		Payload: data,
	}
}

// NewPingFrame creates a keepalive frame
func NewPingFrame() *TunnelFrame {
	return &TunnelFrame{
		Type:    FrameTypePing,
		Payload: nil,
	}
}

// NewCloseFrame creates a graceful close frame
func NewCloseFrame() *TunnelFrame {
	return &TunnelFrame{
		Type:    FrameTypeClose,
		Payload: nil,
	}
}

// FrameReader reads tunnel frames from an underlying connection
type FrameReader struct {
	reader io.Reader
}

// NewFrameReader creates a new frame reader
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{reader: r}
}

// ReadFrame reads the next tunnel frame
func (fr *FrameReader) ReadFrame() (*TunnelFrame, error) {
	return UnmarshalFrame(fr.reader)
}

// FrameWriter writes tunnel frames to an underlying connection
type FrameWriter struct {
	writer io.Writer
}

// NewFrameWriter creates a new frame writer
func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{writer: w}
}

// WriteFrame writes a tunnel frame
func (fw *FrameWriter) WriteFrame(f *TunnelFrame) error {
	return f.MarshalTo(fw.writer)
}

// WriteData writes a data frame
func (fw *FrameWriter) WriteData(data []byte) error {
	return fw.WriteFrame(NewDataFrame(data))
}
