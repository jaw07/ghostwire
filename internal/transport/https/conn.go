package https

import (
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	// tunnelIdleTimeout reaps a tunnel connection that goes silent.
	tunnelIdleTimeout = 5 * time.Minute
	// maxConsecutiveControlFrames bounds ping/unknown frames between data
	// frames, so a peer cannot pin the read loop emitting ping replies.
	maxConsecutiveControlFrames = 64
)

// TunnelConn wraps a connection with tunnel framing
type TunnelConn struct {
	conn         net.Conn
	localPubKey  []byte
	remotePubKey []byte
	reader       *FrameReader
	writer       *FrameWriter
	readBuf      []byte
	readOffset   int
	mu           sync.Mutex
	closed       bool
}

// NewTunnelConn creates a new tunnel connection
func NewTunnelConn(conn net.Conn, localPubKey, remotePubKey []byte) *TunnelConn {
	return &TunnelConn{
		conn:         conn,
		localPubKey:  localPubKey,
		remotePubKey: remotePubKey,
		reader:       NewFrameReader(conn),
		writer:       NewFrameWriter(conn),
	}
}

// Read implements net.Conn
func (tc *TunnelConn) Read(b []byte) (int, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	controlFrames := 0
	for {
		// If we have buffered data, return it first
		if tc.readOffset < len(tc.readBuf) {
			n := copy(b, tc.readBuf[tc.readOffset:])
			tc.readOffset += n
			if tc.readOffset >= len(tc.readBuf) {
				tc.readBuf = nil
				tc.readOffset = 0
			}
			return n, nil
		}

		// Idle deadline: reap a connection that stops sending frames.
		tc.conn.SetReadDeadline(time.Now().Add(tunnelIdleTimeout))

		// Read next frame
		frame, err := tc.reader.ReadFrame()
		if err != nil {
			return 0, err
		}

		switch frame.Type {
		case FrameTypeData:
			controlFrames = 0
			// Copy data to buffer
			if len(frame.Payload) <= len(b) {
				return copy(b, frame.Payload), nil
			}
			// Buffer excess data
			n := copy(b, frame.Payload)
			tc.readBuf = frame.Payload[n:]
			tc.readOffset = 0
			return n, nil

		case FrameTypePing:
			// Respond with ping and loop, but cap consecutive control frames so
			// a peer can't pin this loop generating ping replies.
			controlFrames++
			if controlFrames > maxConsecutiveControlFrames {
				return 0, fmt.Errorf("too many consecutive control frames")
			}
			tc.writer.WriteFrame(NewPingFrame())
			continue

		case FrameTypeClose:
			tc.closed = true
			return 0, net.ErrClosed

		default:
			// Unknown frame type - skip and loop (bounded)
			controlFrames++
			if controlFrames > maxConsecutiveControlFrames {
				return 0, fmt.Errorf("too many consecutive control frames")
			}
			continue
		}
	}
}

// Write implements net.Conn
func (tc *TunnelConn) Write(b []byte) (int, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if tc.closed {
		return 0, net.ErrClosed
	}

	if err := tc.writer.WriteData(b); err != nil {
		return 0, err
	}

	return len(b), nil
}

// Close implements net.Conn
func (tc *TunnelConn) Close() error {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if tc.closed {
		return nil
	}
	tc.closed = true

	// Send close frame (best effort)
	tc.writer.WriteFrame(NewCloseFrame())

	return tc.conn.Close()
}

// LocalAddr implements net.Conn
func (tc *TunnelConn) LocalAddr() net.Addr {
	return tc.conn.LocalAddr()
}

// RemoteAddr implements net.Conn
func (tc *TunnelConn) RemoteAddr() net.Addr {
	return tc.conn.RemoteAddr()
}

// SetDeadline implements net.Conn
func (tc *TunnelConn) SetDeadline(t time.Time) error {
	return tc.conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn
func (tc *TunnelConn) SetReadDeadline(t time.Time) error {
	return tc.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn
func (tc *TunnelConn) SetWriteDeadline(t time.Time) error {
	return tc.conn.SetWriteDeadline(t)
}

// LocalPublicKey returns the local node's public key
func (tc *TunnelConn) LocalPublicKey() []byte {
	return tc.localPubKey
}

// RemotePublicKey returns the remote peer's public key
func (tc *TunnelConn) RemotePublicKey() []byte {
	return tc.remotePubKey
}

// SendPing sends a keepalive ping
func (tc *TunnelConn) SendPing() error {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.writer.WriteFrame(NewPingFrame())
}
