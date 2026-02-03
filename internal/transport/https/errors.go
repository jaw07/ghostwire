package https

import "errors"

var (
	// ErrInvalidConfig indicates the transport configuration is invalid
	ErrInvalidConfig = errors.New("invalid HTTPS transport configuration")

	// ErrMissingServerName indicates the server name (SNI) is not configured
	ErrMissingServerName = errors.New("server name (SNI) is required")

	// ErrInvalidMeshSecret indicates the mesh secret is invalid
	ErrInvalidMeshSecret = errors.New("mesh secret must be 32 bytes")

	// ErrKnockFailed indicates the knock authentication failed
	ErrKnockFailed = errors.New("knock authentication failed")

	// ErrKnockExpired indicates the knock timestamp is outside the valid window
	ErrKnockExpired = errors.New("knock timestamp expired")

	// ErrNotAuthenticated indicates the connection is not authenticated
	ErrNotAuthenticated = errors.New("connection not authenticated")

	// ErrTransportClosed indicates the transport has been closed
	ErrTransportClosed = errors.New("transport closed")

	// ErrInvalidFrame indicates an invalid tunnel frame was received
	ErrInvalidFrame = errors.New("invalid tunnel frame")

	// ErrFrameTooLarge indicates a frame exceeds the maximum size
	ErrFrameTooLarge = errors.New("frame too large")
)
