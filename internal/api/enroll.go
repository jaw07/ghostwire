// Package api provides the GHOSTWIRE enrollment and management API.
package api

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ghostwire/ghostwire/internal/config"
	"github.com/ghostwire/ghostwire/internal/pki"
	"github.com/ghostwire/ghostwire/internal/token"
)

// EnrollmentServer handles node enrollment requests
type EnrollmentServer struct {
	ca          *pki.CertificateAuthority
	adminConfig *config.AdminConfig
	configMu    sync.RWMutex
	meshSecret  []byte
	saveConfig  func(*config.AdminConfig) error

	server   *http.Server
	listener net.Listener
}

// EnrollmentRequest is sent by joining nodes
type EnrollmentRequest struct {
	Token     string `json:"token"`      // Enrollment token
	PublicKey string `json:"public_key"` // Base64 Ed25519 public key
	NodeName  string `json:"node_name"`  // Requested node name
	WGPubKey  string `json:"wg_pub_key"` // Base64 X25519 WireGuard public key
}

// EnrollmentResponse is returned to joining nodes
type EnrollmentResponse struct {
	NodeID          string              `json:"node_id"`
	Certificate     string              `json:"certificate"`      // PEM-encoded node certificate
	CACertificate   string              `json:"ca_certificate"`   // PEM-encoded CA certificate
	MeshName        string              `json:"mesh_name"`
	MeshID          string              `json:"mesh_id"`
	MeshSubnet      string              `json:"mesh_subnet"`
	AssignedIP      string              `json:"assigned_ip"`
	MeshSecret      string              `json:"mesh_secret"`      // Base64 mesh secret for knock auth
	Roles           []string            `json:"roles"`
	Peers           []config.PeerConfig `json:"peers"`
	TransportConfig config.TransportConfig `json:"transport"`
}

// ErrorResponse is returned on errors
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
}

// ServerConfig holds configuration for the enrollment server
type ServerConfig struct {
	ListenAddr  string
	TLSCert     tls.Certificate
	AdminConfig *config.AdminConfig
	CA          *pki.CertificateAuthority
	MeshSecret  []byte
	SaveConfig  func(*config.AdminConfig) error
}

// NewEnrollmentServer creates a new enrollment server
func NewEnrollmentServer(cfg *ServerConfig) (*EnrollmentServer, error) {
	s := &EnrollmentServer{
		ca:          cfg.CA,
		adminConfig: cfg.AdminConfig,
		meshSecret:  cfg.MeshSecret,
		saveConfig:  cfg.SaveConfig,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/enroll", s.handleEnroll)
	mux.HandleFunc("/health", s.handleHealth)

	// TLS 1.3 required. Client certificates are not required for enrollment
	// since new nodes don't have certificates yet (enrollment is how they get one).
	// The enrollment token serves as the authorization gate. The mesh_secret is
	// transmitted over this TLS channel — this is acceptable because:
	// 1. Tokens are one-time use and time-limited
	// 2. TLS 1.3 provides forward secrecy
	// 3. The enrollment endpoint should only be exposed during node provisioning
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cfg.TLSCert},
		MinVersion:   tls.VersionTLS13,
	}

	s.server = &http.Server{
		Addr:      cfg.ListenAddr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	return s, nil
}

// Start starts the enrollment server
func (s *EnrollmentServer) Start() error {
	ln, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = ln

	tlsListener := tls.NewListener(ln, s.server.TLSConfig)
	return s.server.Serve(tlsListener)
}

// Stop gracefully stops the enrollment server
func (s *EnrollmentServer) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

// Addr returns the server's listen address
func (s *EnrollmentServer) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.server.Addr
}

func (s *EnrollmentServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *EnrollmentServer) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}

	var req EnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON")
		return
	}

	// Validate token
	s.configMu.RLock()
	meshID := s.ca.MeshID
	s.configMu.RUnlock()

	validator := token.NewValidator(s.getCAPublicKey(), meshID)
	tok, err := validator.Validate(req.Token)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}

	// Decode public keys before taking the lock
	pubKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		s.writeError(w, http.StatusBadRequest, "invalid_public_key", "Invalid Ed25519 public key")
		return
	}

	wgPubKeyBytes, err := base64.StdEncoding.DecodeString(req.WGPubKey)
	if err != nil || len(wgPubKeyBytes) != 32 {
		s.writeError(w, http.StatusBadRequest, "invalid_wg_key", "Invalid WireGuard public key")
		return
	}

	// Check and update token usage under lock
	s.configMu.Lock()

	tokenUsed := false
	for i := range s.adminConfig.EnrollmentTokens {
		if s.adminConfig.EnrollmentTokens[i].TokenID == hex.EncodeToString(tok.ID[:]) {
			stored := &s.adminConfig.EnrollmentTokens[i]
			if stored.MaxUses > 0 && stored.UsedCount >= stored.MaxUses {
				s.configMu.Unlock()
				s.writeError(w, http.StatusUnauthorized, "token_exhausted", "Token usage limit reached")
				return
			}
			stored.UsedCount++
			tokenUsed = true
			break
		}
	}
	if !tokenUsed {
		s.configMu.Unlock()
		s.writeError(w, http.StatusUnauthorized, "token_not_found", "Token not found in admin config")
		return
	}

	// Determine node name
	nodeName := req.NodeName
	if nodeName == "" && tok.SuggestedName != "" {
		nodeName = tok.SuggestedName
	}
	if nodeName == "" {
		nodeName = fmt.Sprintf("node-%s", hex.EncodeToString(tok.ID[:4]))
	}

	// Allocate IP address
	assignedIP, err := s.allocateIP(nodeName)
	if err != nil {
		s.configMu.Unlock()
		s.writeError(w, http.StatusInternalServerError, "ip_allocation_failed", err.Error())
		return
	}

	// Issue certificate
	var wgPubKey [32]byte
	copy(wgPubKey[:], wgPubKeyBytes)

	meshIP := net.ParseIP(assignedIP)
	certReq := &pki.NodeCertRequest{
		NodeID:          nodeName,
		Roles:           tok.AllowedRoles,
		Compartment:     tok.Compartment,
		PublicKey:       ed25519.PublicKey(pubKeyBytes),
		WireGuardPubKey: wgPubKey,
		MeshIP:          meshIP,
		Validity:        24 * time.Hour,
	}

	cert, _, err := s.ca.IssueCertificate(certReq)
	if err != nil {
		s.configMu.Unlock()
		s.writeError(w, http.StatusInternalServerError, "cert_issue_failed", err.Error())
		return
	}

	// Add new node as a peer in admin config
	newPeer := config.PeerConfig{
		NodeID:    nodeName,
		PublicKey: req.WGPubKey,
		MeshIP:    assignedIP,
		Endpoints: []string{}, // New node doesn't have known endpoints yet
		Roles:     tok.AllowedRoles,
	}
	s.adminConfig.Peers = append(s.adminConfig.Peers, newPeer)

	// Build peer list for the new node (include admin and other peers)
	peers := s.buildPeerList(nodeName)

	// Copy config ref for saving outside the lock
	adminConfigCopy := s.adminConfig
	s.configMu.Unlock()

	// Save updated admin config outside of the lock to avoid holding it during slow I/O
	if s.saveConfig != nil {
		if err := s.saveConfig(adminConfigCopy); err != nil {
			fmt.Printf("Warning: failed to save admin config: %v\n", err)
		}
	}

	// Build response
	resp := &EnrollmentResponse{
		NodeID:        nodeName,
		Certificate:   string(pki.CertificateToPEM(cert)),
		CACertificate: s.adminConfig.CACertChain,
		MeshName:      s.adminConfig.MeshName,
		MeshID:        s.adminConfig.MeshID,
		MeshSubnet:    s.adminConfig.MeshSubnet,
		AssignedIP:    assignedIP,
		MeshSecret:    s.adminConfig.MeshSecret,
		Roles:         tok.AllowedRoles,
		Peers:         peers,
		TransportConfig: s.adminConfig.Transport,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *EnrollmentServer) getCAPublicKey() ed25519.PublicKey {
	// Extract public key from CA certificate
	return s.ca.RootCert.PublicKey.(ed25519.PublicKey)
}

func (s *EnrollmentServer) allocateIP(nodeID string) (string, error) {
	alloc := &s.adminConfig.IPAllocator

	// Check if already allocated
	if ip, exists := alloc.Allocated[nodeID]; exists {
		return ip, nil
	}

	// Parse next IP
	nextIP := net.ParseIP(alloc.NextIP)
	if nextIP == nil {
		return "", fmt.Errorf("invalid next IP: %s", alloc.NextIP)
	}

	// Allocate
	assignedIP := nextIP.String()
	if alloc.Allocated == nil {
		alloc.Allocated = make(map[string]string)
	}
	alloc.Allocated[nodeID] = assignedIP

	// Increment next IP
	ip4 := nextIP.To4()
	if ip4 != nil {
		// Simple increment for IPv4
		ip4[3]++
		if ip4[3] == 0 {
			ip4[2]++
		}
		alloc.NextIP = ip4.String()
	}

	return assignedIP, nil
}

func (s *EnrollmentServer) buildPeerList(excludeNodeID string) []config.PeerConfig {
	var peers []config.PeerConfig

	// Add admin node as a peer
	adminPeer := config.PeerConfig{
		NodeID:    s.adminConfig.NodeID,
		PublicKey: s.getAdminWGPubKey(),
		MeshIP:    s.adminConfig.AssignedIP,
		Endpoints: s.getAdminEndpoints(),
		Roles:     s.adminConfig.Roles,
	}
	peers = append(peers, adminPeer)

	// Add other peers
	for _, p := range s.adminConfig.Peers {
		if p.NodeID != excludeNodeID {
			peers = append(peers, p)
		}
	}

	return peers
}

func (s *EnrollmentServer) getAdminWGPubKey() string {
	// Extract WG public key from admin's certificate
	if s.adminConfig.NodeCertificate != "" {
		block, _ := pem.Decode([]byte(s.adminConfig.NodeCertificate))
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				ext, err := pki.ParseExtensions(cert.Extensions)
				if err == nil {
					return base64.StdEncoding.EncodeToString(ext.WireGuardPubKey[:])
				}
			}
		}
	}
	return ""
}

func (s *EnrollmentServer) getAdminEndpoints() []string {
	// Return the transport listener address (for WireGuard tunnel connections),
	// not the enrollment server address
	if s.adminConfig.Transport.HTTPS.TransportListenAddr != "" {
		return []string{s.adminConfig.Transport.HTTPS.TransportListenAddr}
	}
	// Fall back to enrollment listen addr if transport addr not configured
	if s.adminConfig.Transport.HTTPS.ListenAddr != "" {
		return []string{s.adminConfig.Transport.HTTPS.ListenAddr}
	}
	return []string{}
}

func (s *EnrollmentServer) writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(&ErrorResponse{
		Error: message,
		Code:  code,
	})
}
