package pki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// RenewalConfig configures the certificate renewal service
type RenewalConfig struct {
	// RenewalThreshold is how long before expiry to renew
	RenewalThreshold time.Duration

	// CheckInterval is how often to check certificate status
	CheckInterval time.Duration

	// AdminEndpoint is the admin node URL for renewal requests
	AdminEndpoint string

	// MaxRetries is the maximum renewal attempts before giving up
	MaxRetries int

	// RetryBackoff is the initial backoff between retries
	RetryBackoff time.Duration
}

// DefaultRenewalConfig returns default renewal configuration
func DefaultRenewalConfig() *RenewalConfig {
	return &RenewalConfig{
		RenewalThreshold: 6 * time.Hour, // Renew when 6 hours left
		CheckInterval:    1 * time.Hour,
		MaxRetries:       5,
		RetryBackoff:     1 * time.Minute,
	}
}

// RenewalRequest is sent to request certificate renewal
type RenewalRequest struct {
	NodeID          string `json:"node_id"`
	CurrentCertHash string `json:"current_cert_hash"` // SHA-256 of current cert
	PublicKey       string `json:"public_key"`        // Base64 Ed25519 public key
	CSR             string `json:"csr,omitempty"`     // Optional CSR
	Timestamp       int64  `json:"timestamp"`
	Signature       string `json:"signature"` // Signed with current key
}

// RenewalResponse is returned after successful renewal
type RenewalResponse struct {
	Certificate string `json:"certificate"`  // New PEM-encoded certificate
	ExpiresAt   int64  `json:"expires_at"`
	CACertChain string `json:"ca_cert_chain,omitempty"` // If CA rotated
}

// RenewalService handles automatic certificate renewal
type RenewalService struct {
	cfg *RenewalConfig

	// Current certificate and key
	cert       *x509.Certificate
	privateKey ed25519.PrivateKey
	certPEM    string
	mu         sync.RWMutex

	// Callbacks
	onRenewal func(newCert *x509.Certificate, certPEM string)
	onFailure func(error)

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewRenewalService creates a new renewal service
func NewRenewalService(cfg *RenewalConfig, cert *x509.Certificate, privateKey ed25519.PrivateKey, certPEM string) *RenewalService {
	if cfg == nil {
		cfg = DefaultRenewalConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &RenewalService{
		cfg:        cfg,
		cert:       cert,
		privateKey: privateKey,
		certPEM:    certPEM,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// SetCallbacks sets the renewal callbacks
func (rs *RenewalService) SetCallbacks(onRenewal func(*x509.Certificate, string), onFailure func(error)) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.onRenewal = onRenewal
	rs.onFailure = onFailure
}

// Start begins the renewal service
func (rs *RenewalService) Start() {
	rs.wg.Add(1)
	go rs.renewalLoop()
}

// Stop halts the renewal service
func (rs *RenewalService) Stop() {
	rs.cancel()
	rs.wg.Wait()
}

// GetCertificate returns the current certificate
func (rs *RenewalService) GetCertificate() (*x509.Certificate, string) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.cert, rs.certPEM
}

// UpdateCertificate updates the current certificate (e.g., after initial enrollment)
func (rs *RenewalService) UpdateCertificate(cert *x509.Certificate, certPEM string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.cert = cert
	rs.certPEM = certPEM
}

// TimeUntilExpiry returns the time until certificate expiry
func (rs *RenewalService) TimeUntilExpiry() time.Duration {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if rs.cert == nil {
		return 0
	}
	return time.Until(rs.cert.NotAfter)
}

// NeedsRenewal checks if the certificate needs renewal
func (rs *RenewalService) NeedsRenewal() bool {
	return rs.TimeUntilExpiry() < rs.cfg.RenewalThreshold
}

func (rs *RenewalService) renewalLoop() {
	defer rs.wg.Done()

	ticker := time.NewTicker(rs.cfg.CheckInterval)
	defer ticker.Stop()

	// Check immediately on start
	rs.checkAndRenew()

	for {
		select {
		case <-rs.ctx.Done():
			return
		case <-ticker.C:
			rs.checkAndRenew()
		}
	}
}

func (rs *RenewalService) checkAndRenew() {
	if !rs.NeedsRenewal() {
		return
	}

	// Attempt renewal with retries
	var lastErr error
	backoff := rs.cfg.RetryBackoff

	for attempt := 0; attempt < rs.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-rs.ctx.Done():
				return
			case <-time.After(backoff):
				backoff *= 2 // Exponential backoff
			}
		}

		err := rs.doRenewal()
		if err == nil {
			return // Success
		}
		lastErr = err
	}

	// All retries failed
	rs.mu.RLock()
	onFailure := rs.onFailure
	rs.mu.RUnlock()

	if onFailure != nil {
		onFailure(fmt.Errorf("renewal failed after %d attempts: %w", rs.cfg.MaxRetries, lastErr))
	}
}

func (rs *RenewalService) doRenewal() error {
	rs.mu.RLock()
	endpoint := rs.cfg.AdminEndpoint
	cert := rs.cert
	privateKey := rs.privateKey
	rs.mu.RUnlock()

	if endpoint == "" {
		return fmt.Errorf("no admin endpoint configured")
	}

	if cert == nil {
		return fmt.Errorf("no current certificate")
	}

	// Build renewal request
	req := &RenewalRequest{
		NodeID:          extractNodeID(cert),
		CurrentCertHash: certFingerprint(cert),
		PublicKey:       base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
		Timestamp:       time.Now().Unix(),
	}

	// Sign the request
	signData := []byte(fmt.Sprintf("%s:%s:%d", req.NodeID, req.CurrentCertHash, req.Timestamp))
	signature := ed25519.Sign(privateKey, signData)
	req.Signature = base64.StdEncoding.EncodeToString(signature)

	// Send request
	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	ctx, cancel := context.WithTimeout(rs.ctx, 30*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint+"/renew", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("renewal failed: status %d", resp.StatusCode)
	}

	// Parse response
	var renewResp RenewalResponse
	if err := json.NewDecoder(resp.Body).Decode(&renewResp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	// Parse the new certificate
	block, _ := pem.Decode([]byte(renewResp.Certificate))
	if block == nil {
		return fmt.Errorf("invalid certificate PEM")
	}

	newCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	// Update certificate
	rs.mu.Lock()
	rs.cert = newCert
	rs.certPEM = renewResp.Certificate
	onRenewal := rs.onRenewal
	rs.mu.Unlock()

	// Notify callback
	if onRenewal != nil {
		onRenewal(newCert, renewResp.Certificate)
	}

	return nil
}

func extractNodeID(cert *x509.Certificate) string {
	// Extract node ID from certificate subject
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return ""
}

func certFingerprint(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw[:32])
}

// RenewalHandler handles renewal requests on the admin side
type RenewalHandler struct {
	ca         *CertificateAuthority
	validCerts map[string]bool // nodeID -> has valid cert
	mu         sync.RWMutex
}

// NewRenewalHandler creates a renewal handler for admin nodes
func NewRenewalHandler(ca *CertificateAuthority) *RenewalHandler {
	return &RenewalHandler{
		ca:         ca,
		validCerts: make(map[string]bool),
	}
}

// HandleRenewal processes a renewal request
func (rh *RenewalHandler) HandleRenewal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RenewalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Verify timestamp is recent (within 5 minutes)
	if abs(time.Now().Unix()-req.Timestamp) > 300 {
		http.Error(w, "request expired", http.StatusBadRequest)
		return
	}

	// Decode and verify signature
	pubKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}

	signData := []byte(fmt.Sprintf("%s:%s:%d", req.NodeID, req.CurrentCertHash, req.Timestamp))
	if !ed25519.Verify(pubKey, signData, sigBytes) {
		http.Error(w, "signature verification failed", http.StatusUnauthorized)
		return
	}

	// Issue new certificate
	// Preserve existing roles from the previous certificate
	certReq := &NodeCertRequest{
		NodeID:    req.NodeID,
		PublicKey: pubKey,
		Roles:     []string{"operator"}, // Default, should lookup from previous cert
		Validity:  24 * time.Hour,
	}

	newCert, _, err := rh.ca.IssueCertificate(certReq)
	if err != nil {
		http.Error(w, "certificate issuance failed", http.StatusInternalServerError)
		return
	}

	// Encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: newCert.Raw,
	})

	resp := &RenewalResponse{
		Certificate: string(certPEM),
		ExpiresAt:   newCert.NotAfter.Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
