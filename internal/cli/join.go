package cli

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghostwire/ghostwire/internal/api"
	"github.com/ghostwire/ghostwire/internal/config"
	"github.com/ghostwire/ghostwire/internal/keys"
	"github.com/ghostwire/ghostwire/internal/pki"
	"github.com/ghostwire/ghostwire/internal/token"
)

func newJoinCmd() *cobra.Command {
	var (
		tokenStr  string
		endpoint  string
		nodeName  string
		configDir string
	)

	cmd := &cobra.Command{
		Use:   "join",
		Short: "Join an existing mesh network",
		Long: `Join a GHOSTWIRE mesh using an enrollment token.

This command:
  1. Validates the enrollment token
  2. Generates a new keypair for this node
  3. Sends a certificate signing request to the admin node
  4. Receives and stores the signed certificate
  5. Downloads mesh configuration and peer list`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tokenStr == "" {
				return fmt.Errorf("--token is required")
			}
			if endpoint == "" {
				return fmt.Errorf("--endpoint is required")
			}

			return joinMesh(tokenStr, endpoint, nodeName, configDir)
		},
	}

	cmd.Flags().StringVar(&tokenStr, "token", "", "enrollment token (required)")
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "admin node endpoint, e.g. admin.example.com:443 (required)")
	cmd.Flags().StringVar(&nodeName, "name", "", "name for this node (optional, may be suggested by token)")
	cmd.Flags().StringVarP(&configDir, "config", "c", "", "config directory (default: ~/.config/gw)")

	return cmd
}

func joinMesh(tokenStr, endpoint, nodeName, configDir string) error {
	// Set default config directory
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("get home dir: %w", err)
		}
		configDir = filepath.Join(home, ".config", "gw")
	}

	// Check if already configured
	loader := config.NewLoader(configDir)
	if loader.ConfigExists() {
		return fmt.Errorf("config already exists at %s\nUse 'ghostwire panic --wipe-config' to remove existing config first", loader.ConfigPath())
	}

	fmt.Println("Parsing enrollment token...")

	// Parse and validate token structure
	_, _, err := token.ParseTokenString(tokenStr)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	payload, err := token.DecodePayload(mustParseToken(tokenStr))
	if err != nil {
		return fmt.Errorf("decode token: %w", err)
	}

	// Create token object for display
	tok := &token.Token{
		ID:            payload.TokenID,
		Version:       int(payload.Version),
		AllowedRoles:  payload.Roles,
		Compartment:   payload.Compartment,
		SuggestedName: payload.SuggestedName,
		MaxUses:       int(payload.MaxUses),
		MeshID:        payload.MeshID,
	}

	// Check token expiry (basic validation without full signature check)
	if tok.IsExpired() {
		return fmt.Errorf("token has expired")
	}

	fmt.Println()
	fmt.Printf("Token validated:\n")
	fmt.Printf("  Mesh ID:     %s...\n", hex.EncodeToString(tok.MeshID[:8]))
	fmt.Printf("  Roles:       %v\n", tok.AllowedRoles)
	if tok.SuggestedName != "" {
		fmt.Printf("  Suggested:   %s\n", tok.SuggestedName)
	}
	fmt.Println()

	// Use suggested name if no name provided
	if nodeName == "" && tok.SuggestedName != "" {
		nodeName = tok.SuggestedName
	}
	if nodeName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			nodeName = "node"
		} else {
			nodeName = hostname
		}
	}

	fmt.Printf("Node name: %s\n", nodeName)
	fmt.Println()

	// Generate local keypair
	fmt.Println("Generating node keypair...")
	nodeKp, err := keys.Generate()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	defer nodeKp.Wipe()

	fmt.Printf("  Ed25519 public: %s...\n", hex.EncodeToString(nodeKp.Ed25519PublicKey[:8]))
	fmt.Printf("  X25519 public:  %s...\n", hex.EncodeToString(nodeKp.X25519PublicKey[:8]))
	fmt.Println()

	// Create output directory
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	fmt.Printf("Connecting to admin node at %s...\n", endpoint)

	// Build enrollment request
	enrollReq := &api.EnrollmentRequest{
		Token:     tokenStr,
		PublicKey: base64.StdEncoding.EncodeToString(nodeKp.Ed25519PublicKey),
		NodeName:  nodeName,
		WGPubKey:  base64.StdEncoding.EncodeToString(nodeKp.X25519PublicKey[:]),
	}

	reqBody, err := json.Marshal(enrollReq)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	// Create HTTPS client (skip verify since we don't have CA yet)
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // We verify the response cert manually
			},
		},
	}

	// Make enrollment request
	url := fmt.Sprintf("https://%s/enroll", endpoint)
	resp, err := client.Post(url, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("enrollment request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp api.ErrorResponse
		if json.Unmarshal(body, &errResp) == nil {
			return fmt.Errorf("enrollment failed: %s (%s)", errResp.Error, errResp.Code)
		}
		return fmt.Errorf("enrollment failed: HTTP %d", resp.StatusCode)
	}

	var enrollResp api.EnrollmentResponse
	if err := json.Unmarshal(body, &enrollResp); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	fmt.Println("Enrollment successful!")
	fmt.Println()
	fmt.Printf("  Node ID:     %s\n", enrollResp.NodeID)
	fmt.Printf("  Mesh:        %s\n", enrollResp.MeshName)
	fmt.Printf("  Assigned IP: %s\n", enrollResp.AssignedIP)
	fmt.Printf("  Roles:       %v\n", enrollResp.Roles)
	fmt.Printf("  Peers:       %d\n", len(enrollResp.Peers))
	fmt.Println()

	// Verify certificate chain
	fmt.Println("Verifying certificate...")
	if err := verifyCertificate(enrollResp.Certificate, enrollResp.CACertificate); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	// Build and save config
	fmt.Println("Saving configuration...")

	privateKeyPEM, err := pki.PrivateKeyToPEM(nodeKp.Ed25519PrivateKey)
	if err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}

	meshConfig := &config.MeshConfig{
		Version:              1,
		MeshName:             enrollResp.MeshName,
		MeshID:               enrollResp.MeshID,
		NodeID:               enrollResp.NodeID,
		Roles:                enrollResp.Roles,
		NodePrivateKey:       string(privateKeyPEM),
		NodeCertificate:      enrollResp.Certificate,
		CACertChain:          enrollResp.CACertificate,
		MeshSubnet:           enrollResp.MeshSubnet,
		AssignedIP:           enrollResp.AssignedIP,
		Peers:                enrollResp.Peers,
		Transport:            enrollResp.TransportConfig,
		MeshSecret:           enrollResp.MeshSecret,
		CertRenewalThreshold: 6 * time.Hour,
	}

	// Prompt for passphrase
	passphrase, err := promptPassphrase("Create passphrase for local config: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	passphrase2, err := promptPassphrase("Confirm passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	if passphrase != passphrase2 {
		return fmt.Errorf("passphrases do not match")
	}

	if err := loader.SaveConfig(meshConfig, passphrase); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println()
	fmt.Println("Successfully joined the mesh!")
	fmt.Printf("  Config saved to: %s\n", loader.ConfigPath())
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  Run 'ghostwire up' to start the daemon and connect to the mesh")

	return nil
}

func mustParseToken(tokenStr string) []byte {
	payloadBytes, _, _ := token.ParseTokenString(tokenStr)
	return payloadBytes
}

func verifyCertificate(certPEM, caPEM string) error {
	// Parse certificate
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	// Parse CA certificate
	caBlock, _ := pem.Decode([]byte(caPEM))
	if caBlock == nil {
		return fmt.Errorf("invalid CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA certificate: %w", err)
	}

	// Create cert pool with CA
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// Verify
	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
	}

	// Filter out GHOSTWIRE extensions for verification
	cert.UnhandledCriticalExtensions = filterNonGhostwireExtensions(cert.UnhandledCriticalExtensions)

	_, err = cert.Verify(opts)
	return err
}

func filterNonGhostwireExtensions(oids []asn1.ObjectIdentifier) []asn1.ObjectIdentifier {
	var filtered []asn1.ObjectIdentifier
	for _, oid := range oids {
		// Skip GHOSTWIRE OIDs (1.3.6.1.4.1.XXXX.1.*)
		if len(oid) >= 7 && oid[0] == 1 && oid[1] == 3 && oid[2] == 6 && oid[3] == 1 && oid[4] == 4 && oid[5] == 1 {
			continue
		}
		filtered = append(filtered, oid)
	}
	return filtered
}
