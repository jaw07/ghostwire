package cli

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ghostwire/ghostwire/internal/config"
	"github.com/ghostwire/ghostwire/internal/keys"
	"github.com/ghostwire/ghostwire/internal/pki"
)

func newInitCmd() *cobra.Command {
	var (
		meshName   string
		outputDir  string
		subnet     string
		nodeID     string
		serverName string
		listenAddr string
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new mesh network",
		Long: `Initialize a new GHOSTWIRE mesh network by generating:
  - Root Certificate Authority (CA)
  - Admin node certificate
  - Default mesh configuration
  - Encrypted config bundle

The admin config will be saved to the output directory.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if meshName == "" {
				return fmt.Errorf("--mesh-name is required")
			}

			// Get passphrase
			passphrase, err := promptPassphrase("Enter passphrase for config encryption: ")
			if err != nil {
				return fmt.Errorf("read passphrase: %w", err)
			}

			confirm, err := promptPassphrase("Confirm passphrase: ")
			if err != nil {
				return fmt.Errorf("read passphrase: %w", err)
			}

			if passphrase != confirm {
				return fmt.Errorf("passphrases do not match")
			}

			return initializeMesh(meshName, outputDir, subnet, nodeID, serverName, listenAddr, passphrase)
		},
	}

	cmd.Flags().StringVar(&meshName, "mesh-name", "", "name for the mesh network (required)")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "output directory (default: ~/.config/gw)")
	cmd.Flags().StringVar(&subnet, "subnet", "10.100.0.0/16", "mesh network subnet")
	cmd.Flags().StringVar(&nodeID, "node-id", "", "node ID for the admin node (default: hostname)")
	cmd.Flags().StringVar(&serverName, "server-name", "", "TLS server name (SNI) for HTTPS transport")
	cmd.Flags().StringVar(&listenAddr, "listen", ":443", "listen address for HTTPS transport")

	return cmd
}

func initializeMesh(meshName, outputDir, subnet, nodeID, serverName, listenAddr, passphrase string) error {
	// Set defaults
	if outputDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("get home dir: %w", err)
		}
		outputDir = filepath.Join(home, ".config", "gw")
	}

	if nodeID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			nodeID = "admin"
		} else {
			nodeID = hostname + "-admin"
		}
	}

	fmt.Printf("Initializing GHOSTWIRE mesh: %s\n", meshName)
	fmt.Printf("Output directory: %s\n", outputDir)
	fmt.Printf("Subnet: %s\n", subnet)
	fmt.Printf("Admin node ID: %s\n", nodeID)
	fmt.Println()

	// Create output directory
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	// Generate Root CA
	fmt.Println("Generating Root CA...")
	caCfg := pki.DefaultCAConfig(meshName)
	ca, caKp, err := pki.NewCertificateAuthority(caCfg)
	if err != nil {
		return fmt.Errorf("create CA: %w", err)
	}
	defer caKp.Wipe()

	// Generate admin node keypair
	fmt.Println("Generating admin node keypair...")
	adminKp, err := keys.Generate()
	if err != nil {
		return fmt.Errorf("generate admin keypair: %w", err)
	}
	defer adminKp.Wipe()

	// Allocate first IP for admin node
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return fmt.Errorf("parse subnet: %w", err)
	}
	adminIP := nextIP(ipNet.IP)

	// Issue admin certificate
	fmt.Println("Issuing admin certificate...")
	certReq := &pki.NodeCertRequest{
		NodeID:          nodeID,
		Roles:           []string{pki.RoleAdmin, pki.RoleRelay},
		PublicKey:       adminKp.Ed25519PublicKey,
		WireGuardPubKey: adminKp.X25519PublicKey,
		MeshIP:          adminIP,
	}

	adminCert, _, err := ca.IssueCertificate(certReq)
	if err != nil {
		return fmt.Errorf("issue admin cert: %w", err)
	}

	// Generate mesh secret for knock authentication
	meshSecret := make([]byte, 32)
	if _, err := rand.Read(meshSecret); err != nil {
		return fmt.Errorf("generate mesh secret: %w", err)
	}

	// Compute mesh ID
	meshID := sha256.Sum256(caKp.Ed25519PublicKey)

	// Get private key PEM
	caKeyPEM, err := pki.PrivateKeyToPEM(caKp.Ed25519PrivateKey)
	if err != nil {
		return fmt.Errorf("encode CA key: %w", err)
	}

	adminKeyPEM, err := pki.PrivateKeyToPEM(adminKp.Ed25519PrivateKey)
	if err != nil {
		return fmt.Errorf("encode admin key: %w", err)
	}

	// Build admin config
	adminConfig := &config.AdminConfig{
		MeshConfig: config.MeshConfig{
			Version:         1,
			MeshName:        meshName,
			MeshID:          hex.EncodeToString(meshID[:]),
			NodeID:          nodeID,
			Roles:           []string{pki.RoleAdmin, pki.RoleRelay},
			NodePrivateKey:  string(adminKeyPEM),
			NodeCertificate: string(pki.CertificateToPEM(adminCert)),
			CACertChain:     string(pki.CertificateToPEM(ca.RootCert)),
			MeshSubnet:      subnet,
			AssignedIP:      adminIP.String(),
			MeshSecret:      hex.EncodeToString(meshSecret),
			Transport: config.TransportConfig{
				Active: "https-mimic",
				HTTPS: config.HTTPSTransportConfig{
					ServerName:  serverName,
					Fingerprint: "auto",
					ListenAddr:  listenAddr,
				},
				Direct: config.DirectTransportConfig{
					Enabled: true,
				},
			},
		},
		CAPrivateKey: string(caKeyPEM),
		IPAllocator: config.IPAllocatorState{
			Subnet:    subnet,
			Allocated: map[string]string{nodeID: adminIP.String()},
			NextIP:    nextIP(adminIP).String(),
		},
	}

	// Save encrypted config
	fmt.Println("Saving encrypted configuration...")
	loader := config.NewLoader(outputDir)
	if err := loader.SaveAdminConfig(adminConfig, passphrase); err != nil {
		return fmt.Errorf("save admin config: %w", err)
	}

	// Also save CA certificate separately (for distribution)
	caCertPath := filepath.Join(outputDir, "ca.crt")
	if err := os.WriteFile(caCertPath, pki.CertificateToPEM(ca.RootCert), 0644); err != nil {
		return fmt.Errorf("save CA cert: %w", err)
	}

	fmt.Println()
	fmt.Println("Mesh initialized successfully!")
	fmt.Println()
	fmt.Printf("  Mesh Name:     %s\n", meshName)
	fmt.Printf("  Mesh ID:       %s\n", hex.EncodeToString(meshID[:8])+"...")
	fmt.Printf("  Admin Node:    %s\n", nodeID)
	fmt.Printf("  Admin IP:      %s\n", adminIP)
	fmt.Printf("  Subnet:        %s\n", subnet)
	fmt.Println()
	fmt.Printf("  Config:        %s\n", loader.AdminConfigPath())
	fmt.Printf("  CA Cert:       %s\n", caCertPath)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Run 'ghostwire enroll create --role operator' to create enrollment tokens")
	fmt.Println("  2. Run 'ghostwire up' to start the admin node")
	fmt.Println("  3. Have other nodes join with 'ghostwire join --token <token>'")

	return nil
}

// promptPassphrase prompts for a passphrase without echoing
func promptPassphrase(prompt string) (string, error) {
	fmt.Print(prompt)

	// Check if stdin is a terminal
	fd := int(syscall.Stdin)
	if term.IsTerminal(fd) {
		passphrase, err := term.ReadPassword(fd)
		fmt.Println() // New line after password input
		if err != nil {
			return "", err
		}
		return string(passphrase), nil
	}

	// Not a terminal, read normally (for piping)
	var passphrase string
	_, err := fmt.Scanln(&passphrase)
	return passphrase, err
}

// nextIP returns the next IP address after the given IP
func nextIP(ip net.IP) net.IP {
	ip = ip.To4()
	if ip == nil {
		return nil
	}
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] > 0 {
			break
		}
	}
	return next
}
