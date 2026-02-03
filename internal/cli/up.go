package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghostwire/ghostwire/internal/api"
	"github.com/ghostwire/ghostwire/internal/config"
	"github.com/ghostwire/ghostwire/internal/daemon"
	"github.com/ghostwire/ghostwire/internal/gossip"
	"github.com/ghostwire/ghostwire/internal/keys"
	"github.com/ghostwire/ghostwire/internal/pki"
	"github.com/ghostwire/ghostwire/internal/policy"
	"github.com/ghostwire/ghostwire/internal/routing"
	"github.com/ghostwire/ghostwire/internal/tunnel"
)

func newUpCmd() *cobra.Command {
	var (
		foreground bool
		configDir  string
	)

	cmd := &cobra.Command{
		Use:   "up",
		Short: "Activate mesh interface and connect to peers",
		Long: `Start the GHOSTWIRE daemon, activate the mesh interface,
and establish connections to configured peers.

By default, the daemon runs in the background. Use --foreground
to run in the foreground (useful for systemd or containers).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return startDaemon(configDir, foreground)
		},
	}

	cmd.Flags().BoolVarP(&foreground, "foreground", "f", false,
		"run in foreground (don't daemonize)")
	cmd.Flags().StringVarP(&configDir, "config", "c", "", "config directory (default: ~/.config/gw)")

	return cmd
}

func startDaemon(configDir string, foreground bool) error {
	// Set default config directory
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("get home dir: %w", err)
		}
		configDir = filepath.Join(home, ".config", "gw")
	}

	loader := config.NewLoader(configDir)
	daemonMgr := daemon.NewManager(configDir)

	// Check if daemon is already running
	if running, pid := daemonMgr.IsRunning(); running {
		return fmt.Errorf("daemon is already running (PID %d)\nUse 'ghostwire down' to stop it first", pid)
	}

	// Check for config
	hasAdminConfig := loader.AdminConfigExists()
	hasNodeConfig := loader.ConfigExists()

	if !hasAdminConfig && !hasNodeConfig {
		return fmt.Errorf("no configuration found at %s\nRun 'ghostwire init' or 'ghostwire join' first", configDir)
	}

	// Prompt for passphrase
	passphrase, err := promptPassphrase("Enter passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	fmt.Println()
	fmt.Println("Starting GHOSTWIRE daemon...")
	fmt.Println()

	// Load config
	var meshConfig *config.MeshConfig
	var adminConfig *config.AdminConfig
	var isAdmin bool

	if hasAdminConfig {
		fmt.Println("Loading admin configuration...")
		adminConfig, err = loader.LoadAdminConfig(passphrase)
		if err != nil {
			return fmt.Errorf("load admin config: %w", err)
		}
		meshConfig = &adminConfig.MeshConfig
		isAdmin = true
	} else {
		fmt.Println("Loading node configuration...")
		meshConfig, err = loader.LoadConfig(passphrase)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
	}

	// Display config summary
	fmt.Printf("  Mesh:       %s\n", meshConfig.MeshName)
	fmt.Printf("  Node ID:    %s\n", meshConfig.NodeID)
	fmt.Printf("  Roles:      %v\n", meshConfig.Roles)
	if isAdmin {
		fmt.Printf("  Admin:      yes\n")
	}
	fmt.Printf("  IP:         %s\n", meshConfig.AssignedIP)
	fmt.Printf("  Transport:  %s\n", meshConfig.Transport.Active)
	fmt.Println()

	// Verify certificate validity
	if meshConfig.NodeCertificate != "" {
		block, _ := pem.Decode([]byte(meshConfig.NodeCertificate))
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				now := time.Now()
				if now.After(cert.NotAfter) {
					return fmt.Errorf("node certificate has expired (expired %s)\nAdmin nodes should auto-renew; other nodes need to rejoin", cert.NotAfter.Format(time.RFC3339))
				}
				if now.Before(cert.NotBefore) {
					return fmt.Errorf("node certificate is not yet valid (valid from %s)", cert.NotBefore.Format(time.RFC3339))
				}

				remaining := time.Until(cert.NotAfter)
				if remaining < meshConfig.CertRenewalThreshold {
					fmt.Printf("WARNING: Certificate expires in %s, renewal recommended\n", remaining.Round(time.Minute))
				} else {
					fmt.Printf("Certificate valid for %s\n", remaining.Round(time.Hour))
				}
			}
		}
	}
	fmt.Println()

	// Parse private key from config
	fmt.Println("Parsing node private key...")
	privateKey, err := parsePrivateKey(meshConfig.NodePrivateKey)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	defer keys.WipeBytes(privateKey)

	// Convert Ed25519 seed to X25519 for WireGuard
	var wgPrivateKey [32]byte
	copy(wgPrivateKey[:], privateKey[:32])

	// Decode mesh secret for transport authentication
	var meshSecret []byte
	if meshConfig.MeshSecret != "" {
		meshSecret, err = base64.StdEncoding.DecodeString(meshConfig.MeshSecret)
		if err != nil {
			return fmt.Errorf("decode mesh secret: %w", err)
		}
	}

	// Create tunnel device
	fmt.Println("Creating WireGuard tunnel...")
	dev, err := tunnel.NewFromConfig(meshConfig, wgPrivateKey, meshSecret)
	if err != nil {
		return fmt.Errorf("create tunnel: %w", err)
	}
	defer dev.Close()

	// Bring up the tunnel
	fmt.Println("Bringing up interface...")
	if err := dev.Up(); err != nil {
		return fmt.Errorf("bring up tunnel: %w", err)
	}

	ifname, _ := dev.InterfaceName()
	pubKey := dev.PublicKey()
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	fmt.Println()
	fmt.Println("Tunnel active!")
	fmt.Printf("  Interface:   %s\n", ifname)
	fmt.Printf("  Mesh IP:     %s\n", meshConfig.AssignedIP)
	fmt.Printf("  Public Key:  %s\n", pubKeyB64)
	fmt.Printf("  Subnet:      %s\n", meshConfig.MeshSubnet)
	fmt.Println()

	// Add configured peers
	if len(meshConfig.Peers) > 0 {
		fmt.Printf("Adding %d peer(s)...\n", len(meshConfig.Peers))
		for _, peerCfg := range meshConfig.Peers {
			if err := addPeerFromConfig(dev, &peerCfg); err != nil {
				fmt.Printf("  Warning: failed to add peer %s: %v\n", peerCfg.NodeID, err)
			} else {
				fmt.Printf("  Added peer: %s\n", peerCfg.NodeID)
			}
		}
		fmt.Println()
	}

	// Initialize Phase 2 components: Gossip, Routing, Policy
	fmt.Println("Initializing mesh services...")

	// Parse mesh IP for gossip
	meshIP, _ := netip.ParseAddr(meshConfig.AssignedIP)

	// Create gossip member for self
	selfMember := &gossip.Member{
		NodeID:    meshConfig.NodeID,
		MeshIP:    meshIP,
		Endpoints: []string{meshConfig.Transport.HTTPS.ListenAddr},
		Roles:     meshConfig.Roles,
		PublicKey: pubKeyB64,
		State:     gossip.StateAlive,
		Transport: meshConfig.Transport.Active,
	}

	// Initialize gossip protocol
	gossipCfg := &gossip.Config{
		BindAddr:       ":7946",
		GossipInterval: 1 * time.Second,
		ProbeInterval:  500 * time.Millisecond,
		ProbeTimeout:   500 * time.Millisecond,
		MeshSecret:     meshSecret,
	}

	gossipService, err := gossip.New(gossipCfg, selfMember)
	if err != nil {
		return fmt.Errorf("init gossip: %w", err)
	}

	// Start gossip protocol
	if err := gossipService.Start(); err != nil {
		fmt.Printf("Warning: could not start gossip: %v\n", err)
	} else {
		fmt.Println("  Gossip protocol started")
	}
	defer gossipService.Stop()

	// Initialize routing table
	routeTable := routing.NewTable(meshConfig.NodeID, meshIP)
	routeTable.SetOnChange(func(nodeID string, routes []*routing.Route) {
		// When routes change, update WireGuard peers
		if len(routes) > 0 {
			fmt.Printf("  Route update: %s via %s\n", nodeID, routes[0].Type)
		}
	})

	// Set up gossip callbacks to update routing
	gossipService.Members().SetCallbacks(
		func(m *gossip.Member) {
			fmt.Printf("  Peer joined: %s (%s)\n", m.NodeID, m.MeshIP)
			routeTable.UpdateFromGossip(gossipService.Members())
		},
		func(m *gossip.Member) {
			fmt.Printf("  Peer left: %s\n", m.NodeID)
			routeTable.UpdateFromGossip(gossipService.Members())
		},
		func(m *gossip.Member) {
			routeTable.UpdateFromGossip(gossipService.Members())
		},
	)

	// Initialize policy engine
	policyEngine, err := policy.NewEngine()
	if err != nil {
		return fmt.Errorf("init policy engine: %w", err)
	}

	// Load default policies
	defaultPolicies := policy.DefaultPolicies()
	if err := policyEngine.LoadPolicies(defaultPolicies); err != nil {
		return fmt.Errorf("load policies: %w", err)
	}
	fmt.Println("  Policy engine initialized")

	// Initialize policy enforcer
	enforcer := policy.NewEnforcer(policyEngine, meshConfig.NodeID, meshConfig.Roles, meshConfig.Compartment)
	enforcer.SetOnDeny(func(req *policy.Request, dec *policy.Decision) {
		fmt.Printf("  DENIED: %s -> %s:%d (%s)\n",
			req.SourceNodeID, req.DestNodeID, req.DestPort, dec.Reason)
	})

	// Register known peers with enforcer
	for _, peerCfg := range meshConfig.Peers {
		peerIP, _ := netip.ParseAddr(peerCfg.MeshIP)
		enforcer.RegisterPeer(&policy.PeerInfo{
			NodeID: peerCfg.NodeID,
			Roles:  peerCfg.Roles,
			MeshIP: peerIP,
		})
	}
	fmt.Println("  Policy enforcer initialized")

	// Initialize certificate renewal service (for non-admin nodes)
	var renewalService *pki.RenewalService
	if !isAdmin && meshConfig.NodeCertificate != "" {
		block, _ := pem.Decode([]byte(meshConfig.NodeCertificate))
		if block != nil {
			cert, _ := x509.ParseCertificate(block.Bytes)
			if cert != nil {
				// Get Ed25519 private key for signing renewal requests
				keyBlock, _ := pem.Decode([]byte(meshConfig.NodePrivateKey))
				if keyBlock != nil {
					pkcsKey, _ := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
					if edKey, ok := pkcsKey.(ed25519.PrivateKey); ok {
						renewalCfg := pki.DefaultRenewalConfig()
						renewalCfg.RenewalThreshold = meshConfig.CertRenewalThreshold
						// Find admin endpoint from peers
						for _, peer := range meshConfig.Peers {
							for _, role := range peer.Roles {
								if role == "admin" && len(peer.Endpoints) > 0 {
									renewalCfg.AdminEndpoint = "https://" + peer.Endpoints[0]
									break
								}
							}
						}

						renewalService = pki.NewRenewalService(renewalCfg, cert, edKey, meshConfig.NodeCertificate)
						renewalService.SetCallbacks(
							func(newCert *x509.Certificate, certPEM string) {
								fmt.Println("  Certificate renewed successfully")
								// Update config with new certificate
								meshConfig.NodeCertificate = certPEM
								loader.SaveConfig(meshConfig, passphrase)
							},
							func(err error) {
								fmt.Printf("  Certificate renewal failed: %v\n", err)
							},
						)
						renewalService.Start()
						fmt.Println("  Certificate renewal service started")
						defer renewalService.Stop()
					}
				}
			}
		}
	}

	// Join gossip with configured peers
	if len(meshConfig.Peers) > 0 {
		var gossipPeers []*gossip.Member
		for _, peerCfg := range meshConfig.Peers {
			peerIP, _ := netip.ParseAddr(peerCfg.MeshIP)
			gossipPeers = append(gossipPeers, &gossip.Member{
				NodeID:    peerCfg.NodeID,
				MeshIP:    peerIP,
				Endpoints: peerCfg.Endpoints,
				Roles:     peerCfg.Roles,
				PublicKey: peerCfg.PublicKey,
				State:     gossip.StateAlive,
			})
		}
		gossipService.Join(gossipPeers)
		fmt.Printf("  Joined gossip with %d peers\n", len(gossipPeers))
	}

	fmt.Println("  Mesh services initialized")
	fmt.Println()

	// Start enrollment server for admin nodes
	var enrollServer *api.EnrollmentServer
	if isAdmin && adminConfig != nil {
		fmt.Println("Starting enrollment server...")

		// Load CA
		ca, err := pki.LoadCertificateAuthority(
			[]byte(adminConfig.CACertChain),
			[]byte(adminConfig.CAPrivateKey),
		)
		if err != nil {
			return fmt.Errorf("load CA: %w", err)
		}

		// Decode mesh secret
		meshSecret, err := base64.StdEncoding.DecodeString(adminConfig.MeshSecret)
		if err != nil {
			return fmt.Errorf("decode mesh secret: %w", err)
		}

		// Generate self-signed TLS certificate for enrollment server
		tlsCert, err := generateTLSCert(meshConfig.Transport.HTTPS.ServerName)
		if err != nil {
			return fmt.Errorf("generate TLS cert: %w", err)
		}

		// Determine listen address
		listenAddr := meshConfig.Transport.HTTPS.ListenAddr
		if listenAddr == "" {
			listenAddr = ":443"
		}

		// Create save function
		saveFunc := func(cfg *config.AdminConfig) error {
			return loader.SaveAdminConfig(cfg, passphrase)
		}

		serverCfg := &api.ServerConfig{
			ListenAddr:  listenAddr,
			TLSCert:     tlsCert,
			AdminConfig: adminConfig,
			CA:          ca,
			MeshSecret:  meshSecret,
			SaveConfig:  saveFunc,
		}

		enrollServer, err = api.NewEnrollmentServer(serverCfg)
		if err != nil {
			return fmt.Errorf("create enrollment server: %w", err)
		}

		// Start server in goroutine
		go func() {
			if err := enrollServer.Start(); err != nil {
				fmt.Printf("Enrollment server error: %v\n", err)
			}
		}()

		fmt.Printf("  Enrollment server listening on %s\n", listenAddr)
		fmt.Println()
	}

	// Write PID file
	if err := daemonMgr.WritePID(); err != nil {
		fmt.Printf("Warning: could not write PID file: %v\n", err)
	}
	defer daemonMgr.RemovePID()

	if !foreground {
		fmt.Println("Background mode not yet implemented, running in foreground")
	}

	fmt.Println("GHOSTWIRE is running. Press Ctrl+C to stop.")
	fmt.Println()

	// Wait for shutdown signal
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		fmt.Printf("\nReceived %s, shutting down...\n", sig)
	case <-ctx.Done():
	}

	// Graceful shutdown
	if enrollServer != nil {
		fmt.Println("Stopping enrollment server...")
		enrollServer.Stop()
	}

	fmt.Println("Stopping tunnel...")
	if err := dev.Down(); err != nil {
		fmt.Printf("Warning: error stopping tunnel: %v\n", err)
	}

	fmt.Println("GHOSTWIRE stopped")
	return nil
}

// generateTLSCert generates a self-signed TLS certificate
func generateTLSCert(serverName string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: serverName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if serverName != "" {
		template.DNSNames = []string{serverName}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// parsePrivateKey extracts the private key bytes from PEM format
func parsePrivateKey(pemData string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8: %w", err)
	}

	// Extract the raw private key bytes based on type
	switch k := key.(type) {
	case interface{ Seed() []byte }:
		return k.Seed(), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// addPeerFromConfig adds a peer from the config
func addPeerFromConfig(dev *tunnel.Device, peerCfg *config.PeerConfig) error {
	// Decode public key from base64
	pubKeyBytes, err := base64.StdEncoding.DecodeString(peerCfg.PublicKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	if len(pubKeyBytes) != 32 {
		return fmt.Errorf("invalid public key length: %d", len(pubKeyBytes))
	}

	var pubKey [32]byte
	copy(pubKey[:], pubKeyBytes)

	// Parse mesh IP from peer config
	meshIP, err := netip.ParseAddr(peerCfg.MeshIP)
	if err != nil {
		return fmt.Errorf("parse peer mesh IP: %w", err)
	}

	peer := tunnel.NewPeer(&tunnel.PeerConfig{
		NodeID:              peerCfg.NodeID,
		PublicKey:           pubKey,
		MeshIP:              meshIP,
		Endpoints:           peerCfg.Endpoints,
		PersistentKeepalive: 25,
		Roles:               peerCfg.Roles,
	})

	return dev.AddPeer(peer)
}

func newDownCmd() *cobra.Command {
	var (
		configDir string
		force     bool
	)

	cmd := &cobra.Command{
		Use:   "down",
		Short: "Deactivate mesh interface and disconnect",
		Long:  `Stop the GHOSTWIRE daemon and disconnect from all peers.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Set default config directory
			if configDir == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("get home dir: %w", err)
				}
				configDir = filepath.Join(home, ".config", "gw")
			}

			daemonMgr := daemon.NewManager(configDir)

			running, pid := daemonMgr.IsRunning()
			if !running {
				fmt.Println("Daemon is not running")
				return nil
			}

			fmt.Printf("Stopping GHOSTWIRE daemon (PID %d)...\n", pid)

			var err error
			if force {
				err = daemonMgr.ForceStop()
			} else {
				err = daemonMgr.Stop()
			}

			if err != nil {
				return fmt.Errorf("stop daemon: %w", err)
			}

			fmt.Println("Stop signal sent. Daemon will shut down gracefully.")
			return nil
		},
	}

	cmd.Flags().StringVarP(&configDir, "config", "c", "", "config directory (default: ~/.config/gw)")
	cmd.Flags().BoolVar(&force, "force", false, "force immediate shutdown (SIGKILL)")

	return cmd
}
