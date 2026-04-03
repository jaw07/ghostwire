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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghostwire/ghostwire/internal/api"
	"github.com/ghostwire/ghostwire/internal/chat"
	"github.com/ghostwire/ghostwire/internal/config"
	"github.com/ghostwire/ghostwire/internal/daemon"
	"github.com/ghostwire/ghostwire/internal/gossip"
	"github.com/ghostwire/ghostwire/internal/gui"
	"github.com/ghostwire/ghostwire/internal/keys"
	"github.com/ghostwire/ghostwire/internal/mavlink"
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
			if strings.Contains(err.Error(), "passphrase") || strings.Contains(err.Error(), "identity") || strings.Contains(err.Error(), "decrypt") {
				return fmt.Errorf("incorrect passphrase for admin config at %s", loader.AdminConfigPath())
			}
			return fmt.Errorf("load admin config: %w", err)
		}
		meshConfig = &adminConfig.MeshConfig
		isAdmin = true
	} else {
		fmt.Println("Loading node configuration...")
		meshConfig, err = loader.LoadConfig(passphrase)
		if err != nil {
			if strings.Contains(err.Error(), "passphrase") || strings.Contains(err.Error(), "identity") || strings.Contains(err.Error(), "decrypt") {
				return fmt.Errorf("incorrect passphrase for config at %s\nIf the config is from a previous mesh, run 'ghostwire panic --wipe-config --force' first", loader.ConfigPath())
			}
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

	// Convert Ed25519 seed to X25519 for WireGuard (proper SHA-512 + clamping)
	wgPrivateKey, _, err := keys.Ed25519SeedToX25519(privateKey[:32])
	if err != nil {
		return fmt.Errorf("convert Ed25519 to X25519: %w", err)
	}
	defer keys.WipeBytes(wgPrivateKey[:])

	// Decode mesh secret for transport authentication
	var meshSecret []byte
	if meshConfig.MeshSecret != "" {
		meshSecret, err = hex.DecodeString(meshConfig.MeshSecret)
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

	// Start HTTPS transport listener for incoming tunnel connections.
	// Uses a separate port from the enrollment server to avoid conflicts.
	if meshConfig.Transport.Active == "https-mimic" || meshConfig.Transport.Active == "https" || meshConfig.Transport.Active == "hybrid" {
		transportListenAddr := meshConfig.Transport.HTTPS.TransportListenAddr
		if transportListenAddr == "" {
			// Default: enrollment server port + 1, or :8444
			transportListenAddr = ":8444"
		}

		transportTLSCert, err := generateTLSCert(meshConfig.Transport.HTTPS.ServerName)
		if err != nil {
			fmt.Printf("Warning: could not generate transport TLS cert: %v\n", err)
		} else {
			transportTLS := &tls.Config{
				Certificates: []tls.Certificate{transportTLSCert},
				MinVersion:   tls.VersionTLS13,
			}
			if err := dev.StartTransportListener(transportListenAddr, transportTLS); err != nil {
				fmt.Printf("Warning: could not start transport listener: %v\n", err)
			} else {
				fmt.Printf("  Transport listener started on %s\n", transportListenAddr)
			}
		}
	}

	// Add configured peers that have valid endpoints.
	// Peers without endpoints will be discovered and added via gossip.
	if len(meshConfig.Peers) > 0 {
		added := 0
		for _, peerCfg := range meshConfig.Peers {
			if len(peerCfg.Endpoints) == 0 {
				continue // Will be added via gossip discovery
			}
			if err := addPeerFromConfig(dev, &peerCfg); err != nil {
				fmt.Printf("  Warning: failed to add peer %s: %v\n", peerCfg.NodeID, err)
			} else {
				fmt.Printf("  Added peer: %s (%s)\n", peerCfg.NodeID, peerCfg.Endpoints[0])
				added++
			}
		}
		if added > 0 {
			fmt.Printf("Added %d peer(s) from config, remaining peers via gossip\n", added)
		}
		fmt.Println()
	}

	// Initialize Phase 2 components: Gossip, Routing, Policy
	fmt.Println("Initializing mesh services...")

	// Parse mesh IP for gossip
	meshIP, _ := netip.ParseAddr(meshConfig.AssignedIP)

	// Determine the host's reachable IP for gossip.
	// Gossip probes must use an IP that's routable on the underlay network
	// (not the mesh overlay IP, which requires a working tunnel).
	gossipPort := "7946"
	gossipAdvertiseIP := detectOutboundIP()
	selfGossipAddr := gossipAdvertiseIP + ":" + gossipPort

	selfMember := &gossip.Member{
		NodeID:    meshConfig.NodeID,
		MeshIP:    meshIP,
		Endpoints: []string{selfGossipAddr},
		Roles:     meshConfig.Roles,
		PublicKey: pubKeyB64,
		State:     gossip.StateAlive,
		Transport: meshConfig.Transport.Active,
	}

	// Initialize gossip protocol
	gossipCfg := &gossip.Config{
		BindAddr:       ":" + gossipPort,
		GossipInterval: 1 * time.Second,
		ProbeInterval:    2 * time.Second,
		ProbeTimeout:    3 * time.Second,
		SuspicionTimeout: 15 * time.Second,
		IndirectChecks:  3,
		MeshSecret:      meshSecret,
	}

	fmt.Printf("  Self gossip endpoint: %s\n", selfGossipAddr)

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

	// Create GUI server early so gossip callbacks can reference it
	fmt.Println("Starting GUI server...")
	guiCfg := &gui.Config{
		ListenAddr: "0.0.0.0:9999",
		AutoOpen:   false,
	}
	guiServer, guiErr := gui.New(guiCfg)
	if guiErr != nil {
		fmt.Printf("Warning: could not create GUI server: %v\n", guiErr)
	}

	// Helper to push current gossip member list to GUI
	updateGUIPeers := func() {
		if guiServer == nil {
			return
		}
		members := gossipService.Members().AliveMembers()
		var guiPeers []*gui.Peer
		for _, m := range members {
			ep := ""
			if len(m.Endpoints) > 0 {
				ep = m.Endpoints[0]
			}
			guiPeers = append(guiPeers, &gui.Peer{
				NodeID:    m.NodeID,
				MeshIP:    m.MeshIP.String(),
				Endpoint:  ep,
				Roles:     m.Roles,
				Connected: m.State == gossip.StateAlive,
				Latency:   m.RTT.Milliseconds(),
			})
		}
		guiServer.SetPeers(guiPeers)
	}

	// Initialize routing table
	routeTable := routing.NewTable(meshConfig.NodeID, meshIP)
	routeTable.SetOnChange(func(nodeID string, routes []*routing.Route) {
		if len(routes) > 0 {
			fmt.Printf("  Route update: %s via %s\n", nodeID, routes[0].Type)
		}
	})

	// Initialize chat service
	chatService := chat.New(meshConfig.NodeID, 200)
	chatService.OnSend = func(msg chat.ChatMessage) {
		data, _ := json.Marshal(msg)
		gossipService.BroadcastPayload(gossip.MsgChat, data)
		if guiServer != nil {
			guiServer.BroadcastChat(msg.Sender, msg.Text, msg.Timestamp)
		}
	}
	chatService.OnReceive = func(msg chat.ChatMessage) {
		if guiServer != nil {
			guiServer.BroadcastChat(msg.Sender, msg.Text, msg.Timestamp)
		}
	}
	gossipService.SetCustomHandler(func(msgType gossip.MessageType, from string, payload []byte) {
		if msgType == gossip.MsgChat {
			var msg chat.ChatMessage
			if json.Unmarshal(payload, &msg) == nil {
				chatService.Receive(msg)
			}
		}
	})
	if guiServer != nil {
		guiServer.SetChatHandler(func(text string) {
			chatService.Send(text)
		})
	}
	fmt.Println("  Chat service initialized")

	// Initialize MAVLink proxy
	mavProxy := mavlink.NewProxy(&mavlink.ProxyConfig{
		ListenAddr: "0.0.0.0:14550",
		OnPacket: func(data []byte, info *mavlink.PacketInfo) {
			fmt.Printf("  MAVLink: %s from %s seq=%d\n",
				mavlink.MessageIDString(info.MessageID),
				mavlink.SystemIDString(info.SystemID),
				info.Sequence)
		},
	})
	if err := mavProxy.Start(); err != nil {
		fmt.Printf("Warning: MAVLink proxy not started: %v\n", err)
	} else {
		fmt.Printf("  MAVLink proxy on %s\n", mavProxy.ListenAddr())
		defer mavProxy.Stop()
	}

	// Set up gossip callbacks to update routing + GUI + knock validator + WG peers
	gossipService.Members().SetCallbacks(
		func(m *gossip.Member) {
			fmt.Printf("  Peer joined: %s (%s)\n", m.NodeID, m.MeshIP)
			routeTable.UpdateFromGossip(gossipService.Members())
			updateGUIPeers()
			// Register the new peer's WG public key for knock auth + WireGuard
			if m.PublicKey != "" && m.NodeID != meshConfig.NodeID {
				if keyBytes, err := base64.StdEncoding.DecodeString(m.PublicKey); err == nil {
					dev.RegisterKnockPeer(keyBytes)
					// Also add as a WireGuard peer if not already known
					if _, exists := dev.GetPeer(m.NodeID); !exists {
						var pubKey [32]byte
						copy(pubKey[:], keyBytes)
						ep := ""
						if len(m.Endpoints) > 0 {
							ep = m.Endpoints[0]
							// Use transport port, not gossip port
							h, _, splitErr := net.SplitHostPort(ep)
							if splitErr == nil {
								ep = net.JoinHostPort(h, "8444")
							}
						}
						peer := tunnel.NewPeer(&tunnel.PeerConfig{
							NodeID:              m.NodeID,
							PublicKey:           pubKey,
							MeshIP:              m.MeshIP,
							Endpoints:           []string{ep},
							PersistentKeepalive: 25,
							Roles:               m.Roles,
						})
						if err := dev.AddPeer(peer); err != nil {
							fmt.Printf("  Warning: could not add peer %s to WireGuard: %v\n", m.NodeID, err)
						} else {
							fmt.Printf("  Added WireGuard peer: %s (%s)\n", m.NodeID, m.MeshIP)
						}
					}
				}
			}
		},
		func(m *gossip.Member) {
			fmt.Printf("  Peer left: %s\n", m.NodeID)
			routeTable.UpdateFromGossip(gossipService.Members())
			updateGUIPeers()
		},
		func(m *gossip.Member) {
			routeTable.UpdateFromGossip(gossipService.Members())
			updateGUIPeers()
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

	// Join gossip with configured peers.
	// Gossip endpoints use the peer's underlay IP (from their transport endpoint)
	// with the gossip port, since the mesh overlay isn't up yet.
	if len(meshConfig.Peers) > 0 {
		var gossipPeers []*gossip.Member
		for _, peerCfg := range meshConfig.Peers {
			peerIP, _ := netip.ParseAddr(peerCfg.MeshIP)

			// Extract the peer's reachable underlay IP from their transport endpoints
			var gossipEndpoints []string
			for _, ep := range peerCfg.Endpoints {
				host, _, err := net.SplitHostPort(ep)
				if err != nil {
					host = ep
				}
				if host != "" && host != "0.0.0.0" && host != "::" {
					gossipEndpoints = append(gossipEndpoints, net.JoinHostPort(host, gossipPort))
				}
			}
			// Skip peers with no reachable underlay endpoints — they'll be
			// discovered via gossip sync from other nodes
			if len(gossipEndpoints) == 0 {
				continue
			}

			gossipPeers = append(gossipPeers, &gossip.Member{
				NodeID:    peerCfg.NodeID,
				MeshIP:    peerIP,
				Endpoints: gossipEndpoints,
				Roles:     peerCfg.Roles,
				PublicKey: peerCfg.PublicKey,
				State:     gossip.StateAlive,
			})
		}
		gossipService.Join(gossipPeers)
		for _, gp := range gossipPeers {
			fmt.Printf("  Gossip peer: %s endpoints=%v\n", gp.NodeID, gp.Endpoints)
		}
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
		meshSecret, err := hex.DecodeString(adminConfig.MeshSecret)
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

	// Start GUI server (created earlier, before gossip callbacks)
	if guiServer != nil {
		startTime := time.Now()

		// Set initial status
		guiServer.SetStatus(&gui.Status{
			Connected: true,
			NodeID:    meshConfig.NodeID,
			MeshName:  meshConfig.MeshName,
			MeshIP:    meshConfig.AssignedIP,
			Transport: meshConfig.Transport.Active,
			PeerCount: len(meshConfig.Peers),
		})

		// Set initial peers from config
		updateGUIPeers()

		go func() {
			if err := guiServer.Start(); err != nil {
				fmt.Printf("GUI server error: %v\n", err)
			}
		}()

		// Periodic status + peer refresh
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				members := gossipService.Members().AliveMembers()
				guiServer.SetStatus(&gui.Status{
					Connected: true,
					NodeID:    meshConfig.NodeID,
					MeshName:  meshConfig.MeshName,
					MeshIP:    meshConfig.AssignedIP,
					Transport: meshConfig.Transport.Active,
					PeerCount: len(members),
					Uptime:    int64(time.Since(startTime).Seconds()),
				})
				updateGUIPeers()
			}
		}()

		fmt.Printf("  GUI available at: %s\n", guiServer.URL())
		fmt.Println()
		defer guiServer.Stop(context.Background())
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

// generateTLSCert generates a self-signed TLS certificate (fallback when no CA available)
func generateTLSCert(serverName string) (tls.Certificate, error) {
	return generateTLSCertWithCA(serverName, nil, nil)
}

// generateTLSCertWithCA generates a TLS certificate signed by the mesh CA.
// If caCert/caKey are nil, falls back to self-signing.
func generateTLSCertWithCA(serverName string, caCert *x509.Certificate, caKey interface{}) (tls.Certificate, error) {
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
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	if serverName != "" {
		template.DNSNames = []string{serverName, "localhost"}
	}
	// Add common Docker/local IPs as SANs so cert validates regardless of how peer connects
	template.IPAddresses = []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("0.0.0.0"),
	}
	// Add the host's detected outbound IP
	if hostIP := net.ParseIP(detectOutboundIP()); hostIP != nil {
		template.IPAddresses = append(template.IPAddresses, hostIP)
	}

	// Sign with CA if available, otherwise self-sign
	issuer := &template
	signingKey := interface{}(priv)
	if caCert != nil && caKey != nil {
		issuer = caCert
		signingKey = caKey
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, issuer, &priv.PublicKey, signingKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	// If CA-signed, include the CA cert in the chain so peers can verify
	if caCert != nil {
		tlsCert.Certificate = append(tlsCert.Certificate, caCert.Raw)
	}

	return tlsCert, nil
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

// detectOutboundIP finds this host's preferred outbound IP by dialing a
// dummy UDP address and checking the local address chosen by the OS.
func detectOutboundIP() string {
	conn, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*net.UDPAddr)
	return addr.IP.String()
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

	// Register the peer's public key for knock authentication
	dev.RegisterKnockPeer(pubKeyBytes)

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
