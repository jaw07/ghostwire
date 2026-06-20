package cli

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghostwire/ghostwire/internal/config"
)

func newStatusCmd() *cobra.Command {
	var (
		jsonOutput bool
		configDir  string
	)

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show mesh status and peer information",
		Long: `Display the current status of the GHOSTWIRE mesh including:
  - Mesh name and node identity
  - Connected peers and their status
  - Certificate validity
  - Active transport`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return showStatus(configDir, jsonOutput)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output in JSON format")
	cmd.Flags().StringVarP(&configDir, "config", "c", "", "config directory (default: ~/.config/gw)")

	return cmd
}

type statusOutput struct {
	State       string    `json:"state"`
	MeshName    string    `json:"mesh_name,omitempty"`
	MeshID      string    `json:"mesh_id,omitempty"`
	NodeID      string    `json:"node_id,omitempty"`
	Roles       []string  `json:"roles,omitempty"`
	AssignedIP  string    `json:"assigned_ip,omitempty"`
	Transport   string    `json:"transport,omitempty"`
	CertExpires time.Time `json:"cert_expires,omitempty"`
	CertValid   bool      `json:"cert_valid,omitempty"`
	IsAdmin     bool      `json:"is_admin,omitempty"`
	ConfigPath  string    `json:"config_path,omitempty"`
}

func showStatus(configDir string, jsonOutput bool) error {
	// Set default config directory
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("get home dir: %w", err)
		}
		configDir = filepath.Join(home, ".config", "gw")
	}

	loader := config.NewLoader(configDir)
	status := statusOutput{
		State:      "not_configured",
		ConfigPath: configDir,
	}

	// Check for admin config first
	hasAdminConfig := loader.AdminConfigExists()
	hasNodeConfig := loader.ConfigExists()

	if !hasAdminConfig && !hasNodeConfig {
		if jsonOutput {
			return outputJSON(status)
		}
		fmt.Println("GHOSTWIRE Status")
		fmt.Println("================")
		fmt.Println("State: not configured")
		fmt.Println()
		fmt.Println("Run 'ghostwire init' to create a new mesh, or")
		fmt.Println("    'ghostwire join' to join an existing mesh")
		return nil
	}

	status.State = "configured"

	// Try to show config info (requires passphrase)
	passphrase, err := resolvePassphrase("Enter passphrase to view full status (or press Enter to skip): ")
	if err != nil || passphrase == "" {
		// Show limited status without decryption
		if jsonOutput {
			return outputJSON(status)
		}
		fmt.Println("GHOSTWIRE Status")
		fmt.Println("================")
		fmt.Println("State: configured (locked)")
		fmt.Println()
		if hasAdminConfig {
			fmt.Printf("Admin config: %s\n", loader.AdminConfigPath())
		}
		if hasNodeConfig {
			fmt.Printf("Node config:  %s\n", loader.ConfigPath())
		}
		fmt.Println()
		fmt.Println("Enter passphrase to view full status")
		return nil
	}

	// Load and display full config
	var meshConfig *config.MeshConfig

	if hasAdminConfig {
		adminConfig, err := loader.LoadAdminConfig(passphrase)
		if err != nil {
			return fmt.Errorf("load admin config: %w", err)
		}
		meshConfig = &adminConfig.MeshConfig
		status.IsAdmin = true
	} else if hasNodeConfig {
		meshConfig, err = loader.LoadConfig(passphrase)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
	}

	if meshConfig != nil {
		status.MeshName = meshConfig.MeshName
		status.MeshID = meshConfig.MeshID
		status.NodeID = meshConfig.NodeID
		status.Roles = meshConfig.Roles
		status.AssignedIP = meshConfig.AssignedIP
		status.Transport = meshConfig.Transport.Active

		// Parse certificate to check validity
		if meshConfig.NodeCertificate != "" {
			block, _ := pem.Decode([]byte(meshConfig.NodeCertificate))
			if block != nil {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					status.CertExpires = cert.NotAfter
					status.CertValid = time.Now().Before(cert.NotAfter) && time.Now().After(cert.NotBefore)
				}
			}
		}
	}

	if jsonOutput {
		return outputJSON(status)
	}

	fmt.Println("GHOSTWIRE Status")
	fmt.Println("================")
	fmt.Println("State: configured (not running)")
	fmt.Println()
	fmt.Printf("Mesh Name:    %s\n", status.MeshName)
	fmt.Printf("Mesh ID:      %s...\n", truncateID(status.MeshID))
	fmt.Printf("Node ID:      %s\n", status.NodeID)
	fmt.Printf("Roles:        %v\n", status.Roles)
	if status.IsAdmin {
		fmt.Printf("Admin:        yes\n")
	}
	fmt.Printf("Assigned IP:  %s\n", status.AssignedIP)
	fmt.Printf("Transport:    %s\n", status.Transport)
	fmt.Println()

	if !status.CertExpires.IsZero() {
		fmt.Printf("Certificate:\n")
		fmt.Printf("  Expires:    %s\n", status.CertExpires.Format(time.RFC3339))
		if status.CertValid {
			remaining := time.Until(status.CertExpires)
			fmt.Printf("  Status:     valid (expires in %s)\n", remaining.Round(time.Minute))
		} else {
			fmt.Printf("  Status:     EXPIRED\n")
		}
	}

	fmt.Println()
	fmt.Println("Run 'ghostwire up' to start the daemon")

	return nil
}

func truncateID(id string) string {
	if len(id) > 16 {
		return id[:16]
	}
	return id
}

func outputJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
