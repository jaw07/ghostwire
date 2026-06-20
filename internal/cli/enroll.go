package cli

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghostwire/ghostwire/internal/config"
	"github.com/ghostwire/ghostwire/internal/pki"
	"github.com/ghostwire/ghostwire/internal/token"
)

func newEnrollCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Manage enrollment tokens",
		Long:  `Create and manage enrollment tokens for adding new nodes to the mesh.`,
	}

	cmd.AddCommand(newEnrollCreateCmd())
	cmd.AddCommand(newEnrollListCmd())
	cmd.AddCommand(newEnrollRevokeCmd())

	return cmd
}

func newEnrollCreateCmd() *cobra.Command {
	var (
		roles     []string
		expires   time.Duration
		maxUses   int
		nodeName  string
		configDir string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new enrollment token",
		Long: `Create a one-time, time-limited enrollment token for a new node.

The token encodes:
  - Allowed roles for the new node
  - Expiration time
  - Maximum number of uses
  - Optional suggested node name`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(roles) == 0 {
				roles = []string{"operator"}
			}

			// Validate roles
			for _, role := range roles {
				if !pki.IsValidRole(role) {
					return fmt.Errorf("invalid role: %s (valid: admin, operator, relay, exit, service)", role)
				}
			}

			return createEnrollmentToken(configDir, roles, expires, maxUses, nodeName)
		},
	}

	cmd.Flags().StringSliceVar(&roles, "role", []string{"operator"}, "allowed roles for the new node")
	cmd.Flags().DurationVar(&expires, "expires", 1*time.Hour, "token expiration duration")
	cmd.Flags().IntVar(&maxUses, "uses", 1, "maximum number of uses (0 = unlimited)")
	cmd.Flags().StringVar(&nodeName, "name", "", "suggested name for the new node")
	cmd.Flags().StringVarP(&configDir, "config", "c", "", "config directory (default: ~/.config/gw)")

	return cmd
}

func createEnrollmentToken(configDir string, roles []string, expires time.Duration, maxUses int, nodeName string) error {
	// Set default config directory
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("get home dir: %w", err)
		}
		configDir = filepath.Join(home, ".config", "gw")
	}

	// Check if admin config exists
	loader := config.NewLoader(configDir)
	if !loader.AdminConfigExists() {
		return fmt.Errorf("no admin config found at %s\nRun 'ghostwire init' first to create a mesh", loader.AdminConfigPath())
	}

	// Prompt for passphrase
	passphrase, err := resolvePassphrase("Enter passphrase to unlock admin config: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	// Load admin config
	fmt.Println("Loading admin configuration...")
	adminConfig, err := loader.LoadAdminConfig(passphrase)
	if err != nil {
		return fmt.Errorf("load admin config: %w", err)
	}

	// Parse CA private key
	ca, err := pki.LoadCertificateAuthority(
		[]byte(adminConfig.CACertChain),
		[]byte(adminConfig.CAPrivateKey),
	)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	defer ca.Wipe()

	// Parse mesh ID
	meshIDBytes, err := hex.DecodeString(adminConfig.MeshID)
	if err != nil {
		return fmt.Errorf("parse mesh ID: %w", err)
	}
	var meshID [32]byte
	copy(meshID[:], meshIDBytes)

	// Create token generator
	generator := token.NewGenerator(ca.RootKey(), meshID)

	// Generate token
	opts := &token.GeneratorOptions{
		Roles:         roles,
		Expiry:        expires,
		MaxUses:       maxUses,
		SuggestedName: nodeName,
	}

	tokenStr, tok, err := generator.Generate(opts)
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}

	// Store token in admin config for tracking
	storedToken := config.StoredToken{
		TokenID:   hex.EncodeToString(tok.ID[:]),
		CreatedAt: time.Now(),
		ExpiresAt: tok.NotAfter,
		Roles:     roles,
		MaxUses:   maxUses,
		UsedCount: 0,
	}
	adminConfig.EnrollmentTokens = append(adminConfig.EnrollmentTokens, storedToken)

	// Save updated admin config
	if err := loader.SaveAdminConfig(adminConfig, passphrase); err != nil {
		return fmt.Errorf("save admin config: %w", err)
	}

	// Print results
	fmt.Println()
	fmt.Println("Enrollment token created successfully!")
	fmt.Println()
	fmt.Printf("  Token ID:    %s\n", storedToken.TokenID[:16]+"...")
	fmt.Printf("  Roles:       %v\n", roles)
	fmt.Printf("  Expires:     %s (%s)\n", tok.NotAfter.Format(time.RFC3339), expires)
	fmt.Printf("  Max Uses:    %d\n", maxUses)
	if nodeName != "" {
		fmt.Printf("  Suggested:   %s\n", nodeName)
	}
	fmt.Println()
	fmt.Println("Token (share securely with the new node):")
	fmt.Println()
	fmt.Printf("  %s\n", tokenStr)
	fmt.Println()
	fmt.Println("The new node can join with:")
	fmt.Printf("  ghostwire join --token %s\n", tokenStr)

	return nil
}

func newEnrollListCmd() *cobra.Command {
	var configDir string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List active enrollment tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listEnrollmentTokens(configDir)
		},
	}

	cmd.Flags().StringVarP(&configDir, "config", "c", "", "config directory (default: ~/.config/gw)")
	return cmd
}

func listEnrollmentTokens(configDir string) error {
	// Set default config directory
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("get home dir: %w", err)
		}
		configDir = filepath.Join(home, ".config", "gw")
	}

	loader := config.NewLoader(configDir)
	if !loader.AdminConfigExists() {
		return fmt.Errorf("no admin config found at %s", loader.AdminConfigPath())
	}

	// Prompt for passphrase
	passphrase, err := resolvePassphrase("Enter passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	adminConfig, err := loader.LoadAdminConfig(passphrase)
	if err != nil {
		return fmt.Errorf("load admin config: %w", err)
	}

	if len(adminConfig.EnrollmentTokens) == 0 {
		fmt.Println("No enrollment tokens")
		return nil
	}

	fmt.Println()
	fmt.Println("Enrollment Tokens:")
	fmt.Println()

	now := time.Now()
	activeCount := 0

	for _, tok := range adminConfig.EnrollmentTokens {
		status := "active"
		if tok.ExpiresAt.Before(now) {
			status = "expired"
		} else if tok.MaxUses > 0 && tok.UsedCount >= tok.MaxUses {
			status = "exhausted"
		}

		if status == "active" {
			activeCount++
		}

		fmt.Printf("  ID:       %s\n", tok.TokenID[:16]+"...")
		fmt.Printf("  Status:   %s\n", status)
		fmt.Printf("  Roles:    %v\n", tok.Roles)
		fmt.Printf("  Created:  %s\n", tok.CreatedAt.Format(time.RFC3339))
		fmt.Printf("  Expires:  %s\n", tok.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("  Uses:     %d/%d\n", tok.UsedCount, tok.MaxUses)
		fmt.Println()
	}

	fmt.Printf("Total: %d tokens (%d active)\n", len(adminConfig.EnrollmentTokens), activeCount)
	return nil
}

func newEnrollRevokeCmd() *cobra.Command {
	var configDir string

	cmd := &cobra.Command{
		Use:   "revoke [token-id-prefix]",
		Short: "Revoke an enrollment token",
		Long:  `Revoke an enrollment token by ID prefix. The token will be removed from the config.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return revokeEnrollmentToken(configDir, args[0])
		},
	}

	cmd.Flags().StringVarP(&configDir, "config", "c", "", "config directory (default: ~/.config/gw)")
	return cmd
}

func revokeEnrollmentToken(configDir, tokenIDPrefix string) error {
	// Set default config directory
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("get home dir: %w", err)
		}
		configDir = filepath.Join(home, ".config", "gw")
	}

	loader := config.NewLoader(configDir)
	if !loader.AdminConfigExists() {
		return fmt.Errorf("no admin config found at %s", loader.AdminConfigPath())
	}

	// Prompt for passphrase
	passphrase, err := resolvePassphrase("Enter passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	adminConfig, err := loader.LoadAdminConfig(passphrase)
	if err != nil {
		return fmt.Errorf("load admin config: %w", err)
	}

	// Find matching token
	var matches []int
	for i, tok := range adminConfig.EnrollmentTokens {
		if len(tok.TokenID) >= len(tokenIDPrefix) && tok.TokenID[:len(tokenIDPrefix)] == tokenIDPrefix {
			matches = append(matches, i)
		}
	}

	if len(matches) == 0 {
		return fmt.Errorf("no token found matching prefix: %s", tokenIDPrefix)
	}

	if len(matches) > 1 {
		fmt.Println("Multiple tokens match that prefix:")
		for _, i := range matches {
			fmt.Printf("  %s\n", adminConfig.EnrollmentTokens[i].TokenID)
		}
		return fmt.Errorf("provide a longer prefix to uniquely identify the token")
	}

	// Remove the matching token
	idx := matches[0]
	revokedID := adminConfig.EnrollmentTokens[idx].TokenID
	adminConfig.EnrollmentTokens = append(
		adminConfig.EnrollmentTokens[:idx],
		adminConfig.EnrollmentTokens[idx+1:]...,
	)

	// Save updated config
	if err := loader.SaveAdminConfig(adminConfig, passphrase); err != nil {
		return fmt.Errorf("save admin config: %w", err)
	}

	fmt.Printf("Revoked token: %s\n", revokedID)
	return nil
}
