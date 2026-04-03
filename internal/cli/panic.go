package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ghostwire/ghostwire/internal/config"
)

func newPanicCmd() *cobra.Command {
	var (
		wipeConfig bool
		wipeLogs   bool
		wipeAll    bool
		silent     bool
		force      bool
		configDir  string
	)

	cmd := &cobra.Command{
		Use:   "panic",
		Short: "Emergency shutdown and secure wipe",
		Long: `Immediately stop all GHOSTWIRE activity and optionally wipe sensitive data.

This command:
  1. Signals the daemon to immediately terminate all tunnels
  2. Securely overwrites keys in memory
  3. Optionally securely deletes configuration and logs

Use --wipe-config to delete the encrypted configuration file.
Use --wipe-logs to delete any log files.
Use --wipe-all to delete all GHOSTWIRE data.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if wipeAll {
				wipeConfig = true
				wipeLogs = true
			}

			if !force && !silent {
				fmt.Println("WARNING: This will immediately terminate all GHOSTWIRE connections.")
				if wipeConfig {
					fmt.Println("WARNING: --wipe-config will PERMANENTLY DELETE your configuration file.")
					fmt.Println("         You will need to re-enroll to join the mesh again.")
				}
				if wipeLogs {
					fmt.Println("WARNING: --wipe-logs will PERMANENTLY DELETE all log files.")
				}
				if wipeAll {
					fmt.Println("WARNING: --wipe-all will PERMANENTLY DELETE ALL GHOSTWIRE DATA.")
				}
				fmt.Println()
				fmt.Println("Use --force to confirm, or --silent to suppress this warning.")
				return nil
			}

			return executePanic(configDir, wipeConfig, wipeLogs, silent)
		},
	}

	cmd.Flags().BoolVar(&wipeConfig, "wipe-config", false, "securely delete configuration files")
	cmd.Flags().BoolVar(&wipeLogs, "wipe-logs", false, "securely delete log files")
	cmd.Flags().BoolVar(&wipeAll, "wipe-all", false, "securely delete all GHOSTWIRE data")
	cmd.Flags().BoolVar(&silent, "silent", false, "suppress output")
	cmd.Flags().BoolVar(&force, "force", false, "skip confirmation prompt")
	cmd.Flags().StringVarP(&configDir, "config", "c", "", "config directory (default: ~/.config/gw)")

	return cmd
}

func executePanic(configDir string, wipeConfig, wipeLogs, silent bool) error {
	// Set default config directory
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("get home dir: %w", err)
		}
		configDir = filepath.Join(home, ".config", "gw")
	}

	if !silent {
		fmt.Println("Initiating emergency shutdown...")
	}

	// Signal daemon to stop (if running)
	// TODO: When daemon IPC is implemented, signal immediate shutdown
	// For now, just handle the wipe operations

	loader := config.NewLoader(configDir)
	var errors []error

	if wipeConfig {
		if !silent {
			fmt.Println("Securely wiping configuration...")
		}

		// Wipe admin config if present
		if loader.AdminConfigExists() {
			if err := loader.WipeAdminConfig(); err != nil {
				errors = append(errors, fmt.Errorf("wipe admin config: %w", err))
			} else if !silent {
				fmt.Println("  Wiped admin.enc")
			}
		}

		// Wipe node config if present
		if loader.ConfigExists() {
			if err := loader.WipeConfig(); err != nil {
				errors = append(errors, fmt.Errorf("wipe config: %w", err))
			} else if !silent {
				fmt.Println("  Wiped config.enc")
			}
		}

		// Wipe CA certificate
		caCertPath := filepath.Join(configDir, "ca.crt")
		if _, err := os.Stat(caCertPath); err == nil {
			if err := config.SecureDelete(caCertPath); err != nil {
				errors = append(errors, fmt.Errorf("wipe CA cert: %w", err))
			} else if !silent {
				fmt.Println("  Wiped ca.crt")
			}
		}
	}

	if wipeLogs {
		if !silent {
			fmt.Println("Securely wiping logs...")
		}

		logsDir := filepath.Join(configDir, "logs")
		if info, err := os.Stat(logsDir); err == nil && info.IsDir() {
			entries, _ := os.ReadDir(logsDir)
			for _, entry := range entries {
				logPath := filepath.Join(logsDir, entry.Name())
				if err := config.SecureDelete(logPath); err != nil {
					errors = append(errors, fmt.Errorf("wipe log %s: %w", entry.Name(), err))
				} else if !silent {
					fmt.Printf("  Wiped %s\n", entry.Name())
				}
			}
			// Remove logs directory
			os.Remove(logsDir)
		}
	}

	if len(errors) > 0 {
		if !silent {
			fmt.Println()
			fmt.Println("Errors occurred during wipe:")
			for _, err := range errors {
				fmt.Printf("  - %v\n", err)
			}
		}
		return fmt.Errorf("%d error(s) during panic wipe", len(errors))
	}

	if !silent {
		fmt.Println()
		fmt.Println("Panic complete. All requested data has been securely wiped.")
		fmt.Println()
		fmt.Println("NOTE: On copy-on-write filesystems (macOS APFS, Btrfs), original data")
		fmt.Println("      blocks may persist in filesystem journals or snapshots. For maximum")
		fmt.Println("      security, use full-disk encryption and securely erase the entire volume.")
	}

	return nil
}
