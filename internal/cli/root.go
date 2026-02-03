// Package cli implements the ghostwire command-line interface
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Build-time variables (set via ldflags)
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"

	// Global flags
	cfgFile   string
	verbosity int
)

var rootCmd = &cobra.Command{
	Use:   "ghostwire",
	Short: "Zero-trust obfuscated mesh VPN",
	Long: `GHOSTWIRE is a field-deployable, censorship-resistant, zero-trust mesh network
for small teams operating in contested or surveilled environments.

Features:
  - Zero-trust security with per-node certificates
  - Mesh resilience with automatic peer discovery
  - Traffic obfuscation indistinguishable from HTTPS`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "",
		"config file (default: ~/.config/gw/config.enc)")
	rootCmd.PersistentFlags().IntVarP(&verbosity, "verbose", "v", 0,
		"verbosity level (0-3)")

	// Add subcommands
	rootCmd.AddCommand(
		newVersionCmd(),
		newInitCmd(),
		newEnrollCmd(),
		newJoinCmd(),
		newUpCmd(),
		newDownCmd(),
		newStatusCmd(),
		newPanicCmd(),
	)
}

// Execute runs the root command
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}

// getConfigPath returns the config file path, using default if not specified
func getConfigPath() string {
	if cfgFile != "" {
		return cfgFile
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".config/gw/config.enc"
	}
	return home + "/.config/gw/config.enc"
}
