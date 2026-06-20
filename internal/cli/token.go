package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage enrollment tokens via the running daemon",
	}
	cmd.AddCommand(newTokenCreateCmd())
	return cmd
}

func newTokenCreateCmd() *cobra.Command {
	var (
		configDir string
		roles     []string
		uses      int
		expires   time.Duration
		name      string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an enrollment token via the running daemon's local API",
		Long: `Create a one-time enrollment token by asking the running ghostwire
daemon over its loopback API, rather than decrypting the admin config directly.

This is the recommended workflow: the token is created against the daemon's
in-memory config, so it is honored immediately (no restart) and avoids a second
scrypt decryption of the on-disk config. Requires the daemon to be running.

Only the token string is printed to stdout, for easy scripting.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return createTokenViaDaemon(configDir, roles, uses, expires, name)
		},
	}

	cmd.Flags().StringVarP(&configDir, "config", "c", "", "config directory (default: ~/.config/gw)")
	cmd.Flags().StringSliceVar(&roles, "role", []string{"operator"}, "allowed roles for the new node")
	cmd.Flags().IntVar(&uses, "uses", 1, "maximum number of uses (0 = unlimited)")
	cmd.Flags().DurationVar(&expires, "expires", time.Hour, "token expiration duration")
	cmd.Flags().StringVar(&name, "name", "", "suggested name for the new node")
	return cmd
}

func createTokenViaDaemon(configDir string, roles []string, uses int, expires time.Duration, name string) error {
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("get home dir: %w", err)
		}
		configDir = filepath.Join(home, ".config", "gw")
	}

	baseURL, authToken, err := readDaemonAPI(configDir)
	if err != nil {
		return fmt.Errorf("read daemon API info (is 'ghostwire up' running?): %w", err)
	}

	reqBody, _ := json.Marshal(map[string]interface{}{
		"roles":           roles,
		"max_uses":        uses,
		"expires_seconds": int(expires.Seconds()),
		"name":            name,
	})

	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/enroll/token", bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("call daemon API: %w", err)
	}
	defer resp.Body.Close()

	var out struct {
		Token string `json:"token"`
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("daemon returned %d: %s", resp.StatusCode, out.Error)
	}

	fmt.Println(out.Token)
	return nil
}

// readDaemonAPI reads the loopback API base URL and auth token that the running
// daemon wrote to <configDir>/daemon-api.
func readDaemonAPI(configDir string) (baseURL, token string, err error) {
	f, err := os.Open(filepath.Join(configDir, "daemon-api"))
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			lines = append(lines, t)
		}
	}
	if len(lines) < 2 {
		return "", "", fmt.Errorf("malformed daemon-api file")
	}
	return lines[0], lines[1], nil
}
