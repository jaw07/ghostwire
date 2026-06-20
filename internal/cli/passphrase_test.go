package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePassphraseFromEnv(t *testing.T) {
	t.Setenv("GHOSTWIRE_PASSPHRASE", "s3cret-from-env")
	got, err := resolvePassphrase("unused: ")
	if err != nil {
		t.Fatalf("resolvePassphrase: %v", err)
	}
	if got != "s3cret-from-env" {
		t.Errorf("got %q, want %q", got, "s3cret-from-env")
	}
}

func TestResolvePassphraseFromFile(t *testing.T) {
	// Env var must be unset for the file branch to be reached.
	os.Unsetenv("GHOSTWIRE_PASSPHRASE")
	dir := t.TempDir()
	path := filepath.Join(dir, "pass")
	// Trailing newline must be trimmed (Secret files commonly end in \n).
	if err := os.WriteFile(path, []byte("file-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHOSTWIRE_PASSPHRASE_FILE", path)

	got, err := resolvePassphrase("unused: ")
	if err != nil {
		t.Fatalf("resolvePassphrase: %v", err)
	}
	if got != "file-secret" {
		t.Errorf("got %q, want %q", got, "file-secret")
	}
}

func TestResolvePassphraseEnvBeatsFile(t *testing.T) {
	t.Setenv("GHOSTWIRE_PASSPHRASE", "env-wins")
	t.Setenv("GHOSTWIRE_PASSPHRASE_FILE", "/nonexistent/should-not-be-read")
	got, err := resolvePassphrase("unused: ")
	if err != nil {
		t.Fatalf("resolvePassphrase: %v", err)
	}
	if got != "env-wins" {
		t.Errorf("env should take precedence; got %q", got)
	}
}
