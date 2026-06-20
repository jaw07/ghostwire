package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadDaemonAPI(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "daemon-api"),
		[]byte("http://127.0.0.1:9999\nabc123token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	url, token, err := readDaemonAPI(dir)
	if err != nil {
		t.Fatalf("readDaemonAPI: %v", err)
	}
	if url != "http://127.0.0.1:9999" || token != "abc123token" {
		t.Errorf("got (%q, %q), want (http://127.0.0.1:9999, abc123token)", url, token)
	}
}

func TestReadDaemonAPIMissing(t *testing.T) {
	if _, _, err := readDaemonAPI(t.TempDir()); err == nil {
		t.Error("expected error when daemon-api file is absent")
	}
}

func TestReadDaemonAPIMalformed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "daemon-api"), []byte("only-one-line\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readDaemonAPI(dir); err == nil {
		t.Error("expected error for malformed daemon-api file")
	}
}
