package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// rosterPassphrase is the fixed passphrase every test roster in this
// package's tests is encrypted with.
const rosterPassphrase = "test-roster-pass"

// newTestRosterWithTLSTarget writes a roster.toml with one token-only
// target pointed at srv (a TLS test server — RoutedClient always builds
// an https:// base URL, so tests need a real TLS listener, not a plain
// httptest.Server) and returns the roster's path. insecure_tls is set so
// the client accepts the test server's self-signed cert.
func newTestRosterWithTLSTarget(t *testing.T, srv *httptest.Server, targetID, node string) string {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}

	armored, err := fixtureEncrypt([]byte("test-secret"), rosterPassphrase)
	if err != nil {
		t.Fatalf("fixtureEncrypt: %v", err)
	}

	tomlContent := fmt.Sprintf(`[[targets]]
id = %q
host = %q
node = %q
api_port = %d
insecure_tls = true

  [targets.token]
  id = "root@pam!pveforge"
  secret_enc = '''
%s'''
`, targetID, host, node, port, armored)

	dir := t.TempDir()
	path := filepath.Join(dir, "roster.toml")
	if err := os.WriteFile(path, []byte(tomlContent), 0o600); err != nil {
		t.Fatalf("write test roster: %v", err)
	}
	return path
}

// newTestRosterEmpty writes an empty (no targets) roster.toml and returns
// its path.
func newTestRosterEmpty(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.toml")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("write empty roster: %v", err)
	}
	return path
}

func TestAddOutputFlag_DefaultKV(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	resolveFormat := addOutputFlag(cmd)
	format, err := resolveFormat()
	if err != nil {
		t.Fatalf("resolveFormat: %v", err)
	}
	if format != kvjson.KV {
		t.Errorf("default format = %q, want kv", format)
	}
}

func TestAddOutputFlag_InvalidValue(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	resolveFormat := addOutputFlag(cmd)
	if err := cmd.Flags().Set("output", "yaml"); err != nil {
		t.Fatalf("set --output: %v", err)
	}
	if _, err := resolveFormat(); err == nil {
		t.Fatal("expected an error for an invalid --output value")
	}
}

func TestResolveRoutedClient_MissingRosterFile(t *testing.T) {
	cmd := newNodeGetCmd()
	if err := cmd.Flags().Set("roster", filepath.Join(t.TempDir(), "does-not-exist.toml")); err != nil {
		t.Fatalf("set --roster: %v", err)
	}
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	_, err := resolveRoutedClient(cmd, "qa-pve-01")
	if err == nil {
		t.Fatal("expected an error when the roster file doesn't exist")
	}
}

func TestResolveRoutedClient_MissingTarget(t *testing.T) {
	rosterPath := newTestRosterEmpty(t)
	cmd := newNodeGetCmd()
	if err := cmd.Flags().Set("roster", rosterPath); err != nil {
		t.Fatalf("set --roster: %v", err)
	}
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	_, err := resolveRoutedClient(cmd, "does-not-exist")
	if err == nil {
		t.Fatal("expected an error for a target not in the roster")
	}
}

func TestResolveRoutedClient_Success(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("resolveRoutedClient itself must not make any network calls")
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	cmd := newNodeGetCmd()
	if err := cmd.Flags().Set("roster", rosterPath); err != nil {
		t.Fatalf("set --roster: %v", err)
	}
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	client, err := resolveRoutedClient(cmd, "qa-pve-01")
	if err != nil {
		t.Fatalf("resolveRoutedClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	if client.Node() != "qa-pve-01" {
		t.Errorf("Node() = %q, want qa-pve-01", client.Node())
	}
}
