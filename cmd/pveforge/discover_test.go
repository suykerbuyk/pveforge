package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// fakeAPIDocJS wraps payload (a JSON array literal) the way the real
// apidoc.js does: `const apiSchema = [...]  ;` followed by unrelated
// ExtJS UI code — proving the discover commands work end-to-end through
// the same extraction pve.Client.APIDocTree performs, not just against a
// pre-parsed fixture.
func fakeAPIDocJS(payload string) string {
	return "const apiSchema = " + payload + `;

Ext.define('PVE.APIViewer', { extend: 'Ext.container.Container' });
`
}

// newDiscoverTestServer serves apidoc.js (unauthenticated, matching live
// PVE behavior) containing exactly the path nodes given, and fails the
// test for any other request.
func newDiscoverTestServer(t *testing.T, pathToInfo map[string]string) *httptest.Server {
	t.Helper()
	var nodes []string
	for path, info := range pathToInfo {
		nodes = append(nodes, `{"path":"`+path+`","leaf":1,"info":`+info+`}`)
	}
	payload := "[" + strings.Join(nodes, ",") + "]"

	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pve-docs/api-viewer/apidoc.js" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(fakeAPIDocJS(payload)))
	}))
}

func TestNewDiscoverVMCmd_DefaultVerbConfig(t *testing.T) {
	srv := newDiscoverTestServer(t, map[string]string{
		"/nodes/{node}/qemu/{vmid}/config": `{"GET":{"parameters":{"properties":{"vmid":{"type":"integer"}}}}}`,
	})
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newDiscoverVMCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), `"vmid"`) {
		t.Errorf("expected the vmid parameter schema in output, got:\n%s", out.String())
	}
}

func TestNewDiscoverVMCmd_VerbStatus(t *testing.T) {
	srv := newDiscoverTestServer(t, map[string]string{
		"/nodes/{node}/qemu/{vmid}/status/current": `{"GET":{"description":"vm status"}}`,
	})
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newDiscoverVMCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "--verb", "status", "qa-pve-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "vm status") {
		t.Errorf("expected the status schema in output, got:\n%s", out.String())
	}
}

func TestNewDiscoverVMCmd_InvalidVerb(t *testing.T) {
	cmd := newDiscoverVMCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--verb", "bogus", "qa-pve-01"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for an invalid --verb value")
	}
}

func TestNewDiscoverVMCmd_RequiresOneArg(t *testing.T) {
	cmd := newDiscoverVMCmd()
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a missing target-id argument")
	}
}

func TestNewDiscoverVMCmd_UnknownTarget(t *testing.T) {
	rosterPath := newTestRosterEmpty(t)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newDiscoverVMCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--roster", rosterPath, "does-not-exist"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a target not in the roster")
	}
}

func TestNewDiscoverNodeCmd_Success(t *testing.T) {
	srv := newDiscoverTestServer(t, map[string]string{
		"/nodes/{node}/status": `{"GET":{"returns":{"properties":{"uptime":{"type":"integer"}}}}}`,
	})
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newDiscoverNodeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "uptime") {
		t.Errorf("expected the uptime field in output, got:\n%s", out.String())
	}
}

func TestNewDiscoverStorageCmd_DefaultVerbConfig(t *testing.T) {
	srv := newDiscoverTestServer(t, map[string]string{
		"/storage/{storage}": `{"PUT":{"parameters":{"properties":{"content":{"type":"string"}}}}}`,
	})
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newDiscoverStorageCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), `"content"`) {
		t.Errorf("expected the cluster-config schema (PUT parameters) in output, got:\n%s", out.String())
	}
}

func TestNewDiscoverStorageCmd_VerbStatus(t *testing.T) {
	srv := newDiscoverTestServer(t, map[string]string{
		"/nodes/{node}/storage/{storage}/status": `{"GET":{"returns":{"properties":{"used":{"type":"integer"}}}}}`,
	})
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newDiscoverStorageCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "--verb", "status", "qa-pve-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "used") {
		t.Errorf("expected the per-node status schema in output, got:\n%s", out.String())
	}
}

func TestNewDiscoverStorageCmd_InvalidVerb(t *testing.T) {
	cmd := newDiscoverStorageCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--verb", "bogus", "qa-pve-01"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for an invalid --verb value")
	}
}

func TestNewDiscoverNetworkCmd_Success(t *testing.T) {
	srv := newDiscoverTestServer(t, map[string]string{
		"/nodes/{node}/network/{iface}": `{"PUT":{"parameters":{"properties":{"bridge_ports":{"type":"string"}}}}}`,
	})
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newDiscoverNetworkCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "bridge_ports") {
		t.Errorf("expected bridge_ports in output, got:\n%s", out.String())
	}
}

func TestNewDiscoverNetworkCmd_RequiresOneArg(t *testing.T) {
	cmd := newDiscoverNetworkCmd()
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a missing target-id argument")
	}
}

// TestNewDiscoverVMCmd_UnknownPathInTree proves a mismatch between
// pveforge's hardcoded template path and what a (differently-versioned)
// PVE host's apidoc.js actually contains surfaces as a clear error rather
// than silently rendering nothing.
func TestNewDiscoverVMCmd_UnknownPathInTree(t *testing.T) {
	srv := newDiscoverTestServer(t, map[string]string{
		"/some/other/path": `{"GET":{}}`,
	})
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newDiscoverVMCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error when the path isn't in the tree")
	}
}

func TestNewDiscoverDeviceCmd_Success(t *testing.T) {
	cmd := newDiscoverDeviceCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"NVMeDrive"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "serial") || !strings.Contains(got, "backing") {
		t.Errorf("expected the NVMeDrive schema's fields in output, got:\n%s", got)
	}
}

func TestNewDiscoverDeviceCmd_JSONOutput(t *testing.T) {
	cmd := newDiscoverDeviceCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"-o", "json", "NVMeDrive"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.HasPrefix(out.String(), "{\n") {
		t.Errorf("expected indented JSON output, got:\n%s", out.String())
	}
}

func TestNewDiscoverDeviceCmd_UnknownType(t *testing.T) {
	cmd := newDiscoverDeviceCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"BogusDevice"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for an unknown device type")
	}
}

func TestNewDiscoverDeviceCmd_RequiresOneArg(t *testing.T) {
	cmd := newDiscoverDeviceCmd()
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a missing type argument")
	}
}

func TestVMDiscoverPath(t *testing.T) {
	cases := map[string]string{
		"config": "/nodes/{node}/qemu/{vmid}/config",
		"status": "/nodes/{node}/qemu/{vmid}/status/current",
	}
	for verb, want := range cases {
		got, err := vmDiscoverPath(verb)
		if err != nil {
			t.Fatalf("vmDiscoverPath(%q): %v", verb, err)
		}
		if got != want {
			t.Errorf("vmDiscoverPath(%q) = %q, want %q", verb, got, want)
		}
	}
	if _, err := vmDiscoverPath("bogus"); err == nil {
		t.Error("expected an error for an unknown verb")
	}
}

func TestStorageDiscoverPath(t *testing.T) {
	cases := map[string]string{
		"config": "/storage/{storage}",
		"status": "/nodes/{node}/storage/{storage}/status",
	}
	for verb, want := range cases {
		got, err := storageDiscoverPath(verb)
		if err != nil {
			t.Fatalf("storageDiscoverPath(%q): %v", verb, err)
		}
		if got != want {
			t.Errorf("storageDiscoverPath(%q) = %q, want %q", verb, got, want)
		}
	}
	if _, err := storageDiscoverPath("bogus"); err == nil {
		t.Error("expected an error for an unknown verb")
	}
}
