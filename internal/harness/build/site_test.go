package build

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Direct tests of the env.sh site-file loader (LoadSite): the read-not-sourced
// parse, the allow-list + per-type patterns, never-root, distinctness, and the
// file-mode/symlink gate. Pure (its own temp dir), no process-global state.

var validSite = map[string]string{
	"DOMAIN": "pvh.example.invalid",
	"N1_IP":  "192.0.2.90", "N2_IP": "192.0.2.91", "NFS_IP": "192.0.2.92",
	"GATEWAY": "192.0.2.1", "DNS": "192.0.2.53", "PREFIX": "24",
	"N1_MAC": "02:00:00:00:00:90", "N2_MAC": "02:00:00:00:00:91", "NFS_MAC": "02:00:00:00:00:92",
	"KEYBOARD": "en-us", "COUNTRY": "us", "TIMEZONE": "UTC", "MAILTO": "root@example.invalid",
	"SOURCE_ISO": "/srv/proxmox-ve.iso", "NFS_IMAGE": "debian-13-genericcloud-amd64.qcow2", "NFS_USER": "pvh",
	"CONTAINER_IMAGE": "debian:13", "PVE_KEYRING_SHA512": strings.Repeat("a", 128),
	"NODE_CORES": "4", "NODE_MEMORY_MIB": "16384", "NODE_DISK_GIB": "128",
	"NFS_CORES": "2", "NFS_MEMORY_MIB": "2048", "NFS_DATA_GIB": "200",
}

func writeEnv(t *testing.T, lines string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "harness-build.env")
	if err := os.WriteFile(p, []byte(lines), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func validLines(over map[string]string, omit string) string {
	var b strings.Builder
	for k, v := range validSite {
		if k == omit {
			continue
		}
		if ov, ok := over[k]; ok {
			v = ov
		}
		b.WriteString(k + "=" + v + "\n")
	}
	return b.String()
}

func TestLoadSite_Valid(t *testing.T) {
	s, err := LoadSite(writeEnv(t, "# a comment\n\n"+validLines(nil, ""), 0o600))
	if err != nil {
		t.Fatalf("valid site refused: %v", err)
	}
	if s["NFS_IMAGE"] != "debian-13-genericcloud-amd64.qcow2" || s["NODE_DISK_GIB"] != "128" {
		t.Errorf("loaded site wrong: %v", s)
	}
}

func TestLoadSite_Refusals(t *testing.T) {
	cases := []struct{ name, lines, want string }{
		{"missing key", validLines(nil, "NFS_USER"), "NFS_USER is missing"},
		{"unknown key", validLines(nil, "") + "BOGUS=x\n", "unknown key BOGUS"},
		{"repeated key", validLines(nil, "") + "NFS_USER=pvh\n", "NFS_USER is set twice"},
		{"bad IP", validLines(map[string]string{"N1_IP": "999.1.1.1"}, ""), `N1_IP="999.1.1.1" is not a valid value`},
		{"never root", validLines(map[string]string{"NFS_USER": "root"}, ""), "never root"},
		{"not KEY=value", validLines(nil, "") + "not a pair\n", "not KEY=value"},
		{"ip collides", validLines(map[string]string{"N2_IP": "192.0.2.90"}, ""), "each must be distinct"},
		{"mac collides", validLines(map[string]string{"N2_MAC": "02:00:00:00:00:90"}, ""), "each must be distinct"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := LoadSite(writeEnv(t, c.lines, 0o600)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err=%v, want it to contain %q", err, c.want)
			}
		})
	}
}

func TestLoadSite_ModeAndSymlink(t *testing.T) {
	if _, err := LoadSite(writeEnv(t, validLines(nil, ""), 0o644)); err == nil || !strings.Contains(err.Error(), "want 600") {
		t.Errorf("a 0644 site file was not refused: %v", err)
	}
	// A symlink at the site path is refused ("does not exist").
	dir := t.TempDir()
	real := filepath.Join(dir, "real.env")
	if err := os.WriteFile(real, []byte(validLines(nil, "")), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "harness-build.env")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSite(link); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("a symlinked site file was not refused: %v", err)
	}
}
