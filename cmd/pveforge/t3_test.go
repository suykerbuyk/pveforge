package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

// T3: every REST request to an unpinned insecure_tls target is refused.

// distinctKeyServer is a TLS server on its OWN key (not Go's shared
// httptest one), counting requests and requests that carried a token.
func distinctKeyServer(t *testing.T, body string) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "b"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var hits, authorized atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "" {
			authorized.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &hits, &authorized
}

// An unpinned insecure_tls target is refused before any request; the
// refusal names the target, the command that pins it, and the roster.
func TestT3_UnpinnedInsecureTargetIsRefused(t *testing.T) {
	srv, hits, _ := distinctKeyServer(t, `{"data":{}}`)
	rp := writeTestRoster(t, srv, "t", "n1", "")
	// Strip the pin writeTestRoster adds: the state of a roster from before
	// TLS pins.
	data, _ := os.ReadFile(rp)
	i := bytes.Index(data, []byte("  [targets.tls]"))
	if err := os.WriteFile(rp, data[:i], 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	code, _, stderr := runRootArgs("vm", "get", "--roster", rp, "t", "100")
	if code == 0 || !strings.Contains(stderr, pve.ErrTLSPinRequired.Error()) || !strings.Contains(stderr, "pveforge roster pin-tls t") ||
		!strings.Contains(stderr, "--roster "+rp) {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if hits.Load() != 0 {
		t.Fatalf("%d request(s) reached an unpinned insecure target", hits.Load())
	}
}

// The helper's pin is the server's OWN key: a roster written for one
// server and pointed at another, differently keyed, is refused.
func TestWriteTestRoster_PinIsTheServersOwn(t *testing.T) {
	vmBody := `{"data":{"status":"running","vmid":100}}`
	srvB, hitsB, _ := distinctKeyServer(t, vmBody)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	// Built for B: B's own pin, so it connects.
	rpB := writeTestRoster(t, srvB, "t", "n1", "")
	if code, _, stderr := runRootArgs("vm", "get", "--roster", rpB, "t", "100"); strings.Contains(stderr, "pin") {
		t.Fatalf("a roster built for B does not reach B: exit %d, stderr %q", code, stderr)
	}
	if hitsB.Load() == 0 {
		t.Fatal("the roster built for B never reached B")
	}
	// Built for A (Go's shared httptest key), pointed at B: refused.
	srvA := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srvA.Close)
	rpA := writeTestRoster(t, srvA, "t", "n1", "")
	_, portA, _ := net.SplitHostPort(strings.TrimPrefix(srvA.URL, "https://"))
	_, portB, _ := net.SplitHostPort(strings.TrimPrefix(srvB.URL, "https://"))
	data, _ := os.ReadFile(rpA)
	if err := os.WriteFile(rpA, bytes.Replace(data, []byte("api_port = "+portA), []byte("api_port = "+portB), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	before := hitsB.Load()
	code, _, stderr := runRootArgs("vm", "get", "--roster", rpA, "t", "100")
	if code == 0 || !strings.Contains(stderr, tlspin.ErrPinMismatch.Error()) || hitsB.Load() != before {
		t.Fatalf("A's pin against B: exit %d, stderr %q, B hits %d→%d", code, stderr, before, hitsB.Load())
	}
}

// ---- import-token ----

// R3: an insecure_tls import with no pin is refused BEFORE the secret is
// read, whether the flag or the roster says insecure.
func TestRosterImportToken_UnpinnedInsecureRefusedBeforeStdin(t *testing.T) {
	t.Run("the flag", func(t *testing.T) {
		c := newImportCase(t)
		code, _, stderr := c.run(importSecret+"\n", append(importArgs, "--insecure-tls")...)
		if code == 0 || !strings.Contains(stderr, pve.ErrTLSPinRequired.Error()) || !strings.Contains(stderr, "--expect") || c.stdinReads != 0 || len(c.v.cfgs) != 0 {
			t.Fatalf("exit %d, stderr %q, stdin reads %d, validations %d", code, stderr, c.stdinReads, len(c.v.cfgs))
		}
	})
	t.Run("the roster", func(t *testing.T) {
		c := newImportCase(t)
		if err := roster.AppendTarget(c.rosterPath, roster.Target{ID: "qa-imp", Host: "h.example", Node: "n1", InsecureTLS: true}); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := c.run(importSecret+"\n", importArgs...) // no --insecure-tls
		if code == 0 || !strings.Contains(stderr, pve.ErrTLSPinRequired.Error()) || c.stdinReads != 0 || len(c.v.cfgs) != 0 {
			t.Fatalf("exit %d, stderr %q, stdin reads %d, validations %d", code, stderr, c.stdinReads, len(c.v.cfgs))
		}
	})
	t.Run("an empty --expect", func(t *testing.T) {
		c := newImportCase(t)
		code, _, stderr := c.run(importSecret+"\n", append(importArgs, "--insecure-tls", "--expect", "")...)
		if code == 0 || !strings.Contains(stderr, "not a TLS pin") || c.stdinReads != 0 {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
	})
}

// --expect is wired: the validation goes through that pin, and it is
// written with source expect.
func TestRosterImportToken_ExpectIsWired(t *testing.T) {
	c := newImportCase(t)
	pin := tlspin.Pin("sha256//" + strings.Repeat("A", 43) + "=")
	code, stdout, stderr := c.run(importSecret+"\n", append(importArgs, "--insecure-tls", "--expect", string(pin))...)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if len(c.v.cfgs) != 1 || c.v.cfgs[0].TLSPin != pin {
		t.Fatalf("validated with %+v, want through --expect", c.v.cfgs)
	}
	r, _ := roster.Load(c.rosterPath)
	if tg := r.Find("qa-imp"); tg.TLS == nil || tg.TLS.SPKISHA256 != string(pin) || tg.TLS.Source != "expect" {
		t.Fatalf("[targets.tls] = %+v", tg.TLS)
	}
	if !strings.Contains(stdout, "tls_pin_source=expect") {
		t.Fatalf("stdout %q", stdout)
	}
}

// The real chain: an --expect the server does not serve is refused in the
// handshake, and no request, and so no token, reaches it.
func TestRosterImportToken_WrongExpectSendsNoToken(t *testing.T) {
	srv, hits, authorized := distinctKeyServer(t, `{"data":{}}`)
	c := newImportCase(t)
	newBootstrapValidator = bootstrap.NewAPIValidator
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	wrong := "sha256//" + strings.Repeat("B", 43) + "="
	code, _, stderr := c.run(importSecret+"\n", "--token-id", "ops@pve!ci", "--grant", "/vms/100:PVEVMUser", "--host", host, "--api-port", port, "--node", "n1", "--insecure-tls", "--expect", wrong)
	if code == 0 || hits.Load() != 0 || authorized.Load() != 0 {
		t.Fatalf("exit %d, stderr %q, requests %d (with a token %d)", code, stderr, hits.Load(), authorized.Load())
	}
	if r, _ := roster.Load(c.rosterPath); len(r.Targets) != 0 {
		t.Fatalf("a refused import wrote the roster: %+v", r.Targets)
	}
}

// N7 for T3: every flag the new refusals name exists where they name it.
func TestT3Errors_NameOnlyFlagsThatExist(t *testing.T) {
	root := newRootCmd()
	imp, _, err := root.Find([]string{"roster", "import-token"})
	if err != nil {
		t.Fatal(err)
	}
	pin, _, err := root.Find([]string{"roster", "pin-tls"})
	if err != nil {
		t.Fatal(err)
	}
	flagRE := regexp.MustCompile(`--[a-z][a-z-]*`)
	rp := filepath.Join(t.TempDir(), "r.toml")
	_ = os.WriteFile(rp, nil, 0o600)
	importMsg := bootstrap.CheckImportTLS(bootstrap.ImportOptions{TargetID: "t", InsecureTLS: true, RosterPath: rp}).Error()
	targetMsg := fmt.Sprint(func() error {
		_, err := pve.NewClientForTarget(&roster.Target{ID: "t", Host: "h", Node: "n", InsecureTLS: true, Token: &roster.TokenAuth{ID: "a@pam!b", SecretEnc: mustArmor(t)}}, rosterPassphrase)
		return err
	}())
	for _, f := range flagRE.FindAllString(importMsg, -1) {
		if imp.Flags().Lookup(f[2:]) == nil && imp.InheritedFlags().Lookup(f[2:]) == nil {
			t.Errorf("import-token's refusal names %s, which import-token lacks: %q", f, importMsg)
		}
	}
	for _, f := range flagRE.FindAllString(targetMsg, -1) {
		if pin.Flags().Lookup(f[2:]) == nil && pin.InheritedFlags().Lookup(f[2:]) == nil {
			t.Errorf("the target refusal names %s, which pin-tls lacks: %q", f, targetMsg)
		}
	}
	if !strings.Contains(targetMsg, pve.ErrTLSPinRequired.Error()) {
		t.Fatalf("the target refusal: %q", targetMsg)
	}

	// The conflict refusal names import-token's --expect, then a bootstrap
	// command line: each flag is checked against the command it is given to.
	boot, _, err := root.Find([]string{"bootstrap"})
	if err != nil {
		t.Fatal(err)
	}
	conflictErr := bootstrap.CheckImportTLS(bootstrap.ImportOptions{TargetID: "pinned", RosterPath: writeValidateRoster(t, mixedPinRoster), Expect: tlspin.Pin("sha256//" + strings.Repeat("B", 43) + "=")})
	if !errors.Is(conflictErr, bootstrap.ErrTLSPinDiffers) {
		t.Fatalf("the conflict refusal: %v", conflictErr)
	}
	impPart, bootPart, ok := strings.Cut(conflictErr.Error(), "pveforge bootstrap ")
	if !ok {
		t.Fatalf("the conflict refusal names no bootstrap command: %q", conflictErr)
	}
	for _, part := range []struct {
		name, text string
		cmd        *cobra.Command
	}{{"import-token", impPart, imp}, {"bootstrap", bootPart, boot}} {
		flags := flagRE.FindAllString(part.text, -1)
		if len(flags) == 0 {
			t.Errorf("the conflict refusal names no %s flag: %q", part.name, conflictErr)
		}
		for _, f := range flags {
			if part.cmd.Flags().Lookup(f[2:]) == nil && part.cmd.InheritedFlags().Lookup(f[2:]) == nil {
				t.Errorf("the conflict refusal names %s for %s, which lacks it: %q", f, part.name, conflictErr)
			}
		}
	}
}

func mustArmor(t *testing.T) string {
	t.Helper()
	a, err := fixtureEncrypt([]byte("s"), rosterPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
