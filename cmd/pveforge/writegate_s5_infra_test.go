package main

// Family S5 (bootstrap, roster, exec, api) fixtures for the exit-3/4 write
// gate (contract plan section 3.5, AC-W2/W3/W5/W10). This file is the shared
// fake: a root-SSH host that keeps its OWN write log by command text (never by
// the ctx mark, so a write site that lost sshexec.WithWrite is visible), a
// scripted validator, and the roster seeds. The fixtures that use them are in
// writegate_s5_*_test.go; every one reads the THREE logs of writelogs_test.go
// through writeEnv.observe.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/dispatch"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

const (
	s5Target = "qa-test"
	s5Node   = "qa-pve-01"
	s5Token  = "root@pam!pveforge"
	// s5FP is a well-formed SSH host key fingerprint (SHA256: + 43 base64).
	s5FP = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// s5IsHostWrite classifies a command as a host-state write by its TEXT. It
// never looks at the ctx: this is the independent observer the gate is
// compared against.
func s5IsHostWrite(cmd string) bool {
	for _, p := range []string{"pveum user token add", "pveum user token remove", "pveum acl modify"} {
		if strings.HasPrefix(cmd, p) {
			return true
		}
	}
	return strings.Contains(cmd, "authorized_keys")
}

type s5Rule struct {
	prefix string
	// n is how many matching commands the rule answers (0 = every one).
	n       int
	res     bootstrap.RunResult
	err     error
	applies bool // the command took effect although it reports err
	skip    int  // let this many matching commands through to the defaults first
	used    int
	seen    int
}

// s5Host is a fake PVE host reachable over root SSH: transport and session in
// one. It is NOT safe to share across tests.
type s5Host struct {
	mu       sync.Mutex
	tokens   map[string]bool
	writes   []string // host-state writes, by command text, in order
	unmarked []string // writes that arrived without sshexec.WithWrite
	cmds     []string
	rules    []*s5Rule

	fp             string
	installErr     error // returned after the install script was SENT
	installDialErr error // the dial failed: nothing was sent
	dialPWErr      error
	dialKeyErr     error
	capturePEM     string
	secretN        int
	installs       int
}

func newS5Host(t *testing.T) *s5Host {
	t.Helper()
	return &s5Host{tokens: map[string]bool{}, fp: s5FP, capturePEM: s5CertPEM(t, "served")}
}

var s5Timeout = &sshexec.CommandTimeoutError{Cmd: "pveum", After: time.Second}

func (h *s5Host) addRule(r s5Rule) *s5Rule {
	h.mu.Lock()
	defer h.mu.Unlock()
	rr := r
	h.rules = append(h.rules, &rr)
	return &rr
}

func (h *s5Host) writeLog() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.writes...)
}

func (h *s5Host) record(cmd string, ctx context.Context) {
	if s5IsHostWrite(cmd) {
		h.writes = append(h.writes, cmd)
		if !sshexec.IsWrite(ctx) {
			h.unmarked = append(h.unmarked, cmd)
			// G6: fail every fixture at the moment a host write arrives without
			// the sshexec.WithWrite mark, so a lost mark cannot hide behind this
			// fake (production's NoteWrite opens only a marked ctx).
			panic("s5Host: a host write arrived WITHOUT the sshexec.WithWrite mark (a lost mark): " + cmd)
		}
	}
	h.cmds = append(h.cmds, cmd)
}

func (h *s5Host) InstallPubkeyViaPassword(ctx context.Context, addr, user, password, line, pin string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.installDialErr != nil {
		return "", h.installDialErr // the dial failed: nothing was sent
	}
	// Past the dial the script is sent under WithWrite (sshexec.InstallPubkeyViaPassword).
	wctx := sshexec.WithWrite(ctx)
	sshexec.NoteWrite(wctx)
	h.installs++
	h.writes = append(h.writes, "install pubkey (authorized_keys)")
	if h.installErr != nil {
		if errors.Is(h.installErr, sshexec.ErrCommandTimedOut) {
			return "", fmt.Errorf("install pubkey: run remote script: %w", dispatch.Unobserve(h.installErr))
		}
		return "", fmt.Errorf("install pubkey: run remote script: %w", h.installErr)
	}
	if pin != "" {
		return pin, nil
	}
	return h.fp, nil
}

func (h *s5Host) DialWithKey(ctx context.Context, addr, user string, key []byte, fp string) (bootstrap.SSHSession, error) {
	if h.dialKeyErr != nil {
		return nil, h.dialKeyErr
	}
	return h, nil
}

func (h *s5Host) ReconnectWithPinnedKey(ctx context.Context, addr, user string, key []byte, fp string) (bootstrap.SSHSession, error) {
	return h, nil
}

func (h *s5Host) DialWithPassword(ctx context.Context, addr, user, password, pin string) (bootstrap.SSHSession, string, error) {
	if h.dialPWErr != nil {
		return nil, "", h.dialPWErr
	}
	fp := h.fp
	if pin != "" {
		fp = pin
	}
	return h, fp, nil
}

func (h *s5Host) Close() error { return nil }

// Run answers one command like a small PVE host, and reports a write exactly
// where sshexec.Client.Run does: at the send point (NoteWrite on a marked ctx),
// building dispatch.Unobserved when a marked write was sent and timed out.
func (h *s5Host) Run(ctx context.Context, cmd string) (bootstrap.RunResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return bootstrap.RunResult{}, err
	}
	sshexec.NoteWrite(ctx)
	h.record(cmd, ctx)
	marked := sshexec.IsWrite(ctx)
	fail := func(err error) error {
		if marked && errors.Is(err, sshexec.ErrCommandTimedOut) {
			return dispatch.Unobserve(err)
		}
		return err
	}
	apply := func() {
		switch {
		case strings.HasPrefix(cmd, "pveum user token add"):
			h.tokens[s5TokenID(cmd)] = true
		case strings.HasPrefix(cmd, "pveum user token remove"):
			delete(h.tokens, s5TokenID(cmd))
		}
	}
	for _, r := range h.rules {
		if !strings.HasPrefix(cmd, r.prefix) || (r.n > 0 && r.used >= r.n) {
			continue
		}
		if r.seen < r.skip {
			r.seen++
			continue
		}
		r.used++
		if r.err == nil && r.res.ExitCode == 0 || r.applies {
			apply()
		}
		return r.res, fail(r.err)
	}
	switch {
	case strings.HasPrefix(cmd, "pveum role list"):
		return bootstrap.RunResult{Stdout: `[{"privs":"VM.Allocate","roleid":"PVEVMAdmin","special":1}]`}, nil
	case strings.HasPrefix(cmd, "pvesh get /nodes"):
		return bootstrap.RunResult{Stdout: fmt.Sprintf(`[{"node":%q,"status":"online"}]`, s5Node)}, nil
	case strings.HasPrefix(cmd, "pveum user token list"):
		prefix := strings.Trim(strings.Fields(cmd)[4], "'") + "!"
		var names []string
		for id := range h.tokens {
			if n, ok := strings.CutPrefix(id, prefix); ok {
				names = append(names, fmt.Sprintf(`{"expire":0,"privsep":1,"tokenid":%q}`, n))
			}
		}
		sort.Strings(names)
		return bootstrap.RunResult{Stdout: "[" + strings.Join(names, ",") + "]"}, nil
	case strings.HasPrefix(cmd, "pveum user token add"):
		apply()
		h.secretN++
		return bootstrap.RunResult{Stdout: fmt.Sprintf(`{"full-tokenid":%q,"info":{"privsep":"1"},"value":"secret-%d"}`, s5Token, h.secretN)}, nil
	case strings.HasPrefix(cmd, "pveum user token remove"):
		apply()
		return bootstrap.RunResult{}, nil
	case strings.HasPrefix(cmd, "openssl s_client"):
		return bootstrap.RunResult{Stdout: h.capturePEM}, nil
	case strings.Contains(cmd, "authorized_keys"):
		return bootstrap.RunResult{Stdout: "removed\n"}, nil
	}
	return bootstrap.RunResult{}, nil
}

func s5TokenID(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) < 6 {
		return ""
	}
	return strings.Trim(f[4], "'") + "!" + strings.Trim(f[5], "'")
}

// s5CertPEM is a throwaway self-signed certificate, so a TLS capture has a pin.
func s5CertPEM(t *testing.T, cn string) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func s5PinOf(t *testing.T, certPEM string) tlspin.Pin {
	t.Helper()
	p, _, err := tlspin.ParseCapture([]byte(certPEM))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// s5Validator is the REST half of bootstrap and import-token: ValidateTokenGrants
// answers errs call by call (nil once they run out), ServedPin answers served.
type s5Validator struct {
	mu        sync.Mutex
	errs      []error
	calls     int
	served    tlspin.Pin
	servedErr error
}

func (v *s5Validator) ValidateTokenGrants(context.Context, bootstrap.APIConfig, []bootstrap.Grant) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	i := v.calls
	v.calls++
	if i < len(v.errs) {
		return v.errs[i]
	}
	return nil
}

func (v *s5Validator) ServedPin(context.Context, string, int, bool) (tlspin.Pin, *x509.Certificate, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.served, nil, v.servedErr
}

func (v *s5Validator) callCount() int { v.mu.Lock(); defer v.mu.Unlock(); return v.calls }

// s5Env is one fixture: the host, the validator, the roster file and the
// three-log writeEnv over them. REST has no write log for the bootstrap family
// (its REST is two reads through the validator seam), said explicitly with noLog.
type s5Env struct {
	t      *testing.T
	host   *s5Host
	val    *s5Validator
	roster string
	we     writeEnv
}

const s5SeedRoster = "[[targets]]\nid = \"" + s5Target + "\"\nhost = \"h\"\nnode = \"" + s5Node + "\"\n"
const s5SeedRosterInsecure = "[[targets]]\nid = \"" + s5Target + "\"\nhost = \"h\"\nnode = \"" + s5Node + "\"\ninsecure_tls = true\n"

func newS5Env(t *testing.T, seed string) *s5Env {
	t.Helper()
	t.Cleanup(roster.SetScryptWorkFactorForTests(10))
	e := &s5Env{t: t, host: newS5Host(t), val: &s5Validator{}}
	e.val.served = s5PinOf(t, e.host.capturePEM)
	e.roster = filepath.Join(t.TempDir(), "pveforge.toml")
	if err := os.WriteFile(e.roster, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PVEFORGE_ROSTER", e.roster)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	t.Setenv(pvePasswordEnvVar, "test-pve-pass")
	origT, origV := newBootstrapTransport, newBootstrapValidator
	newBootstrapTransport = func() bootstrap.SSHTransport { return e.host }
	newBootstrapValidator = func() bootstrap.APIValidator { return e.val }
	t.Cleanup(func() { newBootstrapTransport, newBootstrapValidator = origT, origV })
	e.we = writeEnv{roster: e.roster, restWrites: noLog, sshWrites: e.host.writeLog}
	return e
}

// observe runs args through runRoot with the three logs, and fails the test if
// any host write arrived without the write mark (a lost WithWrite).
func (e *s5Env) observe(args ...string) writeObservation {
	e.t.Helper()
	o := e.we.observe(e.t, args...)
	e.host.mu.Lock()
	un := append([]string(nil), e.host.unmarked...)
	e.host.mu.Unlock()
	if len(un) != 0 {
		e.t.Fatalf("host writes arrived WITHOUT sshexec.WithWrite (a write site lost its mark): %q", un)
	}
	return o
}

func (e *s5Env) bootstrapArgs(extra ...string) []string {
	return append([]string{"bootstrap", s5Target, "--host", "h", "--node", s5Node, "--grant", "/:PVEVMAdmin::1"}, extra...)
}

func (e *s5Env) mustLoad() *roster.Roster {
	e.t.Helper()
	r, err := roster.Load(e.roster)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}
