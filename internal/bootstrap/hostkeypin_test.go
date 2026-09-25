package bootstrap

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// --host-key-fingerprint (Options.HostKeyFingerprint): every password
// connection bootstrap makes is checked against the operator's pin.

var pinFP = "SHA256:" + strings.Repeat("P", 43)

// H1: keyless, the password dial is pinned, and the pin is what is reported.
func TestRun_HostKeyPin_Keyless(t *testing.T) {
	_, opts := keylessRoster(t, "")
	opts.NoSSHKey = true
	opts.HostKeyFingerprint = pinFP
	tr := keylessTransport(&fakeSession{})
	res, err := Run(context.Background(), opts, tr, &fakeValidator{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(tr.dialPWPins) == 0 || tr.dialPWPins[0] != pinFP {
		t.Fatalf("dial pins %q, want the first pinned to %s", tr.dialPWPins, pinFP)
	}
	if res.HostKeyFingerprint != pinFP {
		t.Errorf("reported %q", res.HostKeyFingerprint)
	}
}

// H2: a fresh target, the pubkey install is pinned, and the roster holds
// exactly the pin.
func TestRun_HostKeyPin_FreshInstall(t *testing.T) {
	path := newTestRoster(t, "")
	opts := baseOptions(path)
	opts.HostKeyFingerprint = pinFP
	tr := &fakeTransport{installFingerprint: "SHA256:captured", session: &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("s"), ExitCode: 0}},
	}}}
	if _, err := Run(context.Background(), opts, tr, &fakeValidator{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !reflect.DeepEqual(tr.installPins, []string{pinFP}) {
		t.Fatalf("install pins %q", tr.installPins)
	}
	if b := string(rosterBytes(t, path)); !strings.Contains(b, `host_key_fingerprint = "`+pinFP+`"`) {
		t.Errorf("the roster does not hold the pin:\n%s", b)
	}
	// Without the flag: trust on first use, as before.
	path = newTestRoster(t, "")
	tr = &fakeTransport{installFingerprint: "SHA256:captured", session: &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("s"), ExitCode: 0}},
	}}}
	if _, err := Run(context.Background(), baseOptions(path), tr, &fakeValidator{}); err != nil || !reflect.DeepEqual(tr.installPins, []string{""}) {
		t.Fatalf("no flag: %v, pins %q", err, tr.installPins)
	}
}

// H3: a target already pinned: the same pin reconnects; another is refused
// before anything is dialed.
func TestRun_HostKeyPin_ExistingTarget(t *testing.T) {
	path := newTestRoster(t, "")
	session := func() *fakeSession {
		return &fakeSession{byCmd: map[string]fakeRunResult{"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("s"), ExitCode: 0}}}}
	}
	if _, err := Run(context.Background(), baseOptions(path), &fakeTransport{installFingerprint: pinFP, session: session()}, &fakeValidator{}); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	other := "SHA256:" + strings.Repeat("Q", 43)
	opts := baseOptions(path)
	opts.HostKeyFingerprint = other
	tr := &fakeTransport{session: session()}
	_, err := Run(context.Background(), opts, tr, &fakeValidator{})
	if err == nil || !strings.Contains(err.Error(), "--host-key-fingerprint "+other+" is not the host key this target is pinned to ("+pinFP+"); nothing was dialed") {
		t.Fatalf("another pin: %v", err)
	}
	if tr.reconnectCalls != 0 || tr.installCalls != 0 || tr.dialPWCalls != 0 {
		t.Fatalf("dialed: reconnect %d install %d keyless %d", tr.reconnectCalls, tr.installCalls, tr.dialPWCalls)
	}
	opts.HostKeyFingerprint = pinFP
	tr = &fakeTransport{session: session()}
	if _, err := Run(context.Background(), opts, tr, &fakeValidator{}); err != nil || !reflect.DeepEqual(tr.reconnectedFingerprints, []string{pinFP}) {
		t.Fatalf("the same pin: %v, reconnected %q", err, tr.reconnectedFingerprints)
	}
}

// H4: a malformed pin is refused before anything is dialed.
func TestRun_HostKeyPin_Malformed(t *testing.T) {
	for _, bad := range []string{"SHA256:abc", "MD5:12:34", "256 " + pinFP + " root@h (ED25519)", pinFP + " "} {
		path := newTestRoster(t, "")
		opts := baseOptions(path)
		opts.HostKeyFingerprint = bad
		tr := &fakeTransport{installFingerprint: pinFP}
		_, err := Run(context.Background(), opts, tr, &fakeValidator{})
		if err == nil || !strings.Contains(err.Error(), "--host-key-fingerprint") || tr.installCalls+tr.dialPWCalls+tr.reconnectCalls != 0 {
			t.Errorf("%q: %v, calls install %d keyless %d reconnect %d", bad, err, tr.installCalls, tr.dialPWCalls, tr.reconnectCalls)
		}
	}
}

// H5: keyless root access (user/group/acl/access inventory --no-ssh-key)
// dials with the operator's pin.
func TestRootAccess_KeylessDialIsPinned(t *testing.T) {
	tr := &fakeTransport{session: &fakeSession{}, dialPWFingerprint: "SHA256:captured"}
	a := NewRootAccess(AccessOptions{Addr: "h:22", HostKeyFingerprint: pinFP, Password: func(context.Context) (string, error) { return "pw", nil }}, tr)
	defer func() { _ = a.Close() }()
	if _, err := a.root(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tr.dialPWPins, []string{pinFP}) {
		t.Errorf("pins %q", tr.dialPWPins)
	}
}
