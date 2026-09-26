package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

func pinOpts(rosterPath string, opts Options) PinTLSOptions {
	return PinTLSOptions{TargetID: opts.TargetID, RosterPath: rosterPath, Passphrase: opts.Passphrase}
}

// keylessTarget holds a token and no SSH auth (a G4-shaped target).
func keylessTarget(t *testing.T, pin tlspin.Pin) (string, Options) {
	t.Helper()
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node, InsecureTLS: true}); err != nil {
		t.Fatal(err)
	}
	if err := roster.WriteTokenAuth(rosterPath, opts.TargetID, roster.TokenWrite{TokenID: "root@pam!pveforge", SecretPlaintext: []byte("s")}, opts.Passphrase); err != nil {
		t.Fatal(err)
	}
	if pin != "" {
		if err := roster.WriteTLSPin(rosterPath, opts.TargetID, "", pin, tlspin.SourceExpect, opts.Passphrase); err != nil {
			t.Fatal(err)
		}
	}
	return rosterPath, opts
}

func tokenBlock(t *testing.T, path string) string {
	t.Helper()
	data, _ := os.ReadFile(path)
	i := bytes.Index(data, []byte("[targets.token]"))
	if i < 0 {
		return ""
	}
	j := bytes.Index(data[i+1:], []byte("\n["))
	if j < 0 {
		return string(data[i:])
	}
	return string(data[i : i+1+j])
}

// A keyful target: captured over the session pinned to the stored host
// key, checked against the address, written ssh-stored; the token is
// untouched and no PVE command but the capture runs.
func TestPinTLS_KeyfulCapturesOverThePinnedSession(t *testing.T) {
	rosterPath, opts := sshTarget(t, true, "")
	if err := roster.WriteTokenAuth(rosterPath, opts.TargetID, roster.TokenWrite{TokenID: "root@pam!pveforge", SecretPlaintext: []byte("s")}, opts.Passphrase); err != nil {
		t.Fatal(err)
	}
	tokenBefore := tokenBlock(t, rosterPath)
	session := &fakeSession{}
	v := &fakeValidator{}
	cp := newCapturePair(t)
	scriptCapture(session, v, cp)
	tr := &fakeTransport{session: session}
	res, err := PinTLS(context.Background(), pinOpts(rosterPath, opts), tr, v)
	if err != nil {
		t.Fatalf("PinTLS: %v", err)
	}
	if !res.Written || res.Pin != cp.pin || res.Source != tlspin.SourceSSHStored || res.Previous != "" {
		t.Fatalf("result %+v", res)
	}
	if got := rosterTLS(t, rosterPath, opts.TargetID); got == nil || tlspin.Pin(got.SPKISHA256) != cp.pin || got.Source != string(tlspin.SourceSSHStored) {
		t.Fatalf("roster [targets.tls] = %+v", got)
	}
	if tokenBlock(t, rosterPath) != tokenBefore || tokenBefore == "" {
		t.Fatal("the token subtable changed")
	}
	if len(session.commands) != 1 || !strings.HasPrefix(session.commands[0], captureCmdPrefix) || v.calls != 0 || tr.reconnectCalls != 1 {
		t.Fatalf("commands %v, validations %d, reconnects %d; want only the capture, 0, 1", session.commands, v.calls, tr.reconnectCalls)
	}
	// Again: an equal pin is not a write.
	before, _ := os.ReadFile(rosterPath)
	session2 := &fakeSession{}
	scriptCapture(session2, v, cp)
	res, err = PinTLS(context.Background(), pinOpts(rosterPath, opts), &fakeTransport{session: session2}, v)
	if err != nil || res.Written || res.Previous != cp.pin {
		t.Fatalf("an equal pin: %+v, %v", res, err)
	}
	if after, _ := os.ReadFile(rosterPath); !bytes.Equal(before, after) {
		t.Fatal("an equal pin rewrote the roster")
	}
}

func TestPinTLS_KeyfulDiffersNeedsRepin(t *testing.T) {
	old := newCapturePair(t)
	rosterPath, opts := sshTarget(t, true, old.pin)
	before, _ := os.ReadFile(rosterPath)
	cp := newCapturePair(t)
	run := func(repin bool) (*PinTLSResult, error) {
		session := &fakeSession{}
		v := &fakeValidator{}
		scriptCapture(session, v, cp)
		o := pinOpts(rosterPath, opts)
		o.Repin = repin
		return PinTLS(context.Background(), o, &fakeTransport{session: session}, v)
	}
	if _, err := run(false); !errors.Is(err, ErrTLSPinDiffers) || !strings.Contains(err.Error(), "--repin") {
		t.Fatalf("without --repin: err = %v, want ErrTLSPinDiffers naming --repin", err)
	}
	if after, _ := os.ReadFile(rosterPath); !bytes.Equal(before, after) {
		t.Fatal("a refused pin-tls changed the roster")
	}
	res, err := run(true)
	if err != nil || !res.Written || res.Previous != old.pin || rosterPin(t, rosterPath, opts.TargetID) != cp.pin {
		t.Fatalf("with --repin: %+v, %v, roster pin %q", res, err, rosterPin(t, rosterPath, opts.TargetID))
	}
}

func TestPinTLS_KeylessNeedsExpect(t *testing.T) {
	rosterPath, opts := keylessTarget(t, "")
	tr := &fakeTransport{session: &fakeSession{}}
	v := &fakeValidator{}
	if _, err := PinTLS(context.Background(), pinOpts(rosterPath, opts), tr, v); err == nil || !strings.Contains(err.Error(), "--expect") {
		t.Fatalf("no --expect: err = %v", err)
	}
	cp := newCapturePair(t)
	// --expect that the address does not serve: refused, nothing written.
	o := pinOpts(rosterPath, opts)
	o.Expect = cp.pin
	v.served = newCapturePair(t).pin
	if _, err := PinTLS(context.Background(), o, tr, v); !errors.Is(err, ErrTLSPinMismatch) || rosterTLS(t, rosterPath, opts.TargetID) != nil {
		t.Fatalf("a mismatching --expect: err = %v, pin %+v", err, rosterTLS(t, rosterPath, opts.TargetID))
	}
	// The served key: written, source expect, no SSH at all.
	v.served = cp.pin
	res, err := PinTLS(context.Background(), o, tr, v)
	if err != nil || !res.Written || res.Source != tlspin.SourceExpect {
		t.Fatalf("a matching --expect: %+v, %v", res, err)
	}
	if got := rosterTLS(t, rosterPath, opts.TargetID); got == nil || tlspin.Pin(got.SPKISHA256) != cp.pin || got.Source != string(tlspin.SourceExpect) {
		t.Fatalf("roster %+v", got)
	}
	if tr.reconnectCalls+tr.dialCalls+tr.dialPWCalls+tr.installCalls != 0 {
		t.Fatal("a keyless pin-tls dialled SSH")
	}
	// A different key later: refused, and --repin cannot help a target
	// with no SSH auth.
	o.Expect = newCapturePair(t).pin
	v.served = o.Expect
	if _, err := PinTLS(context.Background(), o, tr, v); !errors.Is(err, ErrTLSPinDiffers) || strings.Contains(err.Error(), "--repin") {
		t.Fatalf("a different --expect: err = %v, want ErrTLSPinDiffers without --repin", err)
	}
	o.Repin = true
	if _, err := PinTLS(context.Background(), o, tr, v); err == nil || !strings.Contains(err.Error(), "needs SSH auth") {
		t.Fatalf("--repin on a keyless target: err = %v", err)
	}
}

func TestPinTLS_Refusals(t *testing.T) {
	rosterPath, opts := sshTarget(t, true, "")
	o := pinOpts(rosterPath, opts)
	o.Expect = fixedPin(1)
	if _, err := PinTLS(context.Background(), o, &fakeTransport{session: &fakeSession{}}, &fakeValidator{}); err == nil || !strings.Contains(err.Error(), "drop --expect") {
		t.Errorf("--expect on a keyful target: err = %v", err)
	}
	o.Expect = "sha256//x"
	if _, err := PinTLS(context.Background(), o, &fakeTransport{session: &fakeSession{}}, &fakeValidator{}); !errors.Is(err, tlspin.ErrMalformedPin) {
		t.Errorf("a malformed --expect: err = %v", err)
	}
	o = pinOpts(rosterPath, opts)
	o.TargetID = "nope"
	if _, err := PinTLS(context.Background(), o, &fakeTransport{session: &fakeSession{}}, &fakeValidator{}); err == nil || !strings.Contains(err.Error(), "no such target") {
		t.Errorf("an unknown target: err = %v", err)
	}
	// The address serves another key than the node: ErrTLSPinMismatch.
	session := &fakeSession{}
	v := &fakeValidator{}
	scriptCapture(session, v, newCapturePair(t))
	v.served = newCapturePair(t).pin
	if _, err := PinTLS(context.Background(), pinOpts(rosterPath, opts), &fakeTransport{session: session}, v); !errors.Is(err, ErrTLSPinMismatch) || rosterTLS(t, rosterPath, opts.TargetID) != nil {
		t.Errorf("address mismatch: err = %v", err)
	}
}

// --print writes nothing, whatever it finds.
func TestPinTLS_PrintWritesNothing(t *testing.T) {
	rosterPath, opts := sshTarget(t, true, "")
	before, _ := os.ReadFile(rosterPath)
	session := &fakeSession{}
	v := &fakeValidator{}
	cp := newCapturePair(t)
	scriptCapture(session, v, cp)
	o := pinOpts(rosterPath, opts)
	o.Print = true
	res, err := PinTLS(context.Background(), o, &fakeTransport{session: session}, v)
	if err != nil || res.Written || res.Pin != cp.pin || res.Source != tlspin.SourceSSHStored {
		t.Fatalf("--print: %+v, %v", res, err)
	}
	if after, _ := os.ReadFile(rosterPath); !bytes.Equal(before, after) {
		t.Fatal("--print changed the roster")
	}
}

// PinTLS holds the per-target bootstrap lock: while a bootstrap of the
// target holds it, a pin-tls waits, and gives up within its wait bound
// without writing; --print takes no lock and still runs.
func TestPinTLS_HoldsTheBootstrapLock(t *testing.T) {
	rosterPath, opts := keylessTarget(t, "")
	unlock, err := lock.Mutation(context.Background(), rosterPath, lock.ObjectKey{TargetID: opts.TargetID, Kind: "bootstrap", ID: "token"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unlock() }()
	cp := newCapturePair(t)
	v := &fakeValidator{served: cp.pin}
	o := pinOpts(rosterPath, opts)
	o.Expect = cp.pin
	ctx := lock.WithWait(context.Background(), 50*time.Millisecond)
	if _, err := PinTLS(ctx, o, &fakeTransport{session: &fakeSession{}}, v); err == nil || !strings.Contains(err.Error(), "acquire the per-target bootstrap lock") {
		t.Fatalf("with the lock held: err = %v, want the lock refusal", err)
	}
	if rosterTLS(t, rosterPath, opts.TargetID) != nil || v.servedCalls != 0 {
		t.Fatal("pin-tls proceeded without the lock")
	}
	o.Print = true
	if res, err := PinTLS(ctx, o, &fakeTransport{session: &fakeSession{}}, v); err != nil || res.Pin != cp.pin || res.Written {
		t.Fatalf("--print with the lock held: %+v, %v", res, err)
	}
}

// ---- The Chair's T1b review ----

// sshTargetAt is sshTarget with an API port and insecure_tls as given.
func sshTargetAt(t *testing.T, insecure bool, apiPort int) (string, Options) {
	t.Helper()
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node, APIPort: apiPort, InsecureTLS: insecure}); err != nil {
		t.Fatal(err)
	}
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := roster.WriteSSHAuth(rosterPath, opts.TargetID, roster.SSHWrite{User: "root", PublicKey: kp.AuthorizedKeyLine, HostKeyFingerprint: testHostKey, PrivateKeyPlaintext: kp.PrivateKeyPEM}, opts.Passphrase); err != nil {
		t.Fatal(err)
	}
	return rosterPath, opts
}

// (1) pin-tls probes the address REST will dial: the target's host and
// its api_port as REST reads it; (4b) the SSH dial uses RoutedClient's
// port when none is given.
func TestPinTLS_ProbesTheRESTAddressAndDialsTheRoutedSSHPort(t *testing.T) {
	for _, apiPort := range []int{0, 8443} {
		rosterPath, opts := sshTargetAt(t, true, apiPort)
		session := &fakeSession{}
		v := &fakeValidator{}
		scriptCapture(session, v, newCapturePair(t))
		tr := &fakeTransport{session: session}
		if _, err := PinTLS(context.Background(), pinOpts(rosterPath, opts), tr, v); err != nil {
			t.Fatalf("api port %d: %v", apiPort, err)
		}
		requireProbedTheRESTAddress(t, v, opts.Host, apiPort)
		if want := opts.Host + ":" + strconv.Itoa(pve.RoutedSSHPort()); len(tr.reconnectedAddrs) != 1 || tr.reconnectedAddrs[0] != want {
			t.Fatalf("api port %d: dialled %v, want %s", apiPort, tr.reconnectedAddrs, want)
		}
	}
}

// (3) A CA-verified target is pinned only explicitly, with --expect.
func TestPinTLS_CAVerifiedTargetNeedsExpect(t *testing.T) {
	rosterPath, opts := sshTargetAt(t, false, 0)
	tr := &fakeTransport{session: &fakeSession{}}
	v := &fakeValidator{}
	if _, err := PinTLS(context.Background(), pinOpts(rosterPath, opts), tr, v); err == nil || !strings.Contains(err.Error(), "pinned only explicitly") {
		t.Fatalf("no --expect: err = %v", err)
	}
	if tr.reconnectCalls != 0 || v.servedCalls != 0 || rosterTLS(t, rosterPath, opts.TargetID) != nil {
		t.Fatal("a CA-verified target was captured or pinned without --expect")
	}
	cp := newCapturePair(t)
	o := pinOpts(rosterPath, opts)
	o.Expect, v.served = cp.pin, cp.pin
	res, err := PinTLS(context.Background(), o, tr, v)
	if err != nil || !res.Written || res.Source != tlspin.SourceExpect || tr.reconnectCalls != 0 {
		t.Fatalf("with --expect: %+v, %v (ssh dials %d)", res, err, tr.reconnectCalls)
	}
	requireProbedTheRESTAddress(t, v, opts.Host, 0)
	o.Repin = true
	if _, err := PinTLS(context.Background(), o, tr, v); err == nil || !strings.Contains(err.Error(), "--repin needs") {
		t.Fatalf("--repin on a CA-verified target: err = %v", err)
	}
}

// (4a) An equal pin reports the source the roster recorded.
func TestPinTLS_EqualPinReportsTheRecordedSource(t *testing.T) {
	cp := newCapturePair(t)
	rosterPath, opts := keylessTarget(t, cp.pin) // recorded as expect
	session := &fakeSession{}
	v := &fakeValidator{}
	_ = session
	o := pinOpts(rosterPath, opts)
	o.Expect, v.served = cp.pin, cp.pin
	res, err := PinTLS(context.Background(), o, &fakeTransport{session: session}, v)
	if err != nil || res.Written || res.Source != tlspin.SourceExpect {
		t.Fatalf("%+v, %v", res, err)
	}
	// A keyful target first pinned by expect-style hand edit, now captured
	// over SSH: still the recorded source.
	rp2, o2 := sshTargetAt(t, true, 0)
	if err := roster.WriteTLSPin(rp2, o2.TargetID, "", cp.pin, tlspin.SourceSSHTOFU, o2.Passphrase); err != nil {
		t.Fatal(err)
	}
	s2 := &fakeSession{}
	v2 := &fakeValidator{}
	scriptCapture(s2, v2, cp)
	res, err = PinTLS(context.Background(), pinOpts(rp2, o2), &fakeTransport{session: s2}, v2)
	if err != nil || res.Written || res.Source != tlspin.SourceSSHTOFU {
		t.Fatalf("keyful, equal pin: %+v, %v; want the recorded ssh-tofu", res, err)
	}
}
