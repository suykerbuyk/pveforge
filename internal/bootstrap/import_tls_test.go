package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

// T3: import-token and TLS pins.

func importInsecure(t *testing.T, flag bool) ImportOptions {
	t.Helper()
	o := importOpts(importRoster(t), "ops@pve!ci", "s3cr3t-0001")
	o.InsecureTLS = flag
	return o
}

// R3: the rule reads the ROSTER's insecure_tls, not only the flag.
func TestCheckImportTLS_ReadsTheRoster(t *testing.T) {
	o := importInsecure(t, false)
	if err := roster.AppendTarget(o.RosterPath, roster.Target{ID: o.TargetID, Host: o.Host, Node: o.Node, InsecureTLS: true}); err != nil {
		t.Fatal(err)
	}
	if err := CheckImportTLS(o); !errors.Is(err, pve.ErrTLSPinRequired) || !strings.Contains(err.Error(), "--expect") || !strings.Contains(err.Error(), o.RosterPath) {
		t.Fatalf("an existing insecure target, no flag: err = %v", err)
	}
	o.Expect = fixedPin(1)
	if err := CheckImportTLS(o); err != nil {
		t.Fatalf("with --expect: %v", err)
	}
	// A new target: the flag alone decides; a CA target needs nothing.
	if err := CheckImportTLS(importInsecure(t, true)); !errors.Is(err, pve.ErrTLSPinRequired) {
		t.Fatalf("a new insecure target: err = %v", err)
	}
	if err := CheckImportTLS(importInsecure(t, false)); err != nil {
		t.Fatalf("a new CA-verified target: %v", err)
	}
}

// A new insecure target with --expect: validated THROUGH the pin, then the
// target, the pin (source expect) and the token are written, pin first.
func TestImport_ExpectPinsBeforeTheToken(t *testing.T) {
	o := importInsecure(t, true)
	o.Expect = fixedPin(2)
	var pinAtTokenWrite tlspin.Pin = "unset"
	orig := writeTokenAuthFn
	writeTokenAuthFn = func(path, target string, w roster.TokenWrite, pass roster.Passphrase) error {
		pinAtTokenWrite = rosterPin(t, path, target)
		return orig(path, target, w, pass)
	}
	t.Cleanup(func() { writeTokenAuthFn = orig })
	v := &importValidator{}
	res, err := Import(context.Background(), o, v)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if len(v.cfgs) != 1 || v.cfgs[0].TLSPin != o.Expect || !v.cfgs[0].InsecureTLS {
		t.Fatalf("validated with %+v, want through the --expect pin", v.cfgs)
	}
	if got := rosterTLS(t, o.RosterPath, o.TargetID); got == nil || tlspin.Pin(got.SPKISHA256) != o.Expect || got.Source != string(tlspin.SourceExpect) {
		t.Fatalf("[targets.tls] = %+v", got)
	}
	if pinAtTokenWrite != o.Expect {
		t.Fatalf("at the token write the roster pinned %q: the pin must be written first", pinAtTokenWrite)
	}
	if res.TLSPin != o.Expect || res.TLSPinSource != tlspin.SourceExpect || res.TokenOutcome != OutcomeImported {
		t.Fatalf("result %+v", res)
	}
}

// R2(b): the same token already held, and --expect for an unpinned target:
// the pin is written; success never leaves the target unpinned.
func TestImport_AlreadyHeldStillWritesThePin(t *testing.T) {
	o := importInsecure(t, true)
	o.Expect = fixedPin(3)
	if _, err := Import(context.Background(), o, &importValidator{}); err != nil {
		t.Fatal(err)
	}
	// Remove the pin by rewriting the roster without it, keeping the token:
	// the state an import from before T3 would leave.
	data, _ := os.ReadFile(o.RosterPath)
	i := bytes.Index(data, []byte("[targets.tls]"))
	j := bytes.Index(data[i:], []byte("\n["))
	stripped := append(append([]byte{}, data[:i]...), data[i+j+1:]...)
	if err := os.WriteFile(o.RosterPath, stripped, 0o600); err != nil {
		t.Fatal(err)
	}
	if rosterTLS(t, o.RosterPath, o.TargetID) != nil {
		t.Fatal("setup: the pin is still there")
	}
	res, err := Import(context.Background(), o, &importValidator{})
	if err != nil || res.TokenOutcome != OutcomeAlreadyHeld {
		t.Fatalf("%+v, %v", res, err)
	}
	if got := rosterTLS(t, o.RosterPath, o.TargetID); got == nil || tlspin.Pin(got.SPKISHA256) != o.Expect {
		t.Fatalf("already_held with --expect left the target unpinned: %+v", got)
	}
}

// R2(c): --expect equal to the stored pin writes nothing new.
func TestImport_ExpectEqualToTheStoredPinIsANoOp(t *testing.T) {
	o := importInsecure(t, true)
	o.Expect = fixedPin(4)
	if _, err := Import(context.Background(), o, &importValidator{}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(o.RosterPath)
	if res, err := Import(context.Background(), o, &importValidator{}); err != nil || res.TokenOutcome != OutcomeAlreadyHeld {
		t.Fatalf("%+v, %v", res, err)
	}
	if after, _ := os.ReadFile(o.RosterPath); !bytes.Equal(before, after) {
		t.Fatal("an equal --expect rewrote the roster")
	}
}

// R2(d): an --expect that differs from the stored pin is refused before
// any validation or write, naming the keyless reprovision.
func TestImport_ExpectConflictIsRefused(t *testing.T) {
	o := importInsecure(t, true)
	o.Expect = fixedPin(5)
	if _, err := Import(context.Background(), o, &importValidator{}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(o.RosterPath)
	o.Expect = fixedPin(6)
	v := &importValidator{}
	_, err := Import(context.Background(), o, v)
	if !errors.Is(err, ErrTLSPinDiffers) || !strings.Contains(err.Error(), "--no-ssh-key --reprovisioned --host-key-fingerprint <the console value>") || !strings.Contains(err.Error(), "CONSOLE") {
		t.Fatalf("err = %v", err)
	}
	if len(v.cfgs) != 0 {
		t.Fatal("a conflicting --expect was validated")
	}
	if after, _ := os.ReadFile(o.RosterPath); !bytes.Equal(before, after) {
		t.Fatal("a refused import changed the roster")
	}
}

// A failed validation writes nothing, the --expect pin included.
func TestImport_FailedValidationWritesNoPin(t *testing.T) {
	o := importInsecure(t, true)
	o.Expect = fixedPin(7)
	before, _ := os.ReadFile(o.RosterPath)
	if _, err := Import(context.Background(), o, &importValidator{errs: []error{ErrScopeTooWide}}); err == nil {
		t.Fatal("a refused token was imported")
	}
	if after, _ := os.ReadFile(o.RosterPath); !bytes.Equal(before, after) {
		t.Fatalf("a failed import wrote the roster:\n%s", after)
	}
}

// Import applies the rule itself (under its lock), not only its caller.
func TestImport_RefusesAnUnpinnedInsecureTarget(t *testing.T) {
	o := importInsecure(t, true)
	v := &importValidator{}
	if _, err := Import(context.Background(), o, v); !errors.Is(err, pve.ErrTLSPinRequired) || len(v.cfgs) != 0 {
		t.Fatalf("err = %v, validations %d", err, len(v.cfgs))
	}
}

// The same for a target the roster already holds (unpinned, no token): a
// pin written before the validation would land here, so nothing may.
func TestImport_FailedValidationWritesNoPin_ExistingTarget(t *testing.T) {
	o := importInsecure(t, true)
	o.Expect = fixedPin(8)
	if err := roster.AppendTarget(o.RosterPath, roster.Target{ID: o.TargetID, Host: o.Host, Node: o.Node, InsecureTLS: true}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(o.RosterPath)
	if _, err := Import(context.Background(), o, &importValidator{errs: []error{ErrScopeTooWide}}); err == nil {
		t.Fatal("a refused token was imported")
	}
	if after, _ := os.ReadFile(o.RosterPath); !bytes.Equal(before, after) {
		t.Fatalf("a failed import wrote the roster:\n%s", after)
	}
}
