package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// TestRun_WrongRosterPassphraseRefusedBeforeAnyDial: Run proves the roster
// passphrase itself, whoever called it — here with a passphrase no CLI
// proved. A new target's bootstrap into a roster whose other target holds a
// token sealed under another passphrase is ErrWrongPassphrase before any
// dial or pveum command, and the roster is exactly as it was once the new
// target's plaintext stub is set aside (ensureTargetExists runs first, as a
// plain roster read/append that decrypts nothing).
func TestRun_WrongRosterPassphraseRefusedBeforeAnyDial(t *testing.T) {
	path, opts := keylessRoster(t, "root@pam!pveforge") // its target holds a token under "roster-pass"
	opts.TargetID = "qa-new"
	opts.NoSSHKey = true
	opts.Passphrase = roster.NewPassphrase("mistyped-pass")
	before, _ := os.ReadFile(path)
	session := &fakeSession{}
	tr := &fakeTransport{session: session, dialPWFingerprint: keylessFP}

	_, err := Run(context.Background(), opts, tr, &fakeValidator{})
	if !errors.Is(err, roster.ErrWrongPassphrase) {
		t.Fatalf("Run = %v, want ErrWrongPassphrase", err)
	}
	if tr.dialPWCalls+tr.dialCalls+tr.installCalls+tr.reconnectCalls != 0 || len(session.commands) != 0 {
		t.Fatalf("the target was contacted after a wrong passphrase: dials %d/%d/%d/%d, commands %q",
			tr.dialPWCalls, tr.dialCalls, tr.installCalls, tr.reconnectCalls, session.commands)
	}
	after, _ := os.ReadFile(path)
	if !bytes.HasPrefix(after, before) {
		t.Fatalf("the roster's existing bytes changed")
	}
	r, err := roster.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if tg := r.Find("qa-new"); tg != nil && (tg.Token != nil || tg.SSH != nil) {
		t.Errorf("a secret was written for the new target")
	}
}

// TestImport_WrongRosterPassphraseRefusedBeforeValidation: Import proves the
// passphrase itself, under its lock, whoever called it. A new target's
// import into a roster whose other target holds a token under another
// passphrase is ErrWrongPassphrase before the validator is called, and
// nothing is written.
func TestImport_WrongRosterPassphraseRefusedBeforeValidation(t *testing.T) {
	rp := importRoster(t)
	if _, err := Import(context.Background(), importOpts(rp, "ops@pve!ci", "s3cr3t-0001"), &importValidator{}); err != nil {
		t.Fatalf("seed Import: %v", err)
	}
	before, _ := os.ReadFile(rp)
	o := importOpts(rp, "ops@pve!other", "s3cr3t-0002")
	o.TargetID = "qa-other"
	o.Passphrase = roster.NewPassphrase("mistyped-pass")
	v := &importValidator{}
	_, err := Import(context.Background(), o, v)
	if !errors.Is(err, roster.ErrWrongPassphrase) {
		t.Fatalf("Import = %v, want ErrWrongPassphrase", err)
	}
	if len(v.cfgs) != 0 {
		t.Errorf("the validator was called %d time(s) after a wrong passphrase", len(v.cfgs))
	}
	if after, _ := os.ReadFile(rp); !bytes.Equal(before, after) {
		t.Errorf("the roster changed")
	}
}
