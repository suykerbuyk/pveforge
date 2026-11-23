package bootstrap

// Family S5 package-level write-gate fixtures (contract plan 3.5, AC-W3/W5):
// the function-valued roster writer (F-A), the key removal's write mark (F-B),
// and the refusal sites whose exit class must follow the gate STATE and
// nothing else.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/dispatch"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// s5RosterSnap is the roster snapshot log: sha256 of every file beside the
// roster that is not local bookkeeping (<roster>.lock, <roster>.locks/).
func s5RosterSnap(t *testing.T, rosterPath string) map[string]string {
	t.Helper()
	dir := filepath.Dir(rosterPath)
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	snap := map[string]string{}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || strings.HasSuffix(n, ".lock") || strings.HasSuffix(n, ".locks") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		snap[n] = hex.EncodeToString(s[:])
	}
	if len(snap) == 0 {
		t.Fatal("vacuous roster snapshot")
	}
	return snap
}

func s5Changed(a, b map[string]string) []string {
	var d []string
	for k, v := range a {
		if b[k] != v {
			d = append(d, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			d = append(d, k)
		}
	}
	sort.Strings(d)
	return d
}

const s5ImportSeed = "[[targets]]\nid = \"qa-imp\"\nhost = \"h.example\"\nnode = \"n1\"\n"

// F-A. writeTokenAuthFn is a function-valued roster writer: the census sees it
// only as a reference, so its dispatch.Open (immediately before the invocation
// in Import) is pinned HERE, by behaviour. The read-back fails AFTER the token
// write: the error is not a refusal (it would be exit 4 in a run whose gate is
// closed), the roster really changed, and the gate agrees with the snapshot.
// Refused-before-write twin: a verdict before the write is a refusal, with the
// roster untouched and the gate closed.
func TestS5Import_FA_ReadBackFailureAfterTheTokenWriteIsNotARefusal(t *testing.T) {
	newRoster := func(t *testing.T) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "roster.toml")
		if err := os.WriteFile(p, []byte(s5ImportSeed), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Run("post-write: the read-back fails", func(t *testing.T) {
		rp := newRoster(t)
		orig := writeTokenAuthFn
		writeTokenAuthFn = func(path, target string, w roster.TokenWrite, pass roster.Passphrase) error {
			w.SecretPlaintext = []byte("not-what-was-imported")
			return orig(path, target, w, pass)
		}
		t.Cleanup(func() { writeTokenAuthFn = orig })
		ctx, _ := dispatch.With(context.Background())
		before := s5RosterSnap(t, rp)
		_, err := Import(ctx, importOpts(rp, "ops@pve!ci", "s3cr3t-0001"), &importValidator{})
		changed := s5Changed(before, s5RosterSnap(t, rp))
		if err == nil || !strings.Contains(err.Error(), "did not read back") {
			t.Fatalf("Import = %v, want the read-back failure", err)
		}
		if len(changed) == 0 {
			t.Fatal("vacuous: the token write did not change the roster")
		}
		if !dispatch.Opened(ctx) {
			t.Fatalf("the roster changed (%q) but the write gate stayed closed: writeTokenAuthFn's dispatch.Open is missing", changed)
		}
		if dispatch.IsRefused(err) {
			t.Fatalf("a read-back failure AFTER the write is marked as a refusal (exit 4): %v", err)
		}
	})
	t.Run("pre-write: a verdict is a refusal, the roster untouched, the gate closed", func(t *testing.T) {
		rp := newRoster(t)
		ctx, _ := dispatch.With(context.Background())
		before := s5RosterSnap(t, rp)
		_, err := Import(ctx, importOpts(rp, "ops@pve!ci", "s3cr3t-0001"), &importValidator{errs: []error{ErrScopeTooWide}})
		if err == nil || !errors.Is(err, ErrScopeTooWide) || !dispatch.IsRefused(err) {
			t.Fatalf("Import = %v, want ErrScopeTooWide marked as a refusal", err)
		}
		if d := s5Changed(before, s5RosterSnap(t, rp)); len(d) != 0 || dispatch.Opened(ctx) {
			t.Fatalf("a refusal wrote: changed %q, gate %v", d, dispatch.Opened(ctx))
		}
	})
}

// F-B. dropKeyOver removes the key this run installed. The removal is a
// root-SSH write. cleanupCtx (context.WithoutCancel) keeps the run's values, the
// write gate among them, but never sets the write mark (readToken reads through
// it), so the mark is applied at the call site, after cleanupCtx. The session's own write log (by command
// text) and its record of writes that arrived unmarked make a lost mark
// observable; the unobserved-removal case shows what the mark is FOR: a
// removal that was sent and timed out is an unobserved dispatch (exit 3).
func TestS5DropKeyOver_FB_TheKeyRemovalCarriesTheWriteMark(t *testing.T) {
	line := "ssh-ed25519 AAAAC3 pveforge@qa-test"
	run := func(t *testing.T, s *fakeSession) (error, context.Context) {
		t.Helper()
		ctx, _ := dispatch.With(context.Background())
		r := &runner{ctx: ctx, opts: Options{Host: "h"}}
		return r.dropKeyOver(s, errors.New("the capture refused"), "root", line), ctx
	}
	t.Run("removed", func(t *testing.T) {
		s := &fakeSession{}
		answerRemoval(s, removedOK)
		err, ctx := run(t, s)
		if err == nil || len(removals(s)) != 1 {
			t.Fatalf("err %v removals %q", err, removals(s))
		}
		if len(s.writeLog) != 1 || len(s.unmarkedWrites) != 0 {
			t.Fatalf("writes %q, UNMARKED %q: the key removal lost sshexec.WithWrite", s.writeLog, s.unmarkedWrites)
		}
		if !dispatch.Opened(ctx) {
			t.Fatal("the key removal was sent but the gate stayed closed")
		}
	})
	t.Run("sent and timed out: unobserved", func(t *testing.T) {
		s := &fakeSession{}
		answerRemoval(s, fakeRunResult{err: &sshexec.CommandTimeoutError{Cmd: "sh"}})
		err, _ := run(t, s)
		if err == nil || !dispatch.IsUnobserved(err) {
			t.Fatalf("a timed-out key removal is not an unobserved dispatch: %v", err)
		}
		if len(s.unmarkedWrites) != 0 {
			t.Fatalf("UNMARKED writes %q", s.unmarkedWrites)
		}
	})
}

// The refusal sites inside bootstrap follow the gate STATE. Each row runs the
// same site twice: with the run's gate closed (a refusal, exit 4) and with it
// opened first (the same error, plain: exit 1). A read failure is neither.
func TestS5Preflight_RefusalsFollowTheGateState(t *testing.T) {
	type row struct {
		name  string
		sess  *fakeSession
		opts  func(*Options)
		want  []Grant
		owner ownerReader
		is    error
	}
	rolesWithoutPrivs := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum role list": {res: RunResult{Stdout: `[{"privs":"","roleid":"PVEVMAdmin","special":1}]`}},
	}}
	rows := []row{
		{name: "unknown role", sess: &fakeSession{}, want: []Grant{{Path: "/", Role: "NoSuchRole"}}, is: ErrUnknownRole},
		{name: "role without privileges", sess: rolesWithoutPrivs, is: ErrRoleHasNoPrivileges},
		{name: "pinned privileges mismatch", sess: &fakeSession{}, want: []Grant{{Path: "/", Role: "PVEVMAdmin", Privs: []string{"VM.Audit"}}}, is: ErrPinnedPrivsMismatch},
		{name: "unknown node", sess: &fakeSession{}, opts: func(o *Options) { o.Node = "elsewhere" }, is: ErrUnknownNode},
		{name: "owner disabled", sess: &fakeSession{}, opts: func(o *Options) { o.TokenOwner = "ops@pve" }, owner: s5Owner{active: false}, is: ErrOwnerDisabled},
	}
	for _, r := range rows {
		for _, open := range []bool{false, true} {
			name := r.name + "/gate closed"
			if open {
				name = r.name + "/after a write"
			}
			t.Run(name, func(t *testing.T) {
				ctx, _ := dispatch.With(context.Background())
				if open {
					dispatch.Open(ctx)
				}
				opts := baseOptions(filepath.Join(t.TempDir(), "roster.toml"))
				opts.Node = "qa-pve-01"
				if r.opts != nil {
					r.opts(&opts)
				}
				want := r.want
				if want == nil {
					want = opts.Grants
				}
				var owner ownerReader = s5Owner{active: true}
				if r.owner != nil {
					owner = r.owner
				}
				_, err := preflight(ctx, r.sess, opts, want, owner)
				if err == nil || !errors.Is(err, r.is) {
					t.Fatalf("preflight = %v, want %v", err, r.is)
				}
				if got := dispatch.IsRefused(err); got == open {
					t.Fatalf("gate open=%v but IsRefused=%v: the exit class must follow the gate state", open, got)
				}
			})
		}
	}
	for _, open := range []bool{false, true} {
		t.Run("a role-list READ failure is never a refusal/open="+map[bool]string{false: "no", true: "yes"}[open], func(t *testing.T) {
			ctx, _ := dispatch.With(context.Background())
			if open {
				dispatch.Open(ctx)
			}
			s := &fakeSession{byCmd: map[string]fakeRunResult{"pveum role list": {err: errors.New("connection reset")}}}
			_, err := preflight(ctx, s, baseOptions(filepath.Join(t.TempDir(), "roster.toml")), baseOptions("").Grants, s5Owner{active: true})
			if err == nil || dispatch.IsRefused(err) {
				t.Fatalf("preflight = %v (refused %v), want a plain read failure", err, dispatch.IsRefused(err))
			}
		})
	}
}

// s5Owner is an ownerReader answering one activity verdict.
type s5Owner struct{ active bool }

func (o s5Owner) ownerActive(context.Context, string) (bool, error) { return o.active, nil }
func (o s5Owner) ownerPerms(context.Context, string, string) (map[string]bool, error) {
	return map[string]bool{}, nil
}

// capturePin's own refusals (a failed capture command, an unparseable
// certificate, an address that serves another key) are raised through
// dispatch.Refuse: 4 while the gate is closed (a keyless or stored-key run), 1
// after a key install; a transport failure of the capture command is neither.
func TestS5CapturePin_RefusalsFollowTheGateState(t *testing.T) {
	for _, open := range []bool{false, true} {
		for _, name := range []string{"nonzero exit", "garbage output"} {
			t.Run(name+map[bool]string{false: "/closed", true: "/open"}[open], func(t *testing.T) {
				ctx, _ := dispatch.With(context.Background())
				if open {
					dispatch.Open(ctx)
				}
				res := RunResult{ExitCode: 1}
				if name == "garbage output" {
					res = RunResult{Stdout: "not a certificate"}
				}
				s := &fakeSession{byCmd: map[string]fakeRunResult{"openssl s_client": {res: res}}}
				_, err := capturePin(ctx, s, &importValidator{}, "h", 8006, 0, false)
				if err == nil || !errors.Is(err, ErrTLSCapture) {
					t.Fatalf("capturePin = %v, want ErrTLSCapture", err)
				}
				if dispatch.IsRefused(err) == open {
					t.Fatalf("gate open=%v IsRefused=%v", open, dispatch.IsRefused(err))
				}
			})
		}
	}
	t.Run("the capture command failing to run is a read failure, never refused", func(t *testing.T) {
		ctx, _ := dispatch.With(context.Background())
		s := &fakeSession{byCmd: map[string]fakeRunResult{"openssl s_client": {err: errors.New("session lost")}}}
		_, err := capturePin(ctx, s, &importValidator{}, "h", 8006, 0, false)
		if err == nil || dispatch.IsRefused(err) {
			t.Fatalf("capturePin = %v refused=%v", err, dispatch.IsRefused(err))
		}
	})
}

// ---- isolating each roster writer's own dispatch.Open ----------------------
//
// In most bootstrap runs a key install (or a token command) precedes the
// roster write and has already opened the gate, so the gate-vs-roster agreement
// cannot see a roster writer whose own Open was deleted. These fixtures
// isolate ONE writer: the install is made quiet (fakeTransport.quietInstall:
// it is not counted as a write here, the writer under test is the only thing
// that changes anything) or absent (stored-key modes), and the run is ended by a
// READ failure straight after the writer (the role list), so nothing else can
// open the gate. The assertion is the three-log agreement on the roster log:
// the gate is open iff the roster changed.
func s5Isolated(t *testing.T, rosterPath string, opts Options, tr *fakeTransport, v *fakeValidator, session *fakeSession, mode string) {
	t.Helper()
	if session.byCmd == nil {
		session.byCmd = map[string]fakeRunResult{}
	}
	if mode == "roleListFails" {
		session.byCmd["pveum role list"] = fakeRunResult{err: errors.New("role list: connection reset")}
	}
	ctx, _ := dispatch.With(context.Background())
	before := s5RosterSnap(t, rosterPath)
	_, err := Run(ctx, opts, tr, v)
	changed := s5Changed(before, s5RosterSnap(t, rosterPath))
	if mode == "succeeds" && err != nil {
		t.Fatalf("Run = %v", err)
	}
	if mode != "succeeds" && (err == nil || dispatch.IsRefused(err)) {
		t.Fatalf("Run = %v, want the plain failure that ends the run after the writer", err)
	}
	if len(session.writeLog) != 0 && !session.quietWrites {
		t.Fatalf("host writes %q: the fixture is not isolating the roster writer", session.writeLog)
	}
	if len(changed) == 0 {
		t.Fatal("vacuous: the writer under test changed nothing")
	}
	if !dispatch.Opened(ctx) {
		t.Fatalf("the roster changed (%q) but the write gate stayed closed: that writer's dispatch.Open is missing", changed)
	}
}

func TestS5RosterWriters_EachOpensTheGateItself(t *testing.T) {
	t.Run("SSH-auth persist (writeSSHAuthFn)", func(t *testing.T) {
		rp := newTestRoster(t, "")
		opts := baseOptions(rp)
		if err := roster.AppendTarget(rp, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node}); err != nil {
			t.Fatal(err)
		}
		session := &fakeSession{}
		tr := &fakeTransport{session: session, installFingerprint: testHostKey, quietInstall: true}
		s5Isolated(t, rp, opts, tr, &fakeValidator{}, session, "roleListFails")
	})
	t.Run("ReplaceSSHAuth (a keyful reprovision)", func(t *testing.T) {
		old := newCapturePair(t)
		rp, opts := rebuiltKeyful(t, old)
		session := &fakeSession{}
		v := &fakeValidator{}
		scriptCapture(session, v, old) // the TLS key did not change: only the SSH block is replaced
		tr := &fakeTransport{session: session, installFingerprint: newHostKey, quietInstall: true}
		s5Isolated(t, rp, opts, tr, v, session, "roleListFails")
	})
	t.Run("WriteTLSPin, first pin (stored-key capture)", func(t *testing.T) {
		rp, opts := sshTarget(t, true, "")
		session := &fakeSession{}
		v := &fakeValidator{}
		scriptCapture(session, v, newCapturePair(t))
		s5Isolated(t, rp, opts, &fakeTransport{session: session}, v, session, "roleListFails")
	})
	t.Run("WriteTLSPin, replaced pin (stored-key reprovision)", func(t *testing.T) {
		old := newCapturePair(t)
		rp, opts := sshTarget(t, true, old.pin)
		opts.Reprovisioned, opts.HostKeyFingerprint = true, testHostKey
		session := &fakeSession{}
		v := &fakeValidator{}
		scriptCapture(session, v, newCapturePair(t))
		s5Isolated(t, rp, opts, &fakeTransport{session: session}, v, session, "roleListFails")
	})
	t.Run("AppendTarget (ensureTargetExists)", func(t *testing.T) {
		rp := newTestRoster(t, "")
		opts := baseOptions(rp)
		opts.NoSSHKey = true
		session := &fakeSession{}
		tr := &fakeTransport{session: session, dialPWErr: errors.New("connection refused")}
		// the run ends at the password dial, right after the target was appended
		ctx, _ := dispatch.With(context.Background())
		before := s5RosterSnap(t, rp)
		_, err := Run(ctx, opts, tr, &fakeValidator{})
		if err == nil {
			t.Fatalf("Run = %v", err)
		}
		changed := s5Changed(before, s5RosterSnap(t, rp))
		if len(changed) == 0 {
			t.Fatal("vacuous: the target was not appended")
		}
		if !dispatch.Opened(ctx) {
			t.Fatalf("the roster changed (%q) but the gate stayed closed: ensureTargetExists's dispatch.Open is missing", changed)
		}
		if dispatch.IsRefused(err) {
			t.Fatalf("the dial failure AFTER the target append is marked as a refusal (exit 4): %v", err)
		}
	})
	// The token writers: their funnel (the token commands) is made quiet, and the
	// meta write stubbed out, so each roster writer's own Open is the only opener.
	quietToken := func(t *testing.T) (string, Options) {
		t.Helper()
		orig := persistTargetMetaFn
		persistTargetMetaFn = func(context.Context, Options) error { return nil }
		t.Cleanup(func() { persistTargetMetaFn = orig })
		return sshTarget(t, false, "")
	}
	t.Run("WriteTokenAuth (the mint path)", func(t *testing.T) {
		rp, opts := quietToken(t)
		session := &fakeSession{quietWrites: true, pve: newFakePVE()}
		s5Isolated(t, rp, opts, &fakeTransport{session: session}, &fakeValidator{}, session, "succeeds")
	})
	t.Run("ClearTokenAuth (the held token replaced, tokenPhase)", func(t *testing.T) {
		rp, opts := quietToken(t)
		if err := roster.WriteTokenAuth(rp, opts.TargetID, roster.TokenWrite{TokenID: "root@pam!pveforge", SecretPlaintext: []byte("held-secret")}, opts.Passphrase); err != nil {
			t.Fatal(err)
		}
		session := &fakeSession{quietWrites: true, pve: newFakePVE("pveforge"), byCmd: map[string]fakeRunResult{
			"pveum user token add": {err: errors.New("add failed")}, // ends the run right after the clear
		}}
		s5Isolated(t, rp, opts, &fakeTransport{session: session}, &fakeValidator{errs: []error{ErrWrongScope}}, session, "fails")
	})
	t.Run("ClearTokenAuth (priorUnknown)", func(t *testing.T) {
		rp, opts := quietToken(t)
		if err := roster.WriteTokenAuth(rp, opts.TargetID, roster.TokenWrite{TokenID: "root@pam!pveforge", SecretPlaintext: []byte("held-secret")}, opts.Passphrase); err != nil {
			t.Fatal(err)
		}
		session := &fakeSession{quietWrites: true, pve: newFakePVE("pveforge"), byCmd: map[string]fakeRunResult{
			"pveum user token remove": {err: &sshexec.CommandTimeoutError{Cmd: "pveum"}},
		}}
		s5Isolated(t, rp, opts, &fakeTransport{session: session}, &fakeValidator{errs: []error{ErrWrongScope}}, session, "fails")
	})
	t.Run("UpdateTargetFields (persistTargetMeta on the reuse path)", func(t *testing.T) {
		rp, opts := sshTarget(t, false, "")
		if err := roster.WriteTokenAuth(rp, opts.TargetID, roster.TokenWrite{TokenID: "root@pam!pveforge", SecretPlaintext: []byte("held-secret")}, opts.Passphrase); err != nil {
			t.Fatal(err)
		}
		opts.APIPort = 8443 // differs from the roster: the meta write is the only change
		session := &fakeSession{pve: newFakePVE("pveforge")}
		s5Isolated(t, rp, opts, &fakeTransport{session: session}, &fakeValidator{}, session, "succeeds")
	})
}

// Import's TLS-pin writer, isolated the same way: the target already holds the
// very token being imported, so the pin (--expect) is the only roster write.
func TestS5Import_TheTLSPinWriteOpensTheGateItself(t *testing.T) {
	rp := importRoster(t)
	if _, err := Import(context.Background(), importOpts(rp, "ops@pve!ci", "s3cr3t-0001"), &importValidator{}); err != nil {
		t.Fatal(err)
	}
	opts := importOpts(rp, "ops@pve!ci", "s3cr3t-0001")
	cp := newCapturePair(t)
	opts.Expect = cp.pin
	ctx, _ := dispatch.With(context.Background())
	before := s5RosterSnap(t, rp)
	res, err := Import(ctx, opts, &importValidator{})
	changed := s5Changed(before, s5RosterSnap(t, rp))
	if err != nil || res.TokenOutcome != OutcomeAlreadyHeld {
		t.Fatalf("Import = %+v, %v; want already_held", res, err)
	}
	if len(changed) == 0 || !dispatch.Opened(ctx) {
		t.Fatalf("the pin write changed %q and the gate opened=%v: Import's WriteTLSPin dispatch.Open is missing", changed, dispatch.Opened(ctx))
	}
}

// Run's own option refusal (no grant: bootstrap fails closed) is raised before
// the roster is read, the lock taken or anything dialed: a refusal, with the
// gate closed and no host command sent. (The CLI refuses earlier still, in
// ParseGrants; this pins the library site.)
func TestS5Run_NoGrantIsRefusedBeforeAnything(t *testing.T) {
	rp := newTestRoster(t, "")
	opts := baseOptions(rp)
	opts.Grants = nil
	session := &fakeSession{}
	tr := &fakeTransport{session: session}
	ctx, _ := dispatch.With(context.Background())
	before := s5RosterSnap(t, rp)
	_, err := Run(ctx, opts, tr, &fakeValidator{})
	if err == nil || !dispatch.IsRefused(err) {
		t.Fatalf("Run = %v, want a refusal", err)
	}
	if d := s5Changed(before, s5RosterSnap(t, rp)); len(d) != 0 || dispatch.Opened(ctx) || len(session.writeLog) != 0 || tr.installCalls != 0 {
		t.Fatalf("a refusal wrote: roster %q gate %v host %q installs %d", d, dispatch.Opened(ctx), session.writeLog, tr.installCalls)
	}
}
