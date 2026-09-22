package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
)

// warningLines returns the stderr lines that start with "warning:".
func warningLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "warning:") {
			out = append(out, l)
		}
	}
	return out
}

func render(t *testing.T, f kvjson.Format, res *bootstrap.Result) (string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	if err := renderBootstrapResult(&out, &errOut, f, "qa-pve-01", res); err != nil {
		t.Fatalf("renderBootstrapResult: %v", err)
	}
	return out.String(), errOut.String()
}

// C1: every outcome renders in kv and json; optional keys are present only
// when set; validation is always shown.
func TestRenderBootstrapResult_C1_EveryOutcome(t *testing.T) {
	for name, tc := range map[string]struct {
		res     bootstrap.Result
		present []string
		absent  []string
	}{
		"minted":               {bootstrap.Result{TokenID: "root@pam!pveforge", TokenOutcome: bootstrap.OutcomeMinted, Validation: bootstrap.ValidationVerified}, nil, []string{"replaced_reason", "orphaned_token", "leftover_token", "leftover_state", "roster_token", "prior_token"}},
		"reused":               {bootstrap.Result{TokenID: "root@pam!pveforge", TokenOutcome: bootstrap.OutcomeReused, Validation: bootstrap.ValidationVerified}, nil, []string{"replaced_reason", "leftover_token"}},
		"replaced":             {bootstrap.Result{TokenID: "root@pam!pveforge", TokenOutcome: bootstrap.OutcomeReplaced, Validation: bootstrap.ValidationVerified, ReplacedReason: "no grants", PriorRevoked: true, RosterToken: bootstrap.RosterTokenCleared}, []string{"replaced_reason", "roster_token"}, []string{"leftover_token", "prior_token"}},
		"revoked_not_replaced": {bootstrap.Result{TokenID: "root@pam!pveforge", TokenOutcome: bootstrap.OutcomeRevokedNotReplaced, Validation: bootstrap.ValidationNotRun, LeftoverToken: "root@pam!pveforge", LeftoverState: bootstrap.LeftoverMayExist, PriorToken: bootstrap.PriorTokenUnknown}, []string{"leftover_token", "leftover_state", "prior_token"}, []string{"replaced_reason"}},
		"discarded":            {bootstrap.Result{TokenID: "root@pam!pveforge", TokenOutcome: bootstrap.OutcomeDiscarded, Validation: bootstrap.ValidationFailed}, nil, []string{"replaced_reason", "roster_token"}},
	} {
		t.Run(name, func(t *testing.T) {
			res := tc.res
			for _, f := range []kvjson.Format{kvjson.KV, kvjson.JSON} {
				out, _ := render(t, f, &res)
				var fields map[string]interface{}
				if f == kvjson.JSON {
					if err := json.Unmarshal([]byte(out), &fields); err != nil {
						t.Fatalf("json stdout does not parse: %v\n%s", err, out)
					}
				} else {
					fields = map[string]interface{}{}
					for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
						k, v, _ := strings.Cut(l, "=")
						fields[k] = v
					}
				}
				if fields["token_outcome"] != res.TokenOutcome || fields["validation"] != res.Validation || fields["target"] != "qa-pve-01" {
					t.Fatalf("%s: fields = %v", f, fields)
				}
				for _, k := range tc.present {
					if _, ok := fields[k]; !ok {
						t.Errorf("%s: %s missing: %v", f, k, fields)
					}
				}
				for _, k := range tc.absent {
					if _, ok := fields[k]; ok {
						t.Errorf("%s: %s present: %v", f, k, fields)
					}
				}
				for k := range fields {
					if strings.ContainsAny(k, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
						t.Errorf("%s: a Go field name leaked into the output: %q", f, k)
					}
				}
			}
		})
	}
}

// C1b: the two `replaced` variants carry different fixed warnings.
func TestRenderBootstrapResult_C1b_TwoReplacedWarnings(t *testing.T) {
	base := bootstrap.Result{TokenID: "root@pam!pveforge", TokenOutcome: bootstrap.OutcomeReplaced, Validation: bootstrap.ValidationVerified, ReplacedReason: "no grants"}
	after := base
	after.PriorRevoked = true
	_, e1 := render(t, kvjson.KV, &after)
	_, e2 := render(t, kvjson.KV, &base)
	if !strings.Contains(e1, "now revoked") || strings.Contains(e1, "nothing was revoked") {
		t.Fatalf("after a remove: %q", e1)
	}
	if !strings.Contains(e2, "nothing was revoked by this run") || strings.Contains(e2, "now revoked") {
		t.Fatalf("with no remove: %q", e2)
	}
}

// C1c: a leftover token is reported as its bare id, with its uncertainty
// in leftover_state, never as prose inside the id; and its warning claims no
// grant (a leftover from a failed parse or an ambiguous add has none).
func TestRenderBootstrapResult_C1c_LeftoverIDAndState(t *testing.T) {
	for state, want := range map[string]string{
		bootstrap.LeftoverExists:   "is still live on PVE",
		bootstrap.LeftoverMayExist: "may still be live on PVE",
	} {
		t.Run(state, func(t *testing.T) {
			res := bootstrap.Result{TokenID: "root@pam!pveforge", TokenOutcome: bootstrap.OutcomeDiscarded, Validation: bootstrap.ValidationNotRun, LeftoverToken: "root@pam!pveforge", LeftoverState: state}
			out, errOut := render(t, kvjson.KV, &res)
			lines := "\n" + out
			if !strings.Contains(lines, "\nleftover_token=root@pam!pveforge\n") || !strings.Contains(lines, "\nleftover_state="+state+"\n") {
				t.Fatalf("kv stdout: %q", out)
			}
			w := warningLines(errOut)
			if len(w) != 1 || !strings.Contains(w[0], want) || !strings.Contains(w[0], "secret was lost") {
				t.Fatalf("warnings: %v", w)
			}
			if strings.Contains(w[0], "grant") {
				t.Fatalf("the leftover warning claims a grant: %q", w[0])
			}
		})
	}
}

// C2: each warning appears on stderr only, lowercase, and only for its case;
// JSON stdout stays machine-clean.
func TestRenderBootstrapResult_C2_WarningsOnStderrOnly(t *testing.T) {
	cases := map[string]struct {
		res  bootstrap.Result
		want string
	}{
		"revoked":    {bootstrap.Result{TokenOutcome: bootstrap.OutcomeRevokedNotReplaced, Validation: bootstrap.ValidationNotRun}, "was revoked and NOT replaced"},
		"unverified": {bootstrap.Result{TokenOutcome: bootstrap.OutcomeMinted, Validation: bootstrap.ValidationUnverified}, "could not be verified"},
		"orphaned":   {bootstrap.Result{TokenOutcome: bootstrap.OutcomeMinted, Validation: bootstrap.ValidationVerified, OrphanedToken: "root@pam!old"}, "no longer held by this roster"},
		"leftover":   {bootstrap.Result{TokenOutcome: bootstrap.OutcomeDiscarded, Validation: bootstrap.ValidationFailed, LeftoverToken: "root@pam!x", LeftoverState: bootstrap.LeftoverExists}, "secret was lost"},
		"stale":      {bootstrap.Result{TokenOutcome: bootstrap.OutcomeDiscarded, Validation: bootstrap.ValidationNotRun, RosterToken: bootstrap.RosterTokenStaleAbsent}, "still holds token"},
		"clean":      {bootstrap.Result{TokenOutcome: bootstrap.OutcomeMinted, Validation: bootstrap.ValidationVerified}, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			res := tc.res
			res.TokenID = "root@pam!pveforge"
			out, errOut := render(t, kvjson.JSON, &res)
			if strings.Contains(out, "warning") {
				t.Fatalf("a warning reached stdout: %q", out)
			}
			var v map[string]interface{}
			if err := json.Unmarshal([]byte(out), &v); err != nil {
				t.Fatalf("stdout no longer parses: %v", err)
			}
			w := warningLines(errOut)
			if tc.want == "" {
				if len(w) != 0 {
					t.Fatalf("unexpected warnings: %v", w)
				}
				return
			}
			if len(w) != 1 || !strings.Contains(w[0], tc.want) {
				t.Fatalf("warnings = %v, want one containing %q", w, tc.want)
			}
		})
	}
}

// C3: -o comes from the shared addOutputFlag: default kv, identical usage.
func TestNewBootstrapCmd_C3_OutputFlagIsTheSharedOne(t *testing.T) {
	f := newBootstrapCmd().Flags().Lookup("output")
	if f == nil || f.Shorthand != "o" || f.DefValue != "kv" {
		t.Fatalf("output flag = %+v", f)
	}
	probe := &cobra.Command{Use: "probe"}
	_ = addOutputFlag(probe)
	ref := probe.Flags().Lookup("output")
	if ref.Usage != f.Usage {
		t.Fatalf("usage %q differs from addOutputFlag's %q", f.Usage, ref.Usage)
	}
}

// fakeBootstrapTransport fails the first-bootstrap pubkey install with the
// given error, and counts every call.
type fakeBootstrapTransport struct {
	installErr error
	calls      int
	// per-method counters: `calls` alone cannot tell the keyless dial from
	// the install path, which is what C-T8b has to observe.
	installCalls int
	pwCalls      int
}

func (f *fakeBootstrapTransport) InstallPubkeyViaPassword(context.Context, string, string, string, string) (string, error) {
	f.calls++
	f.installCalls++
	return "", f.installErr
}
func (f *fakeBootstrapTransport) DialWithKey(context.Context, string, string, []byte, string) (bootstrap.SSHSession, error) {
	f.calls++
	return nil, errors.New("unexpected dial")
}
func (f *fakeBootstrapTransport) ReconnectWithPinnedKey(context.Context, string, string, []byte, string) (bootstrap.SSHSession, error) {
	f.calls++
	return nil, errors.New("unexpected reconnect")
}

func (f *fakeBootstrapTransport) DialWithPassword(context.Context, string, string, string, string) (bootstrap.SSHSession, string, error) {
	f.calls++
	f.pwCalls++
	return nil, "", errors.New("unexpected keyless dial")
}

type nopValidator struct{}

func (nopValidator) ValidateTokenGrants(context.Context, bootstrap.APIConfig, []bootstrap.Grant) error {
	return nil
}

// withBootstrapFakes points the bootstrap command's seams at fakes.
func withBootstrapFakes(t *testing.T, tr *fakeBootstrapTransport) string {
	t.Helper()
	origT, origV := newBootstrapTransport, newBootstrapValidator
	newBootstrapTransport = func() bootstrap.SSHTransport { return tr }
	newBootstrapValidator = func() bootstrap.APIValidator { return nopValidator{} }
	t.Cleanup(func() { newBootstrapTransport, newBootstrapValidator = origT, origV })
	rosterPath := filepath.Join(t.TempDir(), "roster.toml")
	if err := os.WriteFile(rosterPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PVEFORGE_ROSTER", rosterPath)
	t.Setenv("PVEFORGE_ROSTER_PASSPHRASE", "test-roster-pass")
	t.Setenv(pvePasswordEnvVar, "test-pve-pass")
	return rosterPath
}

// C4: a bad -o is refused before anything else: the transport is never
// touched.
func TestNewBootstrapCmd_C4_BadOutputRefusedFirst(t *testing.T) {
	tr := &fakeBootstrapTransport{}
	withBootstrapFakes(t, tr)
	root := newRootCmd()
	root.SetArgs([]string{"bootstrap", "qa-test", "--host", "h", "--node", "n", "-o", "bogus"})
	var stderr bytes.Buffer
	if code := runRoot(root, &stderr); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stderr.String(), "bogus") || tr.calls != 0 {
		t.Fatalf("stderr = %q, transport calls = %d", stderr.String(), tr.calls)
	}
}

// C5: given a partial result and an error, the report is rendered and
// warned about, THEN the error is returned.
func TestFinishBootstrap_C5_RendersThenReturnsTheError(t *testing.T) {
	var out, errOut bytes.Buffer
	runErr := errors.New("the add failed")
	res := &bootstrap.Result{TokenID: "root@pam!pveforge", TokenOutcome: bootstrap.OutcomeRevokedNotReplaced, Validation: bootstrap.ValidationNotRun}
	if err := finishBootstrap(&out, &errOut, kvjson.KV, "qa-pve-01", res, runErr); err != runErr {
		t.Fatalf("returned %v, want the run's error", err)
	}
	if !strings.Contains(out.String(), "token_outcome=revoked_not_replaced") || len(warningLines(errOut.String())) != 1 {
		t.Fatalf("stdout = %q, stderr = %q", out.String(), errOut.String())
	}
}

// C6: an id read from a hand-edited roster cannot forge a warning line.
func TestRenderBootstrapResult_C6_ForgedIDStaysOneLine(t *testing.T) {
	res := &bootstrap.Result{TokenID: "root@pam!pveforge", TokenOutcome: bootstrap.OutcomeMinted, Validation: bootstrap.ValidationVerified, OrphanedToken: "A\nwarning: forged"}
	_, errOut := render(t, kvjson.KV, res)
	if w := warningLines(errOut); len(w) != 1 || !strings.Contains(w[0], `"A\nwarning: forged"`) {
		t.Fatalf("warnings = %q", w)
	}
}

// C7: a bootstrap failure whose error carries a line-forging text goes
// through the REAL print site (runRoot) as exactly one line, starting with
// a quote and decoding to the full text. (The failure is injected at the
// first-bootstrap pubkey install so no key derivation runs in this package.)
func TestBootstrap_C7_ErrorThroughRunRootIsOneLine(t *testing.T) {
	tr := &fakeBootstrapTransport{installErr: errors.New("ssh: x\nwarning: forged")}
	withBootstrapFakes(t, tr)
	root := newRootCmd()
	root.SetArgs([]string{"bootstrap", "qa-test", "--host", "h", "--node", "n", "--grant", "/:PVEVMAdmin::1"})
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	if code := runRoot(root, &stderr); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	lines := strings.Split(strings.TrimSuffix(stderr.String(), "\n"), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], `"`) {
		t.Fatalf("stderr = %q", stderr.String())
	}
	var decoded string
	if err := json.Unmarshal([]byte(lines[0]), &decoded); err != nil || !strings.Contains(decoded, "ssh: x\nwarning: forged") {
		t.Fatalf("decoded %q, %v", decoded, err)
	}
	if tr.calls != 1 {
		t.Fatalf("transport calls = %d, want the one failing install", tr.calls)
	}
}
