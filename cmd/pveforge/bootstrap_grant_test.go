package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
)

// seamCounts counts how often the bootstrap command constructs its
// transport and validator.
type seamCounts struct{ transport, validator int }

// withCountingSeams points the constructor seams at counting fakes, with NO
// roster passphrase and NO PVE password in the environment and a non-TTY
// stdin, so any prompt or secret resolution reached before the grant check
// fails with its own, distinguishable error.
func withCountingSeams(t *testing.T) *seamCounts {
	t.Helper()
	c := &seamCounts{}
	origT, origV := newBootstrapTransport, newBootstrapValidator
	newBootstrapTransport = func() bootstrap.SSHTransport { c.transport++; return &fakeBootstrapTransport{} }
	newBootstrapValidator = func() bootstrap.APIValidator { c.validator++; return nopValidator{} }
	t.Cleanup(func() { newBootstrapTransport, newBootstrapValidator = origT, origV })
	t.Setenv("PVEFORGE_ROSTER_PASSPHRASE", "")
	t.Setenv(pvePasswordEnvVar, "")
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	origStdin := os.Stdin
	os.Stdin = devnull
	t.Cleanup(func() { os.Stdin = origStdin; _ = devnull.Close() })
	return c
}

func runBootstrapArgs(t *testing.T, args ...string) (int, string) {
	t.Helper()
	root := newRootCmd()
	root.SetArgs(append([]string{"bootstrap", "qa-test", "--host", "h", "--node", "n"}, args...))
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	code := runRoot(root, &stderr)
	return code, stderr.String()
}

// A-T1c: with no --grant, the command fails on the grant — before the
// roster path, both secret prompts and the transport/validator are ever
// reached (R1).
//
// MUST STAY SERIAL: it swaps the process-wide os.Stdin. No test in this
// package calls t.Parallel(), and none may alongside this one.
func TestBootstrap_AT1c_NoGrantFailsBeforeAnyPromptOrSeam(t *testing.T) {
	c := withCountingSeams(t)
	code, stderr := runBootstrapArgs(t)
	if code == 0 {
		t.Fatal("exit 0 without a grant")
	}
	if !strings.Contains(stderr, "requires at least one --grant PATH:ROLE[:PRIVS[:PROPAGATE]]") ||
		strings.Contains(stderr, "passphrase") || strings.Contains(stderr, "PVE password") {
		t.Fatalf("stderr = %q, want the grant hint and no secret prompt", stderr)
	}
	if c.transport != 0 || c.validator != 0 {
		t.Fatalf("seams constructed: %+v", *c)
	}
}

// B-T8 (MB11): a --token-owner pveforge cannot own a token with fails
// before the roster path, both secret prompts and the seams — like a bad
// --grant. MUST STAY SERIAL (it swaps os.Stdin, via withCountingSeams).
func TestBootstrap_BT8_BadOwnerFailsBeforeAnyPromptOrSeam(t *testing.T) {
	c := withCountingSeams(t)
	code, stderr := runBootstrapArgs(t, "--grant", "/:PVEVMAdmin::1", "--token-owner", "a!b@pve")
	if code == 0 {
		t.Fatal("exit 0 with a bad --token-owner")
	}
	if !strings.Contains(stderr, "invalid token owner") ||
		strings.Contains(stderr, "passphrase") || strings.Contains(stderr, "PVE password") {
		t.Fatalf("stderr = %q, want the owner error and no secret prompt", stderr)
	}
	if c.transport != 0 || c.validator != 0 {
		t.Fatalf("seams constructed: %+v", *c)
	}
}

// A target id the roster would refuse (roster.ValidateTargetID: here a line
// break that could forge an output line) fails before the roster path, both
// secret prompts and the seams, as one stderr line naming the id quoted.
// MUST STAY SERIAL (it swaps os.Stdin, via withCountingSeams).
func TestBootstrap_LineUnsafeTargetIDFailsBeforeAnyPromptOrSeam(t *testing.T) {
	c := withCountingSeams(t)
	root := newRootCmd()
	root.SetArgs([]string{"bootstrap", "qa\nwarning: forged", "--host", "h", "--node", "n", "--grant", "/:PVEVMAdmin::1"})
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	if code := runRoot(root, &stderr); code == 0 {
		t.Fatal("exit 0 with a line-unsafe target id")
	}
	got := stderr.String()
	if strings.Count(got, "\n") != 1 || !strings.Contains(got, `target id "qa\nwarning: forged"`) ||
		strings.Contains(got, "passphrase") || strings.Contains(got, "PVE password") {
		t.Fatalf("stderr = %q, want one line naming the quoted id and no secret prompt", got)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if c.transport != 0 || c.validator != 0 {
		t.Fatalf("seams constructed: %+v", *c)
	}
}

// A-T9: --acl-path and --acl-role are gone: cobra's unknown-flag error,
// no prompt, no seam (one row per flag). MUST STAY SERIAL (os.Stdin).
func TestBootstrap_AT9_RemovedFlagsAreUnknown(t *testing.T) {
	for _, args := range [][]string{
		{"--acl-path", "/", "--grant", "/:PVEVMAdmin::1"},
		{"--acl-role", "PVEVMAdmin", "--grant", "/:PVEVMAdmin::1"},
	} {
		t.Run(args[0], func(t *testing.T) {
			c := withCountingSeams(t)
			code, stderr := runBootstrapArgs(t, args...)
			if code == 0 || !strings.Contains(stderr, "unknown flag: "+args[0]) {
				t.Fatalf("exit %d, stderr %q", code, stderr)
			}
			if strings.Contains(stderr, "passphrase") || strings.Contains(stderr, "PVE password") || c.transport != 0 || c.validator != 0 {
				t.Fatalf("got past the flag parse: stderr %q, seams %+v", stderr, *c)
			}
		})
	}
}

// A-T10: a comma-separated PRIVS list stays one grant (StringArray, not
// StringSlice, which splits on commas).
func TestNewBootstrapCmd_AT10_GrantKeepsCommas(t *testing.T) {
	cmd := newBootstrapCmd()
	if err := cmd.ParseFlags([]string{"--grant", "/storage/local:Iso:Datastore.Audit,SDN.Use", "--grant", "/pool/p:R::1"}); err != nil {
		t.Fatal(err)
	}
	specs, err := cmd.Flags().GetStringArray("grant")
	if err != nil {
		t.Fatal(err)
	}
	grants, err := bootstrap.ParseGrants(specs)
	if err != nil || len(grants) != 2 || len(grants[0].Privs) != 2 || !grants[1].Propagate {
		t.Fatalf("specs %q -> %+v, %v", specs, grants, err)
	}
}

// A-T8 (view side): the surviving token's grants are rendered, kv on one
// line; a result without grants renders no grants key.
func TestRenderBootstrapResult_AT8_Grants(t *testing.T) {
	grants := []bootstrap.Grant{
		{Path: "/pool/p", Role: "R1"},
		{Path: "/storage/s", Role: "R2", Propagate: true, Privs: []string{"B1", "B2"}},
	}
	for _, outcome := range []string{bootstrap.OutcomeMinted, bootstrap.OutcomeReused, bootstrap.OutcomeReplaced} {
		t.Run(outcome, func(t *testing.T) {
			res := bootstrap.Result{TokenID: "root@pam!pveforge", TokenOutcome: outcome, Validation: bootstrap.ValidationVerified, Grants: grants}
			out, _ := render(t, kvjson.JSON, &res)
			var v struct {
				Grants []map[string]interface{} `json:"grants"`
			}
			if err := json.Unmarshal([]byte(out), &v); err != nil {
				t.Fatal(err)
			}
			if len(v.Grants) != 2 || v.Grants[0]["path"] != "/pool/p" || v.Grants[0]["role"] != "R1" || v.Grants[0]["propagate"] != false || v.Grants[0]["privs"] != nil ||
				v.Grants[1]["path"] != "/storage/s" || v.Grants[1]["role"] != "R2" || v.Grants[1]["propagate"] != true || len(v.Grants[1]["privs"].([]interface{})) != 2 {
				t.Fatalf("json grants = %v", v.Grants)
			}
			kv, _ := render(t, kvjson.KV, &res)
			var lines []string
			for _, l := range strings.Split(strings.TrimSpace(kv), "\n") {
				if strings.HasPrefix(l, "grants=") {
					lines = append(lines, l)
				}
			}
			if len(lines) != 1 || !strings.Contains(lines[0], `"path":"/storage/s"`) || !strings.Contains(lines[0], `"role":"R2"`) || !strings.Contains(lines[0], `"role":"R1"`) {
				t.Fatalf("kv grants lines = %q", lines)
			}
		})
	}
	t.Run("a failed run", func(t *testing.T) {
		res := bootstrap.Result{TokenID: "root@pam!pveforge", TokenOutcome: bootstrap.OutcomeDiscarded, Validation: bootstrap.ValidationFailed}
		for _, f := range []kvjson.Format{kvjson.KV, kvjson.JSON} {
			if out, _ := render(t, f, &res); strings.Contains(out, "grants") {
				t.Fatalf("%s: grants rendered for a failed run: %q", f, out)
			}
		}
	})
}

// C-T8b (CR-1): --no-ssh-key must reach Options. Dropping the field from
// the Options literal is invisible to every internal/bootstrap test — they
// set Options.NoSSHKey directly — so the flag could be a no-op and a run
// the operator believes is keyless would install and persist a key. This
// drives the real RunE through runRoot and requires the run to stop at the
// KEYLESS dial, never at the install path.
//
// It also asserts (FO-1) that the PVE password reaches neither rendered
// stream, which is the one leak site C-T6 cannot see from inside the
// bootstrap package.
func TestBootstrap_CT8b_NoSSHKeyReachesOptions(t *testing.T) {
	tr := &fakeBootstrapTransport{installErr: errors.New("install must not run")}
	withBootstrapFakes(t, tr)
	root := newRootCmd()
	root.SetArgs([]string{"bootstrap", "qa-test", "--host", "h", "--node", "n",
		"--grant", "/:PVEVMAdmin::1", "--no-ssh-key"})
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	if code := runRoot(root, &stderr); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if tr.pwCalls != 1 || tr.installCalls != 0 {
		t.Fatalf("keyless dials = %d, install calls = %d: the flag did not reach Options", tr.pwCalls, tr.installCalls)
	}
	if !strings.Contains(stderr.String(), "connect with password (no ssh key)") {
		t.Fatalf("stderr = %q, want the keyless dial's failure", stderr.String())
	}
	// FO-1: the password is in neither rendered stream.
	if pw := os.Getenv(pvePasswordEnvVar); pw == "" ||
		strings.Contains(stdout.String(), pw) || strings.Contains(stderr.String(), pw) {
		t.Fatalf("the PVE password reached the output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
