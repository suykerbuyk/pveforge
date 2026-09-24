package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// elided is the marker boundErrText appends after cutting n bytes.
func elided(n int) string { return fmt.Sprintf(" … [%d bytes elided]", n) }

// decodeErrText returns the text a runRoot-style line carries: the line
// itself, or, when kvjson.QuoteValue quoted it, the decoded JSON string —
// which must decode, or the quoting was broken.
func decodeErrText(t *testing.T, line string) string {
	t.Helper()
	if !strings.HasPrefix(line, `"`) {
		return line
	}
	var s string
	if err := json.Unmarshal([]byte(line), &s); err != nil {
		t.Fatalf("a quoted error text is not valid JSON (%v): %.200q…", err, line)
	}
	return s
}

// oneLine returns stderr's single line, failing unless there is exactly one.
func oneLine(t *testing.T, stderr string) string {
	t.Helper()
	if strings.Count(stderr, "\n") != 1 || !strings.HasSuffix(stderr, "\n") {
		t.Fatalf("stderr is not exactly one line (%d newlines): %.300q…", strings.Count(stderr, "\n"), stderr)
	}
	return strings.TrimSuffix(stderr, "\n")
}

// runRootFailing runs a bare root whose RunE returns err after fn (if any)
// has run with the root's context cancel func.
func runRootFailing(t *testing.T, err error, fn func(cancel context.CancelCauseFunc)) (int, string) {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(nil) })
	root := &cobra.Command{Use: "pveforge", SilenceUsage: true, SilenceErrors: true,
		RunE: func(*cobra.Command, []string) error {
			if fn != nil {
				fn(cancel)
			}
			return err
		}}
	root.SetContext(ctx)
	root.SetArgs(nil)
	var stderr bytes.Buffer
	code := runRoot(root, &stderr)
	return code, stderr.String()
}

// B1: a huge, multi-line error prints as one line — its head, exactly
// maxErrTextBytes of it, then the elided marker with the exact count —
// and the quoting around it still decodes.
func TestBoundErrText_B1_AHugeErrorIsOneBoundedLine(t *testing.T) {
	text := strings.Repeat("line of server text\n", (1<<20)/20)
	code, stderr := runRootFailing(t, errors.New(text), nil)
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	got := decodeErrText(t, oneLine(t, stderr))
	if want := text[:maxErrTextBytes] + elided(len(text)-maxErrTextBytes); got != want {
		t.Fatalf("printed %d bytes ending %q; want the %d-byte head then %q", len(got), got[max(0, len(got)-40):], maxErrTextBytes, elided(len(text)-maxErrTextBytes))
	}
}

// B2: at and under the bound the text is untouched; one byte over, exactly
// one byte is elided. Through runRoot a short text prints as it always did.
func TestBoundErrText_B2_TheBoundIsExact(t *testing.T) {
	at := strings.Repeat("a", maxErrTextBytes)
	if got := boundErrText(at); got != at {
		t.Errorf("a text of exactly %d bytes was changed", maxErrTextBytes)
	}
	if got := boundErrText(""); got != "" {
		t.Errorf("empty text became %q", got)
	}
	if got, want := boundErrText(at+"b"), at+elided(1); got != want {
		t.Errorf("one byte over: got …%q, want …%q", got[len(got)-30:], want[len(want)-30:])
	}
	code, stderr := runRootFailing(t, errors.New("pve returned 500: x\nwarning: forged"), nil)
	if code != 1 || stderr != `"pve returned 500: x\nwarning: forged"`+"\n" {
		t.Errorf("a short error changed: exit %d, stderr %q", code, stderr)
	}
}

// B3: the cut never splits a rune — for a 2-, 3- and 4-byte rune straddling
// the bound at every offset — so the printed text is valid UTF-8, with no
// replacement character.
func TestBoundErrText_B3_TheCutIsOnARuneBoundary(t *testing.T) {
	for _, r := range []string{"é", "€", "𝄞"} {
		for off := 1; off < len(r); off++ {
			head := strings.Repeat("a", maxErrTextBytes-off)
			s := head + r + strings.Repeat("z", 100)
			got := boundErrText(s)
			if want := head + elided(len(s)-len(head)); got != want {
				t.Errorf("%q at offset %d: got …%q, want …%q", r, off, got[len(head)-5:], want[len(head)-5:])
			}
			if !utf8.ValidString(got) || strings.ContainsRune(got, utf8.RuneError) {
				t.Errorf("%q at offset %d: the printed text is not clean UTF-8", r, off)
			}
		}
	}
}

// B4: an interrupted command with a huge error keeps the interrupt prefix
// and the whole "may or may not have been applied" note: the bound cuts the
// error's own text, before it is wrapped.
func TestBoundErrText_B4_TheInterruptNoteIsNeverCut(t *testing.T) {
	text := strings.Repeat("x", 3*maxErrTextBytes)
	code, stderr := runRootFailing(t, errors.New(text), func(cancel context.CancelCauseFunc) {
		cancel(interruptError{sig: syscall.SIGINT})
	})
	if code != 130 {
		t.Fatalf("exit %d, want 130", code)
	}
	want := "interrupted (SIGINT): " + text[:maxErrTextBytes] + elided(2*maxErrTextBytes) +
		"; any change the command had already sent may or may not have been applied"
	if got := decodeErrText(t, oneLine(t, stderr)); got != want {
		t.Errorf("printed %d bytes: %.60q … %q", len(got), got, got[max(0, len(got)-120):])
	}
}

// hugeBody is a 1 MiB PVE error body with line breaks in it.
var hugeBody = strings.Repeat("proxy error page line\n", (1<<20)/22)

// B5: vm set's re-read warning bounds the cause the same way: one line,
// exit 0, the write reported on stdout.
func TestBoundErrText_B5_TheReReadWarningIsBounded(t *testing.T) {
	var mu sync.Mutex
	config := map[string]string{"digest": "d1"}
	getCalls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if answerNothingPending(w, r) { // post-apply-verify's read: not a config GET
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodGet {
			getCalls++
			if getCalls == 3 { // Run's post-Apply re-read
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(hugeBody))
				return
			}
			body, _ := json.Marshal(config)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":` + string(body) + `}`))
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		for k, v := range r.PostForm {
			if k != "digest" {
				config[k] = v[0]
			}
		}
	}))
	t.Cleanup(srv.Close)
	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	code, stdout, stderr := runRootArgs("vm", "set", "--roster", rosterPath, "qa-pve-01", "100", "cores=4")
	if code != 0 || stdout != "qa-pve-01: cores=4\n" {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	const prefix = "warning: qa-pve-01: vm 100: the write was applied but its result could not be re-read: "
	line := oneLine(t, stderr)
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("stderr %.200q…", line)
	}
	got := decodeErrText(t, strings.TrimPrefix(line, prefix))
	if len(got) > maxErrTextBytes+len(elided(1<<20)) || !strings.HasSuffix(got, " bytes elided]") {
		t.Errorf("the cause is %d bytes, ending %q: want it bounded", len(got), got[max(0, len(got)-40):])
	}
}

// B6: pveforge api get against a 500 with a 1 MiB body prints exactly
// RawRequest's text, bounded: its head, then the exact elided count.
func TestBoundErrText_B6_APIGetBoundsAHugeBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(hugeBody))
	}))
	t.Cleanup(srv.Close)
	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	code, stdout, stderr := runRootArgs("api", "get", "/x", "qa-pve-01", "--roster", rosterPath)
	if code != 1 || stdout != "" {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	full := "raw request: pve returned 500 Internal Server Error: " + strings.TrimSpace(hugeBody)
	got := decodeErrText(t, oneLine(t, stderr))
	if want := full[:maxErrTextBytes] + elided(len(full)-maxErrTextBytes); got != want {
		t.Errorf("printed %d bytes ending %q; want RawRequest's text bounded to %d, ending %q", len(got), got[max(0, len(got)-40):], maxErrTextBytes, elided(len(full)-maxErrTextBytes))
	}
}

// B7: a PVE (or proxy) error that echoes the request's Authorization
// header — the imported token's secret — never leaks any prefix of it,
// wherever the bound falls. This runs the real chain: RawRequest, the grant
// validator, bootstrap.Import's redaction, runRoot's bound. The secret is
// placed to straddle byte maxErrTextBytes of the printed text (a bound
// applied before the redaction would split it and leave its head), and of
// RawRequest's own text (a bound inside RawRequest would do the same).
func TestBoundErrText_B7_AnEchoedSecretStraddlingTheBoundNeverLeaks(t *testing.T) {
	const secret = "Zq8-SECRET-4f1c9e77aa"
	const echoLead = "Authorization: " // then the header: PVEAPIToken=<id>=<secret>
	const tokenID = "ops@pve!ci"
	secretInHeader := len("PVEAPIToken=" + tokenID + "=")

	var mu sync.Mutex
	pad := -1 // -1: answer the probe
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		p := pad
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
		if p < 0 {
			_, _ = w.Write([]byte("PROBE-MARK"))
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("p", p) + echoLead + r.Header.Get("Authorization") + " " + strings.Repeat("z", 3*maxErrTextBytes)))
	}))
	t.Cleanup(srv.Close)
	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	run := func(t *testing.T) (int, string) {
		t.Helper()
		c := newImportCase(t)
		newBootstrapValidator = bootstrap.NewAPIValidator // the real chain; newImportCase restores its seam
		code, stdout, stderr := c.run(secret+"\n", "--token-id", tokenID, "--grant", "/vms/100:PVEVMUser",
			"--host", host, "--api-port", port, "--insecure-tls", "--node", "n1")
		if strings.Contains(stdout, secret[:4]) {
			t.Errorf("stdout carries the secret's head: %q", stdout)
		}
		return code, decodeErrText(t, oneLine(t, stderr))
	}
	// The probe fixes where the body starts in the printed text and in
	// RawRequest's own text; neither prefix depends on the body.
	code, probe := run(t)
	bodyAt := strings.Index(probe, "PROBE-MARK")
	rrAt := strings.Index(probe, "raw request: pve returned")
	if code != 1 || bodyAt < 0 || rrAt < 0 || bodyAt+maxErrTextBytes/2 > maxErrTextBytes {
		t.Fatalf("probe: exit %d, text %q", code, probe)
	}
	secretAt := func(prefix int) int { return maxErrTextBytes - len(secret)/2 - prefix - len(echoLead) - secretInHeader }

	for name, p := range map[string]int{
		"straddling the printed bound":     secretAt(bodyAt),
		"straddling RawRequest's own byte": secretAt(bodyAt - rrAt),
	} {
		t.Run(name, func(t *testing.T) {
			mu.Lock()
			pad = p
			mu.Unlock()
			code, got := run(t)
			if code != 1 {
				t.Fatalf("exit %d: %.200q", code, got)
			}
			for k := len(secret); k >= 4; k-- {
				if strings.Contains(got, secret[:k]) {
					t.Fatalf("the printed error carries the secret's first %d bytes %q", k, secret[:k])
				}
			}
			if !strings.HasSuffix(got, " bytes elided]") {
				t.Errorf("the error was not bounded: %d bytes", len(got))
			}
			// Anti-vacuity for the first case: the printed cut really falls
			// inside the echoed credential, which reads as the redaction.
			if name == "straddling the printed bound" && !strings.Contains(got, "PVEAPIToken="+tokenID+"=<redacted> … [") {
				t.Errorf("the cut does not fall inside the redacted secret: …%q", got[max(0, len(got)-80):])
			}
		})
	}
}

// B8: every error text this package prints goes through boundErrText. One
// walker covers every declaration — function bodies, the func literals in
// them, and package-level vars (a func literal held in a var prints too) —
// and applies two rules:
//
//   - An Error method selected on an error value — called or taken as a
//     method value (text := err.Error) — must be exactly
//     boundErrText(x.Error()).
//   - No error-typed expression may appear anywhere inside a print call's
//     arguments (fmt's printers, log, cobra's Print*) — through a
//     conversion (any(err)), a composite literal ([]any{err}) or otherwise —
//     unless it is inside boundErrText's argument.
//
// The one exception is pinned by type object and site: runRoot formats its
// interruptError, whose text is a signal name (SIGINT, SIGTERM), never a
// server's. Anti-vacuity: the bounded sites and the exception are each seen
// exactly as often as expected.
func TestBoundErrText_B8_EveryPrintedErrorTextIsBounded(t *testing.T) {
	wantBounded := map[string]int{
		"main.go: runRoot: err.Error()":              1,
		"reread.go: warnNotReread: afterErr.Error()": 1, // Run's AfterErr, for every command that reports it
		"reread.go: warnPostCheck: postErr.Error()":  1, // Run's PostApplyErr: vm create, vm set, user and group ensure
	}
	fset, files, info := checkedPackage(t)
	errType := types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	isErr := func(e ast.Expr) bool {
		tv, ok := info.Types[e]
		return ok && !tv.IsType() && tv.Type != nil && types.Implements(tv.Type, errType)
	}
	var interruptErrObj types.Object
	for id, obj := range info.Defs {
		if tn, ok := obj.(*types.TypeName); ok && id.Name == "interruptError" && tn.Parent() == tn.Pkg().Scope() {
			interruptErrObj = tn
		}
	}
	if interruptErrObj == nil {
		t.Fatal("interruptError's type object not found: the exception cannot be pinned")
	}
	isBoundCall := func(n ast.Node) (*ast.CallExpr, bool) {
		c, ok := n.(*ast.CallExpr)
		if !ok || len(c.Args) != 1 {
			return nil, false
		}
		id, ok := c.Fun.(*ast.Ident)
		return c, ok && id.Name == "boundErrText"
	}
	isPrintCall := func(c *ast.CallExpr) bool {
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if id, ok := sel.X.(*ast.Ident); ok {
			if pn, ok := info.Uses[id].(*types.PkgName); ok {
				switch pn.Imported().Path() {
				case "fmt":
					return sel.Sel.Name != "Errorf"
				case "log":
					return true
				}
			}
		}
		s, ok := info.Selections[sel]
		return ok && strings.HasPrefix(sel.Sel.Name, "Print") && strings.Contains(s.Recv().String(), "github.com/spf13/cobra.Command")
	}

	gotBounded := map[string]int{}
	exceptions := 0
	for _, f := range files {
		file := filepath.Base(fset.Position(f.Pos()).Filename)
		for _, d := range f.Decls {
			var encl string
			switch x := d.(type) {
			case *ast.FuncDecl:
				encl = x.Name.Name
			case *ast.GenDecl:
				encl = "var"
				for _, s := range x.Specs {
					if vs, ok := s.(*ast.ValueSpec); ok && len(vs.Names) > 0 {
						encl = "var " + vs.Names[0].Name
						break
					}
				}
			}
			var stack []ast.Node
			// under reports whether stack[i+1] is an argument of the call
			// at stack[i] matching pred, for some i.
			under := func(pred func(*ast.CallExpr) bool) bool {
				for i := 0; i+1 < len(stack); i++ {
					c, ok := stack[i].(*ast.CallExpr)
					if !ok || !pred(c) {
						continue
					}
					for _, a := range c.Args {
						if a == stack[i+1] {
							return true
						}
					}
				}
				return false
			}
			underBound := func() bool {
				return under(func(c *ast.CallExpr) bool { _, ok := isBoundCall(c); return ok })
			}
			ast.Inspect(d, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				stack = append(stack, n)
				site := file + ": " + encl + ": "
				// Rule 1: an Error method selected on an error value.
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" {
					if s, ok := info.Selections[sel]; ok && (s.Kind() == types.MethodVal || s.Kind() == types.MethodExpr) &&
						types.Implements(s.Recv(), errType) {
						ok := false
						if k := len(stack); k >= 3 {
							call, isCall := stack[k-2].(*ast.CallExpr)
							if isCall && call.Fun == sel && len(call.Args) == 0 {
								if b, isB := isBoundCall(stack[k-3]); isB && b.Args[0] == call {
									ok = true
									gotBounded[site+types.ExprString(call)]++
								}
							}
						}
						if !ok {
							t.Errorf("%s%s: an error's text is taken other than as boundErrText(x.Error())", site, types.ExprString(sel))
						}
					}
				}
				// Rule 2: an error value inside a print call's arguments.
				if e, ok := n.(ast.Expr); ok && isErr(e) && under(isPrintCall) && !underBound() {
					if named, ok := info.Types[e].Type.(*types.Named); ok && named.Obj() == interruptErrObj && encl == "runRoot" {
						exceptions++
						return true
					}
					t.Errorf("%s%s: an error value inside a print call's arguments, not bounded", site, types.ExprString(e))
				}
				return true
			})
		}
	}
	if exceptions != 1 {
		t.Errorf("runRoot's interruptError formatted %d time(s), want exactly 1: the pinned exception moved", exceptions)
	}
	for s, n := range wantBounded {
		if gotBounded[s] != n {
			t.Errorf("%s: seen %d time(s), want %d (the walk no longer sees the known sites)", s, gotBounded[s], n)
		}
	}
	for s := range gotBounded {
		if _, ok := wantBounded[s]; !ok {
			t.Errorf("%s: a new bounded site; add it here", s)
		}
	}
}

// B9: vm set's pending-check warning (post-apply-verify) bounds its cause
// the same way: a /pending read answered by a 500 with a 1 MiB body is one
// bounded line, exit 0, the write reported on stdout.
func TestBoundErrText_B9_ThePendingCheckWarningIsBounded(t *testing.T) {
	_, code, stdout, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.pendingStatus = http.StatusInternalServerError
		f.pendingBody = hugeBody
	}, "cores=4")
	if code != 0 || stdout != "qa-pve-01: cores=4\n" {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	const prefix = "warning: qa-pve-01: vm 100: the change was applied but whether it is pending could not be checked: "
	line := oneLine(t, stderr)
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("stderr %.200q…", line)
	}
	got := decodeErrText(t, strings.TrimPrefix(line, prefix))
	if len(got) > maxErrTextBytes+len(elided(1<<20)) || !strings.HasSuffix(got, " bytes elided]") {
		t.Errorf("the cause is %d bytes, ending %q: want it bounded", len(got), got[max(0, len(got)-40):])
	}
}
