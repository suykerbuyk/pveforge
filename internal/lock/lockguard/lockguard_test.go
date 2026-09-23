package lockguard

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// fixtureRoot is a small module-shaped tree: cmd/pveforge, the two
// TakerFiles, and one stray lock taker. Each file holds one accepted or
// refused shape of a lock-taking call; see its own comment. It lives under
// testdata, so the go tool never builds it and it need not compile.
const fixtureRoot = "testdata/tree"

// The expected verdicts' distinctive text.
const (
	wantNotCommandCtx = "its context is not <cmd>.Context() of the command's *cobra.Command: pass cmd.Context() directly"
	wantCmdRebound    = "its context is cmd.Context(), but cmd is re-bound in the function that declares it, so it may no longer be the command: pass cmd.Context() directly"
	wantCtxRebound    = "its context is ctx, but ctx is re-bound in the function that declares it, so it may no longer be the caller's context: pass the parameter directly"
)

// expectedCalls is every lock-taking call in the fixture tree, by
// file:line, with the verdict it must get ("" = accepted).
var expectedCalls = map[string]string{
	// accepted
	"cmd/pveforge/accept_direct.go:14":      "", // lock.Read(cmd.Context(), ...)
	"cmd/pveforge/accept_direct.go:19":      "", // idempotent.Run(cmd.Context(), ...), a derived sink
	"cmd/pveforge/accept_alias.go:12":       "", // cb "github.com/spf13/cobra", c.Context()
	"cmd/pveforge/accept_constructor.go:14": "", // the constructor's own cmd := &cobra.Command{}
	"internal/bootstrap/bootstrap.go:11":    "", // Run's own ctx, directly
	"internal/idempotent/op.go:27":          "", // helper's own ctx (a TakerProblem, not a context problem)
	// refused
	"cmd/pveforge/refuse_background.go:15":    wantNotCommandCtx, // lock.Read(context.Background(), ...)
	"cmd/pveforge/refuse_background.go:16":    wantNotCommandCtx, // idempotent.Run(context.Background(), ...)
	"cmd/pveforge/refuse_withoutcancel.go:14": wantNotCommandCtx, // context.WithoutCancel(cmd.Context())
	"cmd/pveforge/refuse_root.go:13":          wantCmdRebound,    // cmd = cmd.Root() before the call
	"cmd/pveforge/refuse_nested.go:15":        wantCmdRebound,    // { cmd := cmd.Root(); ... }
	"cmd/pveforge/refuse_range.go:13":         wantCmdRebound,    // for _, cmd := range ...
	"cmd/pveforge/refuse_closure.go:13":       wantCmdRebound,    // func(cmd *cobra.Command) {...}(cmd.Root())
	"cmd/pveforge/refuse_fp1.go:14":           wantNotCommandCtx, // ctx := cmd.Context(): the documented false positive
	"cmd/pveforge/refuse_notparam.go:13":      wantNotCommandCtx, // root := cmd.Root(); root.Context()
	"internal/idempotent/op.go:12":            wantCtxRebound,    // ctx = context.Background() before the call
	"internal/idempotent/op.go:19":            wantCtxRebound,    // a closure's own ctx parameter shadows Shadow's
}

// TestScanModule_ContextArguments: every lock-taking call in the fixture tree
// gets exactly its expected verdict, and no call is unaccounted for.
func TestScanModule_ContextArguments(t *testing.T) {
	sc, err := ScanModule(fixtureRoot)
	if err != nil {
		t.Fatalf("ScanModule: %v", err)
	}
	got := map[string]string{}
	for _, c := range sc.Calls {
		got[fmt.Sprintf("%s:%d", c.Ref.File, c.Ref.Line)] = c.Problem
	}
	for _, at := range sortedKeys(expectedCalls) {
		want := expectedCalls[at]
		t.Run(at, func(t *testing.T) {
			problem, ok := got[at]
			switch {
			case !ok:
				t.Fatalf("no lock-taking call was checked at %s", at)
			case want == "" && problem != "":
				t.Errorf("accepted shape refused: %s", problem)
			case want != "" && !strings.Contains(problem, want):
				t.Errorf("verdict %q, want it to contain %q", problem, want)
			}
		})
	}
	var extra []string
	for at := range got {
		if _, ok := expectedCalls[at]; !ok {
			extra = append(extra, at)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("calls checked that no expectation covers: %v", extra)
	}
}

// TestScanModule_TakersAndViolations: a lock taken outside cmd/pveforge and
// TakerFiles is a Violation; one in a TakerFiles file but in an unexported
// function is a TakerProblem; every exported taker is derived as a sink.
func TestScanModule_TakersAndViolations(t *testing.T) {
	sc, err := ScanModule(fixtureRoot)
	if err != nil {
		t.Fatalf("ScanModule: %v", err)
	}
	if len(sc.Violations) != 1 || sc.Violations[0].File != "internal/stray/stray.go" || sc.Violations[0].Line != 11 {
		t.Errorf("Violations = %v, want exactly internal/stray/stray.go:11", sc.Violations)
	}
	if len(sc.TakerProblems) != 1 || !strings.Contains(sc.TakerProblems[0], "internal/idempotent/op.go:27") ||
		!strings.Contains(sc.TakerProblems[0], "outside an exported top-level function") {
		t.Errorf("TakerProblems = %q, want exactly the unexported helper at internal/idempotent/op.go:27", sc.TakerProblems)
	}
	for _, sink := range []string{
		LockPkg + ".Mutation", LockPkg + ".Read",
		"github.com/suykerbuyk/pveforge/internal/idempotent.Run",
		"github.com/suykerbuyk/pveforge/internal/idempotent.Shadow",
		"github.com/suykerbuyk/pveforge/internal/bootstrap.Run",
	} {
		if !sc.Sinks[sink] {
			t.Errorf("%s was not derived as a sink; Sinks = %v", sink, sc.Sinks)
		}
	}
	if len(sc.Sinks) != 5 {
		t.Errorf("Sinks = %v, want exactly 5", sc.Sinks)
	}
}
