package netguard

import (
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/sourceguard"
)

// The two files allowed to mention this unit's seams. Everything else in the
// module — every non-test file, in every package — is forbidden to.
const (
	netguardFile = "internal/netguard/netguard.go"
	sshexecFile  = "internal/sshexec/client.go"
)

// The forbidden forms. Both halves of this unit get the same treatment,
// because both mutate process-global state and neither is reachable from a
// shipped pveforge for any legitimate reason.
//
// Each has a runtime testing.Testing() gate as well. The gate and this guard
// answer different questions and neither subsumes the other: the gate stops a
// production caller at run time, in a binary nobody is testing; this stops the
// call from ever being written, at review time, including in code paths no
// test exercises.
var (
	// The HTTP seam. Install swaps http.DefaultTransport, a process-global
	// that every HTTP client in the binary resolves.
	tgtInstallDecl = sourceguard.Target{ImportPath: "github.com/suykerbuyk/pveforge/internal/netguard", Name: "Install"}
	tgtInstallBare = sourceguard.Target{Name: "Install"}
	// The unexported inner half. Forbidding only the exported wrapper would
	// leave a production file inside package netguard free to pass true and
	// bypass the gate, so this NARROWS that hole — it does not close it, and
	// the distinction is load-bearing.
	//
	// What it does not close: netguard.go is itself an AllowFile, and
	// Scope.allows is exact on the file, so a NEW exported wrapper added to
	// THAT file under a name this list does not carry —
	//
	//	func ArmForDiagnostics() (restore func()) { return install(true) }
	//
	// — is permitted, compiles, and can be called from cmd/pveforge/main.go
	// with this guard still green. Production then reaches install(true) and
	// swaps http.DefaultTransport in a shipped binary. No name-based guard
	// can close that, because the laundering name is chosen after the guard
	// is written. It is recorded in the package doc's bounds.
	tgtInstallInner = sourceguard.Target{Name: "install"}

	// The SSH seam, same three shapes.
	tgtDialGuardSetter = sourceguard.Target{ImportPath: "github.com/suykerbuyk/pveforge/internal/sshexec", Name: "SetDialGuardForTests"}
	tgtDialGuardBare   = sourceguard.Target{Name: "SetDialGuardForTests"}
	tgtDialGuardInner  = sourceguard.Target{Name: "setDialGuard"}
	// The var itself: forbidding only the setters would leave a production
	// file in package sshexec free to assign the hook directly.
	tgtDialGuardVar = sourceguard.Target{Name: "dialGuard"}
)

// TestSeam_NoProductionReferences is the static half of this unit's safety
// argument: no non-test file in the module except the two named above may
// mention either seam at all.
//
// Mutants S1-S3 plant each forbidden form in internal/bootstrap/bootstrap.go;
// R1c plants a netguard.Install call there.
func TestSeam_NoProductionReferences(t *testing.T) {
	targets := []sourceguard.Target{
		tgtInstallDecl, tgtInstallBare, tgtInstallInner,
		tgtDialGuardSetter, tgtDialGuardBare, tgtDialGuardInner, tgtDialGuardVar,
	}
	res, err := sourceguard.NonTestReferences(sourceguard.Scope{
		Root:       moduleRoot,
		AllowFiles: []string{netguardFile, sshexecFile},
	}, targets)
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}

	if v := res.Violations(); len(v) > 0 {
		var lines []string
		for _, ref := range v {
			lines = append(lines, "  "+ref.String())
		}
		t.Errorf("the loopback trip-wire's seams are referenced outside %s and %s:\n%s\n"+
			"Only those two files may touch them. Production code has no business "+
			"swapping http.DefaultTransport or installing an SSH dial hook. If a new "+
			"legitimate site really exists, it needs its own review, not an entry here.",
			netguardFile, sshexecFile, strings.Join(lines, "\n"))
	}

	// ANTI-VACUITY. A guard that matches nothing passes forever. Each target
	// below has a real site in one of the two allowed files, and if the walker
	// stops finding it, the "no violations" assertion above has stopped
	// meaning anything. This is why the allow-list MARKS rather than drops:
	// one call answers both questions.
	for _, c := range []struct {
		file string
		tgt  sourceguard.Target
	}{
		{netguardFile, tgtInstallBare},
		{netguardFile, tgtInstallInner},
		{sshexecFile, tgtDialGuardBare},
		{sshexecFile, tgtDialGuardInner},
		{sshexecFile, tgtDialGuardVar},
	} {
		if got := res.Allowed(c.file, c.tgt); len(got) == 0 {
			t.Errorf("target %s matched nothing in %s — the guard is no longer looking at the code it claims to guard",
				c.tgt, c.file)
		}
	}
	// tgtInstallDecl and tgtDialGuardSetter are deliberately absent from that
	// list. They are the QUALIFIED forms (netguard.Install,
	// sshexec.SetDialGuardForTests) and are pre-emptive fences: the only
	// legitimate callers are _test.go files, which this walk does not visit,
	// so they cannot be proven non-vacuous against the real tree. The
	// ImportPath form's mechanism is proven instead by sourceguard's own
	// fixture, in TestNonTestReferences_QualifiedMatchingIsAliasProof.

	// ...and the walk has to have covered the module, not some subtree. A
	// floor rather than an exact count, so an unrelated new file does not
	// break this and the KDF guard at once.
	if len(res.Parsed) < 70 {
		t.Errorf("walked only %d non-test files from %s; the module has ~78 — wrong root?", len(res.Parsed), moduleRoot)
	}
	if !res.Reached("cmd/pveforge/main.go") {
		t.Errorf("the walk never reached cmd/pveforge/main.go, so it did not cover the module; Parsed[0:3]=%v", firstN(res.Parsed, 3))
	}
}

func firstN(s []string, n int) []string {
	if len(s) < n {
		return s
	}
	return s[:n]
}
