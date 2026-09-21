// Package main is this unit's weak probe: a NON-TEST binary that calls each
// of the two seams' exported setters and is required to die.
//
// It exists because of a gap no in-process test can close. Both setters route
// through an inner function that takes "am I in a test binary" as a
// PARAMETER, so the refusal branch is reachable from an ordinary test — that
// is deliberate, and it is what gives the branch real coverage. But it also
// means a mutant that changes only the exported wrapper,
//
//	func Install() (restore func()) { return install(true) }
//
// survives every in-process assertion: the tests call the inner function
// directly and never observe the wrapper's argument. Only a binary that is
// genuinely not built by `go test` can show that testing.Testing() really
// returns false there, and that the wrappers really consult it.
//
// It lives under testdata/ so the module build never sees it: it is not in
// `go list ./...`, `make test` does not build it, and the source guard's
// module walk skips it — which it must, since this file is a non-test file
// deliberately referencing the very names that guard forbids.
// internal/roster/testdata/weakprobe is the precedent this copies.
package main

import (
	"fmt"
	"os"

	"github.com/suykerbuyk/pveforge/internal/netguard"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: weakprobe netguard|sshexec")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "netguard":
		netguard.Install()
	case "sshexec":
		sshexec.SetDialGuardForTests(func(string) error { return nil })
	default:
		fmt.Fprintf(os.Stderr, "unknown seam %q\n", os.Args[1])
		os.Exit(2)
	}
	// Reaching here at all is the failure this probe reports.
	fmt.Printf("SEAM %q ACCEPTED THE CALL FROM A NON-TEST BINARY\n", os.Args[1])
}
