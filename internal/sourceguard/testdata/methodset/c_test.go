package methodset

import "testing"

// OnlyInTest is a real method on T, declared in a _test.go file.
// ExportedMethods reads non-test files only, so it must never report it.
func (t *T) OnlyInTest() {}

// TestUsesAlpha is the root TestCallees is asked about. It calls Alpha only
// inside a closure, reaches Zeta only through a helper defined in this test
// file, and calls Epsilon, which is defined in a non-test file and calls
// Delta.
func TestUsesAlpha(t *testing.T) {
	f := func() {
		var x T
		x.Alpha()
	}
	f()
	helper()
	Epsilon()
}

func helper() {
	var x T
	x.Zeta()
}
