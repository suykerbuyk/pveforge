package clean

import "testing"

func TestPure(t *testing.T) {
	unused := 5 // a local shadowing the package var, declared with :=
	_ = unused
}
