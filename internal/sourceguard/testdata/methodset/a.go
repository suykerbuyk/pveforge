package methodset

// T is the receiver ExportedMethods is asked about. It has an exported
// pointer-receiver method (Alpha), an unexported one (beta), and an exported
// value-receiver method (Gamma), plus Zeta in a sibling file and OnlyInTest in
// a _test.go file. Only Alpha, Gamma and Zeta may be reported.
type T struct{}

func (t *T) Alpha() {}

func (t *T) beta() {}

func (t T) Gamma() {}

// U is a second receiver. Its Delta must never be reported for T, and it is
// also what makes TestCallees' production-code boundary observable: Epsilon
// below calls Delta, and a test calls Epsilon, so Delta is REACHABLE from the
// test — but only through a non-test file, which TestCallees must not enter.
type U struct{}

func (u *U) Delta() {}

func Epsilon() {
	var u U
	u.Delta()
}
