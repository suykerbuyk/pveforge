package hidden

import "net/http"

// Hidden must never be reported. A testdata directory that is not the walk
// root is skipped — without that, the KDF unit's static guard fails against
// its own weakprobe fixture, which is a non-test file that calls the very
// setter the guard forbids. Mutant W2.
func Hidden() *http.Client {
	return &http.Client{}
}
