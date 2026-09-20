package roster

import "testing"

// testWorkFactor is the scrypt work factor this package's non-KDF tests
// encrypt at. At age's default of 18 a single derivation costs about 0.8s,
// and 6.3s under the race detector; this package performs 35 of them.
const testWorkFactor = 10

// withTestWorkFactor lowers the scrypt work factor for the duration of one
// test, restoring it afterwards — the same shape as internal/pve's
// withTaskTimings, and for the same reason: none of these tests can be
// allowed to pay a production cost that has nothing to do with what they
// assert.
//
// It goes at the top of EVERY test in writeback_test.go and load_test.go,
// uniformly, rather than only the ones that happen to encrypt today. Those
// files assert TOML splice behaviour and loading, never KDF parameters, and a
// per-test judgement about which of them reaches a derivation is exactly the
// kind of call that goes stale the moment someone adds an assertion.
//
// It is deliberately NOT hidden inside writeTempRoster or sampleArmored. A
// fixture helper that quietly weakened the KDF would be invisible at the call
// site, and the one thing this package cannot afford is a work-factor change
// nobody can see.
//
// The tests that must NOT use it are kdf_guard_test.go's, which require
// production's 18 exactly, and secrets_test.go's round trip, which is the one
// end-to-end check that a genuine 18-factor header decrypts.
func withTestWorkFactor(t *testing.T) {
	t.Helper()
	restore := SetScryptWorkFactorForTests(testWorkFactor)
	t.Cleanup(restore)
}
