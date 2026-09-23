package pvefake_test

import (
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

// That no production code ever links this package is held by
// internal/sourceguard's TestTestSupportPackagesNeverReachProduction, one
// guard over every test-support package.

// TestSSHServer_SettersPanicAfterStart pins the configure-before-Start rule:
// a setter after Start would race the accept loop, so it panics instead.
func TestSSHServer_SettersPanicAfterStart(t *testing.T) {
	for name, set := range map[string]func(s *pvefake.SSHServer){
		"AllowKey":   func(s *pvefake.SSHServer) { s.AllowKey(nil) },
		"HandleExec": func(s *pvefake.SSHServer) { s.HandleExec(func(string) (string, string, int) { return "", "", 0 }) },
	} {
		s := pvefake.NewSSHServer(t)
		set(s) // before Start: allowed
		s.Start()
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s after Start did not panic", name)
				}
			}()
			set(s)
		}()
	}
}
