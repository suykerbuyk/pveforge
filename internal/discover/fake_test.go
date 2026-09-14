package discover

import (
	"context"
	"encoding/json"
)

// fakeClient is a scriptable Client, used by this package's own tests —
// no network, no pve package dependency beyond compat_test.go's
// compile-time proof.
type fakeClient struct {
	result json.RawMessage
	err    error

	calls    int
	lastPath string
}

func (f *fakeClient) OptionsSchema(_ context.Context, path string) (json.RawMessage, error) {
	f.calls++
	f.lastPath = path
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}
