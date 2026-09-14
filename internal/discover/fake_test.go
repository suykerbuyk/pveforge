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

	calls int
}

func (f *fakeClient) APIDocTree(_ context.Context) (json.RawMessage, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}
