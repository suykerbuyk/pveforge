package outer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// VMPath is the exported form of the package's own vmPath
// (/nodes/<node>/qemu/<vmid>[/sub], the shell's _harness_vm_path, lib.sh:442).
// It is exported so a second in-process consumer (the golden/reset driver)
// can build the same endpoint without cloning the slash rule; the landed
// guard.go and probe.go call sites keep their own helpers (additive lift).
func VMPath(node string, vmid int, sub string) string {
	return vmPath(node, vmid, sub)
}

// RawUPID issues a task-returning write (method+path+params) through a Reader
// and returns the task UPID PVE answers with (an unwrapped JSON string). It is
// the shared form of the per-driver rawUPID helpers (cmd/pveforge/harness_vm.go,
// internal/harness/probe/probe.go); its error text is byte-identical to theirs
// so their tests stay green. It takes a Reader (RawRequest only) so this
// package keeps importing no internal/pve; it issues NO WaitForTask — the
// caller waits with its concrete client, passing its own context (the
// task-wait context guard).
func RawUPID(ctx context.Context, r Reader, method, path string, params url.Values) (string, error) {
	raw, err := r.RawRequest(ctx, method, path, params)
	if err != nil {
		return "", err
	}
	var upid string
	if err := json.Unmarshal(raw, &upid); err != nil {
		return "", fmt.Errorf("%s %s: expected a task UPID, got %s", method, path, string(raw))
	}
	return upid, nil
}
