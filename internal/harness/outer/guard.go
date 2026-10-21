package outer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Mode is the guard's mode, mirroring _harness_guard_existing's second
// argument (lib.sh:474).
type Mode int

const (
	// ModeChange guards a VM before a non-destroy change (snapshot, stop,
	// shutdown): it must be a declared, tagged qemu member of the pool on
	// this node.
	ModeChange Mode = iota
	// ModeDestroy additionally requires the VM to have been created by this
	// run (lib.sh:484).
	ModeDestroy
	// ModeTag is the shell's "tag" mode (lib.sh:487-490): declared + a qemu
	// member of the pool on this node, but the tag check is SKIPPED — used only
	// to tag a VM just created (which does not carry the tag yet, D5).
	ModeTag
)

// poolObj is PVE's /pools?poolid=… answer, decoded exactly enough to make
// lib.sh's type tests. A member's vmid is kept as the raw JSON token so
// numericVMID can reproduce jq's `(.vmid|type)=="number"` (lib.sh:480,:648):
// a quoted "690" is NOT a number and must never alias the number 690
// (Go's json.Number would accept the quoted form, so a plain json.Number
// field would alias — hence the raw token plus an explicit numeric check).
type poolMember struct {
	Type string          `json:"type"`
	VMID json.RawMessage `json:"vmid"`
	Node string          `json:"node"`
}

type poolObj struct {
	PoolID  string       `json:"poolid"`
	Members []poolMember `json:"members"`
}

// numericVMID reports a member's vmid as an int only when its JSON token is
// a bare integer number (jq's `(.vmid|type)=="number"`). A string (even a
// numeric one), float, bool or null is not a number and returns ok=false,
// so a string "690" can never alias the number 690.
func numericVMID(raw json.RawMessage) (int, bool) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s[0] == '"' {
		return 0, false
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false
	}
	i, err := strconv.Atoi(n.String())
	if err != nil {
		return 0, false
	}
	return i, true
}

// vmPath builds /nodes/<node>/qemu/<vmid>[/sub], the shell's
// _harness_vm_path (lib.sh:442).
func vmPath(node string, vmid int, sub string) string {
	p := fmt.Sprintf("/nodes/%s/qemu/%d", node, vmid)
	if sub != "" {
		p += "/" + sub
	}
	return p
}

// readPool reads /pools?poolid=P and returns the single pool object,
// enforcing the shape lib.sh:478 asserts (an array of exactly one object
// whose poolid matches, with a members array).
func readPool(ctx context.Context, r Reader, pool string) (*poolObj, error) {
	raw, err := r.RawRequest(ctx, http.MethodGet, "/pools", url.Values{"poolid": {pool}})
	if err != nil {
		return nil, fmt.Errorf("reading pool %s failed: %w", pool, err)
	}
	var pools []poolObj
	if err := json.Unmarshal(raw, &pools); err != nil {
		return nil, fmt.Errorf("pool %s: the answer has an unexpected shape: %w", pool, err)
	}
	if len(pools) != 1 || pools[0].PoolID != pool || pools[0].Members == nil {
		return nil, fmt.Errorf("pool %s: the answer has an unexpected shape", pool)
	}
	return &pools[0], nil
}

// Guard reproduces _harness_guard_existing (lib.sh:470-492): before a change
// or destroy, prove vmid is a qemu member of cfg.Pool on cfg.Node and (for
// ModeChange and the tag leg of ModeDestroy) carries cfg.Tag; ModeDestroy
// additionally requires that this run created it (the ledger). The VMID
// bound (690–699) is checked first, as _harness_require_declared does.
//
// led may be nil for ModeChange (no ledger is read); ModeDestroy requires a
// non-nil ledger.
func Guard(ctx context.Context, r Reader, cfg Config, led *Ledger, vmid int, mode Mode) error {
	if !ValidVMID(vmid) {
		return fmt.Errorf("VMID %d is not one of 690-699", vmid)
	}
	pool, err := readPool(ctx, r, cfg.Pool)
	if err != nil {
		return err
	}
	// Exactly one qemu member with this vmid → its node; else "" (lib.sh:480).
	node := ""
	matches := 0
	for _, m := range pool.Members {
		if m.Type != "qemu" {
			continue
		}
		if id, ok := numericVMID(m.VMID); ok && id == vmid {
			matches++
			node = m.Node
		}
	}
	if matches != 1 || node == "" {
		return fmt.Errorf("VM %d is not a qemu member of pool %s", vmid, cfg.Pool)
	}
	if node != cfg.Node {
		return fmt.Errorf("VM %d is on node %s, not %s", vmid, node, cfg.Node)
	}
	if mode == ModeTag {
		return nil // lib.sh:487-490: the tag mode returns before the tag check
	}
	if mode == ModeDestroy {
		if led == nil {
			return fmt.Errorf("VM %d: destroying needs a created-VM ledger (--created-file) listing the VM", vmid)
		}
		created, err := led.Has(vmid)
		if err != nil {
			return err
		}
		if !created {
			return fmt.Errorf("VM %d was not created by this run; destroying it needs a fresh operator ask", vmid)
		}
	}
	// Tag check (both modes): read the VM's config and prove it carries the
	// harness tag (lib.sh:490-491).
	raw, err := r.RawRequest(ctx, http.MethodGet, vmPath(cfg.Node, vmid, "config"), nil)
	if err != nil {
		return fmt.Errorf("reading VM %d's config failed: %w", vmid, err)
	}
	var conf struct {
		Tags string `json:"tags"`
	}
	if err := json.Unmarshal(raw, &conf); err != nil {
		return fmt.Errorf("VM %d: config has an unexpected shape: %w", vmid, err)
	}
	if !tagsHave(conf.Tags, cfg.Tag) {
		return fmt.Errorf("VM %d does not carry tag %s", vmid, cfg.Tag)
	}
	return nil
}
