//go:build harness

// Command pveforge-harness-capture is the Batch A A-RO capture instrument's
// runnable entry point (pveforge-nested-pve-test-harness, items 66 and 68). It
// builds the nested target's REST client the production way — the nested roster
// plus its passphrase and TLS pin, through pve.NewRoutedClient — and calls the
// package-pve capture methods (capture_harness.go) that reach the unexported
// pinned client and decode path no accessor exposes.
//
// Being a non-test binary, internal/netguard is never installed (it panics
// outside `go test`), so this tool can dial the nested `pvh` cluster, while the
// package-pve capture code stays verifiable on loopback under the test guard.
//
// It performs ONLY read-only GETs: the item-66 golden gate across the nested
// nodes (every node's qemu list must be empty, else it refuses with
// "cluster not at golden"), and one raw GET whose negotiated protocol and raw
// pre-unwrap body bytes (with sha256) answer item 66's null-vs-[] and item 68's
// HTTP/2. It writes nothing to the cluster.
//
// Usage:
//
//	PVEFORGE_ROSTER_PASSPHRASE=... pveforge-harness-capture \
//	  -roster "$PVEFORGE_HARNESS_ROSTER" -target pvh-n1 \
//	  [-node pvh-n1 -node pvh-n2] [-path /nodes/pvh-n1/qemu]
//
// The roster path is an explicit flag (the caller passes the nested roster,
// e.g. the harness scripts' own value) rather than read from the environment
// here. It is meant to run through unlock.sh so the passphrase reaches it in
// the child environment only. Exit status: 0 captured, 1 a capture error or a
// golden-gate refusal, 2 a usage error.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/suykerbuyk/pveforge/internal/harness"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// nodeList collects repeated -node flags.
type nodeList []string

func (n *nodeList) String() string { return fmt.Sprintf("%v", []string(*n)) }
func (n *nodeList) Set(v string) error {
	*n = append(*n, v)
	return nil
}

// captureReport is the evidence this tool prints as JSON.
type captureReport struct {
	Target       string                   `json:"target"`
	GoldenAtRest bool                     `json:"golden_at_rest"`
	NodeShapes   map[string]pve.ListShape `json:"node_shapes"`
	RawPath      string                   `json:"raw_path"`
	RawProto     string                   `json:"raw_proto"`
	RawStatus    string                   `json:"raw_status"`
	RawSHA256    string                   `json:"raw_sha256"`
	RawBody      string                   `json:"raw_body"`
}

func main() {
	os.Exit(run())
}

func run() int {
	rosterPath := flag.String("roster", "", "nested roster path (required)")
	target := flag.String("target", "", "roster target id to capture through (required)")
	path := flag.String("path", "", "raw-GET path for the item-66/68 capture (default /nodes/<first node>/qemu)")
	var nodes nodeList
	flag.Var(&nodes, "node", "nested node whose qemu list must be empty at golden (repeatable; default pvh-n1, pvh-n2)")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "pveforge-harness-capture: -target is required")
		return 2
	}
	if *rosterPath == "" {
		fmt.Fprintln(os.Stderr, "pveforge-harness-capture: -roster is required")
		return 2
	}
	if len(nodes) == 0 {
		nodes = nodeList(harness.NodeNames) // the nested cluster's nodes, exactly (guard.go:77)
	}
	if *path == "" {
		*path = fmt.Sprintf("/nodes/%s/qemu", nodes[0])
	}

	ctx := context.Background()
	passphrase, err := roster.ResolvePassphraseContext(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pveforge-harness-capture: resolve passphrase: %v\n", err)
		return 1
	}
	r, err := roster.Load(*rosterPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pveforge-harness-capture: load roster %s: %v\n", *rosterPath, err)
		return 1
	}
	t := r.Find(*target)
	if t == nil {
		fmt.Fprintf(os.Stderr, "pveforge-harness-capture: target %q not found in %s\n", *target, *rosterPath)
		return 1
	}
	// NewClientForTarget is the same REST constructor NewRoutedClient uses
	// (routed.go:112): roster target + passphrase + TLS pin, decrypted the
	// production way. The REST side has no persistent connection to close.
	c, err := pve.NewClientForTarget(t, passphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pveforge-harness-capture: build client: %v\n", err)
		return 1
	}

	report := captureReport{Target: *target, RawPath: *path}

	shapes, gateErr := c.GoldenGateEmpty(ctx, []string(nodes))
	report.NodeShapes = shapes
	report.GoldenAtRest = gateErr == nil

	raw, rawErr := c.CaptureRawGET(ctx, *path)
	if rawErr == nil {
		report.RawProto = raw.Proto
		report.RawStatus = raw.Status
		report.RawSHA256 = raw.SHA256
		report.RawBody = string(raw.Body)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(report)

	if errors.Is(gateErr, pve.ErrNotAtGolden) {
		fmt.Fprintf(os.Stderr, "pveforge-harness-capture: %v\n", gateErr)
		return 1
	}
	if gateErr != nil {
		fmt.Fprintf(os.Stderr, "pveforge-harness-capture: golden gate: %v\n", gateErr)
		return 1
	}
	if rawErr != nil {
		fmt.Fprintf(os.Stderr, "pveforge-harness-capture: raw capture: %v\n", rawErr)
		return 1
	}
	return 0
}
