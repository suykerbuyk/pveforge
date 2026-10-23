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
	"net/url"
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

	// Item 67 (read-swallow shapes): absence answers and field presence.
	Item67Absences []pve.AbsenceCapture `json:"item67_absences,omitempty"`
	Item67Fields   []pve.FieldPresence  `json:"item67_fields,omitempty"`

	// Item 66 corroborator: /cluster/resources?type=vm, classified from RAW
	// bytes (N2) — not a findbytag guard decode.
	CorroboratorPath   string        `json:"corroborator_path,omitempty"`
	CorroboratorShape  pve.ListShape `json:"corroborator_shape,omitempty"`
	CorroboratorSHA256 string        `json:"corroborator_sha256,omitempty"`
	CorroboratorBody   string        `json:"corroborator_body,omitempty"`
	CorroboratorNote   string        `json:"corroborator_note,omitempty"`

	// Errors records a per-leg failure without aborting the whole capture.
	Errors []string `json:"errors,omitempty"`
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
	// Item 67 + corroborator probe targets (each optional; 0/empty = skip).
	probeNode := flag.String("probe-node", "", "node for item-67 probes (default first -node)")
	absentVMID := flag.Int("absent-vmid", 0, "a VMID known NOT to exist: item-67 missing-VM-config probe (0=skip)")
	absentIface := flag.String("absent-iface", "", "an interface known NOT to exist: item-67 missing-iface probe (empty=skip)")
	absentStorage := flag.String("absent-storage", "", "a storage known NOT to exist: item-67 missing-storage probe (empty=skip)")
	absentUPID := flag.String("absent-upid", "", "an unknown UPID: item-67 raw probe, no subject (empty=skip)")
	fieldVMID := flag.Int("field-vmid", 0, "an existing VMID: item-67 field presence (status + digest; 0=skip)")
	fieldStorage := flag.String("field-storage", "", "an existing storage: item-67 field presence (type; empty=skip)")
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
	probeNodeName := *probeNode
	if probeNodeName == "" {
		probeNodeName = nodes[0]
	}

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

	// Item 67 absence legs (each optional). A leg's own failure is recorded,
	// not fatal, so one missing probe target does not lose the others.
	type absenceLeg struct {
		on    bool
		probe pve.AbsenceProbe
	}
	for _, leg := range []absenceLeg{
		{*absentVMID != 0, pve.AbsenceProbe{Name: "vm-config-missing", Path: fmt.Sprintf("/nodes/%s/qemu/%d/config", probeNodeName, *absentVMID), Subject: pve.VMConfigMissingSubject(*absentVMID)}},
		{*absentIface != "", pve.AbsenceProbe{Name: "iface-missing", Path: fmt.Sprintf("/nodes/%s/network/%s", probeNodeName, *absentIface), Subject: pve.IfaceMissingSubject(*absentIface)}},
		{*absentStorage != "", pve.AbsenceProbe{Name: "storage-missing", Path: fmt.Sprintf("/nodes/%s/storage/%s/status", probeNodeName, *absentStorage), Subject: pve.StorageMissingSubject(*absentStorage)}},
		{*absentUPID != "", pve.AbsenceProbe{Name: "upid-unknown", Path: fmt.Sprintf("/nodes/%s/tasks/%s/status", probeNodeName, url.PathEscape(*absentUPID)), Subject: pve.Subject{}}},
	} {
		if !leg.on {
			continue
		}
		if cap, err := c.CaptureAbsence(ctx, leg.probe); err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			report.Item67Absences = append(report.Item67Absences, *cap)
		}
	}

	// Item 67 field-presence legs (each optional).
	if *fieldStorage != "" {
		if fp, err := c.CaptureStorageType(ctx, probeNodeName, *fieldStorage); err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			report.Item67Fields = append(report.Item67Fields, *fp)
		}
	}
	if *fieldVMID != 0 {
		if fp, err := c.CaptureVMStatusField(ctx, probeNodeName, *fieldVMID); err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			report.Item67Fields = append(report.Item67Fields, *fp)
		}
		if fp, err := c.CaptureVMConfigDigest(ctx, probeNodeName, *fieldVMID); err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			report.Item67Fields = append(report.Item67Fields, *fp)
		}
	}

	// Item 66 corroborator: raw bytes of the cluster-wide VM list.
	report.CorroboratorPath = "/cluster/resources?type=vm"
	report.CorroboratorNote = "raw bytes + deterministic Go null->nil / []->empty (N2); NOT a findbytag guard decode"
	if corr, err := c.CaptureRawGET(ctx, report.CorroboratorPath); err != nil {
		report.Errors = append(report.Errors, err.Error())
	} else {
		report.CorroboratorSHA256 = corr.SHA256
		report.CorroboratorBody = string(corr.Body)
		if shape, serr := pve.ClassifyRawListEnvelope(corr.Body); serr != nil {
			report.Errors = append(report.Errors, serr.Error())
		} else {
			report.CorroboratorShape = shape
		}
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
	if len(report.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "pveforge-harness-capture: %d capture leg(s) failed (see JSON errors)\n", len(report.Errors))
		return 1
	}
	return 0
}
