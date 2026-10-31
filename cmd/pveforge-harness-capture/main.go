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
// In its A-RO mode it performs read-only GETs: the item-66 golden gate across
// the nested nodes (every node's qemu list must be empty, else it refuses with
// "cluster not at golden"), and one raw GET whose negotiated protocol and raw
// pre-unwrap body bytes (with sha256) answer item 66's null-vs-[] and item 68's
// HTTP/2.
//
// It is NO LONGER read-only. The A-MUT legs read UPIDs of mutations the operator
// ran; the Batch C legs (items 74/75/77) make the tool ITSELF a mutator — it
// clones, snapshots, creates and destroys nested guests — and clean up the
// guests they create via DestroyVM + the gone oracle. Never point a Batch C run
// at anything but the disposable nested `pvh` cluster. Batch C guest VMIDs are
// bounded by the 2026-09-24 operator ruling (create/destroy 690–699 inclusive).
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
	"strconv"

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

	// A-MUT captures (items 68-agent, 69, 70a/70b).
	AgentRejection   *pve.AgentRejection  `json:"agent_rejection,omitempty"`
	UPIDSpellings    []pve.UPIDSpelling   `json:"upid_spellings,omitempty"`
	TaskExitStatuses []pve.TaskExitStatus `json:"task_exit_statuses,omitempty"`

	// Batch C (storage-free safety): items 74/75/76/77.
	CloneVolid     *pve.CloneVolidCapture      `json:"clone_volid,omitempty"`      // C1 (74)
	VmstateSection *pve.SnapshotSectionCapture `json:"vmstate_section,omitempty"`  // C2 (75)
	TokenShortList *pve.TokenShortListCapture  `json:"token_short_list,omitempty"` // C3 (76)
	CrossNodeVMID  *pve.CrossNodeCreateCapture `json:"cross_node_vmid,omitempty"`  // C4 (77)

	// U-CWCV §2 cross-node API-proxy proof (the shared-free MERGE GATE): does
	// node A's API serve node B's OWN config for /nodes/{B}/qemu/{vmid}/config.
	CrossNodeProxy *pve.CrossNodeProxyCapture `json:"cross_node_proxy,omitempty"`

	// Errors records a per-leg failure without aborting the whole capture.
	Errors []string `json:"errors,omitempty"`
}

// amutRequested reports whether any A-MUT capture flag is set. When true the
// golden gate (which requires zero guests) is skipped: A-MUT needs a live guest.
func amutRequested(agentVMID, qmcreateVMID int, upids []string, vzdumpUPID, userUPID, exitstatusUPID string) bool {
	return agentVMID != 0 || qmcreateVMID != 0 || len(upids) > 0 || vzdumpUPID != "" || userUPID != "" || exitstatusUPID != ""
}

// batchcRequested reports whether any Batch C capture flag is set. Like
// amutRequested it suppresses the golden gate: every Batch C leg needs ≥1 live
// nested guest, so a Batch-C-only run must NOT also demand a zero-guest cluster.
// It is folded into amutMode at the same site so a Batch C run skips the gate.
func batchcRequested(c1CloneVMID, c2VMID, c4TakenVMID int, c3RestrictedTarget string) bool {
	return c1CloneVMID != 0 || c2VMID != 0 || c4TakenVMID != 0 || c3RestrictedTarget != ""
}

// cwcvRequested reports whether the U-CWCV §2 cross-node proxy-proof leg is set.
// Like the Batch C legs it needs a LIVE guest (on node B), so it suppresses the
// golden gate: it is folded into amutMode so a cross-node-proxy run does NOT
// also demand a zero-guest cluster.
func cwcvRequested(cwcvVMID int) bool { return cwcvVMID != 0 }

// qmcreateSpellingErrors asserts a recovered qmcreate UPID's spelling: type
// `qmcreate`, id the VMID, and a valid shape.
func qmcreateSpellingErrors(sp *pve.UPIDSpelling, vmid int) []string {
	var errs []string
	qt, vmidStr := "qmcreate", strconv.Itoa(vmid)
	if err := sp.Check(pve.ExpectUPID{Type: &qt, ID: &vmidStr}); err != nil {
		errs = append(errs, "item-70a: "+err.Error())
	}
	if !sp.Valid {
		errs = append(errs, fmt.Sprintf("item-70a: qmcreate UPID %q failed validateUPIDShape: %s", sp.UPID, sp.ValidErr))
	}
	return errs
}

// vzdumpSpellingErrors asserts a vzdump-all UPID: type `vzdump`, an EMPTY id,
// and a valid shape — so a non-vzdump UPID is caught even if its id is empty.
func vzdumpSpellingErrors(sp *pve.UPIDSpelling) []string {
	var errs []string
	vt, empty := "vzdump", ""
	if err := sp.Check(pve.ExpectUPID{Type: &vt, ID: &empty}); err != nil {
		errs = append(errs, "item-70a: "+err.Error())
	}
	if !sp.Valid {
		errs = append(errs, fmt.Sprintf("item-70a: vzdump UPID %q failed validateUPIDShape: %s", sp.UPID, sp.ValidErr))
	}
	return errs
}

// userSpellingErrors asserts a 70(b) UPID's user field equals expectUser (never
// empty here — the caller enforces that) and that its shape is valid.
func userSpellingErrors(sp *pve.UPIDSpelling, expectUser string) []string {
	var errs []string
	if err := sp.Check(pve.ExpectUPID{User: &expectUser}); err != nil {
		errs = append(errs, "item-70b: "+err.Error())
	}
	if !sp.Valid {
		errs = append(errs, fmt.Sprintf("item-70b: UPID %q failed validateUPIDShape: %s", sp.UPID, sp.ValidErr))
	}
	return errs
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
	// A-MUT probes (each optional; 0/empty = skip). The assertion is the gate.
	agentVMID := flag.Int("agent-vmid", 0, "item-68: a running agent-off VMID; captures + asserts the agent-off rejection (0=skip)")
	qmcreateVMID := flag.Int("qmcreate-vmid", 0, "item-70a: recover+record the qmcreate UPID spelling for this VMID from the task list (0=skip)")
	qmcreateSince := flag.Int64("qmcreate-since", 0, "item-70a: the create dispatch time (unix seconds); REQUIRED with -qmcreate-vmid so a stale/reused-id qmcreate is not picked")
	var upids nodeList
	flag.Var(&upids, "upid", "item-70: a UPID to parse+validate (repeatable)")
	vzdumpUPID := flag.String("vzdump-upid", "", "item-70a: a vzdump UPID; asserts its id field is EMPTY (all-guests) (empty=skip)")
	userUPID := flag.String("user-upid", "", "item-70b: a UPID to assert the user field of (empty=skip)")
	expectUser := flag.String("expect-user", "", "item-70b: the user field -user-upid must carry")
	exitstatusUPID := flag.String("exitstatus-upid", "", "item-69: a UPID; reads PVE's own task status and asserts exitstatus ^WARNINGS: n$ (empty=skip)")
	// Batch C probes (each optional; 0/empty = skip). The tool MUTATES for these.
	c1CloneStorage := flag.String("c1-clone-storage", "", "item-74: the nested storage the clone/template live on (e.g. local-lvm)")
	c1TemplateVMID := flag.Int("c1-template-vmid", 0, "item-74: an existing TEMPLATE VMID to linked-clone (operator precondition — OQ-5)")
	c1CloneVMID := flag.Int("c1-clone-vmid", 0, "item-74: the VMID for the linked clone (690–699); created+destroyed by this tool (0=skip)")
	c2Storage := flag.String("c2-storage", "", "item-75: the nested storage the guest's disk lives on")
	c2VMID := flag.Int("c2-vmid", 0, "item-75: an existing guest VMID to start+snapshot (vmstate); its snapshot is deleted after (0=skip)")
	c2Snap := flag.String("c2-snap", "", "item-75: the snapshot name to create (required with -c2-vmid)")
	c3RestrictedTarget := flag.String("c3-restricted-target", "", "item-76: a SECOND roster target (view-restricted token, OQ-3) to compare list length against (empty=skip)")
	c3Storage := flag.String("c3-storage", "", "item-76: the storage the hidden VM's volume lives on")
	c3HiddenVolid := flag.String("c3-hidden-volid", "", "item-76: a volid owned by a VM the restricted token cannot see")
	c3HiddenVMID := flag.Int("c3-hidden-vmid", 0, "item-76: the VMID that owns -c3-hidden-volid (for OrphanVolumesForVMID, the free's DELETE selector)")
	c4TakenVMID := flag.Int("c4-taken-vmid", 0, "item-77: a VMID that already exists on -c4-other-node; a colliding create is attempted on the target node (0=skip)")
	c4OtherNode := flag.String("c4-other-node", "", "item-77: the node where -c4-taken-vmid already exists")
	c4FreeVMID := flag.Int("c4-free-vmid", 0, "item-77: a VMID known FREE, for the nextid free-direction probe")
	// U-CWCV §2 cross-node proxy proof (A-MUT class; needs a live guest on node B).
	cwcvBoundHost := flag.String("cwcv-bound-host", "", "U-CWCV §2: node A's API host (this client's bound host); must match the client's base URL host (empty=skip)")
	cwcvTargetNode := flag.String("cwcv-target-node", "", "U-CWCV §2: node B, whose /nodes/{B}/qemu/{vmid}/config is read through node A's API")
	cwcvVMID := flag.Int("cwcv-vmid", 0, "U-CWCV §2: a VMID that lives on -cwcv-target-node (node B) carrying the B-unique marker (0=skip)")
	cwcvMarkerField := flag.String("cwcv-marker-field", "", "U-CWCV §2: the config field set to a B-unique value (e.g. scsi0 or description)")
	cwcvMarkerValue := flag.String("cwcv-marker-value", "", "U-CWCV §2: the exact B-unique value -cwcv-marker-field must carry")
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

	// F5: the golden gate REQUIRES zero guests; the A-MUT captures REQUIRE a
	// live guest — they cannot both hold in one process. So the golden gate
	// runs ONLY in A-RO mode (no A-MUT flag). The golden precondition for an
	// A-MUT run is a SEPARATE prior A-RO invocation, before the guest is
	// created. In A-MUT mode gateErr stays nil, so the exit reflects the A-MUT
	// assertions alone, never a golden refusal.
	amutMode := amutRequested(*agentVMID, *qmcreateVMID, upids, *vzdumpUPID, *userUPID, *exitstatusUPID) ||
		batchcRequested(*c1CloneVMID, *c2VMID, *c4TakenVMID, *c3RestrictedTarget) ||
		cwcvRequested(*cwcvVMID)
	var gateErr error
	if !amutMode {
		shapes, err := c.GoldenGateEmpty(ctx, []string(nodes))
		report.NodeShapes = shapes
		report.GoldenAtRest = err == nil
		gateErr = err
	}

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

	// ---- A-MUT captures (items 68-agent, 69, 70a/70b) ----
	// item 68: the agent-off rejection on a running agent-declared-but-absent
	// guest. A rejection that is NOT agent-off (a not-found 500, a 595/596, an
	// auth error) fails the assertion.
	if *agentVMID != 0 {
		if rej, err := c.CaptureAgentRejection(ctx, probeNodeName, *agentVMID); err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			report.AgentRejection = rej
			if !rej.AgentOff {
				report.Errors = append(report.Errors, fmt.Sprintf("item-68: vm %d rejection is not agent-off (code=%d, text=%q)", *agentVMID, rej.Code, rej.RejectionText))
			}
		}
	}

	// item 70a: recover the qmcreate UPID by type AND id within the create
	// window (since), then assert its spelling (type+id) and validity.
	if *qmcreateVMID != 0 {
		if *qmcreateSince == 0 {
			report.Errors = append(report.Errors, "item-70a: -qmcreate-since (create dispatch time, unix seconds) is required with -qmcreate-vmid")
		} else {
			vmidStr := strconv.Itoa(*qmcreateVMID)
			if upid, err := c.FindTaskUPID(ctx, probeNodeName, "qmcreate", vmidStr, *qmcreateSince); err != nil {
				report.Errors = append(report.Errors, err.Error())
			} else if sp, err := pve.ParseUPIDSpelling(upid); err != nil {
				report.Errors = append(report.Errors, err.Error())
			} else {
				report.UPIDSpellings = append(report.UPIDSpellings, *sp)
				report.Errors = append(report.Errors, qmcreateSpellingErrors(sp, *qmcreateVMID)...)
			}
		}
	}

	// item 70: parse+validate each supplied UPID; a malformed one fails.
	for _, u := range upids {
		if sp, err := pve.ParseUPIDSpelling(u); err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			report.UPIDSpellings = append(report.UPIDSpellings, *sp)
			if !sp.Valid {
				report.Errors = append(report.Errors, fmt.Sprintf("item-70: UPID %q failed validateUPIDShape: %s", u, sp.ValidErr))
			}
		}
	}

	// item 70a: the vzdump-all UPID must be a VALID vzdump task with an EMPTY id.
	if *vzdumpUPID != "" {
		if sp, err := pve.ParseUPIDSpelling(*vzdumpUPID); err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			report.UPIDSpellings = append(report.UPIDSpellings, *sp)
			report.Errors = append(report.Errors, vzdumpSpellingErrors(sp)...)
		}
	}

	// item 70b: the user/token UPID must carry the expected principal; the
	// expectation is MANDATORY — a UPID with no principal assertion is refused.
	if *userUPID != "" {
		if *expectUser == "" {
			report.Errors = append(report.Errors, "item-70b: -expect-user is required with -user-upid (refusing to record a UPID with no principal assertion)")
		} else if sp, err := pve.ParseUPIDSpelling(*userUPID); err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			report.UPIDSpellings = append(report.UPIDSpellings, *sp)
			report.Errors = append(report.Errors, userSpellingErrors(sp, *expectUser)...)
		}
	}

	// item 69: PVE's own task exitstatus must be exactly WARNINGS: n.
	if *exitstatusUPID != "" {
		if es, err := c.CaptureTaskExitStatus(ctx, probeNodeName, *exitstatusUPID); err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			report.TaskExitStatuses = append(report.TaskExitStatuses, *es)
			if !es.IsWarnings {
				report.Errors = append(report.Errors, fmt.Sprintf("item-69: task %q exitstatus %q is not WARNINGS: n (vacuous — re-induce)", *exitstatusUPID, es.ExitStatus))
			}
		}
	}

	// ---- Batch C captures (items 74/75/76/77). The tool MUTATES here. ----
	// Each leg's Failures() — not any exit status — is the gate: a failed
	// assertion appends to report.Errors (the A-MUT branch), and the tool exits
	// nonzero below. Each live orchestrator cleans up the guests it creates.

	// item 74: linked-clone disk volid identity on nested local-lvm.
	if *c1CloneVMID != 0 {
		if *c1TemplateVMID == 0 || *c1CloneStorage == "" {
			report.Errors = append(report.Errors, "item-74: -c1-template-vmid and -c1-clone-storage are required with -c1-clone-vmid")
		} else if capt, err := c.RunCloneVolidCapture(ctx, probeNodeName, *c1CloneStorage, *c1TemplateVMID, *c1CloneVMID); err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			report.CloneVolid = capt
			report.Errors = append(report.Errors, capt.Failures()...)
		}
	}

	// item 75: vmstate / snapshot-section claimed-surface gap.
	if *c2VMID != 0 {
		if *c2Snap == "" || *c2Storage == "" {
			report.Errors = append(report.Errors, "item-75: -c2-snap and -c2-storage are required with -c2-vmid")
		} else if capt, err := c.RunVmstateCapture(ctx, probeNodeName, *c2Storage, *c2VMID, *c2Snap); err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			report.VmstateSection = capt
			report.Errors = append(report.Errors, capt.Failures()...)
		}
	}

	// item 76: token-view-rights short list (two clients; restricted is OQ-3).
	if *c3RestrictedTarget != "" {
		if *c3Storage == "" || *c3HiddenVolid == "" || *c3HiddenVMID == 0 {
			report.Errors = append(report.Errors, "item-76: -c3-storage, -c3-hidden-volid and -c3-hidden-vmid are required with -c3-restricted-target")
		} else if rt := r.Find(*c3RestrictedTarget); rt == nil {
			report.Errors = append(report.Errors, fmt.Sprintf("item-76: restricted target %q not found in %s", *c3RestrictedTarget, *rosterPath))
		} else if restricted, err := pve.NewClientForTarget(rt, passphrase); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("item-76: build restricted client: %v", err))
		} else if capt, err := c.CaptureTokenShortList(ctx, restricted, probeNodeName, *c3Storage, *target, *c3RestrictedTarget, *c3HiddenVolid, *c3HiddenVMID); err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			report.TokenShortList = capt
			report.Errors = append(report.Errors, capt.Failures()...)
		}
	}

	// item 77: cross-node VMID collision + the nextid oracle, both directions.
	if *c4TakenVMID != 0 {
		if *c4OtherNode == "" || *c4FreeVMID == 0 {
			report.Errors = append(report.Errors, "item-77: -c4-other-node and -c4-free-vmid are required with -c4-taken-vmid")
		} else if capt, err := c.RunCrossNodeCapture(ctx, *c4TakenVMID, *c4FreeVMID, *c4OtherNode, probeNodeName); err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			report.CrossNodeVMID = capt
			report.Errors = append(report.Errors, capt.Failures()...)
		}
	}

	// ---- U-CWCV §2 cross-node API-proxy proof (the shared-free MERGE GATE) ----
	// Reads node B's config through node A's API and proves the answer is B's OWN
	// config by an EXACT B-unique field-value match (not a substring of the raw
	// body) AND that this client is actually bound to node A's host. A false
	// proof, or any read error, appends to report.Errors and exits nonzero. This
	// proof gated the shared-storage free until it passed GREEN on the nested
	// `pvh` harness 2026-10-30; the gate is now removed and this leg remains the
	// re-runnable evidence.
	if *cwcvVMID != 0 {
		if *cwcvBoundHost == "" || *cwcvTargetNode == "" || *cwcvMarkerField == "" || *cwcvMarkerValue == "" {
			report.Errors = append(report.Errors, "cwcv: -cwcv-bound-host, -cwcv-target-node, -cwcv-marker-field and -cwcv-marker-value are all required with -cwcv-vmid")
		} else if capt, err := c.CaptureCrossNodeProxy(ctx, *cwcvBoundHost, *cwcvTargetNode, *cwcvVMID, *cwcvMarkerField, *cwcvMarkerValue); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("cwcv: %v", err))
		} else {
			report.CrossNodeProxy = capt
			if !capt.Proven {
				report.Errors = append(report.Errors, fmt.Sprintf("cwcv: cross-node proxy NOT proven (bound-host-ok=%v, field %q got %q want %q) — node A did not serve node B's own config; the shared-storage free must stay gated", capt.BoundHostOK, capt.MarkerField, capt.GotValue, capt.WantMarker))
			}
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
