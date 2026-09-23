package idempotent

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

// This file is 3b's own full-stack integration test, the sibling of
// networkbridge_integration_test.go (3a): NetworkFieldsEnsure's Apply
// driven against a REAL *pve.RoutedClient — reached only through pve's own
// exported pve.NewRoutedClient constructor — backed by a fake REST server
// AND a fake SSH server together. The fake SSH server and the scripted
// REST server (FieldsREST) come from internal/pvefake; the target comes from
// networkbridge_integration_test.go's bootstrappedIntegrationTarget (same
// package). Only the REST script differs from 3a's: NetworkFieldsEnsure's guard
// reads the raw LIST endpoint (no per-management-bridge GET), and there is
// no second SSH command for a management bridge — see
// NetworkFieldsEnsure's own "no step-4-equivalent guard self-check" doc
// comment for why its SSH surface is smaller than 3a's.

// TestNetworkFieldsEnsure_Apply_MTUSet_FullStack drives NetworkFieldsEnsure
// .Apply against a REAL *pve.RoutedClient, backed by a fake REST server and
// a fake SSH server together. Asserts, in order, the exact HTTP
// method+path sequence hit, the exact SSH command sequence run (just the
// ONE post-apply check on the target iface — no management-bridge SSH call
// at all, unlike 3a), and that Apply returns no error.
func TestNetworkFieldsEnsure_Apply_MTUSet_FullStack(t *testing.T) {
	const node = "qa-pve-01"
	const targetIface = "vmbr5"

	upid := pvefake.NetworkUPID(node, targetIface)
	restScript := pvefake.NewFieldsREST(t, node, targetIface)
	beforeList := `[{"iface":"vmbr5","type":"bridge","mtu":"1500"},{"iface":"vmbr0","bridge_ports":"eth0"}]`
	afterList := `[{"iface":"vmbr5","type":"bridge","mtu":"9000"},{"iface":"vmbr0","bridge_ports":"eth0"}]` // only the target changed
	restScript.ListResponses = []string{beforeList, afterList}
	restScript.CommitUPID = upid
	restSrv := restScript.Server()
	defer restSrv.Close()

	fs := pvefake.NewSSHServer(t)
	targetCmd := fmt.Sprintf("ip -j link show dev '%s'", targetIface)
	fs.HandleExec(func(cmd string) (string, string, int) {
		switch cmd {
		case targetCmd:
			return pvefake.LinkJSON(targetIface, true), "", 0
		default:
			t.Errorf("unexpected ssh command: %q", cmd) // not Fatalf: this runs on the fake server's goroutine
			return "", "unexpected ssh command", 127
		}
	})

	tg := bootstrappedIntegrationTarget(t, restSrv, fs, "roster-pass")
	restore := pve.SetSSHPortForIntegrationTests(fs.Port(t))
	t.Cleanup(restore)

	rc, err := pve.NewRoutedClient(tg, "roster-pass")
	if err != nil {
		t.Fatalf("NewRoutedClient: %v", err)
	}
	defer func() { _ = rc.Close() }()

	op := &NetworkFieldsEnsure{
		Client: rc,
		Node:   rc.Node(),
		Iface:  targetIface,
		Pairs:  []kvjson.Pair{{Field: "mtu", Value: "9000"}},
	}
	if err := op.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	wantREST := []string{
		"GET /api2/json/nodes/qa-pve-01/network",
		"PUT /api2/json/nodes/qa-pve-01/network/vmbr5",
		"GET /api2/json/nodes/qa-pve-01/network",
		"PUT /api2/json/nodes/qa-pve-01/network",
		"GET /api2/json/nodes/qa-pve-01/tasks/" + upid + "/status",
	}
	if got := restScript.Hits(); !equalStringSlices(got, wantREST) {
		t.Fatalf("REST hit sequence:\n got:  %v\n want: %v", got, wantREST)
	}
	wantWrites := []string{
		"PUT /api2/json/nodes/qa-pve-01/network/vmbr5 mtu=9000&type=bridge",
		"PUT /api2/json/nodes/qa-pve-01/network",
	}
	if got := restScript.Writes(); !equalStringSlices(got, wantWrites) {
		t.Fatalf("REST writes:\n got:  %q\n want: %q", got, wantWrites)
	}

	wantSSH := []string{targetCmd}
	if got := fs.Commands(); !equalStringSlices(got, wantSSH) {
		t.Fatalf("SSH command sequence:\n got:  %v\n want: %v", got, wantSSH)
	}
}

// TestNetworkFieldsEnsure_Apply_DecoyInterfaceChanged_FullStack is the
// abort-path mirror: a DIFFERENT (decoy) interface's staged config changes
// between the pre-stage and post-stage LIST reads, so Apply must refuse to
// commit and instead revert — same real RoutedClient/REST/SSH harness.
func TestNetworkFieldsEnsure_Apply_DecoyInterfaceChanged_FullStack(t *testing.T) {
	const node = "qa-pve-01"
	const targetIface = "vmbr5"

	restScript := pvefake.NewFieldsREST(t, node, targetIface)
	beforeList := `[{"iface":"vmbr5","type":"bridge","mtu":"1500"},{"iface":"vmbr0","bridge_ports":"eth0"}]`
	afterList := `[{"iface":"vmbr5","type":"bridge","mtu":"9000"},{"iface":"vmbr0","bridge_ports":"eth9"}]` // decoy vmbr0 changed
	restScript.ListResponses = []string{beforeList, afterList}
	restSrv := restScript.Server()
	defer restSrv.Close()

	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(func(cmd string) (string, string, int) {
		t.Errorf("unexpected ssh command: %q (no SSH call should happen on an aborted apply)", cmd) // not Fatalf: this runs on the fake server's goroutine
		return "", "unexpected ssh command", 127
	})

	tg := bootstrappedIntegrationTarget(t, restSrv, fs, "roster-pass")
	restore := pve.SetSSHPortForIntegrationTests(fs.Port(t))
	t.Cleanup(restore)

	rc, err := pve.NewRoutedClient(tg, "roster-pass")
	if err != nil {
		t.Fatalf("NewRoutedClient: %v", err)
	}
	defer func() { _ = rc.Close() }()

	op := &NetworkFieldsEnsure{
		Client: rc,
		Node:   rc.Node(),
		Iface:  targetIface,
		Pairs:  []kvjson.Pair{{Field: "mtu", Value: "9000"}},
	}
	if err := op.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	err = op.Apply(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "vmbr0") {
		t.Fatalf("expected error to name the changed OTHER interface vmbr0, got %v", err)
	}

	wantREST := []string{
		"GET /api2/json/nodes/qa-pve-01/network",
		"PUT /api2/json/nodes/qa-pve-01/network/vmbr5",
		"GET /api2/json/nodes/qa-pve-01/network",
		"DELETE /api2/json/nodes/qa-pve-01/network", // revert; commit never reached
	}
	if got := restScript.Hits(); !equalStringSlices(got, wantREST) {
		t.Fatalf("REST hit sequence:\n got:  %v\n want: %v", got, wantREST)
	}
	wantWrites := []string{
		"PUT /api2/json/nodes/qa-pve-01/network/vmbr5 mtu=9000&type=bridge",
		"DELETE /api2/json/nodes/qa-pve-01/network", // the revert carries nothing
	}
	if got := restScript.Writes(); !equalStringSlices(got, wantWrites) {
		t.Fatalf("REST writes:\n got:  %q\n want: %q", got, wantWrites)
	}
}
