package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// The success paths of the commands that cross SSH, pinned through runRoot:
// exit status, the exact stdout line, an empty stderr, and the exact REST
// and SSH sequences — the last two prove the fakes were really on the path,
// so a green test cannot mean "the command never got that far".

// TestNetworkBridgeCreate_Success_ThroughRunRoot: a bridge that does not
// exist yet is created and reported "created".
func TestNetworkBridgeCreate_Success_ThroughRunRoot(t *testing.T) {
	const node, mgmt, iface = "qa-pve-01", "vmbr0", "vmbr1"
	upid := pvefake.NetworkUPID(node, iface)

	rest := pvefake.NewBridgeREST(t, node)
	rest.MgmtFields = `{"iface":"vmbr0","type":"bridge","bridge_ports":"eth0","cidr":"10.0.0.5/24"}`
	rest.IfaceResponses = []string{
		pvefake.IfaceAbsent, // Run's Read: not there yet
		pvefake.IfaceAbsent, // Apply's pre-stage read: still not there
		`{"iface":"vmbr1","type":"bridge","bridge_ports":"eth1"}`,            // guard self-check: staged, not active
		`{"iface":"vmbr1","type":"bridge","bridge_ports":"eth1","active":1}`, // Run's re-read: live
	}
	rest.CommitUPID = upid
	srv := rest.Server()
	defer srv.Close()

	fs := pvefake.NewSSHServer(t)
	var mu sync.Mutex
	ifaceCalls := 0
	fs.HandleExec(func(cmd string) (string, string, int) {
		switch cmd {
		case pvefake.LinkShowCmd(mgmt):
			return pvefake.LinkJSON(mgmt, true), "", 0
		case pvefake.LinkShowCmd(iface):
			mu.Lock()
			n := ifaceCalls
			ifaceCalls++
			mu.Unlock()
			if n == 0 {
				return "", fmt.Sprintf(pvefake.LinkMissingStderrFmt, iface), 1
			}
			return pvefake.LinkJSON(iface, true), "", 0
		}
		return "", "unexpected command", 127
	})
	rosterPath := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	code, stdout, stderr := runRootArgs("network", "bridge", "create", "--roster", rosterPath,
		"--management-bridge", mgmt, "qa-pve-01", iface, "type=bridge", "bridge_ports=eth1")
	if code != 0 {
		t.Fatalf("exit %d; stderr %q", code, stderr)
	}
	if want := "qa-pve-01: bridge vmbr1 created\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
	wantREST := []string{
		"GET /api2/json/nodes/qa-pve-01/network/vmbr1", // Run's Read
		"GET /api2/json/nodes/qa-pve-01/network/vmbr0",
		"GET /api2/json/nodes/qa-pve-01/network/vmbr1", // Apply's pre-stage read
		"POST /api2/json/nodes/qa-pve-01/network",
		"GET /api2/json/nodes/qa-pve-01/network/vmbr0",
		"GET /api2/json/nodes/qa-pve-01/network/vmbr1",
		"PUT /api2/json/nodes/qa-pve-01/network",
		"GET /api2/json/nodes/qa-pve-01/tasks/" + upid + "/status",
		"GET /api2/json/nodes/qa-pve-01/network/vmbr1", // Run's re-read
	}
	if got := rest.Hits(); !slices.Equal(got, wantREST) {
		t.Errorf("REST sequence:\n got:  %v\n want: %v", got, wantREST)
	}
	// The payload, not just the endpoint: the stage carries exactly the
	// requested fields and the interface, and the commit carries nothing.
	wantWrites := []string{
		"POST /api2/json/nodes/qa-pve-01/network bridge_ports=eth1&iface=vmbr1&type=bridge",
		"PUT /api2/json/nodes/qa-pve-01/network",
	}
	if got := rest.Writes(); !slices.Equal(got, wantWrites) {
		t.Errorf("REST writes:\n got:  %q\n want: %q", got, wantWrites)
	}
	wantSSH := []string{pvefake.LinkShowCmd(mgmt), pvefake.LinkShowCmd(iface), pvefake.LinkShowCmd(mgmt), pvefake.LinkShowCmd(iface)}
	if got := fs.Commands(); !slices.Equal(got, wantSSH) {
		t.Errorf("SSH sequence:\n got:  %v\n want: %v", got, wantSSH)
	}
}

// TestNetworkBridgeDestroy_Success_ThroughRunRoot: a live bridge is
// destroyed and reported "destroyed".
func TestNetworkBridgeDestroy_Success_ThroughRunRoot(t *testing.T) {
	const node, mgmt, iface = "qa-pve-01", "vmbr0", "vmbr1"
	upid := pvefake.NetworkUPID(node, iface)

	rest := pvefake.NewBridgeREST(t, node)
	rest.MgmtFields = `{"iface":"vmbr0","type":"bridge","bridge_ports":"eth0","cidr":"10.0.0.5/24"}`
	live := `{"iface":"vmbr1","type":"bridge","bridge_ports":"eth1","active":1}`
	rest.IfaceResponses = []string{
		live,                // Run's Read
		live,                // guard self-check: still active pre-commit
		pvefake.IfaceAbsent, // Run's re-read: gone
	}
	rest.CommitUPID = upid
	srv := rest.Server()
	defer srv.Close()

	fs := pvefake.NewSSHServer(t)
	var mu sync.Mutex
	ifaceCalls := 0
	fs.HandleExec(func(cmd string) (string, string, int) {
		switch cmd {
		case pvefake.LinkShowCmd(mgmt):
			return pvefake.LinkJSON(mgmt, true), "", 0
		case pvefake.LinkShowCmd(iface):
			mu.Lock()
			n := ifaceCalls
			ifaceCalls++
			mu.Unlock()
			if n == 0 {
				return pvefake.LinkJSON(iface, true), "", 0
			}
			return "", fmt.Sprintf(pvefake.LinkMissingStderrFmt, iface), 1
		}
		return "", "unexpected command", 127
	})
	rosterPath := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	code, stdout, stderr := runRootArgs("network", "bridge", "destroy", "--roster", rosterPath,
		"--management-bridge", mgmt, "qa-pve-01", iface)
	if code != 0 {
		t.Fatalf("exit %d; stderr %q", code, stderr)
	}
	if want := "qa-pve-01: bridge vmbr1 destroyed\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
	wantREST := []string{
		"GET /api2/json/nodes/qa-pve-01/network/vmbr1", // Run's Read
		"GET /api2/json/nodes/qa-pve-01/network/vmbr0",
		"DELETE /api2/json/nodes/qa-pve-01/network/vmbr1",
		"GET /api2/json/nodes/qa-pve-01/network/vmbr0",
		"GET /api2/json/nodes/qa-pve-01/network/vmbr1",
		"PUT /api2/json/nodes/qa-pve-01/network",
		"GET /api2/json/nodes/qa-pve-01/tasks/" + upid + "/status",
		"GET /api2/json/nodes/qa-pve-01/network/vmbr1", // Run's re-read
	}
	if got := rest.Hits(); !slices.Equal(got, wantREST) {
		t.Errorf("REST sequence:\n got:  %v\n want: %v", got, wantREST)
	}
	// Neither the stage DELETE nor the commit carries a query or a body.
	wantWrites := []string{
		"DELETE /api2/json/nodes/qa-pve-01/network/vmbr1",
		"PUT /api2/json/nodes/qa-pve-01/network",
	}
	if got := rest.Writes(); !slices.Equal(got, wantWrites) {
		t.Errorf("REST writes:\n got:  %q\n want: %q", got, wantWrites)
	}
	wantSSH := []string{pvefake.LinkShowCmd(mgmt), pvefake.LinkShowCmd(iface), pvefake.LinkShowCmd(mgmt), pvefake.LinkShowCmd(iface)}
	if got := fs.Commands(); !slices.Equal(got, wantSSH) {
		t.Errorf("SSH sequence:\n got:  %v\n want: %v", got, wantSSH)
	}
}

// TestNetworkSet_Success_ThroughRunRoot: a field change is staged,
// committed and reported as one applied line.
func TestNetworkSet_Success_ThroughRunRoot(t *testing.T) {
	const node, iface = "qa-pve-01", "vmbr5"
	upid := pvefake.NetworkUPID(node, iface)

	rest := pvefake.NewFieldsREST(t, node, iface)
	before := `[{"iface":"vmbr5","type":"bridge","mtu":"1500"},{"iface":"vmbr0","bridge_ports":"eth0"}]`
	after := `[{"iface":"vmbr5","type":"bridge","mtu":"9000"},{"iface":"vmbr0","bridge_ports":"eth0"}]`
	rest.ListResponses = []string{before, after} // Apply's pre-stage read, then staged
	rest.IfaceResponses = []string{
		`{"iface":"vmbr5","type":"bridge","mtu":"1500"}`, // Run's Read
		`{"iface":"vmbr5","type":"bridge","mtu":"9000"}`, // Run's re-read
	}
	rest.CommitUPID = upid
	srv := rest.Server()
	defer srv.Close()

	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(func(cmd string) (string, string, int) {
		if cmd == pvefake.LinkShowCmd(iface) {
			return pvefake.LinkJSON(iface, true), "", 0
		}
		return "", "unexpected command", 127
	})
	rosterPath := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	code, stdout, stderr := runRootArgs("network", "set", "--roster", rosterPath, "qa-pve-01", iface, "mtu=9000")
	if code != 0 {
		t.Fatalf("exit %d; stderr %q", code, stderr)
	}
	if want := "qa-pve-01: mtu=9000\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
	wantREST := []string{
		"GET /api2/json/nodes/qa-pve-01/network/vmbr5", // Run's Read
		"GET /api2/json/nodes/qa-pve-01/network",
		"PUT /api2/json/nodes/qa-pve-01/network/vmbr5",
		"GET /api2/json/nodes/qa-pve-01/network",
		"PUT /api2/json/nodes/qa-pve-01/network",
		"GET /api2/json/nodes/qa-pve-01/tasks/" + upid + "/status",
		"GET /api2/json/nodes/qa-pve-01/network/vmbr5", // Run's re-read
	}
	if got := rest.Hits(); !slices.Equal(got, wantREST) {
		t.Errorf("REST sequence:\n got:  %v\n want: %v", got, wantREST)
	}
	// The stage carries exactly the requested value — the value the stdout
	// line reports — and the commit carries nothing.
	wantWrites := []string{
		"PUT /api2/json/nodes/qa-pve-01/network/vmbr5 mtu=9000&type=bridge",
		"PUT /api2/json/nodes/qa-pve-01/network",
	}
	if got := rest.Writes(); !slices.Equal(got, wantWrites) {
		t.Errorf("REST writes:\n got:  %q\n want: %q", got, wantWrites)
	}
	if got, want := fs.Commands(), []string{pvefake.LinkShowCmd(iface)}; !slices.Equal(got, want) {
		t.Errorf("SSH sequence:\n got:  %v\n want: %v", got, want)
	}
}

// TestVMSet_RootOnlyField_Success_ThroughRunRoot: `args` is root-only, so it
// is written with `qm set` over SSH rather than the REST API, and reported
// as one applied line. The fake's config reflects the SSH write, so Run's
// re-read sees it.
func TestVMSet_RootOnlyField_Success_ThroughRunRoot(t *testing.T) {
	var mu sync.Mutex
	config := map[string]string{"digest": "d1", "cores": "2"}
	var hits []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if answerNothingPending(w, r) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		hits = append(hits, r.Method+" "+r.URL.Path)
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var b strings.Builder
		b.WriteString(`{"data":{`)
		first := true
		for k, v := range config {
			if !first {
				b.WriteString(",")
			}
			first = false
			fmt.Fprintf(&b, "%q:%q", k, v)
		}
		b.WriteString("}}")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(b.String()))
	}))
	defer srv.Close()

	const wantCmd = `qm set '100' --args '-cpu host'`
	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(func(cmd string) (string, string, int) {
		if cmd != wantCmd {
			return "", "unexpected command", 127
		}
		mu.Lock()
		config["args"] = "-cpu host"
		mu.Unlock()
		return "", "", 0
	})
	rosterPath := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	code, stdout, stderr := runRootArgs("vm", "set", "--roster", rosterPath, "qa-pve-01", "100", "args=-cpu host")
	if code != 0 {
		t.Fatalf("exit %d; stderr %q", code, stderr)
	}
	if want := "qa-pve-01: args=-cpu host\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty (the re-read must see the SSH write)", stderr)
	}
	mu.Lock()
	gotREST := slices.Clone(hits)
	mu.Unlock()
	wantREST := []string{
		"GET /api2/json/nodes/qa-pve-01/qemu/100/config", // Run's Read
		"GET /api2/json/nodes/qa-pve-01/qemu/100/config", // Run's re-read
	}
	if !slices.Equal(gotREST, wantREST) {
		t.Errorf("REST sequence (the write must not go over REST):\n got:  %v\n want: %v", gotREST, wantREST)
	}
	if got := fs.Commands(); !slices.Equal(got, []string{wantCmd}) {
		t.Errorf("SSH sequence:\n got:  %v\n want: %v", got, []string{wantCmd})
	}
}

// TestNetworkBridgeCreate_ExistingOtherType_RefusedThroughRunRoot: asking to
// create vmbr9 (no type named, so a bridge) when vmbr9 already exists as an
// OVSBridge whose fields otherwise match must NOT report "already up to
// date": it is not what was asked for. It is refused, with nothing written.
func TestNetworkBridgeCreate_ExistingOtherType_RefusedThroughRunRoot(t *testing.T) {
	const node, mgmt, iface = "qa-pve-01", "vmbr0", "vmbr9"
	rest := pvefake.NewBridgeREST(t, node)
	rest.MgmtFields = `{"iface":"vmbr0","type":"bridge","bridge_ports":"eth0","cidr":"10.0.0.5/24"}`
	rest.IfaceFields = `{"iface":"vmbr9","type":"OVSBridge","mtu":"9000","active":1}`
	srv := rest.Server()
	defer srv.Close()

	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(func(cmd string) (string, string, int) {
		if cmd == pvefake.LinkShowCmd(mgmt) {
			return pvefake.LinkJSON(mgmt, true), "", 0
		}
		return "", "unexpected command", 127
	})
	rosterPath := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	code, stdout, stderr := runRootArgs("network", "bridge", "create", "--roster", rosterPath,
		"--management-bridge", mgmt, "qa-pve-01", iface, "mtu=9000")
	if code != 1 {
		t.Fatalf("exit %d, want 1; stdout %q, stderr %q", code, stdout, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing: neither created nor already up to date", stdout)
	}
	if strings.Count(stderr, "\n") != 1 || !strings.Contains(stderr, `already exists as type OVSBridge, not bridge`) {
		t.Errorf("stderr = %q, want one line naming the existing type", stderr)
	}
	if got := rest.Writes(); len(got) != 0 {
		t.Errorf("writes = %q, want none: nothing may be staged", got)
	}
}
