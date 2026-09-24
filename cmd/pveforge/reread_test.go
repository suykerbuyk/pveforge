package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// pveforge-run-post-apply-read-error-signal: every command whose Run can
// report a failed final re-read (Result.AfterErr) says so, in one stderr
// line after its own stdout line, with exit status 0 and stdout unchanged.

const rereadWarning = "the write was applied but its result could not be re-read: "

// oneWarning requires stderr to be exactly one line: the re-read warning
// for prefix (e.g. "warning: qa-pve-01: bridge vmbr1: "), whose cause
// carries want. It returns the rendered cause.
func oneWarning(t *testing.T, stderr, prefix, want string) string {
	t.Helper()
	if strings.Count(stderr, "\n") != 1 || !strings.HasPrefix(stderr, prefix+rereadWarning) {
		t.Fatalf("stderr = %q; want exactly one line starting %q", stderr, prefix+rereadWarning)
	}
	cause := strings.TrimSuffix(strings.TrimPrefix(stderr, prefix+rereadWarning), "\n")
	if !strings.Contains(cause, want) {
		t.Errorf("the warning's cause %q lacks %q", cause, want)
	}
	return cause
}

// bridgeCreate runs `network bridge create` with Run's final re-read of the
// interface answered by last, and returns the result and the REST fake.
func bridgeCreate(t *testing.T, last string) (int, string, string, *pvefake.BridgeREST) {
	t.Helper()
	const node, mgmt, iface = "qa-pve-01", "vmbr0", "vmbr1"
	rest := pvefake.NewBridgeREST(t, node)
	rest.MgmtFields = `{"iface":"vmbr0","type":"bridge","bridge_ports":"eth0","cidr":"10.0.0.5/24"}`
	rest.IfaceResponses = []string{
		pvefake.IfaceAbsent, // Run's Read
		pvefake.IfaceAbsent, // Apply's pre-stage read
		`{"iface":"vmbr1","type":"bridge","bridge_ports":"eth1"}`, // guard self-check
		last, // Run's re-read
	}
	rest.CommitUPID = pvefake.NetworkUPID(node, iface)
	srv := rest.Server()
	t.Cleanup(srv.Close)
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
	rp := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	code, stdout, stderr := runRootArgs("network", "bridge", "create", "--roster", rp,
		"--management-bridge", mgmt, "qa-pve-01", iface, "type=bridge", "bridge_ports=eth1")
	return code, stdout, stderr, rest
}

// countHits counts rest's hits equal to hit.
func countHits(hits []string, hit string) int {
	n := 0
	for _, h := range hits {
		if h == hit {
			n++
		}
	}
	return n
}

// N1: network bridge create, the final re-read failing.
func TestNetworkBridgeCreate_N1_ReReadFailureWarns(t *testing.T) {
	code, stdout, stderr, rest := bridgeCreate(t, pvefake.IfaceServerError("pve says no"))
	if code != 0 || stdout != "qa-pve-01: bridge vmbr1 created\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	oneWarning(t, stderr, "warning: qa-pve-01: bridge vmbr1: ", "pve says no")
	if n := countHits(rest.Hits(), "GET /api2/json/nodes/qa-pve-01/network/vmbr1"); n != 4 {
		t.Errorf("%d interface GETs, want 4: the failing re-read was not reached", n)
	}
}

// N2: network bridge destroy, the final re-read failing.
func TestNetworkBridgeDestroy_N2_ReReadFailureWarns(t *testing.T) {
	const node, mgmt, iface = "qa-pve-01", "vmbr0", "vmbr1"
	rest := pvefake.NewBridgeREST(t, node)
	rest.MgmtFields = `{"iface":"vmbr0","type":"bridge","bridge_ports":"eth0","cidr":"10.0.0.5/24"}`
	live := `{"iface":"vmbr1","type":"bridge","bridge_ports":"eth1","active":1}`
	rest.IfaceResponses = []string{live, live, pvefake.IfaceServerError("pve says no")}
	rest.CommitUPID = pvefake.NetworkUPID(node, iface)
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
	rp := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	code, stdout, stderr := runRootArgs("network", "bridge", "destroy", "--roster", rp, "--management-bridge", mgmt, "qa-pve-01", iface)
	if code != 0 || stdout != "qa-pve-01: bridge vmbr1 destroyed\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	oneWarning(t, stderr, "warning: qa-pve-01: bridge vmbr1: ", "pve says no")
	if n := countHits(rest.Hits(), "GET /api2/json/nodes/qa-pve-01/network/vmbr1"); n != 3 {
		t.Errorf("%d interface GETs, want 3: the failing re-read was not reached", n)
	}
}

// N3: network set, the final re-read failing: the applied line is printed
// as always, then the warning.
func TestNetworkSet_N3_ReReadFailureWarns(t *testing.T) {
	const node, iface = "qa-pve-01", "vmbr5"
	rest := pvefake.NewFieldsREST(t, node, iface)
	rest.ListResponses = []string{
		`[{"iface":"vmbr5","type":"bridge","mtu":"1500"},{"iface":"vmbr0","bridge_ports":"eth0"}]`,
		`[{"iface":"vmbr5","type":"bridge","mtu":"9000"},{"iface":"vmbr0","bridge_ports":"eth0"}]`,
	}
	rest.IfaceResponses = []string{`{"iface":"vmbr5","type":"bridge","mtu":"1500"}`, pvefake.IfaceServerError("pve says no")}
	rest.CommitUPID = pvefake.NetworkUPID(node, iface)
	srv := rest.Server()
	defer srv.Close()
	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(func(cmd string) (string, string, int) {
		if cmd == pvefake.LinkShowCmd(iface) {
			return pvefake.LinkJSON(iface, true), "", 0
		}
		return "", "unexpected command", 127
	})
	rp := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	code, stdout, stderr := runRootArgs("network", "set", "--roster", rp, "qa-pve-01", iface, "mtu=9000")
	if code != 0 || stdout != "qa-pve-01: mtu=9000\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	oneWarning(t, stderr, "warning: qa-pve-01: interface vmbr5: ", "pve says no")
	if n := countHits(rest.Hits(), "GET /api2/json/nodes/qa-pve-01/network/vmbr5"); n != 2 {
		t.Errorf("%d interface GETs, want 2: the failing re-read was not reached", n)
	}
}

// accessRereadSetup serves the token's list at path: the first GET
// answers first, every later one fails with 500 and body. Root answers
// pveum as the access tests' fake does.
func accessRereadSetup(t *testing.T, path, first, body string) (string, *int) {
	t.Helper()
	var mu sync.Mutex
	gets := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != path {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		mu.Lock()
		gets++
		n := gets
		mu.Unlock()
		if n == 1 {
			_, _ = w.Write([]byte(first))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(pveumFake(nil))
	rp := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	rootAt(t, fs)
	return rp, &gets
}

// A1: user ensure, the post-write re-read failing: the warning comes right
// after the stdout line and BEFORE the no-password notice.
func TestUserEnsure_A1_ReReadFailureWarnsFirst(t *testing.T) {
	rp, gets := accessRereadSetup(t, "/api2/json/access/users", usersWithoutAlice, "pve says no")
	code, stdout, stderr := runRootArgs("user", "ensure", "--roster", rp, "qa-pve-01", "alice@pve")
	if code != 0 || stdout != "qa-pve-01: user alice@pve created\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	lines := strings.SplitAfter(stderr, "\n")
	if len(lines) != 3 || lines[2] != "" {
		t.Fatalf("stderr = %q; want the warning, then the no-password notice", stderr)
	}
	oneWarning(t, lines[0], "warning: qa-pve-01: user alice@pve: ", "pve says no")
	if want := "notice: qa-pve-01: user alice@pve has no password: it cannot log in until one is set with pveum passwd\n"; lines[1] != want {
		t.Errorf("second line %q, want %q", lines[1], want)
	}
	if *gets != 2 {
		t.Errorf("%d user-list GETs, want 2: the failing re-read was not reached", *gets)
	}
}

// A2: group ensure, the post-write re-read failing.
func TestGroupEnsure_A2_ReReadFailureWarns(t *testing.T) {
	rp, gets := accessRereadSetup(t, "/api2/json/access/groups", `{"data":[]}`, "pve says no")
	code, stdout, stderr := runRootArgs("group", "ensure", "--roster", rp, "qa-pve-01", "ops")
	if code != 0 || stdout != "qa-pve-01: group ops created\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	oneWarning(t, stderr, "warning: qa-pve-01: group ops: ", "pve says no")
	if *gets != 2 {
		t.Errorf("%d group-list GETs, want 2: the failing re-read was not reached", *gets)
	}
}

// F1: server text in the cause is rendered exactly as runRoot renders an
// error's text: bounded (boundErrText) and quoted (kvjson.QuoteValue), so a
// body that tries to forge a line stays in the one warning line, and an
// oversized body is cut as runRoot would cut it.
func TestWarnNotReread_F1_TheCauseIsRenderedAsRunRootRendersIt(t *testing.T) {
	forged := "pve says no\nwarning: qa-pve-01: forged line"
	oversized := strings.Repeat("x", maxErrTextBytes) + "\nwarning: forged tail"

	t.Run("through runRoot, a network site", func(t *testing.T) {
		code, _, stderr, _ := bridgeCreate(t, pvefake.IfaceServerError(forged))
		if code != 0 {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		oneWarning(t, stderr, "warning: qa-pve-01: bridge vmbr1: ", `\nwarning: qa-pve-01: forged line`)
	})
	t.Run("through runRoot, an access site", func(t *testing.T) {
		rp, _ := accessRereadSetup(t, "/api2/json/access/groups", `{"data":[]}`, oversized)
		code, _, stderr := runRootArgs("group", "ensure", "--roster", rp, "qa-pve-01", "ops")
		if code != 0 {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		cause := oneWarning(t, stderr, "warning: qa-pve-01: group ops: ", " bytes elided]")
		if strings.Contains(cause, "forged tail") {
			t.Errorf("the cause was not bounded: its tail %q is printed", "forged tail")
		}
	})
	t.Run("byte for byte what runRoot prints", func(t *testing.T) {
		for _, text := range []string{forged, oversized, "plain cause"} {
			err := errors.New(text)
			_, runRootLine := runRootFailing(t, err, nil)
			var buf bytes.Buffer
			warnNotReread(&buf, "qa-pve-01", "vm", strconv.Itoa(100), err)
			prefix := "warning: qa-pve-01: vm 100: " + rereadWarning
			if got := strings.TrimPrefix(buf.String(), prefix); got != runRootLine {
				t.Errorf("the warning's cause %q\ndiffers from runRoot's line %q", got, runRootLine)
			}
		}
	})
	t.Run("an id that needs quoting is quoted", func(t *testing.T) {
		// The network commands do not validate an interface name for
		// line-safety themselves, so the helper quotes any id that needs it.
		var buf bytes.Buffer
		warnNotReread(&buf, "qa-pve-01", "interface", "vmbr1\nwarning: forged", errors.New("pve says no"))
		if got := buf.String(); strings.Count(got, "\n") != 1 || !strings.HasPrefix(got, `warning: qa-pve-01: interface "vmbr1\nwarning: forged": `) {
			t.Errorf("warnNotReread = %q; want one line with the id quoted", got)
		}
	})
	t.Run("no AfterErr, no line", func(t *testing.T) {
		var buf bytes.Buffer
		warnNotReread(&buf, "qa-pve-01", "vm", "100", nil)
		if buf.Len() != 0 {
			t.Errorf("warnNotReread(nil) printed %q", buf.String())
		}
	})
}

// VC1 pins today's contract, for pveforge-post-apply-verification-and-
// pending (P3) to flip: VMCreate.Read maps any read error to "absent", so a
// vm create whose post-create read fails cannot report it. Exit 0, the
// created line, and no warning. P3 changes VMCreate.Read and must make this
// test's post-create case warn through warnNotReread.
func TestVMCreate_VC1_ReReadFailureIsNotReportedToday(t *testing.T) {
	var mu sync.Mutex
	created := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const base = "/api2/json"
		switch {
		case r.URL.Path == base+"/cluster/nextid":
			_, _ = w.Write([]byte(`{"data":"101"}`))
		case r.Method == http.MethodPost && r.URL.Path == base+"/nodes/qa-pve-01/qemu":
			mu.Lock()
			created = true
			mu.Unlock()
			_, _ = w.Write([]byte(`{"data":"UPID:qa-pve-01:00001234:0000ABCD:5F000000:qmcreate:101:root@pam:"}`))
		case strings.HasPrefix(r.URL.Path, base+"/nodes/qa-pve-01/tasks/"):
			_, _ = w.Write([]byte(`{"data":{"status":"stopped","exitstatus":"OK","upid":"UPID:qa-pve-01:00001234:0000ABCD:5F000000:qmcreate:101:root@pam:","node":"qa-pve-01"}}`))
		case strings.HasPrefix(r.URL.Path, base+"/nodes/qa-pve-01/qemu/101"):
			// Every read of the VM fails, before the create and after it.
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("pve says no"))
		default:
			http.Error(w, "unexpected "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer srv.Close()
	rp := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	code, stdout, stderr := runRootArgs("vm", "create", "--roster", rp, "qa-pve-01", "101", "name=web")
	if code != 0 || stdout != "qa-pve-01: vm 101 created\n" || stderr != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want today's contract: created, no warning", code, stdout, stderr)
	}
	if !created {
		t.Fatal("the create POST was never reached")
	}
}
