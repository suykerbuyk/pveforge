package idempotent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// This file is 3b's own full-stack integration test, the sibling of
// networkbridge_integration_test.go (3a): NetworkFieldsEnsure's Apply
// driven against a REAL *pve.RoutedClient — reached only through pve's own
// exported pve.NewRoutedClient constructor — backed by a fake REST server
// AND a fake SSH server together. It reuses every harness piece
// networkbridge_integration_test.go already built (fakeIntegrationSSHServer,
// bootstrappedIntegrationTarget, linkExistsJSON, linkMissingStderrFmt,
// wellFormedNetworkUPID, equalStringSlices — same package, same file's own
// doc comment explains why this harness had to be hand-rebuilt from
// exported surface rather than reused from internal/pve's own private
// test helpers). Only the REST script differs: NetworkFieldsEnsure's guard
// reads the raw LIST endpoint (no per-management-bridge GET), and there is
// no second SSH command for a management bridge — see
// NetworkFieldsEnsure's own "no step-4-equivalent guard self-check" doc
// comment for why its SSH surface is smaller than 3a's.

// networkFieldsRESTScript is a small, ordered fake REST server for exactly
// the PVE calls NetworkFieldsEnsure.Apply issues: pre/post-stage raw LIST
// GETs against /nodes/{node}/network, the stage PUT against
// /nodes/{node}/network/{iface}, the commit PUT against
// /nodes/{node}/network, an optional revert DELETE against the same
// collection path, and the task status poll GET.
type networkFieldsRESTScript struct {
	t     *testing.T
	node  string
	iface string

	listResponses []string // sequential bodies for GET .../network (list); clamps to last
	stageResp     string
	commitUPID    string
	revertResp    string

	mu        sync.Mutex
	hits      []string
	listCalls int
}

func newNetworkFieldsRESTScript(t *testing.T, node, iface string) *networkFieldsRESTScript {
	t.Helper()
	return &networkFieldsRESTScript{t: t, node: node, iface: iface, stageResp: `null`, revertResp: `null`}
}

func (s *networkFieldsRESTScript) server() *httptest.Server {
	collectionPath := fmt.Sprintf("/api2/json/nodes/%s/network", s.node)
	ifacePath := fmt.Sprintf("%s/%s", collectionPath, s.iface)

	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits = append(s.hits, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodGet && r.URL.Path == collectionPath:
			s.mu.Lock()
			idx := s.listCalls
			s.listCalls++
			s.mu.Unlock()
			body := s.listResponses[len(s.listResponses)-1]
			if idx < len(s.listResponses) {
				body = s.listResponses[idx]
			}
			_, _ = fmt.Fprintf(w, `{"data":%s}`, body)

		case r.Method == http.MethodPut && r.URL.Path == ifacePath:
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.stageResp)

		case r.Method == http.MethodPut && r.URL.Path == collectionPath:
			_, _ = fmt.Fprintf(w, `{"data":%q}`, s.commitUPID)

		case r.Method == http.MethodDelete && r.URL.Path == collectionPath:
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.revertResp)

		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, fmt.Sprintf("/api2/json/nodes/%s/tasks/", s.node)) && strings.HasSuffix(r.URL.Path, "/status"):
			_, _ = fmt.Fprintf(w, `{"data":{"status":"stopped","exitstatus":"OK","upid":%q,"node":%q}}`, s.commitUPID, s.node)

		default:
			s.t.Fatalf("networkFieldsRESTScript: unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
}

func (s *networkFieldsRESTScript) hitSequence() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.hits))
	copy(out, s.hits)
	return out
}

// TestNetworkFieldsEnsure_Apply_MTUSet_FullStack drives NetworkFieldsEnsure
// .Apply against a REAL *pve.RoutedClient, backed by a fake REST server and
// a fake SSH server together. Asserts, in order, the exact HTTP
// method+path sequence hit, the exact SSH command sequence run (just the
// ONE post-apply check on the target iface — no management-bridge SSH call
// at all, unlike 3a), and that Apply returns no error.
func TestNetworkFieldsEnsure_Apply_MTUSet_FullStack(t *testing.T) {
	const node = "qa-pve-01"
	const targetIface = "vmbr5"

	upid := wellFormedNetworkUPID(node, targetIface)
	restScript := newNetworkFieldsRESTScript(t, node, targetIface)
	beforeList := `[{"iface":"vmbr5","mtu":"1500"},{"iface":"vmbr0","bridge_ports":"eth0"}]`
	afterList := `[{"iface":"vmbr5","mtu":"9000"},{"iface":"vmbr0","bridge_ports":"eth0"}]` // only the target changed
	restScript.listResponses = []string{beforeList, afterList}
	restScript.commitUPID = upid
	restSrv := restScript.server()
	defer restSrv.Close()

	fs := newFakeIntegrationSSHServer(t)
	targetCmd := fmt.Sprintf("ip -j link show dev '%s'", targetIface)
	fs.handleExec = func(cmd string) (string, string, int) {
		switch cmd {
		case targetCmd:
			return linkExistsJSON(targetIface, true), "", 0
		default:
			t.Fatalf("unexpected ssh command: %q", cmd)
			return "", "", 1
		}
	}

	tg := bootstrappedIntegrationTarget(t, restSrv, fs, "roster-pass")
	restore := pve.SetSSHPortForIntegrationTests(fs.port(t))
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
	if got := restScript.hitSequence(); !equalStringSlices(got, wantREST) {
		t.Fatalf("REST hit sequence:\n got:  %v\n want: %v", got, wantREST)
	}

	wantSSH := []string{targetCmd}
	if got := fs.cmdSequence(); !equalStringSlices(got, wantSSH) {
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

	restScript := newNetworkFieldsRESTScript(t, node, targetIface)
	beforeList := `[{"iface":"vmbr5","mtu":"1500"},{"iface":"vmbr0","bridge_ports":"eth0"}]`
	afterList := `[{"iface":"vmbr5","mtu":"9000"},{"iface":"vmbr0","bridge_ports":"eth9"}]` // decoy vmbr0 changed
	restScript.listResponses = []string{beforeList, afterList}
	restSrv := restScript.server()
	defer restSrv.Close()

	fs := newFakeIntegrationSSHServer(t)
	fs.handleExec = func(cmd string) (string, string, int) {
		t.Fatalf("unexpected ssh command: %q (no SSH call should happen on an aborted apply)", cmd)
		return "", "", 1
	}

	tg := bootstrappedIntegrationTarget(t, restSrv, fs, "roster-pass")
	restore := pve.SetSSHPortForIntegrationTests(fs.port(t))
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
	if got := restScript.hitSequence(); !equalStringSlices(got, wantREST) {
		t.Fatalf("REST hit sequence:\n got:  %v\n want: %v", got, wantREST)
	}
}
