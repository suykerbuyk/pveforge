package pve

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

func reqServer(t *testing.T, mut func(*pvefake.VMREST)) (*pvefake.VMREST, *Client) {
	t.Helper()
	s := pvefake.NewVMREST(t, detNode)
	s.Permissions = map[string]map[string]bool{
		"/":                 {"Sys.Audit": true},
		"/nodes/" + detNode: {"Sys.Audit": true},
		"/vms/690":          {"VM.PowerMgmt": true, "VM.Allocate": true},
	}
	if mut != nil {
		mut(s)
	}
	srv := s.Server()
	t.Cleanup(srv.Close)
	return s, detClient(t, srv.URL+"/api2/json")
}

func TestRequirementsFor_VMDestroyIsExactlyTheFourRows(t *testing.T) {
	var got []string
	for _, r := range RequirementsFor("vm destroy") {
		got = append(got, r.Privilege+" on "+r.Path)
	}
	want := []string{"Sys.Audit on /nodes/{node}", "Sys.Audit on /", "VM.PowerMgmt on /vms/{vmid}", "VM.Allocate on /vms/{vmid}"}
	if !slices.Equal(got, want) {
		t.Errorf("requirements = %q, want %q", got, want)
	}
	if RequirementsFor("no such verb") != nil {
		t.Error("an unknown verb has requirements")
	}
	RequirementsFor("vm destroy")[0].Privilege = "mutated"
	if RequirementsFor("vm destroy")[0].Privilege != "Sys.Audit" {
		t.Error("RequirementsFor leaks the table")
	}
}

func TestNodeStatusRead_ClassifiesByStatusCodeOnly(t *testing.T) {
	for code, want := range map[int]Verdict{0: VerdictHeld, 403: VerdictMissing, 401: VerdictUnknown, 500: VerdictUnknown, 404: VerdictUnknown} {
		_, c := reqServer(t, func(s *pvefake.VMREST) { s.NodeStatus = code })
		path, v, err := c.NodeStatusRead(context.Background(), detNode)
		if v != want || path != "/nodes/"+detNode+"/status" {
			t.Errorf("status %d: verdict %q path %q, want %q", code, v, path, want)
		}
		if (v == VerdictHeld) != (err == nil) {
			t.Errorf("status %d: verdict %q with err %v", code, v, err)
		}
	}
}

func TestCheckVerb_GETOnly_AndUnknownVerbIsAnError(t *testing.T) {
	s, c := reqServer(t, nil)
	res, err := c.CheckVerb(context.Background(), "vm destroy", detNode, 690)
	if err != nil || len(res) != 4 {
		t.Fatalf("err %v, %d rows", err, len(res))
	}
	for _, r := range res {
		if r.Verdict != VerdictHeld {
			t.Errorf("%s = %s, want held", r.ID, r.Verdict)
		}
	}
	if len(s.Requests()) == 0 {
		t.Fatal("no request made")
	}
	if w := s.Writes(); len(w) != 0 {
		t.Errorf("non-GET requests: %v", w)
	}
	if _, err := c.CheckVerb(context.Background(), "vm nope", detNode, 0); err == nil {
		t.Error("an unknown verb was accepted")
	}
}

func TestCheckVerb_WithoutAVMID_ReadsNoVMPath(t *testing.T) {
	s, c := reqServer(t, nil)
	res, _ := c.CheckVerb(context.Background(), "vm destroy", detNode, 0)
	nc := 0
	for _, r := range res {
		if r.Verdict == VerdictNotChecked {
			nc++
		}
	}
	if nc != 2 {
		t.Errorf("%d not-checked rows, want 2", nc)
	}
	for _, q := range s.Requests() {
		if strings.Contains(q, "/vms/") {
			t.Errorf("read %s without a vmid", q)
		}
	}
}

func TestPvefakePermissionsRoute_IsKeyedByExactlyTheRequestedPath(t *testing.T) {
	_, c := reqServer(t, nil)
	p, err := c.PathPermissions(context.Background(), "/vms/999")
	if err != nil || len(p) != 0 {
		t.Errorf("an absent path = %v, %v; want an empty set", p, err)
	}
	_, c = reqServer(t, func(s *pvefake.VMREST) { s.PermissionsStatus = http.StatusForbidden })
	if _, err := c.PathPermissions(context.Background(), "/vms/690"); err == nil {
		t.Error("a 403 permission read succeeded")
	}
}

// The RoutedClient forwarder binds the TARGET's node and the caller's vmid.
// Two distinct nodes and two distinct non-adjacent vmids, so a swap, a literal
// or vmid+-1 changes a path on the wire.
func TestRoutedForwarding_CheckVerb(t *testing.T) {
	for _, c := range []struct {
		node string
		vmid int
	}{{fwdTargetNode, fwdVMID}, {fwdTargetNode2, fwdVMID2}} {
		t.Run(c.node, func(t *testing.T) {
			srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api2/json/access/permissions" {
					p := r.URL.Query().Get("path")
					writeData(w, fmt.Sprintf(`{%q:{"VM.PowerMgmt":1,"VM.Allocate":1,"Sys.Audit":1}}`, p))
					return
				}
				writeData(w, `{}`)
			})
			res, err := fwdClientOn(t, srv, c.node).CheckVerb(context.Background(), "vm destroy", c.vmid)
			if err != nil || len(res) != 4 {
				t.Fatalf("err %v, %d rows", err, len(res))
			}
			var got []string
			for _, r := range rec.got() {
				got = append(got, r.String())
			}
			joined := strings.Join(got, "\n")
			for _, want := range []string{
				fmt.Sprintf("GET /nodes/%s/status", c.node),
				"GET /cluster/config/nodes",
				"GET /access/permissions?" + url.Values{"path": {fmt.Sprintf("/vms/%d", c.vmid)}}.Encode(),
			} {
				if !strings.Contains(joined, want) {
					t.Errorf("no request %q in:\n%s", want, joined)
				}
			}
			for _, bad := range []string{fwdTargetID, fwdTargetHost, fmt.Sprintf("%d", fwdVMID+fwdVMID2-c.vmid)} {
				if strings.Contains(joined, bad) {
					t.Errorf("a request carries %q:\n%s", bad, joined)
				}
			}
		})
	}
}

// nodeDestroyView must read the node status THROUGH NodeStatusRead, the one
// classifier doctor also uses. A behavioural test cannot tell a byte-identical
// inline copy from the shared call (an inline copy stays green until the two
// drift), so this pins the SOURCE: the function calls NodeStatusRead, and holds
// no RawRequest of its own naming a /status path. Anti-vacuity: the function
// is found and holds at least one call.
func TestNodeDestroyView_ReadsTheStatusThroughNodeStatusRead(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "inflight.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "nodeDestroyView" {
			fn = fd
		}
	}
	if fn == nil {
		t.Fatal("nodeDestroyView not found in inflight.go")
	}
	calls, shared, inlineStatus := 0, 0, 0
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		calls++
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "NodeStatusRead":
			shared++
		case "RawRequest":
			ast.Inspect(call, func(m ast.Node) bool {
				if lit, ok := m.(*ast.BasicLit); ok && strings.Contains(lit.Value, "/status") {
					inlineStatus++
				}
				return true
			})
			// A path built in a variable: any RawRequest with a first path arg
			// that is not the task list is the inline read this pin forbids.
			if len(call.Args) >= 3 {
				if id, ok := call.Args[2].(*ast.Ident); ok && strings.Contains(strings.ToLower(id.Name), "status") {
					inlineStatus++
				}
			}
		}
		return true
	})
	if calls == 0 {
		t.Fatal("the walk saw no call in nodeDestroyView: the pin is vacuous")
	}
	if shared != 1 {
		t.Errorf("nodeDestroyView calls NodeStatusRead %d times, want exactly 1", shared)
	}
	if inlineStatus != 0 {
		t.Errorf("nodeDestroyView holds its own status read (%d): it must go through NodeStatusRead", inlineStatus)
	}
}
