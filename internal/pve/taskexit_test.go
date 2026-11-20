package pve

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

// item 69 (moved here out of the harness build with CaptureTaskExitStatus):
// exitstatus is WARNINGS only when it is EXACTLY `WARNINGS: <n>`.
func TestCaptureTaskExitStatus(t *testing.T) {
	ctx := context.Background()
	const upid = "UPID:pvh-n1:0001:0002:66AC0000:vzdump::root@pam:"
	for _, tc := range []struct {
		exit string
		want bool
	}{
		{"WARNINGS: 3", true},
		{"WARNINGS: 0", true},
		{"OK", false},
		{"WARNINGS: 3x", false},
		{"WARNINGS: 3\n", false},
		{"WARNINGS:3", false},
	} {
		body, _ := json.Marshal(map[string]any{"data": map[string]any{"status": "stopped", "exitstatus": tc.exit, "upid": upid}})
		got, err := rawClient(t, "200 OK", string(body)).CaptureTaskExitStatus(ctx, "pvh-n1", upid)
		if err != nil {
			t.Fatalf("%q: %v", tc.exit, err)
		}
		if got.IsWarnings != tc.want {
			t.Errorf("exitstatus %q: IsWarnings = %v, want %v", tc.exit, got.IsWarnings, tc.want)
		}
	}
}

// The ONE exactness rule, directly. It is NOT taskExitSucceeded.
func TestExactOK(t *testing.T) {
	for in, want := range map[string]bool{
		"OK":          true,
		"WARNINGS: 1": false, "WARNINGS: 0": false, "ok": false, "Ok": false, "OK ": false,
		" OK": false, "OKAY": false, "OK\n": false, "": false, "unexpected status": false,
		"WARNINGS: 1 (OK)": false, "TASK OK": false, "error: OK": false,
	} {
		if got := exactOK(in); got != want {
			t.Errorf("exactOK(%q) = %v, want %v", in, got, want)
		}
		if got := (DestroyEnd{ExitStatus: in}).EndedOK(); got != want {
			t.Errorf("DestroyEnd{%q}.EndedOK() = %v, want %v", in, got, want)
		}
		if got := (TaskRow{Status: in}).EndedOK(); got != want {
			t.Errorf("TaskRow{%q}.EndedOK() = %v, want %v", in, got, want)
		}
	}
	// the sibling predicate really does accept WARNINGS: that is the trap.
	if !taskExitSucceeded("WARNINGS: 1") || exactOK("WARNINGS: 1") {
		t.Fatal("premise broken: taskExitSucceeded must accept WARNINGS while exactOK must not")
	}
}

const endUPID = "UPID:n1:0000ABCD:0000ABCD:66AC0000:qmdestroy:690:root@pam:"

func destroyStatusBody(upid, typ, id, node, status, exit string, withExit bool) string {
	m := map[string]any{"upid": upid, "type": typ, "id": id, "node": node, "status": status, "user": "root@pam"}
	if withExit {
		m["exitstatus"] = exit
	}
	b, _ := json.Marshal(map[string]any{"data": m})
	return string(b)
}

// T-exact-exit (G1/G10): DestroyEnd through the raw per-task endpoint.
func TestDestroyEnd_Table(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		wantErr string // "" = an ended value
		wantOK  bool
	}{
		{"stopped OK", destroyStatusBody(endUPID, "qmdestroy", "690", "n1", "stopped", "OK", true), "", true},
		{"stopped WARNINGS", destroyStatusBody(endUPID, "qmdestroy", "690", "n1", "stopped", "WARNINGS: 1", true), "", false},
		{"stopped error text", destroyStatusBody(endUPID, "qmdestroy", "690", "n1", "stopped", "unable to remove volume", true), "", false},
		{"stopped ok lower", destroyStatusBody(endUPID, "qmdestroy", "690", "n1", "stopped", "ok", true), "", false},
		{"stopped trailing space", destroyStatusBody(endUPID, "qmdestroy", "690", "n1", "stopped", "OK ", true), "", false},
		{"stopped OKAY", destroyStatusBody(endUPID, "qmdestroy", "690", "n1", "stopped", "OKAY", true), "", false},
		{"running", destroyStatusBody(endUPID, "qmdestroy", "690", "n1", "running", "", false), "not stopped", false},
		{"running WITH a stray exitstatus", destroyStatusBody(endUPID, "qmdestroy", "690", "n1", "running", "OK", true), "not stopped", false},
		{"stopped, no exitstatus", destroyStatusBody(endUPID, "qmdestroy", "690", "n1", "stopped", "", false), "no exit status", false},
		{"stopped, empty exitstatus", destroyStatusBody(endUPID, "qmdestroy", "690", "n1", "stopped", "", true), "no exit status", false},
		{"body names another upid", destroyStatusBody("UPID:n1:0000ABCE:0000ABCD:66AC0000:qmdestroy:690:root@pam:", "qmdestroy", "690", "n1", "stopped", "OK", true), "names task", false},
		{"body type qmstop", destroyStatusBody(endUPID, "qmstop", "690", "n1", "stopped", "OK", true), "not qmdestroy", false},
		{"body id of another vmid", destroyStatusBody(endUPID, "qmdestroy", "691", "n1", "stopped", "OK", true), "for id", false},
		{"body id numeric (shape)", `{"data":{"upid":"` + endUPID + `","type":"qmdestroy","id":690,"node":"n1","status":"stopped","exitstatus":"OK"}}`, "shape", false},
		{"body node another", destroyStatusBody(endUPID, "qmdestroy", "690", "n2", "stopped", "OK", true), "ran on node", false},
		{"null payload", `{"data":null}`, "names task", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			end, err := rawClient(t, "200 OK", tc.body).DestroyEnd(context.Background(), "n1", 690, endUPID)
			if tc.wantErr != "" {
				if err == nil || end != nil {
					t.Fatalf("got (%+v, %v), want an error containing %q — an unproven end must never be a value", end, err, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q lacks %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || end == nil {
				t.Fatalf("got (%+v, %v), want an ended value", end, err)
			}
			if end.UPID != endUPID {
				t.Errorf("UPID %q", end.UPID)
			}
			if end.EndedOK() != tc.wantOK {
				t.Errorf("EndedOK = %v, want %v for %q", end.EndedOK(), tc.wantOK, end.ExitStatus)
			}
		})
	}
	for _, status := range []string{"404 Not Found", "500 Internal Server Error", "403 Forbidden", "595 no route"} {
		end, err := rawClient(t, status, `{"data":null}`).DestroyEnd(context.Background(), "n1", 690, endUPID)
		if err == nil || end != nil {
			t.Errorf("%s: (%+v, %v), want an error", status, end, err)
		}
	}
	if _, err := rawClient(t, "200 OK", `{}`).DestroyEnd(context.Background(), "n1", 690, "not-a-upid"); err == nil {
		t.Error("a malformed UPID must be refused")
	}
}

// Through the fixture, in the REAL per-task shape (S4): the fake and the
// production reader agree on what a stopped task looks like.
func TestDestroyEnd_AgainstTheFixture(t *testing.T) {
	s := pvefake.NewVMREST(t, "n1")
	mk := func(upid, status string, end int64) pvefake.TaskRow {
		return pvefake.TaskRow{UPID: upid, Type: "qmdestroy", ID: "690", StartTime: 5, Status: status, EndTime: end, Saved: true, Node: "n1", User: "root@pam"}
	}
	okU := "UPID:n1:00000001:00000001:00000001:qmdestroy:690:root@pam:"
	wU := "UPID:n1:00000002:00000002:00000002:qmdestroy:690:root@pam:"
	rU := "UPID:n1:00000003:00000003:00000003:qmdestroy:690:root@pam:"
	s.Tasks = []pvefake.TaskRow{mk(okU, "OK", 6), mk(wU, "WARNINGS: 1", 6), mk(rU, "RUNNING", 0)}
	srv := s.Server()
	defer srv.Close()
	c := detClient(t, srv.URL+"/api2/json")
	for upid, want := range map[string]string{okU: "OK", wU: "WARNINGS: 1"} {
		end, err := c.DestroyEnd(context.Background(), "n1", 690, upid)
		if err != nil || end.ExitStatus != want || end.EndedOK() != (want == "OK") {
			t.Errorf("%s: (%+v, %v), want exit %q", upid, end, err, want)
		}
	}
	if end, err := c.DestroyEnd(context.Background(), "n1", 690, rU); err == nil || end != nil {
		t.Errorf("a running task is an error, got (%+v, %v)", end, err)
	}
	if end, err := c.DestroyEnd(context.Background(), "n1", 691, okU); err == nil || end != nil {
		t.Errorf("another vmid's binding must fail, got (%+v, %v)", end, err)
	}
}
