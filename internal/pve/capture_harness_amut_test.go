//go:build harness

package pve

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func strptr(s string) *string { return &s }

// amutClient points a plain-HTTP client at a loopback server that answers every
// request with statusLine + body (rawStatusServer, notfound_test.go).
func amutClient(t *testing.T, statusLine, body string) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{
		BaseURLOverride: rawStatusServer(t, statusLine, body),
		TokenID:         "root@pam!amut",
		TokenSecret:     "s",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// item 68: a rejection matching an agentUnavailableSubstrings entry is
// agent-off; a not-found 500 or an auth 401 (whatever its body) is NOT.
func TestCaptureAgentRejection(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, status, body string
		wantOff, wantAuth  bool
	}{
		{"agent off (not running)", "500 QEMU guest agent is not running", `{"data":null}`, true, false},
		{"agent off (not configured)", "500 No QEMU guest agent configured", `{"data":null}`, true, false},
		{"not found is not agent-off", "500 Configuration file 'nodes/pvh-n1/qemu-server/150.conf' does not exist", `{"data":null}`, false, false},
		{"auth is not agent-off", "401 QEMU guest agent is not running", `{"data":null}`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := amutClient(t, tc.status, tc.body).CaptureAgentRejection(ctx, "pvh-n1", 150)
			if err != nil {
				t.Fatalf("CaptureAgentRejection: %v", err)
			}
			if got.AgentOff != tc.wantOff {
				t.Errorf("AgentOff = %v, want %v (text=%q)", got.AgentOff, tc.wantOff, got.RejectionText)
			}
			if got.Auth != tc.wantAuth {
				t.Errorf("Auth = %v, want %v", got.Auth, tc.wantAuth)
			}
		})
	}

	// A reachable agent → no rejection to capture.
	ifaces := `{"data":{"result":[{"name":"eth0","hardware-address":"aa:bb:cc:dd:ee:ff"}]}}`
	_, err := amutClient(t, "200 OK", ifaces).CaptureAgentRejection(ctx, "pvh-n1", 150)
	if !errors.Is(err, ErrAgentReachable) {
		t.Errorf("reachable agent: err = %v, want ErrAgentReachable", err)
	}
}

// item 70: per-field spelling, including the empty-id (vzdump --all) and
// token user-field cases.
func TestUPIDSpelling(t *testing.T) {
	const (
		qmcreate = "UPID:pvh-n1:00001A2B:0003C4D5:66AC0000:qmcreate:150:root@pam:"
		vzdump   = "UPID:pvh-n1:00001A2C:0003C4D6:66AC0001:vzdump::root@pam:" // empty id
		tokenUP  = "UPID:pvh-n1:00001A2D:0003C4D7:66AC0002:qmstart:150:batcha-amut@pve!amut:"
		userUP   = "UPID:pvh-n1:00001A2E:0003C4D8:66AC0003:qmstop:150:batcha-amut@pve:"
	)

	t.Run("fields parse and validate", func(t *testing.T) {
		sp, err := ParseUPIDSpelling(qmcreate)
		if err != nil {
			t.Fatal(err)
		}
		if sp.Node != "pvh-n1" || sp.Type != "qmcreate" || sp.ID != "150" || sp.User != "root@pam" || !sp.Valid {
			t.Errorf("spelling = %+v", sp)
		}
	})

	t.Run("vzdump --all has an EMPTY id", func(t *testing.T) {
		sp, err := ParseUPIDSpelling(vzdump)
		if err != nil {
			t.Fatal(err)
		}
		if sp.ID != "" {
			t.Errorf("id = %q, want empty", sp.ID)
		}
		if err := sp.Check(ExpectUPID{Type: strptr("vzdump"), ID: strptr("")}); err != nil {
			t.Errorf("empty-id check: %v", err)
		}
		// A non-empty id expectation must fail on this empty-id UPID.
		if err := sp.Check(ExpectUPID{ID: strptr("150")}); err == nil {
			t.Error("Check(ID=150) on an empty-id UPID: want a mismatch")
		}
	})

	t.Run("token and user UPIDs stamp their principal", func(t *testing.T) {
		sp, _ := ParseUPIDSpelling(tokenUP)
		if err := sp.Check(ExpectUPID{User: strptr("batcha-amut@pve!amut")}); err != nil {
			t.Errorf("token user-field: %v", err)
		}
		if err := sp.Check(ExpectUPID{User: strptr("root@pam")}); err == nil {
			t.Error("a root-stamped expectation must fail on a token UPID")
		}
		spu, _ := ParseUPIDSpelling(userUP)
		if err := spu.Check(ExpectUPID{User: strptr("batcha-amut@pve")}); err != nil {
			t.Errorf("user-field: %v", err)
		}
	})

	t.Run("not a UPID is an error, not a half-filled spelling", func(t *testing.T) {
		if _, err := ParseUPIDSpelling("not-a-upid"); err == nil {
			t.Error("want an error")
		}
	})
}

// item 69/70: FindTaskUPID filters on TYPE AND id, so a qmstart sharing the id
// is never mistaken for the qmcreate.
func TestFindTaskUPID_TypeAndID(t *testing.T) {
	// Both a qmcreate and a qmstart for id 150; the create is OLDER.
	rows := []map[string]any{
		{"upid": "UPID:pvh-n1:0001:0002:66AC0000:qmcreate:150:root@pam:", "type": "qmcreate", "id": "150", "starttime": 1000},
		{"upid": "UPID:pvh-n1:0003:0004:66AC0005:qmstart:150:root@pam:", "type": "qmstart", "id": "150", "starttime": 2000},
	}
	body, _ := json.Marshal(map[string]any{"data": rows})
	c := amutClient(t, "200 OK", string(body))

	got, err := c.FindTaskUPID(context.Background(), "pvh-n1", "qmcreate", "150", 0)
	if err != nil {
		t.Fatalf("FindTaskUPID: %v", err)
	}
	if got != "UPID:pvh-n1:0001:0002:66AC0000:qmcreate:150:root@pam:" {
		t.Errorf("got %q, want the qmcreate row (not the qmstart with the same id)", got)
	}

	// No qmcreate present → an error, never a silent wrong pick.
	only := []map[string]any{{"upid": "UPID:pvh-n1:0003:0004:66AC0005:qmstart:150:root@pam:", "type": "qmstart", "id": "150", "starttime": 2000}}
	b2, _ := json.Marshal(map[string]any{"data": only})
	if _, err := amutClient(t, "200 OK", string(b2)).FindTaskUPID(context.Background(), "pvh-n1", "qmcreate", "150", 0); err == nil {
		t.Error("want an error when no qmcreate matches")
	}
}

// A `since` window excludes a STALE qmcreate (a reused id from an earlier run)
// and keeps the one in this run's create window.
func TestFindTaskUPID_SinceWindow(t *testing.T) {
	rows := []map[string]any{
		{"upid": "UPID:pvh-n1:00AA:00BB:66000000:qmcreate:150:root@pam:", "type": "qmcreate", "id": "150", "starttime": 500},  // stale, before the window
		{"upid": "UPID:pvh-n1:00CC:00DD:66AC0000:qmcreate:150:root@pam:", "type": "qmcreate", "id": "150", "starttime": 1500}, // this run
	}
	body, _ := json.Marshal(map[string]any{"data": rows})
	got, err := amutClient(t, "200 OK", string(body)).FindTaskUPID(context.Background(), "pvh-n1", "qmcreate", "150", 1000)
	if err != nil {
		t.Fatalf("FindTaskUPID: %v", err)
	}
	if got != "UPID:pvh-n1:00CC:00DD:66AC0000:qmcreate:150:root@pam:" {
		t.Errorf("got %q, want the in-window qmcreate (not the stale one before since)", got)
	}
	// If ONLY the stale row exists and the window excludes it → an error.
	stale := []map[string]any{rows[0]}
	sb, _ := json.Marshal(map[string]any{"data": stale})
	if _, err := amutClient(t, "200 OK", string(sb)).FindTaskUPID(context.Background(), "pvh-n1", "qmcreate", "150", 1000); err == nil {
		t.Error("want an error when the only qmcreate is before the since window")
	}
}

// item 69: exitstatus is WARNINGS only when it is EXACTLY `WARNINGS: <n>`.
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
		got, err := amutClient(t, "200 OK", string(body)).CaptureTaskExitStatus(ctx, "pvh-n1", upid)
		if err != nil {
			t.Fatalf("%q: %v", tc.exit, err)
		}
		if got.IsWarnings != tc.want {
			t.Errorf("exitstatus %q: IsWarnings = %v, want %v", tc.exit, got.IsWarnings, tc.want)
		}
	}
}
