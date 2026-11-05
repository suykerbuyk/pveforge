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
