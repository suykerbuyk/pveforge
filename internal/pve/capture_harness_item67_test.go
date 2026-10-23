//go:build harness

package pve

import (
	"context"
	"testing"
)

// item67Client builds a plain-HTTP client pointed at a loopback server that
// answers every request with statusLine + body (the rawStatusServer helper from
// notfound_test.go, reused under -tags harness). netguard permits loopback.
func item67Client(t *testing.T, statusLine, body string) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{
		BaseURLOverride: rawStatusServer(t, statusLine, body),
		TokenID:         "root@pam!batcha",
		TokenSecret:     "s",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// Item 67 error-shape classification: the matcher classifies by subject-named
// TEXT (code-agnostic — VM miss 500, iface miss 400), and a 401/403 auth
// rejection is NEVER an absence, even when its body would otherwise match.
func TestItem67_Absence_Classification(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, status, body string
		subject            Subject
		wantCode           int
		wantAbsence        bool
		wantAuth           bool
	}{
		{
			name:     "vm config miss is a 500 absence",
			status:   "500 Configuration file 'nodes/qa-pve-01/qemu-server/100.conf' does not exist",
			body:     `{"data":null}`,
			subject:  VMConfigMissingSubject(100),
			wantCode: 500, wantAbsence: true, wantAuth: false,
		},
		{
			name:     "iface miss is a 400 absence (not 500)",
			status:   "400 Parameter verification failed.",
			body:     `{"errors":{"iface":"interface does not exist"},"data":null}`,
			subject:  IfaceMissingSubject("vmbr1"),
			wantCode: 400, wantAbsence: true, wantAuth: false,
		},
		{
			name:     "storage miss is a 500 absence",
			status:   "500 storage 'nope' does not exist",
			body:     `{"data":null}`,
			subject:  StorageMissingSubject("nope"),
			wantCode: 500, wantAbsence: true, wantAuth: false,
		},
		{
			name:     "a 401 whose body would match is NOT an absence",
			status:   "401 Unauthorized",
			body:     `{"errors":{"storage":"storage 'nope' does not exist"},"data":null}`,
			subject:  StorageMissingSubject("nope"),
			wantCode: 401, wantAbsence: false, wantAuth: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := item67Client(t, tc.status, tc.body)
			got, err := c.CaptureAbsence(ctx, AbsenceProbe{Name: tc.name, Path: "/nodes/qa-pve-01/qemu/100/config", Subject: tc.subject})
			if err != nil {
				t.Fatalf("CaptureAbsence: %v", err)
			}
			if got.Code != tc.wantCode {
				t.Errorf("Code = %d, want %d", got.Code, tc.wantCode)
			}
			if got.Absence != tc.wantAbsence {
				t.Errorf("Absence = %v, want %v (text=%q, matcher=%v, auth=%v)", got.Absence, tc.wantAbsence, got.AnswerText, got.MatcherNotFound, got.Auth)
			}
			if got.Auth != tc.wantAuth {
				t.Errorf("Auth = %v, want %v", got.Auth, tc.wantAuth)
			}
		})
	}
}

// Item 67 field presence: a field the guards assume is always present, present
// → flagged present; a {"data":null} payload → flagged absent (the capture does
// not silently read a zero value as a real one).
func TestItem67_FieldPresence(t *testing.T) {
	ctx := context.Background()

	t.Run("storage type present then absent", func(t *testing.T) {
		got, err := item67Client(t, "200 OK", `{"data":{"type":"dir","active":1}}`).CaptureStorageType(ctx, "pvh-n1", "local")
		if err != nil {
			t.Fatalf("present: %v", err)
		}
		if !got.Present || got.Value != "dir" {
			t.Errorf("present: got %+v, want Present=true Value=dir", got)
		}
		got, err = item67Client(t, "200 OK", `{"data":null}`).CaptureStorageType(ctx, "pvh-n1", "local")
		if err != nil {
			t.Fatalf("absent: %v", err)
		}
		if got.Present {
			t.Errorf("absent: Present=true, want the capture to flag a missing type")
		}
	})

	t.Run("vm status present then absent", func(t *testing.T) {
		got, err := item67Client(t, "200 OK", `{"data":{"status":"running"}}`).CaptureVMStatusField(ctx, "pvh-n1", 100)
		if err != nil {
			t.Fatalf("present: %v", err)
		}
		if !got.Present || got.Value != "running" {
			t.Errorf("present: got %+v, want Present=true Value=running", got)
		}
		got, err = item67Client(t, "200 OK", `{"data":null}`).CaptureVMStatusField(ctx, "pvh-n1", 100)
		if err != nil {
			t.Fatalf("absent: %v", err)
		}
		if got.Present {
			t.Errorf("absent: Present=true, want the capture to flag a missing status")
		}
	})

	t.Run("vm config digest present then absent", func(t *testing.T) {
		got, err := item67Client(t, "200 OK", `{"data":{"digest":"abc123"}}`).CaptureVMConfigDigest(ctx, "pvh-n1", 100)
		if err != nil {
			t.Fatalf("present: %v", err)
		}
		if !got.Present || got.Value != "abc123" {
			t.Errorf("present: got %+v, want Present=true Value=abc123", got)
		}
		got, err = item67Client(t, "200 OK", `{"data":null}`).CaptureVMConfigDigest(ctx, "pvh-n1", 100)
		if err != nil {
			t.Fatalf("absent: %v", err)
		}
		if got.Present {
			t.Errorf("absent: Present=true, want the capture to flag a missing digest")
		}
	})
}

// Item 66 corroborator: raw-byte null-vs-[] classification of a list envelope.
func TestItem67_Corroborator_RawListShape(t *testing.T) {
	for _, tc := range []struct {
		body string
		want ListShape
	}{
		{`{"data":null}`, ShapeNull},
		{`{"data":[]}`, ShapeEmpty},
		{`{"data":[{"vmid":100}]}`, ShapeItems},
	} {
		got, err := ClassifyRawListEnvelope([]byte(tc.body))
		if err != nil {
			t.Fatalf("%s: %v", tc.body, err)
		}
		if got != tc.want {
			t.Errorf("ClassifyRawListEnvelope(%s) = %q, want %q", tc.body, got, tc.want)
		}
	}

	// Round-trip: CaptureRawGET's raw bytes feed the corroborator.
	c := item67Client(t, "200 OK", `{"data":[]}`)
	raw, err := c.CaptureRawGET(context.Background(), "/cluster/resources?type=vm")
	if err != nil {
		t.Fatalf("CaptureRawGET: %v", err)
	}
	shape, err := ClassifyRawListEnvelope(raw.Body)
	if err != nil {
		t.Fatalf("corroborator on raw body: %v", err)
	}
	if shape != ShapeEmpty {
		t.Errorf("round-trip shape = %q, want [] (raw body %q)", shape, raw.Body)
	}
}
