package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// Exit 3/4 for `storage create`, `storage set-content`, `storage alloc` and
// `storage free-orphans` (contract plan §3.5, §4, AC-W2/W3), through runRoot
// with the three write logs and the gate-agreement assertion; each refusal has
// a post-write twin that must exit NOT 4.

const (
	s2StorNode = "qa-pve-07"
	s2StorID   = "pveforge-harness"
	s2NoSuch   = `{"data":null,"errors":{"storage":"No such storage."}}`
)

func s2UPID(node string) string {
	return "UPID:" + node + ":00001234:00ABCDEF:5F000000:imgdel:storage:root@pam:"
}

// storageFx is a REST-only target (no root SSH: the SSH log is noLog).
func storageFx(t *testing.T, route func(method, path string, form url.Values) (int, string)) (writeEnv, *s2Rest, string) {
	t.Helper()
	srv, f := newS2Rest(t, route)
	rp := newTestRosterWithTLSTarget(t, srv, s2StorNode, s2StorNode)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	return writeEnv{roster: rp, restWrites: f.writes, sshWrites: noLog}, f, rp
}

// ---- storage create ---------------------------------------------------------

func createRoute(existing string, post func(form url.Values) (int, string), polls func() (int, string)) func(string, string, url.Values) (int, string) {
	return func(m, p string, form url.Values) (int, string) {
		switch {
		case m == http.MethodGet && p == "/api2/json/storage/"+s2StorID:
			if existing == "" {
				return http.StatusBadRequest, s2NoSuch
			}
			return 200, `{"data":` + existing + `}`
		case m == http.MethodPost && p == "/api2/json/storage":
			return post(form)
		case m == http.MethodGet && strings.Contains(p, "/tasks/"):
			return polls()
		}
		return 404, `{"data":null}`
	}
}

func storageCreateArgs(rp string, extra ...string) []string {
	return append([]string{"storage", "create", "--roster", rp, s2StorNode, s2StorID, "--type", "zfspool", "--data", "pool=tank", "--data", "content=images"}, extra...)
}

// A present storage whose definition differs is refused with NO POST: exit 4.
func TestExit4_StorageCreate_DifferingDefinition_RefusedBeforeAnyWrite(t *testing.T) {
	env, _, rp := storageFx(t, createRoute(`{"storage":"`+s2StorID+`","type":"dir","content":"iso"}`,
		func(url.Values) (int, string) { return 500, `{"data":null}` }, func() (int, string) { return 500, `{}` }))
	o := env.observe(t, storageCreateArgs(rp)...)
	o.wantRefusedBeforeAnyWrite(t)
	if !strings.Contains(o.stderr, "differ") && !strings.Contains(o.stderr, "desired") {
		t.Errorf("stderr = %q, want the differing-definition refusal", o.stderr)
	}
}

// The required-keys guard: a zfspool with no pool is refused before any request.
func TestExit4_StorageCreate_RequiredKeyMissing_RefusedBeforeAnyWrite(t *testing.T) {
	env, f, rp := storageFx(t, createRoute("", func(url.Values) (int, string) { return 500, `{}` }, func() (int, string) { return 500, `{}` }))
	o := env.observe(t, "storage", "create", "--roster", rp, s2StorNode, s2StorID, "--type", "zfspool", "--data", "content=images")
	o.wantRefusedBeforeAnyWrite(t)
	if n := len(f.all); n != 0 {
		t.Errorf("requests = %q, want none", f.all)
	}
}

// Post-write twin: the POST is SENT and PVE rejects it: exit 1, never 4.
func TestExit1_StorageCreate_PostRejected_IsNotRefused(t *testing.T) {
	env, _, rp := storageFx(t, createRoute("", func(url.Values) (int, string) {
		return 500, `{"data":null,"errors":{"pool":"storage 'x': pool does not exist"}}`
	}, func() (int, string) { return 500, `{}` }))
	o := env.observe(t, storageCreateArgs(rp)...)
	o.wantNotRefusedAfterWrite(t)
	if o.code != 1 || len(o.rest) != 1 {
		t.Errorf("exit %d, REST writes %q: want 1 after one POST", o.code, o.rest)
	}
}

// Wait boundary (storagecreate.go): the POST answers a bare UPID, the poll
// fails: the create was dispatched and its outcome is unknown: exit 3.
func TestExit3_StorageCreate_WaitNotObserved(t *testing.T) {
	fastTaskTimings(t)
	upid := s2UPID(s2StorNode)
	env, f, rp := storageFx(t, createRoute("", func(url.Values) (int, string) { return 200, `{"data":"` + upid + `"}` },
		func() (int, string) { return 500, `{"data":null}` }))
	o := env.observe(t, storageCreateArgs(rp)...)
	if o.code != 3 {
		t.Fatalf("exit %d, want 3; stderr %q", o.code, o.stderr)
	}
	if f.count("POST /api2/json/storage") != 1 || f.polls.Load() < 1 || !o.opened {
		t.Errorf("POSTs %d, polls %d, gate %v: want one POST and a failed poll", f.count("POST /api2/json/storage"), f.polls.Load(), o.opened)
	}
	if !strings.Contains(o.stderr, upid) {
		t.Errorf("stderr = %q, want the UPID", o.stderr)
	}
}

// ---- storage set-content ----------------------------------------------------

func contentRoute(put func(form url.Values) (int, string), polls func() (int, string)) func(string, string, url.Values) (int, string) {
	cfg := `{"data":{"storage":"` + s2StorID + `","type":"dir","content":"images","digest":"d1"}}`
	return func(m, p string, form url.Values) (int, string) {
		switch {
		case m == http.MethodGet && p == "/api2/json/storage/"+s2StorID:
			return 200, cfg
		case m == http.MethodPut && p == "/api2/json/storage/"+s2StorID:
			return put(form)
		case m == http.MethodGet && strings.Contains(p, "/tasks/"):
			return polls()
		}
		return 404, `{"data":null}`
	}
}

func setContentArgs(rp, ct string) []string {
	return []string{"storage", "set-content", "--roster", rp, s2StorNode, s2StorID, ct}
}

// A storage that does not exist: refused (PVE's authoritative "No such
// storage") before any write: exit 4.
func TestExit4_StorageSetContent_StorageMissing_RefusedBeforeAnyWrite(t *testing.T) {
	env, _, rp := storageFx(t, func(m, p string, _ url.Values) (int, string) {
		if m == http.MethodGet && p == "/api2/json/storage/"+s2StorID {
			return http.StatusBadRequest, s2NoSuch
		}
		return 404, `{"data":null}`
	})
	o := env.observe(t, setContentArgs(rp, "iso")...)
	o.wantRefusedBeforeAnyWrite(t)
	if !strings.Contains(o.stderr, "does not exist") {
		t.Errorf("stderr = %q, want the missing-storage refusal", o.stderr)
	}
}

func TestExit4_StorageSetContent_UnknownContentType_RefusedBeforeAnyWrite(t *testing.T) {
	env, f, rp := storageFx(t, contentRoute(func(url.Values) (int, string) { return 200, `{"data":null}` }, func() (int, string) { return 500, `{}` }))
	env.observe(t, setContentArgs(rp, "bogus")...).wantRefusedBeforeAnyWrite(t)
	if len(f.all) != 0 {
		t.Errorf("requests = %q, want none", f.all)
	}
}

// Post-write twin: the PUT is sent and rejected: exit 1, never 4.
func TestExit1_StorageSetContent_PutRejected_IsNotRefused(t *testing.T) {
	env, _, rp := storageFx(t, contentRoute(func(url.Values) (int, string) { return 500, `{"data":null}` }, func() (int, string) { return 500, `{}` }))
	o := env.observe(t, setContentArgs(rp, "iso")...)
	o.wantNotRefusedAfterWrite(t)
	if o.code != 1 || len(o.rest) != 1 {
		t.Errorf("exit %d, REST writes %q: want 1 after one PUT", o.code, o.rest)
	}
}

// Wait boundary (storagecontent.go): the PUT answers a bare UPID, the poll
// fails: exit 3.
func TestExit3_StorageSetContent_WaitNotObserved(t *testing.T) {
	fastTaskTimings(t)
	upid := s2UPID(s2StorNode)
	env, f, rp := storageFx(t, contentRoute(func(url.Values) (int, string) { return 200, `{"data":"` + upid + `"}` },
		func() (int, string) { return 500, `{"data":null}` }))
	o := env.observe(t, setContentArgs(rp, "iso")...)
	if o.code != 3 {
		t.Fatalf("exit %d, want 3; stderr %q", o.code, o.stderr)
	}
	if f.count("PUT ") != 1 || f.polls.Load() < 1 || !o.opened || !strings.Contains(o.stderr, upid) {
		t.Errorf("PUTs %d, polls %d, gate %v, stderr %q", f.count("PUT "), f.polls.Load(), o.opened, o.stderr)
	}
}

// ---- storage alloc (synchronous REST: no wait boundary) ---------------------

func allocRoute(post func() (int, string), listed string) func(string, string, url.Values) (int, string) {
	content := "/api2/json/nodes/" + s2StorNode + "/storage/local-lvm/content"
	return func(m, p string, _ url.Values) (int, string) {
		switch {
		case m == http.MethodGet && p == content:
			return 200, `{"data":` + listed + `}`
		case m == http.MethodPost && p == content:
			return post()
		}
		return 404, `{"data":null}`
	}
}

func allocArgs(rp, size string) []string {
	return []string{"storage", "alloc", "--roster", rp, s2StorNode, "local-lvm", "vm-105-disk-0", size, "105"}
}

// An empty size is refused before any request.
func TestExit4_StorageAlloc_InvalidOp_RefusedBeforeAnyWrite(t *testing.T) {
	env, f, rp := storageFx(t, allocRoute(func() (int, string) { return 200, `{"data":"x"}` }, `[]`))
	env.observe(t, allocArgs(rp, "")...).wantRefusedBeforeAnyWrite(t)
	if len(f.all) != 0 {
		t.Errorf("requests = %q, want none", f.all)
	}
}

// Post-write twin: the allocate POST is sent and rejected (the size grammar is
// PVE's to refuse, after the POST): exit 1, never 4.
func TestExit1_StorageAlloc_PostRejected_IsNotRefused(t *testing.T) {
	env, _, rp := storageFx(t, allocRoute(func() (int, string) { return 500, `{"data":null,"errors":{"size":"invalid"}}` }, `[]`))
	o := env.observe(t, allocArgs(rp, "bogus")...)
	o.wantNotRefusedAfterWrite(t)
	if o.code != 1 || len(o.rest) != 1 {
		t.Errorf("exit %d, REST writes %q: want 1 after one POST", o.code, o.rest)
	}
}

// Second twin: the POST succeeded but the read-back does not list the volid:
// a refusal after the write: exit 1.
func TestExit1_StorageAlloc_ReadBackMismatch_IsNotRefused(t *testing.T) {
	env, _, rp := storageFx(t, allocRoute(func() (int, string) { return 200, `{"data":"local-lvm:vm-105-disk-0"}` }, `[]`))
	o := env.observe(t, allocArgs(rp, "32G")...)
	o.wantNotRefusedAfterWrite(t)
	if o.code != 1 {
		t.Errorf("exit %d, want 1", o.code)
	}
}

// ---- storage free-orphans ---------------------------------------------------

// freeFx builds the free-orphans fixture: REST answers routes (a status poll
// answers poll), root SSH answers the quorum/VM-list reads.
func freeFx(t *testing.T, shared int, quorate int, guests string, del func() (int, string)) (writeEnv, *s2Rest, string) {
	t.Helper()
	const node = "qa-pve-01"
	base := "/api2/json/nodes/" + node + "/storage/local-lvm"
	srv, f := newS2Rest(t, func(m, p string, _ url.Values) (int, string) {
		switch {
		case m == http.MethodGet && p == base+"/status":
			return 200, `{"data":{"storage":"local-lvm","type":"lvmthin","shared":` + itoa(shared) + `}}`
		case m == http.MethodGet && p == base+"/content":
			return 200, `{"data":[{"volid":"local-lvm:vm-690-disk-0","vmid":690,"content":"images"}]}`
		case m == http.MethodDelete && strings.HasPrefix(p, base+"/content/"):
			return del()
		case m == http.MethodGet && strings.Contains(p, "/tasks/"):
			return 500, `{"data":null}`
		}
		return 404, `{"data":null}`
	})
	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(func(cmd string) (string, string, int) {
		switch {
		case strings.HasPrefix(cmd, "readlink /etc/pve/local"):
			return "nodes/qa-pve-01\n", "", 0
		case strings.Contains(cmd, "/cluster/resources"):
			return guests, "", 0
		case strings.Contains(cmd, "/cluster/status"):
			return `[{"type":"cluster","name":"c","nodes":1,"quorate":` + itoa(quorate) + `},{"type":"node","name":"qa-pve-01","online":1}]`, "", 0
		case strings.Contains(cmd, "/qemu"):
			return "[]", "", 0
		}
		return "", "", 0
	})
	rp := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	rootAt(t, fs)
	return writeEnv{roster: rp, restWrites: f.writes, sshWrites: sshWritesNotIn(fs, s2StorageSSHRead)}, f, rp
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	return "1"
}

func freeArgs(rp string) []string {
	return []string{"storage", "free-orphans", "--roster", rp, "qa-pve-01", "local-lvm", "690"}
}

// A non-quorate node is refused before any DELETE: exit 4.
func TestExit4_StorageFreeOrphans_NonQuorate_RefusedBeforeAnyWrite(t *testing.T) {
	env, _, rp := freeFx(t, 0, 0, `[]`, func() (int, string) { return 200, `{"data":"` + s2UPID("qa-pve-01") + `"}` })
	o := env.observe(t, freeArgs(rp)...)
	o.wantRefusedBeforeAnyWrite(t)
	if !strings.Contains(o.stderr, "not quorate") {
		t.Errorf("stderr = %q, want the quorum refusal", o.stderr)
	}
}

// Shared storage whose cluster guest list names a node that is not online: the
// membership gate refuses, before any DELETE: exit 4.
func TestExit4_StorageFreeOrphans_SharedGuestOnOfflineNode_RefusedBeforeAnyWrite(t *testing.T) {
	env, _, rp := freeFx(t, 1, 1, `[{"type":"qemu","vmid":690,"node":"qa-pve-09"}]`, func() (int, string) { return 200, `{"data":"x"}` })
	env.observe(t, freeArgs(rp)...).wantRefusedBeforeAnyWrite(t)
}

// Post-write twin: the DELETE is SENT and PVE rejects it: exit 1, never 4.
func TestExit1_StorageFreeOrphans_DeleteRejected_IsNotRefused(t *testing.T) {
	env, _, rp := freeFx(t, 0, 1, `[]`, func() (int, string) { return 500, `{"data":null}` })
	o := env.observe(t, freeArgs(rp)...)
	o.wantNotRefusedAfterWrite(t)
	if o.code != 1 || len(o.rest) != 1 || !strings.HasPrefix(o.rest[0], "DELETE ") {
		t.Errorf("exit %d, REST writes %q: want 1 after one DELETE", o.code, o.rest)
	}
}

// Wait boundary (storagevolume.go): the DELETE answers a UPID, the poll fails:
// the free was dispatched and its outcome is unknown: exit 3.
func TestExit3_StorageFreeOrphans_WaitNotObserved(t *testing.T) {
	fastTaskTimings(t)
	upid := s2UPID("qa-pve-01")
	env, f, rp := freeFx(t, 0, 1, `[]`, func() (int, string) { return 200, `{"data":"` + upid + `"}` })
	o := env.observe(t, freeArgs(rp)...)
	if o.code != 3 {
		t.Fatalf("exit %d, want 3; stderr %q", o.code, o.stderr)
	}
	if f.count("DELETE ") != 1 || f.polls.Load() < 1 || !o.opened || !strings.Contains(o.stderr, upid) {
		t.Errorf("DELETEs %d, polls %d, gate %v, stderr %q", f.count("DELETE "), f.polls.Load(), o.opened, o.stderr)
	}
}
