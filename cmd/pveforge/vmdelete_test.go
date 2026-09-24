package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// deleteFakePVE is a stateful VM 100 config for vm set's delete tests. A
// write stores each field (so `k=` stores ""), PVE's `delete` parameter
// removes the keys it lists, and the digest advances on every write. Tests
// assert on the final config — whether a key is present at all — which is
// the only thing that tells "deleted" from "written empty".
type deleteFakePVE struct {
	mu       sync.Mutex
	config   map[string]string
	digestN  int
	gets     int
	requests int
	writes   []string // each PUT's form, re-encoded with sorted keys
	failGet  int      // 1-based GET to answer 500 (0: none)

	// pendingStatus and pendingBody answer GET .../pending (post-apply-verify):
	// a status other than 200 is sent with pendingBody as its raw body; a 200
	// wraps pendingBody (default: an empty list) in PVE's data envelope.
	// pendingReads counts those reads, which are not config GETs.
	pendingStatus int
	pendingBody   string
	pendingReads  int

	// cloudInitStatus, cloudInitBody and cloudInitReads do the same for
	// GET .../cloudinit (P2′).
	cloudInitStatus int
	cloudInitBody   string
	cloudInitReads  int

	// conflictOn, when set, makes the first PUT that writes that key lose a
	// race (P3's conflict-then-no-op): an outside writer applies the same
	// value first, and PVE refuses this write for its stale digest.
	conflictOn string
	conflicted bool
}

func newDeleteFakePVE(t *testing.T, config map[string]string) (*deleteFakePVE, *httptest.Server) {
	t.Helper()
	f := &deleteFakePVE{config: config, digestN: 1}
	srv := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *deleteFakePVE) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/qa-pve-01/qemu/100/cloudinit" {
		f.cloudInitReads++
		if f.cloudInitStatus != 0 && f.cloudInitStatus != http.StatusOK {
			w.WriteHeader(f.cloudInitStatus)
			_, _ = w.Write([]byte(f.cloudInitBody))
			return
		}
		body := f.cloudInitBody
		if body == "" {
			body = "[]"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":` + body + `}`))
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/qa-pve-01/qemu/100/pending" {
		f.pendingReads++
		if f.pendingStatus != 0 && f.pendingStatus != http.StatusOK {
			w.WriteHeader(f.pendingStatus)
			_, _ = w.Write([]byte(f.pendingBody))
			return
		}
		body := f.pendingBody
		if body == "" {
			body = "[]"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":` + body + `}`))
		return
	}
	f.requests++
	if r.URL.Path != "/api2/json/nodes/qa-pve-01/qemu/100/config" {
		http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		f.gets++
		if f.gets == f.failGet {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		out := map[string]string{"digest": fmt.Sprintf("d%d", f.digestN)}
		for k, v := range f.config {
			out[k] = v
		}
		body, _ := json.Marshal(map[string]any{"data": out})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	case http.MethodPut:
		raw, _ := io.ReadAll(r.Body)
		form, err := url.ParseQuery(string(raw))
		if err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if v, ok := form[f.conflictOn]; ok && f.conflictOn != "" && !f.conflicted {
			f.conflicted = true
			f.config[f.conflictOn] = v[0]
			f.digestN++
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"data":null,"errors":{"digest":"detected modified configuration - file changed by other user? Try again."}}`))
			return
		}
		f.writes = append(f.writes, form.Encode())
		for k, v := range form {
			switch k {
			case "digest":
			case "delete":
				for _, key := range strings.Split(v[0], ",") {
					delete(f.config, key)
				}
			default:
				f.config[k] = v[0]
			}
		}
		f.digestN++
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
	}
}

// removeKey deletes k from the config, as a `qm set --delete` over SSH does
// on the host behind the REST API.
func (f *deleteFakePVE) removeKey(k string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.config, k)
	f.digestN++
}

// state returns a copy of the config, the recorded writes and the request count.
func (f *deleteFakePVE) state() (map[string]string, []string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cfg := make(map[string]string, len(f.config))
	for k, v := range f.config {
		cfg[k] = v
	}
	return cfg, slices.Clone(f.writes), f.requests
}

// TestVMSet_DeleteRemovesTheKey_WriteEmptyKeepsIt is the task's own bar:
// the two operations differ in EFFECT, not just spelling. field= leaves the
// key present with empty content; --delete leaves no key at all.
func TestVMSet_DeleteRemovesTheKey_WriteEmptyKeepsIt(t *testing.T) {
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	t.Run("write empty", func(t *testing.T) {
		f, srv := newDeleteFakePVE(t, map[string]string{"description": "x"})
		rp := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
		code, stdout, stderr := runRootArgs("vm", "set", "--roster", rp, "qa-pve-01", "100", "description=")
		if code != 0 || stderr != "" {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		cfg, writes, _ := f.state()
		if v, ok := cfg["description"]; !ok || v != "" {
			t.Errorf("description = %q (present %v), want present and empty", v, ok)
		}
		if want := []string{"description=&digest=d1"}; !slices.Equal(writes, want) {
			t.Errorf("writes = %q, want %q", writes, want)
		}
		if stdout != "qa-pve-01: description=\n" {
			t.Errorf("stdout = %q", stdout)
		}
	})

	t.Run("delete", func(t *testing.T) {
		f, srv := newDeleteFakePVE(t, map[string]string{"description": "x", "cores": "2"})
		rp := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
		code, stdout, stderr := runRootArgs("vm", "set", "--roster", rp, "--delete", "description", "qa-pve-01", "100")
		if code != 0 || stderr != "" {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		cfg, writes, _ := f.state()
		if v, ok := cfg["description"]; ok {
			t.Errorf("description still present (%q): a delete must remove the key", v)
		}
		if cfg["cores"] != "2" {
			t.Errorf("cores = %q, want untouched 2", cfg["cores"])
		}
		if want := []string{"delete=description&digest=d1"}; !slices.Equal(writes, want) {
			t.Errorf("writes = %q, want %q", writes, want)
		}
		if want := "qa-pve-01: delete=description\n"; stdout != want {
			t.Errorf("stdout = %q, want %q", stdout, want)
		}
	})
}

// TestVMSet_SetAndDelete_KVAndJSON: one batch can write and delete, from kv
// args with --delete or from JSON with null; writes go first, each on its
// own fresh digest, and stdout reports each in its own line shape.
func TestVMSet_SetAndDelete_KVAndJSON(t *testing.T) {
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	for name, extra := range map[string][]string{
		"kv and --delete": {"--delete", "description", "cores=4"},
		"JSON null":       {"--json", `{"cores":"4","description":null}`},
		"JSON + --delete": {"--json", `{"cores":"4"}`, "--delete", "description"},
	} {
		t.Run(name, func(t *testing.T) {
			f, srv := newDeleteFakePVE(t, map[string]string{"description": "x", "cores": "2"})
			rp := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
			args := append([]string{"vm", "set", "--roster", rp, "qa-pve-01", "100"}, extra...)
			code, stdout, stderr := runRootArgs(args...)
			if code != 0 || stderr != "" {
				t.Fatalf("exit %d, stderr %q", code, stderr)
			}
			cfg, writes, _ := f.state()
			if _, ok := cfg["description"]; ok || cfg["cores"] != "4" {
				t.Errorf("config = %v, want cores=4 and no description", cfg)
			}
			if want := []string{"cores=4&digest=d1", "delete=description&digest=d2"}; !slices.Equal(writes, want) {
				t.Errorf("writes = %q, want %q", writes, want)
			}
			if want := "qa-pve-01: cores=4\nqa-pve-01: delete=description\n"; stdout != want {
				t.Errorf("stdout = %q, want %q", stdout, want)
			}
		})
	}
}

// TestVMSet_DeleteOfAbsentKeyIsANoOp: nothing is sent and nothing printed.
func TestVMSet_DeleteOfAbsentKeyIsANoOp(t *testing.T) {
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	f, srv := newDeleteFakePVE(t, map[string]string{"cores": "2"})
	rp := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	code, stdout, stderr := runRootArgs("vm", "set", "--roster", rp, "--delete", "description", "qa-pve-01", "100")
	if code != 0 || stdout != "" || stderr != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 0 and no output", code, stdout, stderr)
	}
	if _, writes, _ := f.state(); len(writes) != 0 {
		t.Errorf("writes = %q, want none", writes)
	}
}

// TestVMSet_SetAndDeleteSameFieldRefusedBeforeAnyRequest: a field both set
// and deleted is refused before the roster or any request.
func TestVMSet_SetAndDeleteSameFieldRefusedBeforeAnyRequest(t *testing.T) {
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	f, srv := newDeleteFakePVE(t, map[string]string{"cores": "2"})
	rp := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	for _, args := range [][]string{
		{"--delete", "cores", "cores=4"},
		{"--json", `{"cores":"4"}`, "--delete", "cores"},
		{"--delete", "cores", "--delete", "cores"},
	} {
		code, stdout, stderr := runRootArgs(append([]string{"vm", "set", "--roster", rp, "qa-pve-01", "100"}, args...)...)
		if code != 1 || stdout != "" || strings.Count(stderr, "\n") != 1 {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want exit 1 and one error line", args, code, stdout, stderr)
		}
	}
	if _, _, n := f.state(); n != 0 {
		t.Errorf("%d request(s) reached PVE, want none", n)
	}
}

// TestVMSet_DeleteThenReReadFails_WarnsAndExits0: the Part 2a contract holds
// for a delete: a failed post-apply re-read is one stderr warning, stdout
// still reports the delete, and the exit status is 0.
func TestVMSet_DeleteThenReReadFails_WarnsAndExits0(t *testing.T) {
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	f, srv := newDeleteFakePVE(t, map[string]string{"description": "x"})
	f.failGet = 3 // GET 1 Read, 2 fresh digest, 3 Run's re-read
	rp := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	code, stdout, stderr := runRootArgs("vm", "set", "--roster", rp, "--delete", "description", "qa-pve-01", "100")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if want := "qa-pve-01: delete=description\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if strings.Count(stderr, "\n") != 1 || !strings.HasPrefix(stderr, "warning: qa-pve-01: vm 100: the write was applied but its result could not be re-read") {
		t.Errorf("stderr = %q, want the one AfterErr warning line", stderr)
	}
	cfg, _, _ := f.state()
	if v, ok := cfg["description"]; ok {
		t.Errorf("description still present (%q): the delete itself succeeded", v)
	}
}

// TestVMSet_DeleteRootOnlyKeyOverSSH_ThroughRunRoot: `args` is root-only, so
// its delete is `qm set <vmid> --delete args` over the SSH vector — never a
// REST write — and it is reported like any delete. The fake host's SSH
// handler removes the key from the same config the REST fake serves, so
// Run's re-read sees it gone.
func TestVMSet_DeleteRootOnlyKeyOverSSH_ThroughRunRoot(t *testing.T) {
	f, srv := newDeleteFakePVE(t, map[string]string{"args": "-cpu host", "cores": "2"})

	const wantCmd = `qm set '100' --delete 'args'`
	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(func(cmd string) (string, string, int) {
		if cmd != wantCmd {
			return "", "unexpected command", 127
		}
		f.removeKey("args")
		return "", "", 0
	})
	rosterPath := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	code, stdout, stderr := runRootArgs("vm", "set", "--roster", rosterPath, "--delete", "args", "qa-pve-01", "100")
	if code != 0 {
		t.Fatalf("exit %d; stderr %q", code, stderr)
	}
	if want := "qa-pve-01: delete=args\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty (the re-read must see the key gone)", stderr)
	}
	cfg, writes, _ := f.state()
	if len(writes) != 0 {
		t.Errorf("REST writes = %q, want none: a root-only delete never goes over REST", writes)
	}
	if _, ok := cfg["args"]; ok || cfg["cores"] != "2" {
		t.Errorf("config = %v, want args gone and cores untouched", cfg)
	}
	if got := fs.Commands(); !slices.Equal(got, []string{wantCmd}) {
		t.Errorf("SSH commands = %q, want exactly %q", got, wantCmd)
	}
}
