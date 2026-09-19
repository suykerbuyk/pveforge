package pve

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sourceguard"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// This file pins the SEAM between RoutedClient and Client: that each
// RoutedClient pass-through threads the node and every caller-supplied
// argument into the right position of the request that reaches the wire.
//
// Each layer's own suite looks complete without this. The internal/idempotent
// tests drive fakes and never execute a pass-through, and most internal/pve
// tests call Client directly and skip it. Swapping CloneVM's two adjacent int
// arguments once compiled and passed both complete suites, which in
// production would have cloned the new vmid onto the source. See task
// pveforge-routedclient-passthrough-seam for the full inventory and the
// mutation table every test here was checked against.
//
// Two rules hold for every test in this file:
//
//   - Every request is recorded and compared against an EXACT expected list.
//     A test that only checked err == nil would pass against a pass-through
//     that sent the right call to the wrong VM.
//   - This file never names a go-proxmox type, so it stays out of the set of
//     files an import-path change to that library has to touch.

// Fixture values. Each is chosen so that a wrong argument lands somewhere
// distinguishable, never on another fixture value.
//
// Every method is also exercised with TWO values of each argument it
// forwards (two target nodes, two vmids, ...). With a single value, a
// pass-through that hard-coded that value in place of its parameter would
// pass every assertion.
const (
	// fwdTargetNode is deliberately NOT "qa-pve-01". For a pass-through that
	// binds c.target.Node, the only node mutation expressible in its body is
	// replacing c.target.Node with a string literal, and "qa-pve-01" — the
	// real lab host, used by nearly every other test — is the likeliest one.
	// A target of "qa-pve-01" would make that mutation invisible.
	fwdTargetNode = "qa-pve-03"
	// fwdCallerNode is what a test passes as an explicit node argument. It
	// differs from fwdTargetNode, so substituting one for the other moves the
	// request to a different path.
	fwdCallerNode = "qa-pve-02"
	// fwdTargetNode2 is the second target node, for the second case of each
	// target-bound method.
	fwdTargetNode2 = "qa-pve-04"
	// fwdTargetID and fwdTargetHost are the target's roster id and host. They
	// are distinct from every node value, because a roster id need not match
	// its PVE node name: a pass-through that forwarded c.target.ID or
	// c.target.Host where it meant c.target.Node would send the request to
	// /nodes/<roster-id>/..., and with an id equal to the node it would be
	// invisible.
	fwdTargetID   = "roster-id-x"
	fwdTargetHost = "pve-host-x.example.com"
	// fwdVMID and fwdVMID2 are non-adjacent to each other and to every other
	// id in play, so vmid±1 is never a valid fixture value.
	fwdVMID  = 4242
	fwdVMID2 = 5151
)

// fwdRequest is one request as the fake REST server saw it.
type fwdRequest struct {
	Method   string
	Path     string
	RawQuery string
	Form     string // url.Values.Encode() of the POST/PUT form; sorted, so deterministic
}

// String renders a request as "METHOD path?query form", the single form
// every expected list in this file is written in.
func (r fwdRequest) String() string {
	s := r.Method + " " + r.Path
	if r.RawQuery != "" {
		s += "?" + r.RawQuery
	}
	if r.Form != "" {
		s += " " + r.Form
	}
	return s
}

// fwdRecorder records every request that reaches a fake REST server.
type fwdRecorder struct {
	mu   sync.Mutex
	reqs []fwdRequest
}

func (rec *fwdRecorder) record(t *testing.T, r *http.Request) {
	t.Helper()
	fr := fwdRequest{Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		fr.Form = r.PostForm.Encode()
	}
	rec.mu.Lock()
	rec.reqs = append(rec.reqs, fr)
	rec.mu.Unlock()
}

func (rec *fwdRecorder) got() []fwdRequest {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]fwdRequest(nil), rec.reqs...)
}

// newFwdServer starts a fake REST server that records every request and
// then hands it to respond.
func newFwdServer(t *testing.T, respond http.HandlerFunc) (*httptest.Server, *fwdRecorder) {
	t.Helper()
	rec := &fwdRecorder{}
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		rec.record(t, r)
		respond(w, r)
	})
	return srv, rec
}

// fwdClient builds a RoutedClient bound to fwdTargetNode and talking to srv.
func fwdClient(t *testing.T, srv *httptest.Server) *RoutedClient {
	t.Helper()
	return fwdClientOn(t, srv, fwdTargetNode)
}

// fwdClientOn builds a RoutedClient bound to node and talking to srv. Its
// roster id and host are fwdTargetID and fwdTargetHost, distinct from any node.
func fwdClientOn(t *testing.T, srv *httptest.Server, node string) *RoutedClient {
	t.Helper()
	tg := &roster.Target{ID: fwdTargetID, Host: fwdTargetHost, Node: node}
	return &RoutedClient{rest: testClient(t, srv), target: tg, passphrase: "roster-pass"}
}

// writeData answers a request with PVE's {"data": ...} envelope.
func writeData(w http.ResponseWriter, data string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"data":` + data + `}`))
}

// assertRequests fails unless got is exactly want, in order. want must be
// non-empty: an empty expected list compares equal to "nothing happened",
// which is the vacuous-pass shape this file exists to rule out. Use
// assertNoRequests to assert that nothing reached the server.
func assertRequests(t *testing.T, got []fwdRequest, want ...string) {
	t.Helper()
	if len(want) == 0 {
		t.Fatal("assertRequests called with no expected requests; use assertNoRequests")
	}
	gotStrs := make([]string, len(got))
	for i, r := range got {
		gotStrs[i] = r.String()
	}
	if strings.Join(gotStrs, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests on the wire:\n  got:  %q\n  want: %q", gotStrs, want)
	}
}

func assertNoRequests(t *testing.T, got []fwdRequest) {
	t.Helper()
	if len(got) != 0 {
		t.Errorf("expected no REST requests, got %d: %v", len(got), got)
	}
}

// fwdSSH is a fake SSH server that records every command it is asked to run.
type fwdSSH struct {
	fs   *fakeSSHServer
	mu   sync.Mutex
	cmds []string
}

// newFwdSSH starts a fake SSH server that answers every command with exit
// status 0, points this process's sshPort at it, and returns a target
// bootstrapped against it with its node set to fwdTargetNode.
func newFwdSSH(t *testing.T) (*fwdSSH, *roster.Target) {
	t.Helper()
	return newFwdSSHWith(t, nil)
}

// newFwdSSHWith is newFwdSSH with the command's stdout, stderr and exit
// status supplied by respond. A nil respond answers every command with exit
// status 0 and no output.
func newFwdSSHWith(t *testing.T, respond func(cmd string) (stdout, stderr string, exitCode int)) (*fwdSSH, *roster.Target) {
	t.Helper()
	s := &fwdSSH{fs: newFakeSSHServer(t)}
	s.fs.handleExec = func(cmd string) (string, string, int) {
		s.mu.Lock()
		s.cmds = append(s.cmds, cmd)
		s.mu.Unlock()
		if respond == nil {
			return "", "", 0
		}
		return respond(cmd)
	}
	withFakeSSHPort(t, s.fs)
	tg := bootstrappedTarget(t, s.fs, "roster-pass")
	// bootstrappedTarget fixes both ID and Node at "qa-pve-01"; see
	// fwdTargetNode and fwdTargetID for why these tests use neither. Host stays
	// 127.0.0.1, which is where the fake SSH server listens and is distinct
	// from every node value.
	tg.ID = fwdTargetID
	tg.Node = fwdTargetNode
	return s, tg
}

func (s *fwdSSH) got() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.cmds...)
}

// assertNoCommands fails if any SSH command ran.
func assertNoCommands(t *testing.T, got []string) {
	t.Helper()
	if len(got) != 0 {
		t.Errorf("expected no ssh commands, got %d: %q", len(got), got)
	}
}

// assertCommands fails unless the SSH commands run are exactly want.
func assertCommands(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(want) == 0 {
		t.Fatal("assertCommands called with no expected commands")
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("ssh commands:\n  got:  %q\n  want: %q", got, want)
	}
}

// --- Phase 1: the pass-throughs that destroy or mutate ---------------------

// TestRoutedForwarding_DestroyVM pins DestroyVM, the most destructive
// pass-through on the type: its one production caller hard-codes purge=true,
// so a wrong vmid deletes another VM's config AND disks. Before this test, no
// test anywhere invoked DestroyVM on a RoutedClient.
//
// The two cases differ in every forwarded value: node, vmid and purge. The
// production caller always passes purge=true, so without the no_purge case a
// hard-coded purge would be indistinguishable from a forwarded one.
func TestRoutedForwarding_DestroyVM(t *testing.T) {
	cases := []struct {
		name      string
		node      string
		vmid      int
		purge     bool
		wantPath  string
		wantQuery string
	}{
		{"purge", fwdTargetNode, fwdVMID, true, "/nodes/qa-pve-03/qemu/4242", "purge=1"},
		{"no_purge", fwdTargetNode2, fwdVMID2, false, "/nodes/qa-pve-04/qemu/5151", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			upid := wellFormedUPID(c.node)
			srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
				writeData(w, `"`+upid+`"`)
			})

			got, err := fwdClientOn(t, srv, c.node).DestroyVM(context.Background(), c.vmid, c.purge)
			if err != nil {
				t.Fatalf("DestroyVM: %v", err)
			}
			if got != upid {
				t.Errorf("upid = %q, want %q returned verbatim", got, upid)
			}

			reqs := rec.got()
			if len(reqs) != 1 {
				t.Fatalf("got %d requests, want exactly 1: %v", len(reqs), reqs)
			}
			r := reqs[0]
			if r.Method != http.MethodDelete {
				t.Errorf("method = %q, want DELETE", r.Method)
			}
			if r.Path != c.wantPath {
				t.Errorf("path = %q, want %q", r.Path, c.wantPath)
			}
			if r.RawQuery != c.wantQuery {
				t.Errorf("query = %q, want exactly %q", r.RawQuery, c.wantQuery)
			}
		})
	}
}

// TestRoutedForwarding_StopVM pins StopVM, which the destroy Op calls first:
// a wrong vmid hard-stops some other running VM.
func TestRoutedForwarding_StopVM(t *testing.T) {
	cases := []struct {
		node string
		vmid int
		want string
	}{
		{fwdTargetNode, fwdVMID, "POST /nodes/qa-pve-03/qemu/4242/status/stop"},
		{fwdTargetNode2, fwdVMID2, "POST /nodes/qa-pve-04/qemu/5151/status/stop"},
	}
	for _, c := range cases {
		t.Run(c.node, func(t *testing.T) {
			srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
				writeData(w, `"`+wellFormedUPID(c.node)+`"`)
			})

			if _, err := fwdClientOn(t, srv, c.node).StopVM(context.Background(), c.vmid); err != nil {
				t.Fatalf("StopVM: %v", err)
			}
			assertRequests(t, rec.got(), c.want)
		})
	}
}

// TestRoutedForwarding_SetVMConfigField_REST pins the REST leg of
// SetVMConfigField: the config write with no digest guard, so whatever it is
// handed lands unconditionally. field and value are adjacent strings, so a
// transposition compiles. The existing REST-leg test's handler inspects
// nothing, which is why a wrong vmid and a field/value swap both passed.
func TestRoutedForwarding_SetVMConfigField_REST(t *testing.T) {
	cases := []struct {
		node  string
		vmid  int
		value string
		want  string
	}{
		{fwdTargetNode, fwdVMID, "web-4242", "PUT /nodes/qa-pve-03/qemu/4242/config name=web-4242"},
		{fwdTargetNode2, fwdVMID2, "web-5151", "PUT /nodes/qa-pve-04/qemu/5151/config name=web-5151"},
	}
	for _, c := range cases {
		t.Run(c.node, func(t *testing.T) {
			srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			rc := fwdClientOn(t, srv, c.node)

			if err := rc.SetVMConfigField(context.Background(), c.vmid, "name", c.value); err != nil {
				t.Fatalf("SetVMConfigField: %v", err)
			}
			assertRequests(t, rec.got(), c.want)
			if rc.ssh != nil {
				t.Error("a non-root-only field must never dial SSH")
			}
		})
	}
}

// TestRoutedForwarding_SetVMConfigField_SSHRootOnly pins the SSH leg taken
// for a registered root-only field. internal/device writes "args" through
// this leg, and args is a whole-line replacement of the QEMU argument string,
// so a wrong vmid detaches passthrough devices from some other VM.
//
// The SSH command carries no node, so the two calls share one target and
// differ in vmid and value. One fake SSH server per test, not per call: each
// bootstrapped target costs three scrypt derivations.
func TestRoutedForwarding_SetVMConfigField_SSHRootOnly(t *testing.T) {
	sshSrv, tg := newFwdSSH(t)
	srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "a root-only field must never reach REST", http.StatusInternalServerError)
	})
	rc := &RoutedClient{rest: testClient(t, srv), target: tg, passphrase: "roster-pass"}
	defer rc.Close()

	for _, c := range []struct {
		vmid  int
		value string
	}{
		{fwdVMID, "-device nvme,drive=seam4242"},
		{fwdVMID2, "-device nvme,drive=seam5151"},
	} {
		if err := rc.SetVMConfigField(context.Background(), c.vmid, "args", c.value); err != nil {
			t.Fatalf("SetVMConfigField(%d): %v", c.vmid, err)
		}
	}
	assertCommands(t, sshSrv.got(),
		"qm set '4242' --args '-device nvme,drive=seam4242'",
		"qm set '5151' --args '-device nvme,drive=seam5151'")
	assertNoRequests(t, rec.got())
}

// TestRoutedForwarding_SetVMConfigField_SSHFallback pins the second SSH call
// site: a field not in the root-only registry that PVE rejects as root-only
// over REST is retried once over SSH. It is a separate call from the
// root-only leg above, so a wrong argument there needs its own test. The node
// on the REST attempt is pinned with two values by the _REST test, which
// exercises the same call site.
func TestRoutedForwarding_SetVMConfigField_SSHFallback(t *testing.T) {
	sshSrv, tg := newFwdSSH(t)
	srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "only root can set 'hookscript' config", http.StatusInternalServerError)
	})
	rc := &RoutedClient{rest: testClient(t, srv), target: tg, passphrase: "roster-pass"}
	defer rc.Close()

	for _, c := range []struct {
		vmid  int
		value string
	}{
		{fwdVMID, "local:snippets/hook-4242.sh"},
		{fwdVMID2, "local:snippets/hook-5151.sh"},
	} {
		if err := rc.SetVMConfigField(context.Background(), c.vmid, "hookscript", c.value); err != nil {
			t.Fatalf("SetVMConfigField(%d): %v", c.vmid, err)
		}
	}
	assertRequests(t, rec.got(),
		"PUT /nodes/qa-pve-03/qemu/4242/config hookscript=local%3Asnippets%2Fhook-4242.sh",
		"PUT /nodes/qa-pve-03/qemu/5151/config hookscript=local%3Asnippets%2Fhook-5151.sh")
	assertCommands(t, sshSrv.got(),
		"qm set '4242' --hookscript 'local:snippets/hook-4242.sh'",
		"qm set '5151' --hookscript 'local:snippets/hook-5151.sh'")
}

// TestRoutedForwarding_SetVMConfigField_NoFallbackOnOtherErrors pins the
// guard on that fallback. Only PVE's root-only rejection may be retried over
// SSH. The SSH vector runs as root, so retrying any other failure over it —
// a 403 permission denial above all — would escalate past the API token's
// ACL. Each non-root-only failure must come back as the original REST error,
// with no SSH connection ever dialed.
//
// A fake SSH server IS configured, and that is what gives this test teeth.
// Without one, an unguarded retry would fail to dial and fall back to
// returning the REST error anyway, so the test would pass for the wrong
// reason.
func TestRoutedForwarding_SetVMConfigField_NoFallbackOnOtherErrors(t *testing.T) {
	sshSrv, tg := newFwdSSH(t)
	srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/qemu/4242/") {
			http.Error(w, "Permission check failed (/vms/4242, VM.Config.Options)", http.StatusForbidden)
			return
		}
		http.Error(w, "unable to parse value of 'name'", http.StatusInternalServerError)
	})
	rc := &RoutedClient{rest: testClient(t, srv), target: tg, passphrase: "roster-pass"}
	defer rc.Close()

	for _, c := range []struct {
		vmid    int
		field   string
		wantErr string
	}{
		{fwdVMID, "description", "Permission check failed (/vms/4242, VM.Config.Options)"},
		{fwdVMID2, "name", "unable to parse value of 'name'"},
	} {
		err := rc.SetVMConfigField(context.Background(), c.vmid, c.field, "x")
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("SetVMConfigField(%d, %q) err = %v, want the original REST error %q", c.vmid, c.field, err, c.wantErr)
		}
	}
	assertRequests(t, rec.got(),
		"PUT /nodes/qa-pve-03/qemu/4242/config description=x",
		"PUT /nodes/qa-pve-03/qemu/5151/config name=x")
	assertNoCommands(t, sshSrv.got())
	if rc.ssh != nil {
		t.Error("a non-root-only REST failure must never dial SSH")
	}
}

// TestRoutedForwarding_SetVMConfigFieldCAS pins the digest-guarded config
// write. It carries three adjacent strings — field, value, expectDigest — so
// three different transpositions compile, and each one sends a different
// wrong form.
func TestRoutedForwarding_SetVMConfigFieldCAS(t *testing.T) {
	cases := []struct {
		node   string
		vmid   int
		value  string
		digest string
		want   string
	}{
		{fwdTargetNode, fwdVMID, "web-4242", "d1g3st", "PUT /nodes/qa-pve-03/qemu/4242/config digest=d1g3st&name=web-4242"},
		{fwdTargetNode2, fwdVMID2, "web-5151", "d2g3st", "PUT /nodes/qa-pve-04/qemu/5151/config digest=d2g3st&name=web-5151"},
	}
	for _, c := range cases {
		t.Run(c.node, func(t *testing.T) {
			srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			if err := fwdClientOn(t, srv, c.node).SetVMConfigFieldCAS(context.Background(), c.vmid, "name", c.value, c.digest); err != nil {
				t.Fatalf("SetVMConfigFieldCAS: %v", err)
			}
			assertRequests(t, rec.got(), c.want)
		})
	}
}

// snippetPayloadArg extracts the base64 argument sshexec.Client.WriteFile
// embeds in its remote script.
var snippetPayloadArg = regexp.MustCompile(`printf '%s' '([A-Za-z0-9+/=]*)' \| base64 -d`)

// wantSnippetScript is the exact remote script UploadSnippet must send for
// one file. It is written out in full, rather than matched by fragment,
// because every fragment matters. In particular the mode: PVE runs a
// hookscript as an executable, so a snippet written 0644 breaks every start
// of every VM that points at it.
func wantSnippetScript(base, filename string, content []byte) string {
	dir := base + "/snippets"
	tmp := dir + "/" + filename + ".pveforge-tmp"
	return "set -e\n" +
		"mkdir -p '" + dir + "'\n" +
		"printf '%s' '" + base64.StdEncoding.EncodeToString(content) + "' | base64 -d > '" + tmp + "'\n" +
		"chmod '0755' '" + tmp + "'\n" +
		"mv '" + tmp + "' '" + dir + "/" + filename + "'\n"
}

// TestRoutedForwarding_UploadSnippet pins UploadSnippet's REST storage lookup
// and its SSH write. A wrong-but-valid filename silently replaces another
// VM's hookscript — a script that runs as root on that VM's every boot — and
// before this test nothing asserted the bytes that were written at all.
//
// Two uploads differ in storage, filename and content. The first content is
// deliberately hostile to any lossy path: a backslash, a single quote, a
// newline, a NUL and bytes above 0x7f.
func TestRoutedForwarding_UploadSnippet(t *testing.T) {
	sshSrv, tg := newFwdSSH(t)
	// Any storage id resolves, to a path derived from that id. A lookup of
	// the wrong storage is therefore caught by the assertions below, rather
	// than depending on how the client library happens to handle a 404.
	srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeData(w, `{"type":"dir","path":"/srv/`+strings.TrimPrefix(r.URL.Path, "/storage/")+`"}`)
	})
	rc := &RoutedClient{rest: testClient(t, srv), target: tg, passphrase: "roster-pass"}
	defer rc.Close()

	uploads := []struct {
		storage, filename, base string
		content                 []byte
	}{
		{"snipstore", "hook-4242.sh", "/srv/snipstore", []byte("#!/bin/sh\nprintf 'a\\\\b'\n\x00\xfe\xff")},
		{"snipstore2", "hook-5151.sh", "/srv/snipstore2", []byte("#!/bin/sh\nexit 0\n")},
	}
	var want []string
	for _, u := range uploads {
		if err := rc.UploadSnippet(context.Background(), u.storage, u.filename, u.content); err != nil {
			t.Fatalf("UploadSnippet(%s, %s): %v", u.storage, u.filename, err)
		}
		want = append(want, wantSnippetScript(u.base, u.filename, u.content))
	}
	assertRequests(t, rec.got(), "GET /storage/snipstore", "GET /storage/snipstore2")

	cmds := sshSrv.got()
	assertCommands(t, cmds, want...)

	// A second, independent observation of each payload. The exact-script
	// assertion compares against strings this test built with the same
	// encoder; this decodes what actually arrived and compares bytes.
	if len(cmds) != len(uploads) {
		t.Fatalf("got %d ssh commands, want %d", len(cmds), len(uploads))
	}
	for i, u := range uploads {
		m := snippetPayloadArg.FindStringSubmatch(cmds[i])
		if m == nil {
			t.Errorf("upload %d: no base64 payload argument in command:\n%s", i+1, cmds[i])
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(m[1])
		if err != nil {
			t.Errorf("upload %d: decode payload: %v", i+1, err)
			continue
		}
		if !bytes.Equal(decoded, u.content) {
			t.Errorf("upload %d: bytes written = %q, want %q", i+1, decoded, u.content)
		}
	}
}

// --- Phase 2: reads that feed a decision, and the remaining escapes --------

// TestRoutedForwarding_TagStillClaimed pins the destroy Op's post-destroy tag
// recheck. Both arguments are client-side filters over one cluster-wide
// listing, so the request is identical whatever is passed: forwarding is only
// observable through the answer. The fixture makes each answer depend on the
// arguments. 4242 and 5151 each carry a different tag, so excluding the wrong
// vmid, or asking about the wrong tag, flips at least one case.
func TestRoutedForwarding_TagStillClaimed(t *testing.T) {
	srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeData(w, `[`+
			`{"id":"qemu/4242","type":"qemu","vmid":4242,"tags":"t-a"},`+
			`{"id":"qemu/5151","type":"qemu","vmid":5151,"tags":"t-b"}]`)
	})
	rc := fwdClient(t, srv)

	cases := []struct {
		tag     string
		exclude int
		want    bool
	}{
		{"t-a", 4242, false}, // its only claimant is the excluded vmid
		{"t-a", 5151, true},  // 4242 still claims it
		{"t-b", 5151, false}, // its only claimant is the excluded vmid
	}
	for _, c := range cases {
		got, err := rc.TagStillClaimed(context.Background(), c.tag, c.exclude)
		if err != nil {
			t.Fatalf("TagStillClaimed(%q, %d): %v", c.tag, c.exclude, err)
		}
		if got != c.want {
			t.Errorf("TagStillClaimed(%q, %d) = %v, want %v", c.tag, c.exclude, got, c.want)
		}
	}
	const listing = "GET /cluster/resources?type=vm"
	assertRequests(t, rec.got(), listing, listing, listing)
}

// TestRoutedForwarding_WaitForAgentExec pins the poll loop's six arguments.
// pollInterval and timeout are adjacent time.Durations, so swapping them
// compiles: it would turn a short poll under a long deadline into one poll
// and an immediate timeout, reported as a guest command failure that never
// happened. The durations are chosen so the swapped order provably times out
// while the correct order completes.
//
// Two subtests are needed. "completes" catches the swap and a dropped
// pollInterval. It cannot catch a dropped timeout, because the 2-minute
// default deadline still lets it complete in ~200ms. "times_out" observes the
// timeout value itself, through AgentExecTimeoutError.Timeout. Both run under
// a bounded context, so no mutant can hang on a default.
//
// The two subtests use different values for every argument — node, vmid,
// pid, pollInterval and timeout — so a pass-through that hard-coded any one
// of them fails at least one subtest. The durations are chosen so that EVERY
// constant fails one of them, using only bounds that hold for any correct run
// because a ticker never fires early:
//
//   - "completes" polls every 100ms and cannot finish in under 200ms, which
//     kills any constant interval below 100ms.
//   - "times_out" polls every 15ms under a 60ms deadline and must poll at
//     least twice, which kills any constant interval of 60ms or more; and it
//     cannot poll more than once per 15ms, which kills any below 15ms.
//   - A constant timeout other than 60ms fails "times_out"'s exact Timeout
//     check, and exactly 60ms times "completes" out, since it needs ~200ms.
//
// No assertion bounds elapsed time from above, which is what would make a
// timing test flaky under load.
func TestRoutedForwarding_WaitForAgentExec(t *testing.T) {
	t.Run("completes", func(t *testing.T) {
		const poll = "GET /nodes/qa-pve-03/qemu/4242/agent/exec-status?pid=7"
		// Not exited for two polls, exited on the third. With a 100ms interval
		// that returns at ~200ms, inside a 900ms deadline: a 4.5x margin.
		// Swapped, the 100ms deadline beats the first 900ms tick, so it times
		// out after one poll. With pollInterval dropped, the 500ms default
		// ticks twice by 1000ms, later than the 900ms deadline, so it times out.
		var polls atomic.Int32
		srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
			if polls.Add(1) < 3 {
				writeData(w, `{"exited":0}`)
				return
			}
			writeData(w, `{"exited":1,"exitcode":0}`)
		})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		start := time.Now()
		status, err := fwdClient(t, srv).WaitForAgentExec(ctx, fwdVMID, 7, 100*time.Millisecond, 900*time.Millisecond)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("WaitForAgentExec: %v", err)
		}
		if status.Exited == 0 {
			t.Errorf("Exited = 0, want the exited status from the third poll")
		}
		if elapsed < 200*time.Millisecond {
			t.Errorf("completed in %v; three polls 100ms apart cannot take under 200ms, so a shorter interval was used", elapsed)
		}
		assertRequests(t, rec.got(), poll, poll, poll)
	})

	t.Run("times_out", func(t *testing.T) {
		// Never exits. A 15ms interval under a 60ms deadline gives ~5 polls;
		// asserting only >= 2 leaves a 4x margin. The exact count depends on
		// the scheduler, and asserting it would make a flaky test, not a
		// stronger one.
		const poll = "GET /nodes/qa-pve-04/qemu/5151/agent/exec-status?pid=9"
		const interval = 15 * time.Millisecond
		srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeData(w, `{"exited":0}`)
		})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		start := time.Now()
		_, err := fwdClientOn(t, srv, fwdTargetNode2).WaitForAgentExec(ctx, fwdVMID2, 9, interval, 60*time.Millisecond)
		elapsed := time.Since(start)
		var te *AgentExecTimeoutError
		if !errors.As(err, &te) {
			t.Fatalf("err = %v, want *AgentExecTimeoutError", err)
		}
		if te.Timeout != 60*time.Millisecond {
			t.Errorf("Timeout = %v, want exactly the 60ms the caller passed", te.Timeout)
		}
		if te.VMID != fwdVMID2 || te.PID != 9 {
			t.Errorf("VMID/PID = %d/%d, want %d/9", te.VMID, te.PID, fwdVMID2)
		}
		if te.Polls < 2 {
			t.Errorf("Polls = %d, want at least 2", te.Polls)
		}
		if limit := 1 + int(elapsed/interval); te.Polls > limit {
			t.Errorf("Polls = %d in %v; one poll per 15ms allows at most %d, so a shorter interval was used", te.Polls, elapsed, limit)
		}
		reqs := rec.got()
		if len(reqs) != te.Polls {
			t.Errorf("server saw %d requests, but the error reports %d polls", len(reqs), te.Polls)
		}
		for i, r := range reqs {
			if r.String() != poll {
				t.Errorf("poll %d = %q, want %q", i+1, r.String(), poll)
			}
		}
	})
}

// TestRoutedForwarding_RawRequest pins the generic escape hatch that the
// network Ops use for their DELETE and commit PUT. method and path are
// adjacent strings, so they can be swapped. The paths name nodes other than
// the target, to show RawRequest forwards a caller's path untouched, and the
// two calls differ in method, path and params.
func TestRoutedForwarding_RawRequest(t *testing.T) {
	srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeData(w, `{"ok":1}`)
	})

	rc := fwdClient(t, srv)
	for _, c := range []struct {
		method, path string
		params       url.Values
	}{
		{http.MethodPut, "/nodes/qa-pve-02/network/vmbr7", url.Values{"comments": {"seam"}}},
		{http.MethodDelete, "/nodes/qa-pve-04/network/vmbr8", url.Values{"force": {"1"}}},
	} {
		got, err := rc.RawRequest(context.Background(), c.method, c.path, c.params)
		if err != nil {
			t.Fatalf("RawRequest(%s %s): %v", c.method, c.path, err)
		}
		if string(got) != `{"ok":1}` {
			t.Errorf("RawRequest(%s %s) data = %s, want {\"ok\":1} returned unwrapped", c.method, c.path, got)
		}
	}
	assertRequests(t, rec.got(),
		"PUT /nodes/qa-pve-02/network/vmbr7 comments=seam",
		"DELETE /nodes/qa-pve-04/network/vmbr8?force=1")
}

// TestRoutedForwarding_LinkState pins the management-bridge canary. The
// network Op reads it before and after a commit and compares the two reads.
// A pass-through that ignored iface would read the same interface both times,
// so the comparison would always pass. Two different interfaces with two
// different answers make that visible here, on the RoutedClient itself.
// Until now it was only covered indirectly, through an idempotent integration
// test.
func TestRoutedForwarding_LinkState(t *testing.T) {
	sshSrv, tg := newFwdSSHWith(t, func(cmd string) (string, string, int) {
		switch cmd {
		case "ip -j link show dev 'vmbr7'":
			return `[{"ifname":"vmbr7","flags":["BROADCAST","UP"],"operstate":"UP"}]`, "", 0
		case "ip -j link show dev 'vmbr8'":
			return `[{"ifname":"vmbr8","flags":["BROADCAST"],"operstate":"DOWN"}]`, "", 0
		}
		return "[]", "", 0
	})
	rc := &RoutedClient{rest: testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("LinkState must not reach REST, got %s %s", r.Method, r.URL.Path)
	})), target: tg, passphrase: "roster-pass"}
	defer rc.Close()

	up, err := rc.LinkState(context.Background(), "vmbr7")
	if err != nil {
		t.Fatalf("LinkState(vmbr7): %v", err)
	}
	down, err := rc.LinkState(context.Background(), "vmbr8")
	if err != nil {
		t.Fatalf("LinkState(vmbr8): %v", err)
	}
	if want := (sshexec.LinkState{Exists: true, Up: true}); up != want {
		t.Errorf("LinkState(vmbr7) = %+v, want %+v", up, want)
	}
	if want := (sshexec.LinkState{Exists: true, Up: false}); down != want {
		t.Errorf("LinkState(vmbr8) = %+v, want %+v", down, want)
	}
	assertCommands(t, sshSrv.got(), "ip -j link show dev 'vmbr7'", "ip -j link show dev 'vmbr8'")
}

// TestRoutedForwarding_APIDocTree pins the schema fetch behind the discover
// commands. It takes no argument to get wrong, so the only thing to pin is
// that it forwards at all and returns what the host served.
func TestRoutedForwarding_APIDocTree(t *testing.T) {
	srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`const apiSchema = [{"path":"/seam-probe"}];` + "\nExt.define('x');\n"))
	})

	got, err := fwdClient(t, srv).APIDocTree(context.Background())
	if err != nil {
		t.Fatalf("APIDocTree: %v", err)
	}
	if string(got) != `[{"path":"/seam-probe"}]` {
		t.Errorf("tree = %s, want the served array", got)
	}
	assertRequests(t, rec.got(), "GET /pve-docs/api-viewer/apidoc.js")
}

// TestRoutedForwarding_NextVMID_Exclude pins NextVMID's exclude list. No
// existing test and no production caller passes it, so dropping it from the
// pass-through was invisible. exclude is applied client-side: PVE offers
// 4242 and the walk must skip whatever is excluded, verifying only the first
// id it lands on. Two exclude lists land on two different ids.
func TestRoutedForwarding_NextVMID_Exclude(t *testing.T) {
	cases := []struct {
		name    string
		exclude []int
		want    int
		reqs    []string
	}{
		{"one", []int{4242}, 4243, []string{"GET /cluster/nextid", "GET /cluster/nextid?vmid=4243"}},
		{"two", []int{4242, 4243}, 4244, []string{"GET /cluster/nextid", "GET /cluster/nextid?vmid=4244"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.RawQuery == "" {
					writeData(w, `"4242"`)
					return
				}
				writeData(w, `"`+r.URL.Query().Get("vmid")+`"`)
			})

			got, err := fwdClient(t, srv).NextVMID(context.Background(), 0, c.exclude...)
			if err != nil {
				t.Fatalf("NextVMID: %v", err)
			}
			if got != c.want {
				t.Errorf("NextVMID(exclude %v) = %d, want %d", c.exclude, got, c.want)
			}
			assertRequests(t, rec.got(), c.reqs...)
		})
	}
}

// --- Phase 3: node binding across every node-resolving pass-through -------

// fwdPVE is a fake PVE REST API for the node-binding sweep. It answers a valid
// body for every request SHAPE the node-resolving pass-throughs issue, on any
// node, vmid or storage. A pass-through that sent its request to the wrong
// node therefore still succeeds, and is caught by the exact request-list
// assertion rather than by an error path. The one piece of state is the
// snapshot list: a snapshot POST adds that name to later listings, which
// CreateSnapshot's post-verify reads.
type fwdPVE struct {
	t         *testing.T
	mu        sync.Mutex
	snapshots []string
}

func (f *fwdPVE) serve(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	parts := strings.Split(strings.Trim(p, "/"), "/")
	node := parts[1]
	switch {
	case r.Method == http.MethodPut:
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/agent/exec"):
		writeData(w, `{"pid":7}`)
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/snapshot"):
		f.mu.Lock()
		f.snapshots = append(f.snapshots, r.PostForm.Get("snapname"))
		f.mu.Unlock()
		writeData(w, `"`+wellFormedUPID(node)+`"`)
	case r.Method == http.MethodPost, r.Method == http.MethodDelete:
		writeData(w, `"`+wellFormedUPID(node)+`"`)
	case strings.HasSuffix(p, "/agent/exec-status"):
		writeData(w, `{"exited":1,"exitcode":0}`)
	case strings.HasSuffix(p, "/agent/network-get-interfaces"):
		writeData(w, `{"result":[]}`)
	case strings.HasSuffix(p, "/snapshot"):
		f.mu.Lock()
		list := `{"name":"current"}`
		for _, s := range f.snapshots {
			list += `,{"name":"` + s + `","vmstate":1}`
		}
		f.mu.Unlock()
		writeData(w, `[`+list+`]`)
	case len(parts) == 5 && parts[2] == "tasks":
		writeData(w, fmt.Sprintf(`{"status":"stopped","exitstatus":"OK","upid":%q,"node":%q}`, parts[3], node))
	case len(parts) == 5 && parts[2] == "storage" && parts[4] == "status":
		writeData(w, `{"type":"dir","shared":0}`)
	case len(parts) == 5 && parts[2] == "storage" && parts[4] == "content":
		s := parts[3]
		writeData(w, `[`+
			`{"volid":"`+s+`:vm-4242-disk-0","vmid":4242,"content":"images"},`+
			`{"volid":"`+s+`:vm-4243-disk-0","vmid":4243,"content":"images"},`+
			`{"volid":"`+s+`:vm-5151-disk-0","vmid":5151,"content":"images"}]`)
	// Each object read carries the one identity field real PVE always sends
	// and pve refuses to read without: a VM's run status, an interface's type.
	case strings.HasSuffix(p, "/status/current"):
		writeData(w, `{"status":"running"}`)
	case len(parts) == 4 && parts[2] == "network":
		writeData(w, `{"type":"bridge"}`)
	case strings.HasSuffix(p, "/config"), len(parts) == 3 && parts[2] == "status":
		writeData(w, `{}`)
	case len(parts) == 3:
		writeData(w, `[]`)
	default:
		f.t.Errorf("fake PVE has no answer for %s %s", r.Method, p)
		http.NotFound(w, r)
	}
}

// fwdCallerNode2 is the second caller-supplied node, distinct from both
// target nodes, for the second case of each caller-node method.
const fwdCallerNode2 = "qa-pve-05"

// bindingCase is one call to one pass-through, and the exact requests it must
// put on the wire.
type bindingCase struct {
	target string // the RoutedClient's target node
	call   func(t *testing.T, ctx context.Context, rc *RoutedClient) error
	want   []string
}

// TestRoutedForwarding_NodeBinding pins how each of the 27 node-resolving
// pass-throughs picks its node. The other 10 take no node at all.
//
// Two different node sources exist, and each has its own wrong answer:
//
//   - The 13 CALLER-NODE methods take an explicit node argument. Their bodies
//     can wrongly substitute c.target.Node, or c.target.ID, for it. Every one of
//     these cases uses a caller node that differs from the target's node, so
//     either substitution moves the request.
//   - The 14 TARGET-BOUND methods take no node and bind c.target.Node. Their
//     bodies can wrongly use a literal node name, or c.target.ID. The target's
//     node, id and host are mutually distinct, and none of them is the likeliest
//     literal, "qa-pve-01".
//
// Every method has at least two cases, differing in the node and in every
// other argument it forwards. A pass-through that hard-coded any one of those
// values fails the case that uses the other value.
//
// Each row must call only the method it is named for. GetStorage and
// StorageType put identical requests on the wire, and so do GetVM and
// ClaimedVolumes, so a row that called its twin would still pass here.
// TestRoutedForwarding_NodeBindingRowsCallTheirOwnMethod checks that.
func TestRoutedForwarding_NodeBinding(t *testing.T) {
	withTaskTimings(t, time.Millisecond, 5*time.Second)
	upid := wellFormedUPID
	params := func(kv ...string) url.Values {
		v := url.Values{}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	volids := func(t *testing.T, got []string, want ...string) {
		t.Helper()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("volids = %v, want %v", got, want)
		}
	}

	methods := []struct {
		name  string
		cases []bindingCase
	}{
		// --- caller-node methods: the node comes from the caller ---
		{"GetNode", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetNode(ctx, fwdCallerNode)
				return err
			}, []string{"GET /nodes/qa-pve-02/status"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetNode(ctx, fwdCallerNode2)
				return err
			}, []string{"GET /nodes/qa-pve-05/status"}},
		}},
		{"GetVM", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetVM(ctx, fwdCallerNode, fwdVMID)
				return err
			}, []string{"GET /nodes/qa-pve-02/qemu/4242/status/current", "GET /nodes/qa-pve-02/qemu/4242/config"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetVM(ctx, fwdCallerNode2, fwdVMID2)
				return err
			}, []string{"GET /nodes/qa-pve-05/qemu/5151/status/current", "GET /nodes/qa-pve-05/qemu/5151/config"}},
		}},
		{"GetVMs", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetVMs(ctx, fwdCallerNode)
				return err
			}, []string{"GET /nodes/qa-pve-02/qemu"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetVMs(ctx, fwdCallerNode2)
				return err
			}, []string{"GET /nodes/qa-pve-05/qemu"}},
		}},
		{"GetStorage", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetStorage(ctx, fwdCallerNode, "stor-x")
				return err
			}, []string{"GET /nodes/qa-pve-02/storage/stor-x/status"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetStorage(ctx, fwdCallerNode2, "stor-y")
				return err
			}, []string{"GET /nodes/qa-pve-05/storage/stor-y/status"}},
		}},
		{"GetStorages", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetStorages(ctx, fwdCallerNode)
				return err
			}, []string{"GET /nodes/qa-pve-02/storage"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetStorages(ctx, fwdCallerNode2)
				return err
			}, []string{"GET /nodes/qa-pve-05/storage"}},
		}},
		{"GetStorageVolumes", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetStorageVolumes(ctx, fwdCallerNode, "stor-x")
				return err
			}, []string{"GET /nodes/qa-pve-02/storage/stor-x/content"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetStorageVolumes(ctx, fwdCallerNode2, "stor-y")
				return err
			}, []string{"GET /nodes/qa-pve-05/storage/stor-y/content"}},
		}},
		{"ClaimedVolumes", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.ClaimedVolumes(ctx, fwdCallerNode, fwdVMID)
				return err
			}, []string{"GET /nodes/qa-pve-02/qemu/4242/status/current", "GET /nodes/qa-pve-02/qemu/4242/config"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.ClaimedVolumes(ctx, fwdCallerNode2, fwdVMID2)
				return err
			}, []string{"GET /nodes/qa-pve-05/qemu/5151/status/current", "GET /nodes/qa-pve-05/qemu/5151/config"}},
		}},
		{"OrphanVolumes", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.OrphanVolumes(ctx, fwdCallerNode, "stor-x")
				return err
			}, []string{"GET /nodes/qa-pve-02/storage/stor-x/status", "GET /nodes/qa-pve-02/storage/stor-x/content", "GET /nodes/qa-pve-02/qemu"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.OrphanVolumes(ctx, fwdCallerNode2, "stor-y")
				return err
			}, []string{"GET /nodes/qa-pve-05/storage/stor-y/status", "GET /nodes/qa-pve-05/storage/stor-y/content", "GET /nodes/qa-pve-05/qemu"}},
		}},
		// OrphanVolumesForVMID applies its vmid as a client-side filter, so the
		// vmid is only visible in which volume survives.
		{"OrphanVolumesForVMID", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				got, err := rc.OrphanVolumesForVMID(ctx, fwdCallerNode, "stor-x", fwdVMID)
				var ids []string
				for _, v := range got {
					ids = append(ids, v.Volid)
				}
				volids(t, ids, "stor-x:vm-4242-disk-0")
				return err
			}, []string{"GET /nodes/qa-pve-02/storage/stor-x/status", "GET /nodes/qa-pve-02/storage/stor-x/content", "GET /nodes/qa-pve-02/qemu"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				got, err := rc.OrphanVolumesForVMID(ctx, fwdCallerNode2, "stor-y", fwdVMID2)
				var ids []string
				for _, v := range got {
					ids = append(ids, v.Volid)
				}
				volids(t, ids, "stor-y:vm-5151-disk-0")
				return err
			}, []string{"GET /nodes/qa-pve-05/storage/stor-y/status", "GET /nodes/qa-pve-05/storage/stor-y/content", "GET /nodes/qa-pve-05/qemu"}},
		}},
		{"GetNetworkInterface", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetNetworkInterface(ctx, fwdCallerNode, "vmbr7")
				return err
			}, []string{"GET /nodes/qa-pve-02/network/vmbr7"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetNetworkInterface(ctx, fwdCallerNode2, "vmbr8")
				return err
			}, []string{"GET /nodes/qa-pve-05/network/vmbr8"}},
		}},
		{"GetNetworkInterfaces", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetNetworkInterfaces(ctx, fwdCallerNode, "bridge")
				return err
			}, []string{"GET /nodes/qa-pve-02/network?type=bridge"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetNetworkInterfaces(ctx, fwdCallerNode2, "bond")
				return err
			}, []string{"GET /nodes/qa-pve-05/network?type=bond"}},
			// No filter at all: the variadic must forward as empty, not grow a
			// default type the caller never asked for.
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.GetNetworkInterfaces(ctx, fwdCallerNode)
				return err
			}, []string{"GET /nodes/qa-pve-02/network"}},
		}},
		// WaitForTask refuses a UPID whose embedded node differs from its node
		// argument before sending anything, so each case's UPID names its
		// caller node.
		{"WaitForTask", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				return rc.WaitForTask(ctx, fwdCallerNode, upid(fwdCallerNode))
			}, []string{
				"GET /nodes/qa-pve-02/tasks/" + upid(fwdCallerNode) + "/status"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				return rc.WaitForTask(ctx, fwdCallerNode2, upid(fwdCallerNode2))
			}, []string{
				"GET /nodes/qa-pve-05/tasks/" + upid(fwdCallerNode2) + "/status"}},
		}},
		{"StorageType", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.StorageType(ctx, fwdCallerNode, "stor-x")
				return err
			}, []string{"GET /nodes/qa-pve-02/storage/stor-x/status"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.StorageType(ctx, fwdCallerNode2, "stor-y")
				return err
			}, []string{"GET /nodes/qa-pve-05/storage/stor-y/status"}},
		}},

		// --- target-bound methods: the node comes from c.target.Node ---
		{"CreateVM", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.CreateVM(ctx, fwdVMID, params("cores", "2"))
				return err
			}, []string{"POST /nodes/qa-pve-03/qemu cores=2&vmid=4242"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.CreateVM(ctx, fwdVMID2, params("cores", "4"))
				return err
			}, []string{"POST /nodes/qa-pve-04/qemu cores=4&vmid=5151"}},
		}},
		{"StopVM", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.StopVM(ctx, fwdVMID)
				return err
			}, []string{"POST /nodes/qa-pve-03/qemu/4242/status/stop"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.StopVM(ctx, fwdVMID2)
				return err
			}, []string{"POST /nodes/qa-pve-04/qemu/5151/status/stop"}},
		}},
		{"DestroyVM", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.DestroyVM(ctx, fwdVMID, true)
				return err
			}, []string{"DELETE /nodes/qa-pve-03/qemu/4242?purge=1"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.DestroyVM(ctx, fwdVMID2, false)
				return err
			}, []string{"DELETE /nodes/qa-pve-04/qemu/5151"}},
		}},
		{"AgentExec", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.AgentExec(ctx, fwdVMID, []string{"/bin/true"}, "seam-stdin")
				return err
			}, []string{"POST /nodes/qa-pve-03/qemu/4242/agent/exec command=%2Fbin%2Ftrue&input-data=seam-stdin"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.AgentExec(ctx, fwdVMID2, []string{"/bin/echo", "x"}, "seam-stdin-2")
				return err
			}, []string{"POST /nodes/qa-pve-04/qemu/5151/agent/exec command=%2Fbin%2Fecho&command=x&input-data=seam-stdin-2"}},
		}},
		{"AgentExecStatus", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.AgentExecStatus(ctx, fwdVMID, 7)
				return err
			}, []string{"GET /nodes/qa-pve-03/qemu/4242/agent/exec-status?pid=7"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.AgentExecStatus(ctx, fwdVMID2, 9)
				return err
			}, []string{"GET /nodes/qa-pve-04/qemu/5151/agent/exec-status?pid=9"}},
		}},
		{"WaitForAgentExec", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.WaitForAgentExec(ctx, fwdVMID, 7, time.Millisecond, time.Second)
				return err
			}, []string{"GET /nodes/qa-pve-03/qemu/4242/agent/exec-status?pid=7"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.WaitForAgentExec(ctx, fwdVMID2, 9, 2*time.Millisecond, 2*time.Second)
				return err
			}, []string{"GET /nodes/qa-pve-04/qemu/5151/agent/exec-status?pid=9"}},
		}},
		{"AgentInterfaces", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.AgentInterfaces(ctx, fwdVMID)
				return err
			}, []string{"GET /nodes/qa-pve-03/qemu/4242/agent/network-get-interfaces"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.AgentInterfaces(ctx, fwdVMID2)
				return err
			}, []string{"GET /nodes/qa-pve-04/qemu/5151/agent/network-get-interfaces"}},
		}},
		{"VMNetMACs", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.VMNetMACs(ctx, fwdVMID)
				return err
			}, []string{"GET /nodes/qa-pve-03/qemu/4242/config"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.VMNetMACs(ctx, fwdVMID2)
				return err
			}, []string{"GET /nodes/qa-pve-04/qemu/5151/config"}},
		}},
		{"SetVMConfigField", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				return rc.SetVMConfigField(ctx, fwdVMID, "name", "web-4242")
			}, []string{"PUT /nodes/qa-pve-03/qemu/4242/config name=web-4242"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				return rc.SetVMConfigField(ctx, fwdVMID2, "description", "web-5151")
			}, []string{"PUT /nodes/qa-pve-04/qemu/5151/config description=web-5151"}},
		}},
		{"SetVMConfigFieldCAS", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				return rc.SetVMConfigFieldCAS(ctx, fwdVMID, "name", "web-4242", "d1g3st")
			}, []string{"PUT /nodes/qa-pve-03/qemu/4242/config digest=d1g3st&name=web-4242"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				return rc.SetVMConfigFieldCAS(ctx, fwdVMID2, "description", "web-5151", "d2g3st")
			}, []string{"PUT /nodes/qa-pve-04/qemu/5151/config description=web-5151&digest=d2g3st"}},
		}},
		{"ListSnapshots", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.ListSnapshots(ctx, fwdVMID)
				return err
			}, []string{"GET /nodes/qa-pve-03/qemu/4242/snapshot"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.ListSnapshots(ctx, fwdVMID2)
				return err
			}, []string{"GET /nodes/qa-pve-04/qemu/5151/snapshot"}},
		}},
		// CreateSnapshot is a sequence: collision pre-check, create, task wait,
		// post-verify. Every request in it must carry the target's node.
		{"CreateSnapshot", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				return rc.CreateSnapshot(ctx, fwdVMID, "seam-snap-1", "desc-one")
			}, []string{
				"GET /nodes/qa-pve-03/qemu/4242/snapshot",
				"POST /nodes/qa-pve-03/qemu/4242/snapshot description=desc-one&snapname=seam-snap-1&vmstate=1",
				"GET /nodes/qa-pve-03/tasks/" + upid(fwdTargetNode) + "/status",
				"GET /nodes/qa-pve-03/qemu/4242/snapshot"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				return rc.CreateSnapshot(ctx, fwdVMID2, "seam-snap-2", "desc-two")
			}, []string{
				"GET /nodes/qa-pve-04/qemu/5151/snapshot",
				"POST /nodes/qa-pve-04/qemu/5151/snapshot description=desc-two&snapname=seam-snap-2&vmstate=1",
				"GET /nodes/qa-pve-04/tasks/" + upid(fwdTargetNode2) + "/status",
				"GET /nodes/qa-pve-04/qemu/5151/snapshot"}},
		}},
		{"ShutdownVM", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.ShutdownVM(ctx, fwdVMID)
				return err
			}, []string{"POST /nodes/qa-pve-03/qemu/4242/status/shutdown"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.ShutdownVM(ctx, fwdVMID2)
				return err
			}, []string{"POST /nodes/qa-pve-04/qemu/5151/status/shutdown"}},
		}},
		{"CloneVM", []bindingCase{
			{fwdTargetNode, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.CloneVM(ctx, fwdVMID, 6161, params("storage", "local-lvm"))
				return err
			}, []string{"POST /nodes/qa-pve-03/qemu/4242/clone newid=6161&storage=local-lvm"}},
			{fwdTargetNode2, func(t *testing.T, ctx context.Context, rc *RoutedClient) error {
				_, err := rc.CloneVM(ctx, fwdVMID2, 7171, params("storage", "tank"))
				return err
			}, []string{"POST /nodes/qa-pve-04/qemu/5151/clone newid=7171&storage=tank"}},
		}},
	}

	if len(methods) != 27 {
		t.Fatalf("node-binding table covers %d methods, want all 27 node-resolving pass-throughs", len(methods))
	}
	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			if len(m.cases) < 2 {
				t.Fatalf("%s has %d case(s); every method needs at least two, or a hard-coded argument passes", m.name, len(m.cases))
			}
			for i, c := range m.cases {
				t.Run(fmt.Sprint(i+1), func(t *testing.T) {
					fake := &fwdPVE{t: t}
					srv, rec := newFwdServer(t, fake.serve)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					if err := c.call(t, ctx, fwdClientOn(t, srv, c.target)); err != nil {
						t.Fatalf("%s: %v", m.name, err)
					}
					assertRequests(t, rec.got(), c.want...)
				})
			}
		})
	}
}

// --- Phase 3, continued: second values for single-valued existing coverage --
//
// FindByTag, TapLinkState and SetBridgePortIsolated take no node, so they are
// outside the node-binding sweep. Their existing tests in routed_test.go each
// exercise one value, which a pass-through that hard-coded that value would
// also pass. Those tests are left untouched; these add the second value.

// TestRoutedForwarding_FindByTag pins FindByTag's tag. The tag is matched
// client-side, so only the answer shows which tag was forwarded: two VMs carry
// two different tags, and each lookup must find its own.
func TestRoutedForwarding_FindByTag(t *testing.T) {
	srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeData(w, `[`+
			`{"id":"qemu/4242","type":"qemu","vmid":4242,"tags":"t-a"},`+
			`{"id":"qemu/5151","type":"qemu","vmid":5151,"tags":"t-b"}]`)
	})
	rc := fwdClient(t, srv)

	for _, c := range []struct {
		tag  string
		want uint64
	}{{"t-a", 4242}, {"t-b", 5151}} {
		res, err := rc.FindByTag(context.Background(), c.tag)
		if err != nil {
			t.Fatalf("FindByTag(%q): %v", c.tag, err)
		}
		if res.VMID != c.want {
			t.Errorf("FindByTag(%q) = vmid %d, want %d", c.tag, res.VMID, c.want)
		}
	}
	const listing = "GET /cluster/resources?type=vm"
	assertRequests(t, rec.got(), listing, listing)
}

// TestRoutedForwarding_TapPortSSH pins the two tap-device pass-throughs the
// bridge-isolation Op uses. isolated is the one to watch: the Op always passes
// true, so without a false case a pass-through that hard-coded true would be
// indistinguishable from one that forwarded it. One fake SSH server serves
// both methods, because each one costs three scrypt derivations.
func TestRoutedForwarding_TapPortSSH(t *testing.T) {
	sshSrv, tg := newFwdSSHWith(t, func(cmd string) (string, string, int) {
		switch cmd {
		case "bridge -j link show dev 'tap4242i0'":
			return `[{"ifname":"tap4242i0","isolated":true}]`, "", 0
		case "bridge -j link show dev 'tap5151i1'":
			return `[{"ifname":"tap5151i1","isolated":false}]`, "", 0
		case "bridge link set dev 'tap4242i0' isolated on", "bridge link set dev 'tap5151i1' isolated off":
			return "", "", 0
		}
		return "[]", "", 0
	})
	rc := &RoutedClient{rest: testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("tap pass-throughs must not reach REST, got %s %s", r.Method, r.URL.Path)
	})), target: tg, passphrase: "roster-pass"}
	defer rc.Close()
	ctx := context.Background()

	for _, c := range []struct {
		tap  string
		want sshexec.TapLinkState
	}{
		{"tap4242i0", sshexec.TapLinkState{Exists: true, Isolated: true}},
		{"tap5151i1", sshexec.TapLinkState{Exists: true, Isolated: false}},
	} {
		got, err := rc.TapLinkState(ctx, c.tap)
		if err != nil {
			t.Fatalf("TapLinkState(%s): %v", c.tap, err)
		}
		if got != c.want {
			t.Errorf("TapLinkState(%s) = %+v, want %+v", c.tap, got, c.want)
		}
	}
	for _, c := range []struct {
		tap      string
		isolated bool
	}{{"tap4242i0", true}, {"tap5151i1", false}} {
		if err := rc.SetBridgePortIsolated(ctx, c.tap, c.isolated); err != nil {
			t.Fatalf("SetBridgePortIsolated(%s, %v): %v", c.tap, c.isolated, err)
		}
	}
	assertCommands(t, sshSrv.got(),
		"bridge -j link show dev 'tap4242i0'",
		"bridge -j link show dev 'tap5151i1'",
		"bridge link set dev 'tap4242i0' isolated on",
		"bridge link set dev 'tap5151i1' isolated off")
}

// --- Phase 4: the completeness gate ----------------------------------------

// seamEntry accounts for one exported RoutedClient method: either the tests
// that pin its forwarding, or the reason it needs none.
type seamEntry struct {
	tests  []string // forwarding tests that exercise the method on a *RoutedClient
	exempt string   // non-empty: why the method needs no forwarding test
}

// routedClientSeam accounts for every exported method of RoutedClient.
// TestRoutedForwarding_EveryExportedMethodIsAccountedFor fails if a method is
// missing from it, if it names a method that no longer exists, or if a test it
// names does not call the method.
//
// Every test named here has been shown BY MUTATION to fail when that method
// forwards a wrong argument. A test that merely calls the method does not
// qualify. That evidence lives in task pveforge-routedclient-passthrough-seam,
// except for the three rollback-era methods, whose forwarding test and
// evidence came with unit 5b. A new pass-through needs a forwarding test and
// an entry here: the gate forces the entry, and review has to check that the
// test is real.
var routedClientSeam = map[string]seamEntry{
	"Node":  {exempt: "accessor: returns c.target.Node and forwards nothing"},
	"Close": {exempt: "lifecycle: closes the lazily dialed SSH connection and forwards nothing"},

	"GetNode":               {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"GetNodes":              {tests: []string{"TestRoutedClient_TypedReadForwarding"}},
	"FindByTag":             {tests: []string{"TestRoutedForwarding_FindByTag", "TestRoutedClient_FindByTag_Forwards"}},
	"GetVM":                 {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"GetVMs":                {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"GetStorage":            {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"GetStorages":           {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"GetStorageVolumes":     {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"ClaimedVolumes":        {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"OrphanVolumes":         {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"OrphanVolumesForVMID":  {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"GetNetworkInterface":   {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"GetNetworkInterfaces":  {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"NextVMID":              {tests: []string{"TestRoutedForwarding_NextVMID_Exclude", "TestRoutedClient_NextVMID_Forwards"}},
	"WaitForTask":           {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"CreateVM":              {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"StopVM":                {tests: []string{"TestRoutedForwarding_StopVM", "TestRoutedForwarding_NodeBinding"}},
	"DestroyVM":             {tests: []string{"TestRoutedForwarding_DestroyVM", "TestRoutedForwarding_NodeBinding"}},
	"TagStillClaimed":       {tests: []string{"TestRoutedForwarding_TagStillClaimed"}},
	"AgentExec":             {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"AgentExecStatus":       {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"WaitForAgentExec":      {tests: []string{"TestRoutedForwarding_WaitForAgentExec", "TestRoutedForwarding_NodeBinding"}},
	"AgentInterfaces":       {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"VMNetMACs":             {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"APIDocTree":            {tests: []string{"TestRoutedForwarding_APIDocTree"}},
	"RawRequest":            {tests: []string{"TestRoutedForwarding_RawRequest"}},
	"SetVMConfigField":      {tests: []string{"TestRoutedForwarding_SetVMConfigField_REST", "TestRoutedForwarding_SetVMConfigField_SSHRootOnly", "TestRoutedForwarding_SetVMConfigField_SSHFallback", "TestRoutedForwarding_SetVMConfigField_NoFallbackOnOtherErrors", "TestRoutedForwarding_NodeBinding"}},
	"SetVMConfigFieldCAS":   {tests: []string{"TestRoutedForwarding_SetVMConfigFieldCAS", "TestRoutedForwarding_NodeBinding"}},
	"UploadSnippet":         {tests: []string{"TestRoutedForwarding_UploadSnippet"}},
	"TapLinkState":          {tests: []string{"TestRoutedForwarding_TapPortSSH", "TestRoutedClient_TapLinkState_Forwards"}},
	"LinkState":             {tests: []string{"TestRoutedForwarding_LinkState"}},
	"SetBridgePortIsolated": {tests: []string{"TestRoutedForwarding_TapPortSSH", "TestRoutedClient_SetBridgePortIsolated_Forwards"}},
	"ListSnapshots":         {tests: []string{"TestRoutedForwarding_NodeBinding"}},
	"CreateSnapshot":        {tests: []string{"TestRoutedForwarding_NodeBinding", "TestRoutedClient_Snapshot_Forwards"}},
	"ShutdownVM":            {tests: []string{"TestRoutedForwarding_NodeBinding", "TestShutdownVM_MakesExactlyOneRequestOnEveryPath"}},
	"CloneVM":               {tests: []string{"TestRoutedForwarding_NodeBinding", "TestRoutedClient_CloneVM_Forwards"}},
	"StorageType":           {tests: []string{"TestRoutedForwarding_NodeBinding", "TestRoutedClient_StorageType_Forwards"}},

	// Added by unit 5b, with their forwarding test in snapshot_test.go.
	"NewerSnapshots":         {tests: []string{"TestRoutedClient_SnapshotRollback_Forwards"}},
	"Rollback":               {tests: []string{"TestRoutedClient_SnapshotRollback_Forwards"}},
	"CascadeDeleteSnapshots": {tests: []string{"TestRoutedClient_SnapshotRollback_Forwards"}},
}

// TestRoutedForwarding_EveryExportedMethodIsAccountedFor is the completeness
// gate. The claim "every RoutedClient pass-through is pinned" was true when
// this file was written, and would rot the moment someone added a
// pass-through. This test makes adding one without accounting for it fail.
//
// What it proves is ACCOUNTING, not checking. It matches the methods a test
// calls by name, not by receiver type, so it cannot tell a call on a
// *RoutedClient from one on a *Client, and it says nothing about whether the
// test's assertions are real. The mutation evidence behind each entry is what
// shows that.
func TestRoutedForwarding_EveryExportedMethodIsAccountedFor(t *testing.T) {
	fromSource, err := sourceguard.ExportedMethods(".", "RoutedClient")
	if err != nil {
		t.Fatalf("ExportedMethods: %v", err)
	}

	// C1: two independent observers of the method set must agree. The AST
	// scan and runtime reflection would disagree over a missed file, a parser
	// quirk, or a method promoted through an embedded field; either one alone
	// would miss that silently.
	rt := reflect.TypeOf((*RoutedClient)(nil))
	fromReflect := make([]string, 0, rt.NumMethod())
	for i := 0; i < rt.NumMethod(); i++ {
		fromReflect = append(fromReflect, rt.Method(i).Name)
	}
	if strings.Join(fromSource, ",") != strings.Join(fromReflect, ",") {
		t.Errorf("source and reflection disagree on RoutedClient's methods:\n  source:     %v\n  reflection: %v", fromSource, fromReflect)
	}

	methods := map[string]bool{}
	for _, m := range append(fromSource, fromReflect...) {
		methods[m] = true
	}

	// C2: every method is accounted for.
	for m := range methods {
		if _, ok := routedClientSeam[m]; !ok {
			t.Errorf("RoutedClient.%s is not in routedClientSeam: add a forwarding test that fails on a wrong argument, and an entry naming it", m)
		}
	}

	// Every test the table names, resolved in one parse of the package's test
	// files. A name that is not a test function fails here, which is C5's
	// existence half.
	var named []string
	for _, e := range routedClientSeam {
		for _, name := range e.tests {
			if !slices.Contains(named, name) {
				named = append(named, name)
			}
		}
	}
	callees, err := sourceguard.TestCallees(".", named...)
	if err != nil {
		t.Fatalf("routedClientSeam names a test that does not exist: %v", err)
	}

	for m, e := range routedClientSeam {
		// C3: no entry for a method that no longer exists.
		if !methods[m] {
			t.Errorf("routedClientSeam has an entry for %s, which RoutedClient does not have", m)
		}
		// C4: exactly one of tests or exempt.
		if (len(e.tests) == 0) == (e.exempt == "") {
			t.Errorf("routedClientSeam[%q] must name tests OR give an exempt reason, exactly one of the two", m)
			continue
		}
		// C5: each named test calls the method.
		for _, name := range e.tests {
			if !slices.Contains(callees[name], m) {
				t.Errorf("routedClientSeam[%q] names %s, which never calls %s", m, name, m)
			}
		}
	}

	if len(methods) == 0 {
		t.Fatal("no RoutedClient methods found at all; the gate would pass vacuously")
	}
}

// TestRoutedForwarding_NodeBindingRowsCallTheirOwnMethod ties each row of the
// node-binding table to the method it is named for. GetStorage and
// StorageType put identical requests on the wire, and so do GetVM and
// ClaimedVolumes. A StorageType row that called rc.GetStorage would therefore
// still pass NodeBinding, and StorageType would lose its node-binding
// coverage.
//
// The completeness gate's C5 catches that only while no OTHER row also calls
// StorageType, because C5 checks each test as a whole. A single dead-code
// call in another row would satisfy it. This test checks each row on its own:
// the only RoutedClient calls a row makes must be to the method it is named
// for.
//
// A call counts whatever its receiver expression is. The method name is
// looked up in RoutedClient's method set, so aliasing the client (r := rc;
// r.GetStorage(...)) does not hide a call. A dead-code call to the right
// method does not help either, because the wrong one is still seen.
func TestRoutedForwarding_NodeBindingRowsCallTheirOwnMethod(t *testing.T) {
	routedMethods := map[string]bool{}
	rt := reflect.TypeOf((*RoutedClient)(nil))
	for i := 0; i < rt.NumMethod(); i++ {
		routedMethods[rt.Method(i).Name] = true
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "routedforwarding_test.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "TestRoutedForwarding_NodeBinding" {
			body = fd.Body
		}
	}
	if body == nil {
		t.Fatal("TestRoutedForwarding_NodeBinding not found")
	}

	rows := 0
	ast.Inspect(body, func(n ast.Node) bool {
		// A row is {"<Method>", []bindingCase{...}}.
		row, ok := n.(*ast.CompositeLit)
		if !ok || len(row.Elts) != 2 {
			return true
		}
		lit, ok := row.Elts[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if _, ok := row.Elts[1].(*ast.CompositeLit); !ok {
			return true
		}
		name, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatalf("row name %s: %v", lit.Value, err)
		}
		rows++

		var called []string
		ast.Inspect(row.Elts[1], func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && routedMethods[sel.Sel.Name] {
				called = append(called, sel.Sel.Name)
			}
			return true
		})
		if len(called) == 0 {
			t.Errorf("row %q calls no RoutedClient method at all", name)
		}
		for _, c := range called {
			if c != name {
				t.Errorf("row %q calls %s; a row must call only the method it is named for", name, c)
			}
		}
		return false
	})
	if rows != 27 {
		t.Errorf("found %d node-binding rows, want 27", rows)
	}
}
