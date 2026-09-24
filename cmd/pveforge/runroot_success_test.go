package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// Success paths of the REST-only commands, pinned through the WHOLE CLI:
// newRootCmd, root flag parsing and command registration, runRoot's exit
// status and stderr. A leaf test calls newXxxCmd().Execute() directly, so it
// cannot see a command dropped from its parent, or a flag its parent owns —
// these pins can. Each asserts exit 0, the exact stdout, an empty stderr and
// the exact requests the fake received (proof the fake was on the path).

// routeFake serves fixed JSON bodies by "METHOD path" and records every
// request as "METHOD path", plus, for a POST or PUT, " " and its form body
// re-encoded (sorted) — so a pin sees the parameters a write sent, not only
// where it went. An unexpected request is a test error and a 404.
type routeFake struct {
	mu   sync.Mutex
	hits []string
}

func newRouteFake(t *testing.T, routes map[string]string) (*httptest.Server, *routeFake) {
	t.Helper()
	f := &routeFake{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		hit := key
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			if err := r.ParseForm(); err != nil {
				t.Errorf("routeFake: %s: parse form: %v", key, err)
			}
			hit += " " + r.PostForm.Encode()
		}
		f.mu.Lock()
		f.hits = append(f.hits, hit)
		f.mu.Unlock()
		body, ok := routes[key]
		if !ok {
			t.Errorf("routeFake: unexpected request %s", key)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, f
}

func (f *routeFake) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.hits)
}

// pinRunRoot runs args through runRoot and requires exit 0, exactly
// wantStdout and an empty stderr.
func pinRunRoot(t *testing.T, wantStdout string, args ...string) {
	t.Helper()
	code, stdout, stderr := runRootArgs(args...)
	if code != 0 {
		t.Fatalf("exit %d; stderr %q", code, stderr)
	}
	if stdout != wantStdout {
		t.Errorf("stdout = %q\nwant     %q", stdout, wantStdout)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
}

func requireHits(t *testing.T, f *routeFake, want ...string) {
	t.Helper()
	if got := f.got(); !slices.Equal(got, want) {
		t.Errorf("requests = %q\nwant       %q", got, want)
	}
}

func tlsRoster(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	rp := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	return rp
}

func TestRunRootSuccess_VMGet(t *testing.T) {
	srv, f := newRouteFake(t, map[string]string{
		"GET /api2/json/nodes/qa-pve-01/qemu/100/status/current": `{"data":{"status":"running","vmid":100}}`,
		"GET /api2/json/nodes/qa-pve-01/qemu/100/config":         `{"data":{"name":"web-01","cores":2}}`,
	})
	pinRunRoot(t, "Agent=0\nCPU=0\nCPUs=0\nDisk=0\nDiskRead=0\nDiskWrite=0\nHA={\"Managed\":0}\nMaxDisk=0\nMaxMem=0\nMem=0\nName=\nNetIn=0\nNetout=0\nNode=qa-pve-01\nPID=0\nSpice=0\nStatus=running\nTemplate=false\nUptime=0\nVMID=100\nVirtualMachineConfig={\"digest\":\"\",\"name\":\"web-01\",\"cores\":2}\n", "vm", "get", "--roster", tlsRoster(t, srv), "qa-pve-01", "100")
	requireHits(t, f, "GET /api2/json/nodes/qa-pve-01/qemu/100/status/current", "GET /api2/json/nodes/qa-pve-01/qemu/100/config")
}

func TestRunRootSuccess_NodeGet(t *testing.T) {
	srv, f := newRouteFake(t, map[string]string{
		"GET /api2/json/nodes/qa-pve-01/status": `{"data":{"uptime":12345,"pveversion":"pve-manager/9.2.11"}}`,
	})
	pinRunRoot(t, "CPU=0\nCPUInfo={\"user_hz\":0,\"MHZ\":0,\"Model\":\"\",\"Cores\":0,\"Sockets\":0,\"Flags\":\"\",\"CPUs\":0,\"HVM\":\"\"}\nIdle=0\nKsm={\"Shared\":0}\nKversion=\nLoadAvg=null\nMemory={\"Used\":0,\"Free\":0,\"Total\":0}\nName=qa-pve-01\nPVEVersion=pve-manager/9.2.11\nRootFS={\"Avail\":0,\"Total\":0,\"Free\":0,\"Used\":0}\nSwap={\"Used\":0,\"Free\":0,\"Total\":0}\nUptime=12345\nWait=0\n", "node", "get", "--roster", tlsRoster(t, srv), "qa-pve-01")
	requireHits(t, f, "GET /api2/json/nodes/qa-pve-01/status")
}

func TestRunRootSuccess_NetworkGet(t *testing.T) {
	srv, f := newRouteFake(t, map[string]string{
		"GET /api2/json/nodes/qa-pve-01/network/vmbr0": `{"data":{"type":"bridge","cidr":"10.0.0.5/24","gateway":"10.0.0.1"}}`,
	})
	pinRunRoot(t, "cidr=10.0.0.5/24\ngateway=10.0.0.1\niface=vmbr0\ntype=bridge\n", "network", "get", "--roster", tlsRoster(t, srv), "qa-pve-01", "vmbr0")
	requireHits(t, f, "GET /api2/json/nodes/qa-pve-01/network/vmbr0")
}

func TestRunRootSuccess_StorageGet(t *testing.T) {
	srv, f := newRouteFake(t, map[string]string{
		"GET /api2/json/nodes/qa-pve-01/storage/local-lvm/status": `{"data":{"type":"lvmthin","total":1000000,"used":250000}}`,
	})
	pinRunRoot(t, "Active=0\nAvail=0\nContent=\nEnabled=0\nNode=qa-pve-01\nShared=0\nTotal=1000000\nType=lvmthin\nUsed=250000\nstorage=local-lvm\nused_fraction=0\n", "storage", "get", "--roster", tlsRoster(t, srv), "qa-pve-01", "local-lvm")
	requireHits(t, f, "GET /api2/json/nodes/qa-pve-01/storage/local-lvm/status")
}

func TestRunRootSuccess_StorageOrphans(t *testing.T) {
	srv, f := newRouteFake(t, map[string]string{
		"GET /api2/json/nodes/qa-pve-01/storage/local-lvm/status":  `{"data":{"storage":"local-lvm","type":"lvmthin","shared":0}}`,
		"GET /api2/json/nodes/qa-pve-01/storage/local-lvm/content": `{"data":[{"volid":"local-lvm:vm-105-disk-0","vmid":105,"content":"images"}]}`,
		"GET /api2/json/nodes/qa-pve-01/qemu":                      `{"data":[]}`,
	})
	pinRunRoot(t, "orphans=[{\"volid\":\"local-lvm:vm-105-disk-0\",\"vmid\":105}]\n", "storage", "orphans", "--roster", tlsRoster(t, srv), "qa-pve-01", "local-lvm")
	requireHits(t, f,
		"GET /api2/json/nodes/qa-pve-01/storage/local-lvm/status",
		"GET /api2/json/nodes/qa-pve-01/storage/local-lvm/content",
		"GET /api2/json/nodes/qa-pve-01/qemu")
}

// apidoc serves the one unauthenticated apidoc.js the discover commands read.
func apidocRoutes(pathToInfo map[string]string) map[string]string {
	var nodes []string
	for path, info := range pathToInfo {
		nodes = append(nodes, `{"path":"`+path+`","leaf":1,"info":`+info+`}`)
	}
	return map[string]string{"GET /pve-docs/api-viewer/apidoc.js": fakeAPIDocJS("[" + strings.Join(nodes, ",") + "]")}
}

func TestRunRootSuccess_DiscoverVM(t *testing.T) {
	srv, f := newRouteFake(t, apidocRoutes(map[string]string{
		"/nodes/{node}/qemu/{vmid}/config": `{"GET":{"parameters":{"properties":{"vmid":{"type":"integer"}}}}}`,
	}))
	pinRunRoot(t, "GET={\"parameters\":{\"properties\":{\"vmid\":{\"type\":\"integer\"}}}}\n", "discover", "vm", "--roster", tlsRoster(t, srv), "qa-pve-01")
	requireHits(t, f, "GET /pve-docs/api-viewer/apidoc.js")
}

func TestRunRootSuccess_DiscoverNode(t *testing.T) {
	srv, f := newRouteFake(t, apidocRoutes(map[string]string{
		"/nodes/{node}/status": `{"GET":{"returns":{"properties":{"uptime":{"type":"integer"}}}}}`,
	}))
	pinRunRoot(t, "GET={\"returns\":{\"properties\":{\"uptime\":{\"type\":\"integer\"}}}}\n", "discover", "node", "--roster", tlsRoster(t, srv), "qa-pve-01")
	requireHits(t, f, "GET /pve-docs/api-viewer/apidoc.js")
}

func TestRunRootSuccess_DiscoverStorage(t *testing.T) {
	srv, f := newRouteFake(t, apidocRoutes(map[string]string{
		"/storage/{storage}": `{"PUT":{"parameters":{"properties":{"content":{"type":"string"}}}}}`,
	}))
	pinRunRoot(t, "PUT={\"parameters\":{\"properties\":{\"content\":{\"type\":\"string\"}}}}\n", "discover", "storage", "--roster", tlsRoster(t, srv), "qa-pve-01")
	requireHits(t, f, "GET /pve-docs/api-viewer/apidoc.js")
}

func TestRunRootSuccess_DiscoverNetwork(t *testing.T) {
	srv, f := newRouteFake(t, apidocRoutes(map[string]string{
		"/nodes/{node}/network/{iface}": `{"PUT":{"parameters":{"properties":{"bridge_ports":{"type":"string"}}}}}`,
	}))
	pinRunRoot(t, "PUT={\"parameters\":{\"properties\":{\"bridge_ports\":{\"type\":\"string\"}}}}\n", "discover", "network", "--roster", tlsRoster(t, srv), "qa-pve-01")
	requireHits(t, f, "GET /pve-docs/api-viewer/apidoc.js")
}

// discover device is local: it describes a device type from pveforge's own
// registry and makes no request.
func TestRunRootSuccess_DiscoverDevice(t *testing.T) {
	pinRunRoot(t, "description=An emulated NVMe drive attached via the args: raw-QEMU escape hatch (Proxmox has no first-class NVMe bus type).\nproperties={\"backing\":{\"type\":\"string\",\"description\":\"The QEMU -drive file= target: a PVE volid (e.g. \\\"local-lvm:vm-100-disk-1\\\") or a raw host path.\",\"pattern\":\"^[A-Za-z0-9\\\\-_./:]+$\"},\"format\":{\"type\":\"string\",\"description\":\"The QEMU -drive format= value (e.g. \\\"raw\\\", \\\"qcow2\\\"). PVE/QEMU infer it when unset.\",\"pattern\":\"^[A-Za-z0-9]+$\",\"optional\":true},\"serial\":{\"type\":\"string\",\"description\":\"The drive's emulated serial number, surfaced inside the guest OS.\",\"pattern\":\"^[A-Za-z0-9\\\\-_]+$\"}}\nrequired=[\"serial\",\"backing\"]\ntype=object\n", "discover", "device", "NVMeDrive")
}

func TestRunRootSuccess_APIGet(t *testing.T) {
	srv, f := newRouteFake(t, map[string]string{
		"GET /api2/json/nodes/qa-pve-01/status": `{"data":{"uptime":12345}}`,
	})
	pinRunRoot(t, "uptime=12345\n", "api", "get", "--roster", tlsRoster(t, srv), "/nodes/qa-pve-01/status", "qa-pve-01")
	requireHits(t, f, "GET /api2/json/nodes/qa-pve-01/status")
}

func TestRunRootSuccess_APIPost(t *testing.T) {
	srv, f := newRouteFake(t, map[string]string{
		"POST /api2/json/nodes/qa-pve-01/qemu/100/config": `{"data":null}`,
	})
	pinRunRoot(t, "data=null\n", "api", "post", "--roster", tlsRoster(t, srv), "--data", "cores=4", "/nodes/qa-pve-01/qemu/100/config", "qa-pve-01")
	requireHits(t, f, "POST /api2/json/nodes/qa-pve-01/qemu/100/config cores=4")
}

func TestRunRootSuccess_APIPut(t *testing.T) {
	srv, f := newRouteFake(t, map[string]string{
		"PUT /api2/json/nodes/qa-pve-01/qemu/100/config": `{"data":null}`,
	})
	pinRunRoot(t, "data=null\n", "api", "put", "--roster", tlsRoster(t, srv), "--data", "cores=4", "/nodes/qa-pve-01/qemu/100/config", "qa-pve-01")
	requireHits(t, f, "PUT /api2/json/nodes/qa-pve-01/qemu/100/config cores=4")
}

func TestRunRootSuccess_APIDelete(t *testing.T) {
	srv, f := newRouteFake(t, map[string]string{
		"DELETE /api2/json/nodes/qa-pve-01/qemu/100/snapshot/before-upgrade": `{"data":null}`,
	})
	pinRunRoot(t, "data=null\n", "api", "delete", "--roster", tlsRoster(t, srv), "/nodes/qa-pve-01/qemu/100/snapshot/before-upgrade", "qa-pve-01")
	requireHits(t, f, "DELETE /api2/json/nodes/qa-pve-01/qemu/100/snapshot/before-upgrade")
}

// vm create reuses its own stateful fake (vmCreateFake), whose counters
// prove the NextVMID pin check and the create both happened.
func TestRunRootSuccess_VMCreate(t *testing.T) {
	f := &vmCreateFake{}
	srv := newVMCreateServer(t, "qa-pve-01", 100, f)
	defer srv.Close()
	pinRunRoot(t, "qa-pve-01: vm 100 created\n", "vm", "create", "--roster", vmCreateRoster(t, srv), "qa-pve-01", "100", "cores=4")
	if got := atomic.LoadInt32(&f.createCalls); got != 1 {
		t.Errorf("create calls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&f.nextIDChecks); got != 1 {
		t.Errorf("NextVMID pin checks = %d, want 1", got)
	}
}

// schema describes the root's whole tree, so only a run through the root
// shows it: checked against literals, never against the builder itself.
// Every command path is compared exactly — a token match would let `set`
// be satisfied by network set with vm set gone — and vm set must still
// describe itself as a mutation with its own flags.
func TestRunRootSuccess_Schema(t *testing.T) {
	code, stdout, stderr := runRootArgs("schema")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	type node struct {
		Name        string                  `json:"name"`
		Mutation    string                  `json:"mutation"`
		Flags       []struct{ Name string } `json:"flags"`
		Subcommands []node                  `json:"subcommands"`
	}
	var root node
	if err := json.Unmarshal([]byte(stdout), &root); err != nil {
		t.Fatalf("stdout is not the schema JSON: %v\n%s", err, stdout)
	}
	if root.Name != "pveforge" {
		t.Fatalf("root name = %q, want pveforge", root.Name)
	}
	var paths []string
	byPath := map[string]node{}
	var walk func(n node, prefix string)
	walk = func(n node, prefix string) {
		for _, c := range n.Subcommands {
			p := prefix + c.Name
			paths = append(paths, p)
			byPath[p] = c
			walk(c, p+"/")
		}
	}
	walk(root, "")
	want := []string{
		"api", "api/delete", "api/get", "api/post", "api/put",
		"bootstrap",
		"completion", "completion/bash", "completion/fish", "completion/powershell", "completion/zsh",
		"discover", "discover/device", "discover/network", "discover/node", "discover/storage", "discover/vm",
		"exec",
		"help",
		"network", "network/bridge", "network/bridge/create", "network/bridge/destroy", "network/get", "network/set",
		"node", "node/get",
		"roster", "roster/import-token", "roster/init", "roster/validate",
		"schema",
		"storage", "storage/get", "storage/orphans",
		"vm", "vm/create", "vm/get", "vm/set",
	}
	slices.Sort(paths)
	if !slices.Equal(paths, want) {
		t.Errorf("command paths = %q\nwant           %q", paths, want)
	}
	var vmSetFlags []string
	for _, f := range byPath["vm/set"].Flags {
		vmSetFlags = append(vmSetFlags, f.Name)
	}
	if byPath["vm/set"].Mutation == "" || !slices.Contains(vmSetFlags, "delete") {
		t.Errorf("vm/set = mutation %q, flags %q: want a mutation level and its --delete flag", byPath["vm/set"].Mutation, vmSetFlags)
	}
}

func TestRunRootSuccess_RosterInit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roster.toml")
	pinRunRoot(t, "Initialized empty roster at "+path+"\n", "roster", "init", path)
	b, err := os.ReadFile(path)
	if err != nil || !strings.HasPrefix(string(b), "# pveforge roster") {
		t.Errorf("roster file = %q, %v; want the roster template", b, err)
	}
}

// roster validate through the parent's --roster flag: that flag lives on
// `roster`, not on the leaf, so only a run through the root reaches it.
func TestRunRootSuccess_RosterValidate(t *testing.T) {
	srv, f := newRouteFake(t, nil)
	rp := tlsRoster(t, srv)
	pinRunRoot(t, rp+": valid, 1 target(s)\n  - qa-pve-01 (127.0.0.1, node=qa-pve-01): token configured\n", "roster", "validate", "--roster", rp)
	requireHits(t, f) // validate reads the roster only; it never calls PVE
}
