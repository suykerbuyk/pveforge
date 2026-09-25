package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// Fixtures use example.com names and TEST-NET addresses (RFC 5737) only:
// the repository never names a real lab host.

type ftarget struct{ id, host, node, fp, token string }

func writeRoster(t *testing.T, dir, name string, targets ...ftarget) string {
	t.Helper()
	var b strings.Builder
	for _, x := range targets {
		fmt.Fprintf(&b, "[[targets]]\nid = %q\nhost = %q\nnode = %q\n", x.id, x.host, x.node)
		if x.token != "" {
			fmt.Fprintf(&b, "[targets.token]\nid = %q\nsecret_enc = '''\n-----BEGIN AGE ENCRYPTED FILE-----\nZmFrZQ==\n-----END AGE ENCRYPTED FILE-----\n'''\n", x.token)
		}
		if x.fp != "" {
			fmt.Fprintf(&b, "[targets.ssh]\nuser = \"root\"\npublic_key = \"ssh-ed25519 AAAA test\"\nhost_key_fingerprint = %q\nprivate_key_enc = '''\n-----BEGIN AGE ENCRYPTED FILE-----\nZmFrZQ==\n-----END AGE ENCRYPTED FILE-----\n'''\n", x.fp)
		}
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var (
	pvh1   = ftarget{"pvh-n1", "pvh-n1.example.com", "pvh-n1", "SHA256:harness-one", "root@pam!harness"}
	pvh2   = ftarget{"pvh-n2", "pvh-n2.example.com", "pvh-n2", "SHA256:harness-two", "root@pam!harness"}
	outerA = ftarget{"outer-a", "outer-a.example.com", "outer-a", "SHA256:outer-one", "root@pam!pveforge"}
	outerB = ftarget{"outer-b-harness", "192.0.2.10", "outer-b", "", "harness@pve!build"} // a keyless target, as the harness-outer one is
)

// resolver is the fake name service.
var resolver = map[string][]string{
	"pvh-n1.example.com":   {"198.51.100.11"},
	"pvh-n2.example.com":   {"198.51.100.12"},
	"outer-a.example.com":  {"192.0.2.20", "2001:db8::20"},
	"alias.example.com":    {"192.0.2.20"},
	"lab.example.com":      {"192.0.2.30"},
	"v4mapped.example.com": {"::ffff:192.0.2.20"},
	"empty.example.com":    {},
}

func lookup(_ context.Context, host string) ([]string, error) {
	if a, ok := resolver[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

const goodStatus = `[{"type":"cluster","name":"pvh","nodes":2,"quorate":1,"version":2},` +
	`{"type":"node","name":"pvh-n1","ip":"198.51.100.11","online":1},` +
	`{"type":"node","name":"pvh-n2","ip":"198.51.100.12","online":1}]`

// fakeClient answers CheckLive's three reads and records them.
type fakeClient struct {
	status   string
	statusEr error
	nodes    []string
	nodesNil bool
	nodesErr error
	linkErr  error
	calls    []string
	closed   bool
}

func (f *fakeClient) RawRequest(_ context.Context, method, path string, _ url.Values) (json.RawMessage, error) {
	f.calls = append(f.calls, method+" "+path)
	if f.statusEr != nil {
		return nil, f.statusEr
	}
	return json.RawMessage(f.status), nil
}

func (f *fakeClient) GetNodes(context.Context) (proxmox.NodeStatuses, error) {
	f.calls = append(f.calls, "nodes")
	if f.nodesErr != nil {
		return nil, f.nodesErr
	}
	var out proxmox.NodeStatuses
	for _, n := range f.nodes {
		out = append(out, &proxmox.NodeStatus{Node: n})
	}
	if f.nodesNil {
		out = append(out, nil)
	}
	return out, nil
}

func (f *fakeClient) LinkState(_ context.Context, iface string) (sshexec.LinkState, error) {
	f.calls = append(f.calls, "ssh link "+iface)
	return sshexec.LinkState{}, f.linkErr
}

func (f *fakeClient) Close() error { f.closed = true; return nil }

func goodClient() *fakeClient {
	return &fakeClient{status: goodStatus, nodes: []string{"pvh-n2", "pvh-n1"}}
}

// world is one test's rosters, environment and fakes.
type world struct {
	dir, harness, outer string
	env                 []string
	clients             map[string]*fakeClient
	dialed              []string
	dialErr             error
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{dir: t.TempDir(), clients: map[string]*fakeClient{"pvh-n1": goodClient(), "pvh-n2": goodClient()}}
	w.harness = writeRoster(t, w.dir, "harness.toml", pvh1, pvh2)
	w.outer = writeRoster(t, w.dir, "outer.toml", outerA, outerB)
	w.env = []string{RosterVar + "=" + w.harness, OuterRostersVar + "=" + w.outer, roster.PassphraseEnvVar + "=pass", "HOME=/home/test"}
	return w
}

// set replaces (or, with value "<unset>", removes) one variable.
func (w *world) set(name, value string) {
	var out []string
	for _, kv := range w.env {
		if !strings.HasPrefix(kv, name+"=") {
			out = append(out, kv)
		}
	}
	if value != "<unset>" {
		out = append(out, name+"="+value)
	}
	w.env = out
}

func (w *world) open() (*Harness, error) {
	return open(context.Background(), deps{
		environ: w.env,
		lookup:  lookup,
		dial: func(t *roster.Target, pass string) (liveClient, error) {
			w.dialed = append(w.dialed, t.ID)
			if pass != "pass" {
				return nil, errors.New("wrong passphrase handed to the client")
			}
			if w.dialErr != nil {
				return nil, w.dialErr
			}
			return w.clients[t.ID], nil
		},
	})
}

func TestOpen_AcceptsTheNestedCluster(t *testing.T) {
	w := newWorld(t)
	h, err := w.open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !slices.Equal(w.dialed, []string{"pvh-n1", "pvh-n2"}) {
		t.Errorf("dialed %q", w.dialed)
	}
	for id, c := range w.clients {
		if want := []string{"GET /cluster/status", "nodes", "ssh link lo"}; !slices.Equal(c.calls, want) {
			t.Errorf("%s: calls %q, want %q (every target checked live)", id, c.calls, want)
		}
	}
	if len(h.clients) != 2 {
		t.Errorf("vetted %d clients", len(h.clients))
	}
	// Addresses are compared normalised: a harness host that resolves to
	// the v4-mapped form of the address its node reports is that node.
	resolver["pvh-n1.example.com"] = []string{"::ffff:198.51.100.11"}
	t.Cleanup(func() { resolver["pvh-n1.example.com"] = []string{"198.51.100.11"} })
	if _, err := newWorld(t).open(); err != nil {
		t.Errorf("a v4-mapped harness address: %v", err)
	}
}

// Every refusal made before any request: nothing is dialed.
func TestOpen_StaticRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(t *testing.T, w *world)
		want string
	}{
		"the outer root password is set":        {func(_ *testing.T, w *world) { w.set(outerPasswordVar, "x") }, outerPasswordVar + " is set"},
		"the outer password is set empty":       {func(_ *testing.T, w *world) { w.set(outerPasswordVar, "") }, outerPasswordVar + " is set"},
		"no harness roster":                     {func(_ *testing.T, w *world) { w.set(RosterVar, "<unset>") }, RosterVar + " is not set"},
		"a relative harness roster":             {func(_ *testing.T, w *world) { w.set(RosterVar, "harness.toml") }, "absolute path"},
		"no outer rosters":                      {func(_ *testing.T, w *world) { w.set(OuterRostersVar, "<unset>") }, "names no outer roster"},
		"an empty outer list":                   {func(_ *testing.T, w *world) { w.set(OuterRostersVar, ":") }, "names no outer roster"},
		"a relative outer roster":               {func(_ *testing.T, w *world) { w.set(OuterRostersVar, "outer.toml") }, "not an absolute path"},
		"the operator roster is set":            {func(_ *testing.T, w *world) { w.set(operatorRosterVar, w.dir+"/operator.toml") }, operatorRosterVar + " is set"},
		"the operator roster is set empty":      {func(_ *testing.T, w *world) { w.set(operatorRosterVar, "") }, operatorRosterVar + " is set"},
		"a missing outer roster":                {func(_ *testing.T, w *world) { w.set(OuterRostersVar, w.dir+"/none.toml") }, "load outer roster"},
		"the harness roster is an outer roster": {func(_ *testing.T, w *world) { w.set(OuterRostersVar, w.outer+":"+w.harness) }, "same file as outer roster"},
		"the harness roster is a symlink to the outer roster": {func(t *testing.T, w *world) {
			link := filepath.Join(w.dir, "link.toml")
			if err := os.Symlink(w.outer, link); err != nil {
				t.Fatal(err)
			}
			w.set(RosterVar, link)
		}, "same file as outer roster"},
		"a collision only in the second outer roster": {func(t *testing.T, w *world) {
			second := writeRoster(t, w.dir, "second.toml", ftarget{"lab", "pvh-n2.example.com", "lab", "", ""})
			w.set(OuterRostersVar, w.outer+":"+second)
		}, "is also a target, host or node in outer roster <dir>/second.toml"},
		"a shared API token id": {func(t *testing.T, w *world) {
			w.set(RosterVar, writeRoster(t, w.dir, "h.toml", ftarget{"pvh-n1", "pvh-n1.example.com", "pvh-n1", "SHA256:h", "harness@pve!build"}))
		}, "uses API token harness@pve!build"},
		"a harness alias resolving to the v4-mapped form of an outer address": {func(t *testing.T, w *world) {
			w.set(RosterVar, writeRoster(t, w.dir, "h.toml", ftarget{"pvh-n1", "v4mapped.example.com", "pvh-n1", "SHA256:h", ""}))
		}, "both resolve to 192.0.2.20"},
		"a host whose lookup answers nothing": {func(t *testing.T, w *world) {
			w.set(RosterVar, writeRoster(t, w.dir, "h.toml", ftarget{"pvh-n1", "empty.example.com", "pvh-n1", "SHA256:h", ""}))
		}, "resolve empty.example.com"},
		"a harness roster with no targets": {func(t *testing.T, w *world) {
			w.set(RosterVar, writeRoster(t, w.dir, "empty.toml"))
		}, "no targets"},
		"a target that is not pvh-*": {func(t *testing.T, w *world) {
			w.set(RosterVar, writeRoster(t, w.dir, "h.toml", ftarget{"lab-n1", "pvh-n1.example.com", "pvh-n1", "SHA256:h", ""}))
		}, "is not a pvh-* target"},
		"a node outside the nested cluster": {func(t *testing.T, w *world) {
			w.set(RosterVar, writeRoster(t, w.dir, "h.toml", ftarget{"pvh-n3", "pvh-n1.example.com", "pvh-n3", "SHA256:h", ""}))
		}, "names node"},
		"a target with no pinned SSH key": {func(t *testing.T, w *world) {
			w.set(RosterVar, writeRoster(t, w.dir, "h.toml", ftarget{"pvh-n1", "pvh-n1.example.com", "pvh-n1", "", ""}))
		}, "no pinned SSH host key"},
		"a host that is an outer host (any case)": {func(t *testing.T, w *world) {
			w.set(RosterVar, writeRoster(t, w.dir, "h.toml", ftarget{"pvh-n1", "OUTER-A.example.com", "pvh-n1", "SHA256:h", ""}))
		}, "is also a target, host or node"},
		"a target id that is an outer target id": {func(t *testing.T, w *world) {
			w.set(OuterRostersVar, writeRoster(t, w.dir, "o.toml", ftarget{"pvh-n1", "outer-a.example.com", "outer-a", "", ""}))
		}, "is also a target, host or node"},
		"a node that is an outer node": {func(t *testing.T, w *world) {
			w.set(OuterRostersVar, writeRoster(t, w.dir, "o.toml", ftarget{"outer-a", "outer-a.example.com", "pvh-n2", "", ""}))
		}, "is also a target, host or node"},
		"a shared SSH fingerprint": {func(t *testing.T, w *world) {
			w.set(RosterVar, writeRoster(t, w.dir, "h.toml", ftarget{"pvh-n1", "pvh-n1.example.com", "pvh-n1", outerA.fp, ""}))
		}, "same SSH host key"},
		"a harness alias resolving to an outer host": {func(t *testing.T, w *world) {
			w.set(RosterVar, writeRoster(t, w.dir, "h.toml", ftarget{"pvh-n1", "alias.example.com", "pvh-n1", "SHA256:h", ""}))
		}, "both resolve to 192.0.2.20"},
		"a harness address literal of an outer host": {func(t *testing.T, w *world) {
			w.set(RosterVar, writeRoster(t, w.dir, "h.toml", ftarget{"pvh-n1", "192.0.2.10", "pvh-n1", "SHA256:h", ""}))
		}, "is also a target, host or node"},
		"a harness address resolving to an outer literal": {func(t *testing.T, w *world) {
			resolver["literal-alias.example.com"] = []string{"192.0.2.10"}
			t.Cleanup(func() { delete(resolver, "literal-alias.example.com") })
			w.set(RosterVar, writeRoster(t, w.dir, "h.toml", ftarget{"pvh-n1", "literal-alias.example.com", "pvh-n1", "SHA256:h", ""}))
		}, "both resolve to 192.0.2.10"},
		"a harness host that does not resolve": {func(t *testing.T, w *world) {
			w.set(RosterVar, writeRoster(t, w.dir, "h.toml", ftarget{"pvh-n1", "nowhere.example.com", "pvh-n1", "SHA256:h", ""}))
		}, "resolve nowhere.example.com"},
		"an outer host that does not resolve": {func(t *testing.T, w *world) {
			w.set(OuterRostersVar, writeRoster(t, w.dir, "o.toml", ftarget{"o", "gone.example.com", "o", "", ""}))
		}, "resolve gone.example.com"},
		"no roster passphrase": {func(_ *testing.T, w *world) { w.set(roster.PassphraseEnvVar, "<unset>") }, roster.PassphraseEnvVar + " is not set"},
		"HTTP_PROXY":           {func(_ *testing.T, w *world) { w.set("HTTP_PROXY", "http://proxy.example.com:3128") }, "HTTP_PROXY is set"},
		"HTTPS_PROXY":          {func(_ *testing.T, w *world) { w.set("HTTPS_PROXY", "http://proxy.example.com:3128") }, "HTTPS_PROXY is set"},
		"ALL_PROXY":            {func(_ *testing.T, w *world) { w.set("ALL_PROXY", "socks5://proxy.example.com") }, "ALL_PROXY is set"},
		"NO_PROXY":             {func(_ *testing.T, w *world) { w.set("NO_PROXY", "") }, "NO_PROXY is set"},
		"http_proxy":           {func(_ *testing.T, w *world) { w.set("http_proxy", "http://proxy.example.com:3128") }, "http_proxy is set"},
		"https_proxy":          {func(_ *testing.T, w *world) { w.set("https_proxy", "http://proxy.example.com:3128") }, "https_proxy is set"},
		"all_proxy":            {func(_ *testing.T, w *world) { w.set("all_proxy", "socks5://proxy.example.com") }, "all_proxy is set"},
		"no_proxy":             {func(_ *testing.T, w *world) { w.set("no_proxy", "localhost") }, "no_proxy is set"},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			tc.edit(t, w)
			want := strings.ReplaceAll(tc.want, "<dir>", w.dir)
			_, err := w.open()
			if !errors.Is(err, ErrGuard) || !strings.Contains(err.Error(), want) {
				t.Fatalf("Open = %v; want ErrGuard saying %q", err, want)
			}
			if len(w.dialed) != 0 {
				t.Errorf("a static refusal still dialed %q", w.dialed)
			}
		})
	}
}

// The live checks: the target itself must say it is pvh.
func TestOpen_LiveRefusals(t *testing.T) {
	status := func(s string) func(*fakeClient) { return func(c *fakeClient) { c.status = s } }
	for name, tc := range map[string]struct {
		edit func(c *fakeClient)
		want string
	}{
		"/cluster/status fails":                {func(c *fakeClient) { c.statusEr = errors.New("503") }, "read /cluster/status"},
		"/cluster/status null":                 {status(`null`), "not a JSON array"},
		"/cluster/status not an array":         {status(`{"type":"cluster"}`), "not a JSON array"},
		"a null entry":                         {status(`[null]`), "not an object"},
		"an entry with no name":                {status(`[{"type":"node"}]`), "no type or name"},
		"another cluster":                      {status(strings.Replace(goodStatus, `"name":"pvh"`, `"name":"lab"`, 1)), `the cluster is "lab"`},
		"three nodes":                          {status(strings.Replace(goodStatus, `"nodes":2`, `"nodes":3`, 1)), "with 3 nodes"},
		"no node count":                        {status(strings.Replace(goodStatus, `"nodes":2,`, ``, 1)), "no node count"},
		"a standalone node (no cluster entry)": {status(`[{"type":"node","name":"pvh-n1","ip":"198.51.100.11"}]`), "0 cluster entries"},
		"two cluster entries": {status(`[{"type":"cluster","name":"pvh","nodes":2},{"type":"cluster","name":"pvh","nodes":2},` +
			`{"type":"node","name":"pvh-n1","ip":"198.51.100.11"},{"type":"node","name":"pvh-n2","ip":"198.51.100.12"}]`), "2 cluster entries"},
		"one node missing":                                 {status(`[{"type":"cluster","name":"pvh","nodes":2},{"type":"node","name":"pvh-n1","ip":"198.51.100.11"}]`), "the nodes are"},
		"an extra node (a subset is not enough)":           {status(strings.TrimSuffix(goodStatus, "]") + `,{"type":"node","name":"pvh-n3","ip":"198.51.100.13"}]`), "the nodes are"},
		"an outer node name":                               {status(`[{"type":"cluster","name":"pvh","nodes":2},{"type":"node","name":"pvh-n1","ip":"198.51.100.11"},{"type":"node","name":"outer-a","ip":"198.51.100.12"}]`), "the nodes are"},
		"a node with no ip":                                {status(strings.Replace(goodStatus, `,"ip":"198.51.100.12"`, ``, 1)), "carries no ip"},
		"node addresses unrelated to the harness hosts":    {status(strings.NewReplacer(`"198.51.100.11"`, `"198.51.100.50"`, `"198.51.100.12"`, `"198.51.100.51"`).Replace(goodStatus)), "the node addresses are"},
		"one node at an unrelated address":                 {status(strings.Replace(goodStatus, `"198.51.100.12"`, `"198.51.100.99"`, 1)), "the node addresses are"},
		"a node at the v4-mapped form of an outer address": {status(strings.Replace(goodStatus, `"198.51.100.12"`, `"::ffff:192.0.2.20"`, 1)), "an address of outer host outer-a.example.com"},
		"an unknown entry type":                            {status(strings.TrimSuffix(goodStatus, "]") + `,{"type":"qdevice","name":"q"}]`), "unknown type"},
		"a node at an outer address":                       {status(strings.Replace(goodStatus, `"198.51.100.12"`, `"192.0.2.20"`, 1)), "an address of outer host outer-a.example.com"},
		"a node at an outer IPv6 address":                  {status(strings.Replace(goodStatus, `"198.51.100.12"`, `"2001:db8:0::20"`, 1)), "an address of outer host"},
		"a node ip that is not an address":                 {status(strings.Replace(goodStatus, `"198.51.100.12"`, `"nope"`, 1)), "not an address"},
		"/nodes fails":                                     {func(c *fakeClient) { c.nodesErr = errors.New("403") }, "list nodes"},
		"/nodes lists one node":                            {func(c *fakeClient) { c.nodes = []string{"pvh-n1"} }, "the node list is"},
		"/nodes lists an extra node":                       {func(c *fakeClient) { c.nodes = []string{"pvh-n1", "pvh-n2", "lab"} }, "the node list is"},
		"/nodes has a null entry":                          {func(c *fakeClient) { c.nodesNil = true }, "null entry"},
		"the pinned SSH dial fails":                        {func(c *fakeClient) { c.linkErr = errors.New("host key mismatch") }, "pinned SSH dial failed"},
	} {
		t.Run(name, func(t *testing.T) {
			// Break the SECOND target, so a guard that checked only the
			// first would pass; the first's client must then be closed.
			w := newWorld(t)
			tc.edit(w.clients["pvh-n2"])
			_, err := w.open()
			if !errors.Is(err, ErrGuard) || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "pvh-n2") {
				t.Fatalf("Open = %v; want ErrGuard naming pvh-n2 and saying %q", err, tc.want)
			}
			if !w.clients["pvh-n1"].closed || !w.clients["pvh-n2"].closed {
				t.Errorf("a refused Open left a client open")
			}
		})
	}
	w := newWorld(t)
	w.dialErr = errors.New("decrypt")
	if _, err := w.open(); !errors.Is(err, ErrGuard) || !strings.Contains(err.Error(), "build its client") {
		t.Errorf("a client that cannot be built: %v", err)
	}
}

func TestHarness_Client(t *testing.T) {
	w := newWorld(t)
	h, err := w.open()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Client("lab"); !errors.Is(err, ErrGuard) {
		t.Errorf("an unvetted target: %v", err)
	}
	if _, err := h.Client("pvh-n1"); !errors.Is(err, ErrGuard) || !strings.Contains(err.Error(), "no pve client") {
		t.Errorf("a fake client is not a pve client: %v", err)
	}
	h.Close()
	if !w.clients["pvh-n1"].closed {
		t.Errorf("Close left a client open")
	}
}
