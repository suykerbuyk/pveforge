// Package harness is the nested-harness guard (pveforge-harness-guard, H2):
// what makes a harness test suite (//go:build harness) refuse to touch
// anything but the disposable nested cluster pvh (pvh-n1, pvh-n2). A suite
// gets its clients only from Open, which fails closed unless every check
// below passes.
//
// Nothing here names a real outer host: the deny-list is DERIVED from the
// outer rosters the environment names, never hardcoded.
//
// Threat model: a CARELESS suite or environment — a roster pointed at the
// wrong cluster, an operator's variables left set, a suite that reaches for
// its own client — not a deliberate attacker. DNS answers changing during a
// run, and IP-level spoofing, are out of scope: the REST client re-resolves
// names per request and its TLS is not pinned (insecure_tls), which
// certificate pinning, a separate product task, would close. What is in
// scope is refused before a single request: a proxy that would carry every
// request somewhere else, the operator's own roster, and any overlap with
// the outer rosters.
package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// The environment the guard reads.
const (
	// RosterVar is the harness roster: an absolute path to the roster whose
	// targets are the nested nodes.
	RosterVar = "PVEFORGE_HARNESS_ROSTER"
	// OuterRostersVar lists the outer rosters, colon-separated, absolute:
	// every roster that can reach the outer cluster. Required. Their
	// targets are what the harness must never be.
	OuterRostersVar = "PVEFORGE_HARNESS_OUTER_ROSTERS"
	// operatorRosterVar is the operator's own roster: it must be UNSET for
	// a harness run, so no command a suite runs can fall back to it. The
	// guard refuses rather than unsets it, so the operator's environment is
	// made explicit.
	operatorRosterVar = "PVEFORGE_ROSTER"
	// outerPasswordVar must be unset: at D5 G4 it holds the OUTER root
	// password. Suites give the nested password to a nested bootstrap
	// child's environment only (PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD
	// mapped to it), never to the test process.
	outerPasswordVar = "PVEFORGE_PVE_PASSWORD"
)

// The nested cluster, as the harness builds it.
const (
	ClusterName  = "pvh"
	targetPrefix = "pvh-"
)

// proxyVars are the variables net/http's ProxyFromEnvironment reads, in
// both cases: any one set would carry the REST requests somewhere other
// than the host the guard checked.
var proxyVars = []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"}

// NodeNames are the nested cluster's nodes, exactly.
var NodeNames = []string{"pvh-n1", "pvh-n2"}

// ErrGuard marks every refusal.
var ErrGuard = errors.New("harness guard")

// liveClient is what CheckLive needs of a target's client. *pve.RoutedClient
// satisfies it; tests substitute a fake.
type liveClient interface {
	RawRequest(ctx context.Context, method, path string, params url.Values) (json.RawMessage, error)
	GetNodes(ctx context.Context) (proxmox.NodeStatuses, error)
	LinkState(ctx context.Context, iface string) (sshexec.LinkState, error)
	Close() error
}

var _ liveClient = (*pve.RoutedClient)(nil)

// deps are the guard's outside world: the process environment, name
// resolution and client construction.
type deps struct {
	environ []string
	lookup  func(ctx context.Context, host string) ([]string, error)
	dial    func(t *roster.Target, passphrase string) (liveClient, error)
}

// Harness holds the vetted targets' clients. A suite gets clients only from
// here.
type Harness struct {
	clients map[string]liveClient
}

// Open runs every check against the real environment, resolver and pve
// clients, and returns the vetted harness, or an error wrapping ErrGuard.
func Open(ctx context.Context) (*Harness, error) {
	return open(ctx, deps{
		environ: os.Environ(),
		lookup:  net.DefaultResolver.LookupHost,
		dial: func(t *roster.Target, passphrase string) (liveClient, error) {
			return pve.NewRoutedClient(t, passphrase)
		},
	})
}

// Client returns the vetted client for a harness target.
func (h *Harness) Client(targetID string) (*pve.RoutedClient, error) {
	c, ok := h.clients[targetID]
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a vetted harness target", ErrGuard, targetID)
	}
	rc, ok := c.(*pve.RoutedClient)
	if !ok {
		return nil, fmt.Errorf("%w: %s has no pve client", ErrGuard, targetID)
	}
	return rc, nil
}

// Close closes every client.
func (h *Harness) Close() {
	for _, c := range h.clients {
		_ = c.Close()
	}
}

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrGuard}, args...)...)
}

func lookupEnv(environ []string, name string) (string, bool) {
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v, true
		}
	}
	return "", false
}

// rosterFile is one roster, loaded, with the path it came from.
type rosterFile struct {
	path string
	r    *roster.Roster
}

func open(ctx context.Context, d deps) (*Harness, error) {
	harnessRoster, hrAddrs, outerAddrs, err := staticChecks(ctx, d)
	if err != nil {
		return nil, err
	}
	pass, _ := lookupEnv(d.environ, roster.PassphraseEnvVar)
	if pass == "" {
		return nil, refuse("%s is not set: the harness roster's passphrase (run through hack/harness/unlock.sh)", roster.PassphraseEnvVar)
	}
	h := &Harness{clients: map[string]liveClient{}}
	for i := range harnessRoster.r.Targets {
		t := &harnessRoster.r.Targets[i]
		c, err := d.dial(t, pass)
		if err != nil {
			h.Close()
			return nil, refuse("%s: build its client: %v", t.ID, err)
		}
		h.clients[t.ID] = c
		if err := checkLive(ctx, t, c, hrAddrs, outerAddrs); err != nil {
			h.Close()
			return nil, err
		}
	}
	return h, nil
}

// staticChecks is everything decided before any request: the rosters, the
// derived deny-list, the fingerprints and the environment.
func staticChecks(ctx context.Context, d deps) (rosterFile, map[string]string, map[string]string, error) {
	for _, v := range proxyVars {
		if _, set := lookupEnv(d.environ, v); set {
			return rosterFile{}, nil, nil, refuse("%s is set: a proxy would carry the harness's requests past the hosts this guard checks; unset it for a harness run", v)
		}
	}
	if _, set := lookupEnv(d.environ, operatorRosterVar); set {
		return rosterFile{}, nil, nil, refuse("%s is set: unset the operator's roster for a harness run (the guard never unsets it for you)", operatorRosterVar)
	}
	if _, set := lookupEnv(d.environ, outerPasswordVar); set {
		return rosterFile{}, nil, nil, refuse("%s is set in the test environment; it may hold the OUTER root password, so the harness refuses to run (a nested bootstrap gets its password in its own child environment only)", outerPasswordVar)
	}
	hp, _ := lookupEnv(d.environ, RosterVar)
	if hp == "" {
		return rosterFile{}, nil, nil, refuse("%s is not set", RosterVar)
	}
	if !filepath.IsAbs(hp) {
		return rosterFile{}, nil, nil, refuse("%s must be an absolute path (go test runs in the package directory), got a relative one", RosterVar)
	}
	var outerPaths []string
	list, _ := lookupEnv(d.environ, OuterRostersVar)
	for _, p := range strings.Split(list, ":") {
		if p != "" {
			outerPaths = append(outerPaths, p)
		}
	}
	if len(outerPaths) == 0 {
		return rosterFile{}, nil, nil, refuse("%s names no outer roster; name every roster that reaches the outer cluster", OuterRostersVar)
	}
	for _, p := range outerPaths {
		if !filepath.IsAbs(p) {
			return rosterFile{}, nil, nil, refuse("outer roster %s is not an absolute path", p)
		}
		same, err := sameFile(hp, p)
		if err != nil {
			return rosterFile{}, nil, nil, refuse("compare the harness roster with outer roster %s: %v", p, err)
		}
		if same {
			return rosterFile{}, nil, nil, refuse("the harness roster is the same file as outer roster %s", p)
		}
	}
	hr, err := roster.Load(hp)
	if err != nil {
		return rosterFile{}, nil, nil, refuse("load the harness roster: %v", err)
	}
	if len(hr.Targets) == 0 {
		return rosterFile{}, nil, nil, refuse("the harness roster has no targets")
	}
	var outer []rosterFile
	for _, p := range outerPaths {
		r, err := roster.Load(p)
		if err != nil {
			return rosterFile{}, nil, nil, refuse("load outer roster %s: %v", p, err)
		}
		outer = append(outer, rosterFile{p, r})
	}

	// The derived deny-list: every outer target's id, host and node, and
	// every SSH fingerprint the outer rosters pin.
	names := map[string]string{}
	prints := map[string]string{}
	tokens := map[string]string{}
	for _, o := range outer {
		for _, t := range o.r.Targets {
			for _, n := range []string{t.ID, t.Host, t.Node} {
				if n != "" {
					names[strings.ToLower(n)] = o.path
				}
			}
			if t.SSH != nil && t.SSH.HostKeyFingerprint != "" {
				prints[t.SSH.HostKeyFingerprint] = o.path
			}
			if t.Token != nil && t.Token.ID != "" {
				tokens[t.Token.ID] = o.path
			}
		}
	}
	for _, t := range hr.Targets {
		if !strings.HasPrefix(t.ID, targetPrefix) {
			return rosterFile{}, nil, nil, refuse("harness target %q is not a %s* target", t.ID, targetPrefix)
		}
		if !slices.Contains(NodeNames, t.Node) {
			return rosterFile{}, nil, nil, refuse("harness target %s names node %q, not one of %s", t.ID, t.Node, strings.Join(NodeNames, ", "))
		}
		if t.SSH == nil || t.SSH.HostKeyFingerprint == "" {
			return rosterFile{}, nil, nil, refuse("harness target %s has no pinned SSH host key", t.ID)
		}
		for _, n := range []string{t.ID, t.Host, t.Node} {
			if src, ok := names[strings.ToLower(n)]; ok && n != "" {
				return rosterFile{}, nil, nil, refuse("harness target %s: %q is also a target, host or node in outer roster %s", t.ID, n, src)
			}
		}
		if t.Token != nil {
			if src, ok := tokens[t.Token.ID]; ok {
				return rosterFile{}, nil, nil, refuse("harness target %s uses API token %s, which outer roster %s also holds", t.ID, t.Token.ID, src)
			}
		}
		if src, ok := prints[t.SSH.HostKeyFingerprint]; ok {
			return rosterFile{}, nil, nil, refuse("harness target %s pins the same SSH host key as a target in outer roster %s", t.ID, src)
		}
	}
	// The addresses: a harness host resolving to an outer host's address is
	// the outer host under another name.
	hrAddrs, err := addresses(ctx, d, hostsOf(hr))
	if err != nil {
		return rosterFile{}, nil, nil, err
	}
	outerAddrs, err := addresses(ctx, d, outerHosts(outer))
	if err != nil {
		return rosterFile{}, nil, nil, err
	}
	for a, host := range hrAddrs {
		if o, ok := outerAddrs[a]; ok {
			return rosterFile{}, nil, nil, refuse("harness host %s and outer host %s both resolve to %s", host, o, a)
		}
	}
	return rosterFile{hp, hr}, hrAddrs, outerAddrs, nil
}

// sameFile reports whether two paths are the same file, through symlinks.
// A path that does not exist is not the same file as anything.
func sameFile(a, b string) (bool, error) {
	fa, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	fb, err := os.Stat(b)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return os.SameFile(fa, fb), nil
}

func hostsOf(r *roster.Roster) []string {
	var out []string
	for _, t := range r.Targets {
		out = append(out, t.Host)
	}
	return out
}

func outerHosts(outer []rosterFile) []string {
	var out []string
	for _, o := range outer {
		out = append(out, hostsOf(o.r)...)
	}
	return out
}

// addresses resolves hosts (an IP literal is itself) to a set of normalised
// addresses, each mapped to the host it came from. A host that does not
// resolve is refused: disjointness cannot be shown for it.
func addresses(ctx context.Context, d deps, hosts []string) (map[string]string, error) {
	out := map[string]string{}
	for _, h := range hosts {
		if h == "" {
			continue
		}
		addrs := []string{h}
		if net.ParseIP(h) == nil {
			var err error
			if addrs, err = d.lookup(ctx, h); err != nil || len(addrs) == 0 {
				return nil, refuse("resolve %s: %v", h, err)
			}
		}
		for _, a := range addrs {
			ip := net.ParseIP(a)
			if ip == nil {
				return nil, refuse("resolve %s: %q is not an address", h, a)
			}
			out[ip.String()] = h
		}
	}
	return out, nil
}

// checkLive asks the target itself what it is: PVE's /cluster/status must
// name cluster pvh with exactly the nodes pvh-n1 and pvh-n2 (none at an
// outer address); /nodes must list
// exactly those nodes; and a read-only SSH call must succeed through the
// pinned dial (RoutedClient pins the host key on every dial, so the live
// host key is the harness roster's, which staticChecks proved no outer
// roster pins).
func checkLive(ctx context.Context, t *roster.Target, c liveClient, hrAddrs, outerAddrs map[string]string) error {
	raw, err := c.RawRequest(ctx, http.MethodGet, "/cluster/status", nil)
	if err != nil {
		return refuse("%s: read /cluster/status: %v", t.ID, err)
	}
	// The node set must equal NodeNames exactly, and staticChecks already
	// holds every target's node to NodeNames, so the target's own node is
	// in the cluster by construction.
	if err := decodeClusterStatus(raw, hrAddrs, outerAddrs); err != nil {
		return refuse("%s: /cluster/status: %v", t.ID, err)
	}
	ns, err := c.GetNodes(ctx)
	if err != nil {
		return refuse("%s: list nodes: %v", t.ID, err)
	}
	var listed []string
	for _, n := range ns {
		if n == nil {
			return refuse("%s: the node list has a null entry", t.ID)
		}
		listed = append(listed, n.Node)
	}
	slices.Sort(listed)
	if !slices.Equal(listed, NodeNames) {
		return refuse("%s: the node list is %q, want exactly %q", t.ID, listed, NodeNames)
	}
	if _, err := c.LinkState(ctx, "lo"); err != nil {
		return refuse("%s: the pinned SSH dial failed: %v", t.ID, err)
	}
	return nil
}

// decodeClusterStatus strictly decodes GET /cluster/status: exactly one
// cluster entry, named pvh with 2 nodes, and node entries named exactly
// NodeNames, each with an ip, none at an outer address, and together at
// exactly the addresses the harness hosts resolve to. Anything else — a standalone node
// (no cluster entry), an unknown entry type, a null — is refused.
func decodeClusterStatus(raw json.RawMessage, hrAddrs, outerAddrs map[string]string) error {
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || entries == nil {
		return errors.New("not a JSON array")
	}
	var clusters int
	var nodes, ips []string
	for i, e := range entries {
		if e == nil {
			return fmt.Errorf("entry %d is not an object", i)
		}
		var typ, name string
		if json.Unmarshal(e["type"], &typ) != nil || json.Unmarshal(e["name"], &name) != nil || name == "" {
			return fmt.Errorf("entry %d has no type or name", i)
		}
		switch typ {
		case "cluster":
			clusters++
			var n int
			if json.Unmarshal(e["nodes"], &n) != nil {
				return errors.New("the cluster entry has no node count")
			}
			if name != ClusterName || n != len(NodeNames) {
				return fmt.Errorf("the cluster is %q with %d nodes, want %q with %d", name, n, ClusterName, len(NodeNames))
			}
		case "node":
			var ip string
			if json.Unmarshal(e["ip"], &ip) != nil || ip == "" {
				return fmt.Errorf("node %s carries no ip", name)
			}
			parsed := net.ParseIP(ip)
			if parsed == nil {
				return fmt.Errorf("node %s has an ip that is not an address", name)
			}
			if o, bad := outerAddrs[parsed.String()]; bad {
				return fmt.Errorf("node %s is at %s, an address of outer host %s", name, ip, o)
			}
			nodes = append(nodes, name)
			ips = append(ips, parsed.String())
		default:
			return fmt.Errorf("entry %d has an unknown type", i)
		}
	}
	if clusters != 1 {
		return fmt.Errorf("%d cluster entries, want exactly 1 (a standalone node has none)", clusters)
	}
	slices.Sort(nodes)
	if !slices.Equal(nodes, NodeNames) {
		return fmt.Errorf("the nodes are %q, want exactly %q", nodes, NodeNames)
	}
	// The nodes PVE reports are exactly the hosts the harness roster names:
	// the set of node addresses equals the set the harness hosts resolve to.
	want := make([]string, 0, len(hrAddrs))
	for a := range hrAddrs {
		want = append(want, a)
	}
	slices.Sort(want)
	slices.Sort(ips)
	if !slices.Equal(slices.Compact(ips), want) {
		return fmt.Errorf("the node addresses are %q, but the harness hosts resolve to %q", ips, want)
	}
	return nil
}
