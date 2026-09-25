package pve

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
)

// answer is one canned PVE response: a status and a raw body.
type answer struct {
	status int
	body   string
}

// data wraps v in PVE's {"data": ...} envelope with a 200.
func data(v string) answer { return answer{http.StatusOK, `{"data":` + v + `}`} }

// permRouter is a strict fake of the two endpoints the validator may call.
// It serves GET /access/permissions (no query: the tree; exactly one
// "path" query: that path's answer) and GET /access/roles/<id>. Anything
// else — /nodes, a userid, a second query parameter, another method — is
// a test failure and a 404. Every request is recorded as "tree",
// "path:<p>" or "role:<id>".
type permRouter struct {
	t     *testing.T
	tree  answer
	paths map[string]answer
	roles map[string]answer
	reqs  []string

	// pveforge-validator-pool-membership's reads, each recorded:
	// trees answers the tree reads after the first, in order (the last
	// repeats; unset, tree answers every read) — "tree";
	// pools answers GET /pools?poolid=<id> in order (the last repeats) —
	// "pools:<id>"; nextid answers GET /cluster/nextid?vmid=<n> —
	// "nextid:<n>"; storage answers GET /storage — "storage".
	trees   []answer
	pools   map[string][]answer
	nextid  map[string]answer
	storage *answer
	nTree   int
	nPools  map[string]int
}

func (pr *permRouter) serve(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var a answer
	var ok bool
	switch {
	case r.Method != http.MethodGet:
		pr.t.Errorf("unexpected method %s %s", r.Method, r.URL)
	case q.Has("userid"):
		pr.t.Errorf("the validator sent a userid: %s", r.URL)
	case r.URL.Path == "/access/permissions" && len(q) == 0:
		pr.reqs = append(pr.reqs, "tree")
		a, ok = pr.tree, true
		if pr.nTree > 0 && len(pr.trees) > 0 {
			a = pr.trees[min(pr.nTree-1, len(pr.trees)-1)]
		}
		pr.nTree++
	case r.URL.Path == "/pools" && len(q) == 1 && len(q["poolid"]) == 1:
		id := q.Get("poolid")
		pr.reqs = append(pr.reqs, "pools:"+id)
		seq := pr.pools[id]
		if ok = len(seq) > 0; ok {
			if pr.nPools == nil {
				pr.nPools = map[string]int{}
			}
			a = seq[min(pr.nPools[id], len(seq)-1)]
			pr.nPools[id]++
		} else {
			pr.t.Errorf("unexpected pool read %q", id)
		}
	case r.URL.Path == "/cluster/nextid" && len(q) == 1 && len(q["vmid"]) == 1:
		n := q.Get("vmid")
		pr.reqs = append(pr.reqs, "nextid:"+n)
		if a, ok = pr.nextid[n]; !ok {
			pr.t.Errorf("unexpected nextid check %q", n)
		}
	case r.URL.Path == "/storage" && len(q) == 0:
		pr.reqs = append(pr.reqs, "storage")
		if ok = pr.storage != nil; ok {
			a = *pr.storage
		} else {
			pr.t.Errorf("unexpected storage list read")
		}
	case r.URL.Path == "/access/permissions" && len(q) == 1 && len(q["path"]) == 1:
		p := q.Get("path")
		pr.reqs = append(pr.reqs, "path:"+p)
		a, ok = pr.paths[p]
		if !ok {
			pr.t.Errorf("unexpected path query %q", p)
		}
	case strings.HasPrefix(r.URL.Path, "/access/roles/") && len(q) == 0:
		id := strings.TrimPrefix(r.URL.Path, "/access/roles/")
		pr.reqs = append(pr.reqs, "role:"+id)
		a, ok = pr.roles[id]
		if !ok {
			pr.t.Errorf("unexpected role read %q", id)
		}
	default:
		pr.t.Errorf("unexpected request %s %s", r.Method, r.URL)
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(a.status)
	_, _ = w.Write([]byte(a.body))
}

func (pr *permRouter) count(prefix string) int {
	n := 0
	for _, r := range pr.reqs {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/permissions/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// liveTree is root@pam!pveforge's whole tree on qa-pve-02 (PVEVMAdmin on /,
// propagate 1): 8 default paths × PVEVMAdmin's 23 privileges, flag 1.
func liveTree(t *testing.T) string { return readFixture(t, "root-pam-pveforge.json") }

// liveVMAdmin is GET /access/roles/PVEVMAdmin on qa-pve-02.
func liveVMAdmin(t *testing.T) string { return readFixture(t, "role-pvevmadmin.json") }

// d5 returns D5 r3's four pinned grants (all propagate 0, as in the
// settled D5 design) and its expected post-build effective tree, both
// generated from D5 r3's pinned JSON files.
func d5(t *testing.T) ([]Grant, map[string]map[string]int) {
	t.Helper()
	var roles map[string][]string
	if err := json.Unmarshal([]byte(readFixture(t, "d5r3-expected-roles.json")), &roles); err != nil {
		t.Fatal(err)
	}
	var tree map[string]map[string]int
	if err := json.Unmarshal([]byte(readFixture(t, "d5r3-expected-tree-post-build.json")), &tree); err != nil {
		t.Fatal(err)
	}
	var want []Grant
	for path, role := range map[string]string{
		"/pool/pveforge-harness":        "ForgeHarness",
		"/sdn/zones/localnetwork/vmbr0": "ForgeHarnessNet",
		"/storage/local":                "ForgeHarnessIso",
		"/storage/pveforge-harness":     "ForgeHarnessSpace",
	} {
		want = append(want, Grant{Path: path, Role: role, Privs: roles[role]})
	}
	sort.Slice(want, func(i, j int) bool { return want[i].Path < want[j].Path })
	return want, tree
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// d5Paths answers ?path= for each D5 grant from tree (an absent path
// answers {}).
func d5Paths(t *testing.T, want []Grant, tree map[string]map[string]int) map[string]answer {
	out := map[string]answer{}
	for _, g := range want {
		set := tree[g.Path]
		if set == nil {
			set = map[string]int{}
		}
		out[g.Path] = data(mustJSON(t, map[string]map[string]int{g.Path: set}))
	}
	return out
}

// notAny is an expectation: an error that is none of the verdicts.
var errNotAny = errors.New("an error that is no verdict")

type vcase struct {
	want  []Grant
	tree  answer
	paths map[string]answer
	roles map[string]answer
	// expect: nil, a sentinel (errors.Is), or errNotAny.
	expect error
	// names: substrings the error must contain.
	names []string
	// requests, if non-negative, is the exact request count.
	requests int
	check    func(t *testing.T, pr *permRouter)

	trees   []answer
	pools   map[string][]answer
	nextid  map[string]answer
	storage *answer
	// seq, if set, is the exact request sequence.
	seq []string
}

func runVCase(t *testing.T, tc vcase) {
	t.Helper()
	pr := &permRouter{t: t, tree: tc.tree, paths: tc.paths, roles: tc.roles, trees: tc.trees, pools: tc.pools, nextid: tc.nextid, storage: tc.storage}
	c := testClient(t, newFakeAPIServer(t, pr.serve))
	err := ValidateTokenGrants(context.Background(), c, tc.want)
	switch {
	case tc.expect == nil:
		if err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	case tc.expect == errNotAny:
		if err == nil {
			t.Fatal("want an error, got nil")
		}
		for _, s := range []error{ErrNoGrants, ErrWrongScope, ErrScopeTooWide, ErrNotAuthorized, ErrUnverifiableRead, ErrInvalidGrant} {
			if errors.Is(err, s) {
				t.Fatalf("want no sentinel, got %v (is %v)", err, s)
			}
		}
	default:
		if !errors.Is(err, tc.expect) {
			t.Fatalf("want %v, got %v", tc.expect, err)
		}
		// ErrNotAuthorized too: bootstrap revokes on it (isVerdict), so a row
		// expecting any other outcome must not carry it anywhere in the chain.
		for _, other := range []error{ErrNoGrants, ErrWrongScope, ErrScopeTooWide, ErrNotAuthorized} {
			if other != tc.expect && errors.Is(err, other) {
				t.Fatalf("want only %v, got %v", tc.expect, err)
			}
		}
	}
	for _, n := range tc.names {
		if err == nil || !strings.Contains(err.Error(), n) {
			t.Errorf("the error does not name %q: %v", n, err)
		}
	}
	if err != nil && (len(err.Error()) > 2048 || strings.ContainsAny(err.Error(), "\x1b") || strings.Contains(err.Error(), "xxxxxxxx") || strings.Contains(err.Error(), "line two")) {
		t.Errorf("the error is not one bounded line of our own text (%d bytes): %.200q", len(err.Error()), err.Error())
	}
	if err != nil && strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("the error spans lines: %q", err.Error())
	}
	if tc.requests >= 0 && len(pr.reqs) != tc.requests {
		t.Errorf("requests = %v, want %d", pr.reqs, tc.requests)
	}
	if tc.seq != nil && strings.Join(pr.reqs, " ") != strings.Join(tc.seq, " ") {
		t.Errorf("request sequence:\n got:  %q\n want: %q", pr.reqs, tc.seq)
	}
	if tc.check != nil {
		tc.check(t, pr)
	}
}

func pin(path string, prop bool, privs ...string) Grant {
	return Grant{Path: path, Role: "R", Propagate: prop, Privs: privs}
}

func pathAns(path, set string) answer { return data(`{"` + path + `":` + set + `}`) }

func TestValidateTokenGrants(t *testing.T) {
	poolR := []Grant{{Path: "/pool/p", Role: "R"}}
	roleA := map[string]answer{"R": data(`{"A":1}`)}
	cases := map[string]vcase{
		"T1 empty tree: ErrNoGrants, one request": {
			want: poolR, tree: data(`{}`), expect: ErrNoGrants, requests: 1,
		},
		"T2 data null": {want: poolR, tree: data(`null`), expect: ErrUnverifiableRead, requests: 1},
		"T2b no data key": {
			want: poolR, tree: answer{http.StatusOK, `{}`}, expect: ErrUnverifiableRead, requests: 1,
		},
		"T2c a privilege name with a line break": {
			want: poolR, tree: data(`{"/":{"A\nb":1}}`), expect: ErrUnverifiableRead, requests: 1,
		},
		"T2d a flag other than 0/1/true/false": {
			want: poolR, tree: data(`{"/pool/p":{"A":2}}`), expect: ErrUnverifiableRead, requests: 1,
		},
		"T2e a path key outside the ACL charset": {
			want: poolR, tree: data(`{"pool p":{"A":1}}`), expect: ErrUnverifiableRead, requests: 1,
		},
		"T2f a top level that is not an object": {
			want: poolR, tree: data(`[]`), expect: ErrUnverifiableRead, requests: 1,
		},
		"T2g a privilege set that is not an object": {
			want: poolR, tree: data(`{"/pool/p":1}`), expect: ErrUnverifiableRead, requests: 1,
		},
		"T3 one grant present, the other absent": {
			want: []Grant{{Path: "/pool/p", Role: "R"}, {Path: "/storage/local", Role: "PVEDatastoreUser", Privs: []string{"Datastore.Audit"}}},
			tree: data(`{"/storage/local":{"Datastore.Audit":0}}`),
			paths: map[string]answer{
				"/storage/local": pathAns("/storage/local", `{"Datastore.Audit":0}`),
				"/pool/p":        pathAns("/pool/p", `{}`),
			},
			roles: roleA, expect: ErrWrongScope, names: []string{"/pool/p", "[A]"}, requests: 4,
		},
		"T4 a privilege missing": {
			want: []Grant{pin("/pool/p", false, "A", "B")}, tree: data(`{"/pool/p":{"A":0}}`),
			paths: map[string]answer{"/pool/p": pathAns("/pool/p", `{"A":0}`)}, expect: ErrWrongScope, names: []string{"lacks [B]"}, requests: 2,
		},
		"T5 today's live token against a pool request": {
			want: []Grant{{Path: "/pool/p", Role: "PVEVMAdmin"}}, tree: data(liveTree(t)),
			paths:  map[string]answer{"/pool/p": pathAns("/pool/p", mustJSON(t, liveTreeAt(t, "/")))},
			roles:  map[string]answer{"PVEVMAdmin": data(liveVMAdmin(t))},
			expect: ErrScopeTooWide, names: []string{"at / "}, requests: 3,
		},
		"T5b a propagating grant at /": {
			want: poolR, tree: data(`{"/":{"A":1},"/pool/p":{"A":1}}`),
			paths: map[string]answer{"/pool/p": pathAns("/pool/p", `{"A":1}`)}, roles: roleA,
			expect: ErrScopeTooWide, names: []string{"at / "}, requests: 3,
		},
		"T5c too wide wins over missing": {
			want: []Grant{pin("/pool/p", false, "A", "B")}, tree: data(`{"/":{"A":1}}`),
			paths: map[string]answer{"/pool/p": pathAns("/pool/p", `{"A":1}`)}, expect: ErrScopeTooWide, requests: 2,
		},
		"T6 propagate held, not requested": {
			want: []Grant{pin("/storage/s", false, "A")}, tree: data(`{"/storage/s":{"A":1}}`),
			paths: map[string]answer{"/storage/s": pathAns("/storage/s", `{"A":1}`)}, expect: ErrScopeTooWide, requests: 2,
		},
		"T7 an extra privilege at the grant's path": {
			want: []Grant{pin("/pool/p", false, "A")}, tree: data(`{"/pool/p":{"A":0,"X":0}}`),
			paths: map[string]answer{"/pool/p": pathAns("/pool/p", `{"A":0,"X":0}`)}, expect: ErrScopeTooWide, names: []string{"holds X,"}, requests: 2,
		},
		"T8 a pool member at propagate 1": {
			want: []Grant{pin("/pool/p", false, "A")}, tree: data(`{"/pool/p":{"A":0},"/vms/105":{"A":1}}`),
			paths: map[string]answer{"/pool/p": pathAns("/pool/p", `{"A":0}`)}, expect: ErrScopeTooWide, names: []string{"/vms/105"}, requests: 2,
		},
		"T9 the default grant against today's live token": {
			want: []Grant{{Path: "/", Role: "PVEVMAdmin", Propagate: true}}, tree: data(liveTree(t)),
			paths: map[string]answer{"/": pathAns("/", mustJSON(t, liveTreeAt(t, "/")))},
			roles: map[string]answer{"PVEVMAdmin": data(liveVMAdmin(t))}, expect: nil, requests: 3,
		},
		"T10 a pool member at propagate 0": {
			want: []Grant{{Path: "/pool/p", Role: "R", Propagate: true}}, tree: data(`{"/pool/p":{"A":1},"/vms/690":{"A":0}}`),
			paths: map[string]answer{"/pool/p": pathAns("/pool/p", `{"A":1}`)}, roles: roleA, expect: nil, requests: 3,
		},
		"T12 403":  {want: poolR, tree: answer{http.StatusForbidden, `{"data":null}`}, expect: ErrNotAuthorized, requests: 1},
		"T12b 401": {want: poolR, tree: answer{http.StatusUnauthorized, `{"data":null}`}, expect: ErrNotAuthorized, requests: 1},
		"T12c 500 keeps PVE's text": {
			want: poolR, tree: answer{http.StatusInternalServerError, `{"errors":"boom"}`}, expect: errNotAny, names: []string{"boom"}, requests: 1,
		},
		"T13 the role read fails": {
			want: []Grant{{Path: "/pool/p", Role: "Nope"}}, tree: data(`{"/pool/p":{"A":0}}`),
			roles: map[string]answer{"Nope": {http.StatusInternalServerError, `{"errors":"no such role"}`}}, expect: errNotAny, requests: 2,
		},
		"T13b a role with no privileges": {
			want: []Grant{{Path: "/pool/p", Role: "Nope"}}, tree: data(`{"/pool/p":{"A":0}}`),
			roles: map[string]answer{"Nope": data(`{}`)}, expect: ErrUnverifiableRead, requests: 2,
		},
		"T13c a role privilege present but unset": {
			want: []Grant{{Path: "/pool/p", Role: "Nope"}}, tree: data(`{"/pool/p":{"A":0}}`),
			roles: map[string]answer{"Nope": data(`{"A":0}`)}, expect: ErrUnverifiableRead, requests: 2,
		},
		"T14 no grants":          {want: nil, expect: ErrInvalidGrant, requests: 0},
		"T14b a non-normal path": {want: []Grant{{Path: "/pool/p/", Role: "R"}}, expect: ErrInvalidGrant, requests: 0},
		"T14c two grants on one path": {
			want: []Grant{{Path: "/pool/p", Role: "R"}, {Path: "/pool/p", Role: "S"}}, expect: ErrInvalidGrant, requests: 0,
		},
		"T16 a pinned set catches a widened role": {
			want: []Grant{pin("/pool/p", false, "A")}, tree: data(`{"/pool/p":{"A":0,"Permissions.Modify":0}}`),
			paths:  map[string]answer{"/pool/p": pathAns("/pool/p", `{"A":0,"Permissions.Modify":0}`)},
			expect: ErrScopeTooWide, names: []string{"Permissions.Modify"}, requests: 2,
		},
		"T17 unpinned, the widened role widens the bound (known limit 3)": {
			want: poolR, tree: data(`{"/pool/p":{"A":0,"Permissions.Modify":0}}`),
			paths: map[string]answer{"/pool/p": pathAns("/pool/p", `{"A":0,"Permissions.Modify":0}`)},
			roles: map[string]answer{"R": data(`{"A":1,"Permissions.Modify":1}`)}, expect: nil, requests: 3,
		},
		"T18 empty pinned privileges": {want: []Grant{{Path: "/pool/p", Role: "R", Privs: []string{}}}, expect: ErrInvalidGrant, requests: 0},
		"T18b a pinned grant without a role": {
			want: []Grant{{Path: "/pool/p", Privs: []string{"A"}}}, expect: ErrInvalidGrant, names: []string{"role"}, requests: 0,
		},
		"T18c a duplicate pinned privilege": {want: []Grant{pin("/pool/p", false, "A", "A")}, expect: ErrInvalidGrant, requests: 0},
		"T19 a sibling path is not a descendant": {
			want: []Grant{pin("/storage/s", true, "A")}, tree: data(`{"/storage/s":{"A":1},"/storage/s2":{"A":1}}`),
			paths: map[string]answer{"/storage/s": pathAns("/storage/s", `{"A":1}`)}, expect: ErrScopeTooWide, names: []string{"/storage/s2"}, requests: 2,
		},
		"T20 the pool rule needs a pool grant": {
			want: []Grant{pin("/storage/s", false, "A")}, tree: data(`{"/storage/s":{"A":0},"/vms/105":{"A":0}}`),
			paths: map[string]answer{"/storage/s": pathAns("/storage/s", `{"A":0}`)}, expect: ErrScopeTooWide, names: []string{"/vms/105"}, requests: 2,
		},
		"T22 propagate requested, not held": {
			want: []Grant{pin("/storage/s", true, "A")}, tree: data(`{"/storage/s":{"A":0}}`),
			paths: map[string]answer{"/storage/s": pathAns("/storage/s", `{"A":0}`)}, expect: ErrWrongScope, names: []string{"without propagate [A]"}, requests: 2,
		},
		"T23 per-privilege sources on one member path": {
			want: []Grant{
				{Path: "/pool/p", Role: "R", Privs: []string{"VM.Audit", "VM.PowerMgmt"}},
				{Path: "/vms", Role: "S", Propagate: true, Privs: []string{"VM.Audit"}},
			},
			tree: data(`{"/vms":{"VM.Audit":1},"/pool/p":{"VM.Audit":0,"VM.PowerMgmt":0},"/vms/690":{"VM.Audit":1,"VM.PowerMgmt":0}}`),
			paths: map[string]answer{
				"/vms":    pathAns("/vms", `{"VM.Audit":1}`),
				"/pool/p": pathAns("/pool/p", `{"VM.Audit":0,"VM.PowerMgmt":0}`),
			},
			expect: nil, requests: 3,
		},
		"T24 mixed flags on a member": {
			want: []Grant{pin("/pool/p", false, "A", "B")}, tree: data(`{"/pool/p":{"A":0,"B":0},"/vms/105":{"A":0,"B":1}}`),
			paths: map[string]answer{"/pool/p": pathAns("/pool/p", `{"A":0,"B":0}`)}, expect: ErrScopeTooWide, names: []string{"at /vms/105 the token holds B,"}, requests: 2,
		},
		"T25 a path answer keyed by another path": {
			want: []Grant{pin("/pool/p", false, "A")}, tree: data(`{"/pool/p":{"A":0}}`),
			paths: map[string]answer{"/pool/p": pathAns("/other", `{"A":0}`)}, expect: ErrUnverifiableRead, requests: 2,
		},
		"T25b a path answer with an extra key": {
			want: []Grant{pin("/pool/p", false, "A")}, tree: data(`{"/pool/p":{"A":0}}`),
			paths: map[string]answer{"/pool/p": data(`{"/pool/p":{"A":0},"/":{}}`)}, expect: ErrUnverifiableRead, requests: 2,
		},
		"T26 mixed pinned and unpinned grants": {
			want: []Grant{pin("/pool/p", false, "A"), {Path: "/storage/s", Role: "PVEDatastoreUser"}},
			tree: data(`{"/pool/p":{"A":0},"/storage/s":{"Datastore.AllocateSpace":0,"Datastore.Audit":0}}`),
			paths: map[string]answer{
				"/pool/p":    pathAns("/pool/p", `{"A":0}`),
				"/storage/s": pathAns("/storage/s", `{"Datastore.AllocateSpace":0,"Datastore.Audit":0}`),
			},
			roles:  map[string]answer{"PVEDatastoreUser": data(`{"Datastore.AllocateSpace":1,"Datastore.Audit":1}`)},
			expect: nil, requests: 4,
			check: func(t *testing.T, pr *permRouter) {
				if pr.count("role:PVEDatastoreUser") != 1 || pr.count("role:R") != 0 {
					t.Errorf("role reads = %v; want exactly one PVEDatastoreUser and none of R", pr.reqs)
				}
			},
		},
		"T26b one role read per distinct unpinned role": {
			want: []Grant{{Path: "/pool/p", Role: "R"}, {Path: "/pool/q", Role: "R"}},
			tree: data(`{"/pool/p":{"A":0},"/pool/q":{"A":0}}`),
			paths: map[string]answer{
				"/pool/p": pathAns("/pool/p", `{"A":0}`),
				"/pool/q": pathAns("/pool/q", `{"A":0}`),
			},
			roles: roleA, expect: nil, requests: 4,
		},
	}

	// ---- round 1 ----
	// R2 (A4): a null privilege set is a non-answer, never zero privileges
	// (which would be a revoking verdict).
	cases["X1 a null privilege set in the ?path= answer"] = vcase{
		want: []Grant{pin("/pool/p", false, "A")}, tree: data(`{"/pool/p":{"A":0}}`),
		paths: map[string]answer{"/pool/p": pathAns("/pool/p", `null`)}, expect: ErrUnverifiableRead, requests: 2,
	}
	cases["X1b a null privilege set in the tree"] = vcase{
		want: []Grant{pin("/pool/p", false, "A")}, tree: data(`{"/pool/p":null}`), expect: ErrUnverifiableRead, requests: 1,
	}
	// R1: a propagate-0 row BELOW a non-propagating grant (D5's shape) is
	// too wide.
	cases["X2 a flag-0 row below a non-propagating grant"] = vcase{
		want:   []Grant{pin("/sdn/zones/z/vmbr0", false, "SDN.Use")},
		tree:   data(`{"/sdn/zones/z/vmbr0":{"SDN.Use":0},"/sdn/zones/z/vmbr0/5":{"SDN.Use":0}}`),
		paths:  map[string]answer{"/sdn/zones/z/vmbr0": pathAns("/sdn/zones/z/vmbr0", `{"SDN.Use":0}`)},
		expect: ErrScopeTooWide, names: []string{"/sdn/zones/z/vmbr0/5"}, requests: 2,
	}
	// CH1: two DIFFERENT unpinned roles with disjoint privileges, each read
	// once. Reusing one role's privileges for the other is wrong both ways.
	twoRoles := []Grant{{Path: "/pool/p", Role: "R1"}, {Path: "/sdn/zones/z", Role: "R2"}}
	disjoint := map[string]answer{"R1": data(`{"A":1}`), "R2": data(`{"B":1}`)}
	oneReadEach := func(t *testing.T, pr *permRouter) {
		if pr.count("role:R1") != 1 || pr.count("role:R2") != 1 {
			t.Errorf("role reads = %v; want R1 once and R2 once", pr.reqs)
		}
	}
	cases["CH1a two distinct unpinned roles: correct tree accepted"] = vcase{
		want: twoRoles, tree: data(`{"/pool/p":{"A":0},"/sdn/zones/z":{"B":0}}`),
		paths: map[string]answer{"/pool/p": pathAns("/pool/p", `{"A":0}`), "/sdn/zones/z": pathAns("/sdn/zones/z", `{"B":0}`)},
		roles: disjoint, expect: nil, requests: 5, check: oneReadEach,
	}
	cases["CH1b two distinct unpinned roles: the first role's privilege at the second path is refused"] = vcase{
		want: twoRoles, tree: data(`{"/pool/p":{"A":0},"/sdn/zones/z":{"A":0}}`),
		paths: map[string]answer{"/pool/p": pathAns("/pool/p", `{"A":0}`), "/sdn/zones/z": pathAns("/sdn/zones/z", `{"A":0}`)},
		roles: disjoint, expect: ErrScopeTooWide, names: []string{"at /sdn/zones/z the token holds A,"}, requests: 5, check: oneReadEach,
	}
	// CH2 / CH3: the pool rule covers pool MEMBERS (/vms/<n>, /storage/<s>),
	// never a direct propagate-0 ACL on /vms or /storage itself.
	for _, top := range []string{"/vms", "/storage"} {
		cases["CH2/3 flag 0 at exactly "+top+" with a pool grant"] = vcase{
			want: []Grant{pin("/pool/p", false, "A")}, tree: data(`{"/pool/p":{"A":0},"` + top + `":{"A":0}}`),
			paths:  map[string]answer{"/pool/p": pathAns("/pool/p", `{"A":0}`)},
			expect: ErrScopeTooWide, names: []string{"at " + top + " the token holds A,"}, requests: 2,
		}
	}
	// F1: a 401/403 verdict carries fixed text plus the status, never PVE's
	// body (here multi-line, with an ESC, 5 KB).
	hostile := `line one\nline two \u001b[31m` + strings.Repeat("x", 5000)
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		for name, tc := range map[string]vcase{
			"tree": {want: poolR, tree: answer{code, `{"errors":"` + hostile + `"}` + "\n\x1b[0m trailing"}, requests: 1},
			"role": {want: poolR, tree: data(`{"/pool/p":{"A":0}}`), roles: map[string]answer{"R": {code, "raw\nbody\x1b" + hostile}}, requests: 2},
			"path": {want: []Grant{pin("/pool/p", false, "A")}, tree: data(`{"/pool/p":{"A":0}}`), paths: map[string]answer{"/pool/p": {code, "raw\nbody\x1b" + hostile}}, requests: 2},
		} {
			tc.expect = ErrNotAuthorized
			tc.names = []string{fmt.Sprintf("(PVE answered HTTP %d)", code)}
			cases[fmt.Sprintf("F1 a hostile %d body on the %s read is not carried", code, name)] = tc
		}
	}

	want, tree := d5(t)
	// pveforge-validator-pool-membership: D5's pool grant carries Pool.Audit
	// and its ?path= answer shows it held, so a tree with members resolves
	// the pool: tree, the pool's ?path=, members, tree again, members
	// again, then the other three grants' ?path=.
	d5Pools := map[string][]answer{"pveforge-harness": {d5MembersAns}}
	d5Seq := func(extra ...string) []string {
		seq := []string{"tree", "path:/pool/pveforge-harness", "pools:pveforge-harness", "tree", "pools:pveforge-harness"}
		seq = append(seq, extra...)
		return append(seq, "path:/sdn/zones/localnetwork/vmbr0", "path:/storage/local", "path:/storage/pveforge-harness")
	}
	// P0: the post-build tree, every privilege at 0, members 690-692.
	cases["T11/P0 D5's four pinned grants, members resolved"] = vcase{want: want, tree: data(mustJSON(t, tree)), paths: d5Paths(t, want, tree),
		pools: d5Pools, expect: nil, requests: 8, seq: d5Seq()}
	{
		absent := clone(tree)
		delete(absent, "/sdn/zones/localnetwork/vmbr0")
		cases["T11b D5 with the SDN grant absent"] = vcase{want: want, tree: data(mustJSON(t, absent)), paths: d5Paths(t, want, absent),
			pools: d5Pools, expect: ErrWrongScope, names: []string{"/sdn/zones/localnetwork/vmbr0"}, requests: 8}
	}
	{
		// A propagate-0 subset of the pool role on a VM that is NOT a pool
		// member (a delegated row): refused now that membership is read,
		// since /vms/105 exists. Known limits 1 and 2 still hold where the
		// pool cannot be resolved (T11c-fallback).
		deleg := clone(tree)
		deleg["/vms/105"] = map[string]int{"VM.Audit": 0, "VM.PowerMgmt": 0}
		cases["T11c D5 plus a delegated row on a non-member VM"] = vcase{want: want, tree: data(mustJSON(t, deleg)), paths: d5Paths(t, want, deleg),
			pools: d5Pools, nextid: map[string]answer{"105": vmidTaken(105)}, expect: ErrScopeTooWide,
			names: []string{"at /vms/105 the token holds VM.Audit,VM.PowerMgmt,"}, requests: 9, seq: d5Seq("nextid:105")}
		wantNA, delegNA := d5WithoutPoolAudit(want, deleg)
		cases["T11c-fallback D5 without Pool.Audit plus a delegated row (known limits 1, 2)"] = vcase{want: wantNA, tree: data(mustJSON(t, delegNA)),
			paths: d5Paths(t, wantNA, delegNA), expect: nil, requests: 5}
	}
	{
		// One grant's privilege at another grant's path: each grant alone
		// fails to confer it, though the union of the grants would.
		cross := clone(tree)
		cross["/storage/local"]["SDN.Use"] = 0
		cases["T21 D5 plus SDN.Use on /storage/local"] = vcase{want: want, tree: data(mustJSON(t, cross)), paths: d5Paths(t, want, tree),
			pools: d5Pools, expect: ErrScopeTooWide, names: []string{"at /storage/local the token holds SDN.Use,"}, requests: 8}
	}
	{
		// The plan's original T21 fixture: VM.Allocate IS in the pool role,
		// so only the pool clause could confer it on /storage/local, which
		// is not a pool member and exists: too wide. Unresolved (Pool.Audit
		// not held), known limit 1 still accepts it.
		kl1 := clone(tree)
		kl1["/storage/local"]["VM.Allocate"] = 0
		local := data(`[{"storage":"local","type":"dir"},{"storage":"pveforge-harness","type":"zfspool"}]`)
		cases["T21b/P2 D5 plus VM.Allocate on a non-member, existing /storage/local"] = vcase{want: want, tree: data(mustJSON(t, kl1)), paths: d5Paths(t, want, tree),
			pools: d5Pools, storage: &local, expect: ErrScopeTooWide, names: []string{"at /storage/local the token holds VM.Allocate,"}, requests: 9}
		wantNA, kl1NA := d5WithoutPoolAudit(want, kl1)
		cases["T21b-fallback D5 without Pool.Audit plus VM.Allocate on /storage/local (known limit 1)"] = vcase{want: wantNA, tree: data(mustJSON(t, kl1NA)),
			paths: d5Paths(t, wantNA, kl1NA), expect: nil, requests: 5}
		// P3: Pool.Audit requested but absent from PVE's ?path= answer: no
		// resolution, no /pools read — and the missing privilege itself is
		// ErrWrongScope, never ErrScopeTooWide.
		noAudit := clone(kl1)
		delete(noAudit["/pool/pveforge-harness"], "Pool.Audit")
		cases["P3 Pool.Audit requested but not held: no /pools read"] = vcase{want: want, tree: data(mustJSON(t, kl1)),
			paths: d5Paths(t, want, noAudit), expect: ErrWrongScope, names: []string{"lacks [Pool.Audit]"}, requests: 5,
			check: func(t *testing.T, pr *permRouter) {
				if pr.count("pools:") != 0 {
					t.Errorf("requests = %v; want no /pools read", pr.reqs)
				}
			}}
	}
	{
		// G4 (c1): D5 at mint — the pool has no members yet, so nothing
		// needs resolving: byte-for-byte today's requests, no /pools read.
		g4 := clone(tree)
		for _, id := range []string{"690", "691", "692"} {
			delete(g4, "/vms/"+id)
		}
		cases["G4 D5 at mint, empty pool: no /pools request"] = vcase{want: want, tree: data(mustJSON(t, g4)), paths: d5Paths(t, want, g4), expect: nil, requests: 5,
			seq: []string{"tree", "path:/pool/pveforge-harness", "path:/sdn/zones/localnetwork/vmbr0", "path:/storage/local", "path:/storage/pveforge-harness"}}
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) { runVCase(t, tc) })
	}
}

// d5WithoutPoolAudit is D5 with Pool.Audit dropped from the pool role and
// from every path of tree: a pool grant membership is never resolved for.
func d5WithoutPoolAudit(want []Grant, tree map[string]map[string]int) ([]Grant, map[string]map[string]int) {
	out := make([]Grant, len(want))
	for i, g := range want {
		g.Privs = slices.DeleteFunc(slices.Clone(g.Privs), func(p string) bool { return p == "Pool.Audit" })
		out[i] = g
	}
	t := clone(tree)
	for _, set := range t {
		delete(set, "Pool.Audit")
	}
	return out, t
}

// d5MembersAns is GET /pools?poolid=pveforge-harness after the build, from
// pve-manager Pool.pm c7d5332's source, NOT live-captured.
var d5MembersAns = data(`[{"poolid":"pveforge-harness","comment":"pveforge nested harness (D5)","members":[` +
	`{"id":"qemu/690","node":"qa-pve-02","type":"qemu","vmid":690},` +
	`{"id":"qemu/691","node":"qa-pve-02","type":"qemu","vmid":691},` +
	`{"id":"qemu/692","node":"qa-pve-02","type":"qemu","vmid":692}]}]`)

// vmidTaken is PVE's /cluster/nextid answer for a vmid in use; vmidFreeAns
// its answer for a free one (the id itself).
func vmidTaken(n int) answer {
	return answer{http.StatusBadRequest, fmt.Sprintf(`{"errors":{"vmid":"VM %d already exists"},"data":null}`, n)}
}
func vmidFreeAns(n int) answer { return data(fmt.Sprintf(`"%d"`, n)) }

func liveTreeAt(t *testing.T, path string) map[string]int {
	t.Helper()
	var tree map[string]map[string]int
	if err := json.Unmarshal([]byte(liveTree(t)), &tree); err != nil {
		t.Fatal(err)
	}
	return tree[path]
}

func clone(tree map[string]map[string]int) map[string]map[string]int {
	out := make(map[string]map[string]int, len(tree))
	for p, set := range tree {
		out[p] = make(map[string]int, len(set))
		for k, v := range set {
			out[p][k] = v
		}
	}
	return out
}

// The D5 fixtures are what they claim: r3's pool role has 13 privileges,
// and the post-build tree is exactly the four grant paths plus the three
// members. A drifted fixture would make T11-T21 test something else.
func TestD5Fixtures(t *testing.T) {
	want, tree := d5(t)
	if len(want) != 4 || len(want[0].Privs) != 13 || want[0].Path != "/pool/pveforge-harness" {
		t.Fatalf("D5 grants = %+v", want)
	}
	var paths []string
	for p := range tree {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if got := strings.Join(paths, " "); got != "/pool/pveforge-harness /sdn/zones/localnetwork/vmbr0 /storage/local /storage/pveforge-harness /vms/690 /vms/691 /vms/692" {
		t.Fatalf("D5 tree paths = %s", got)
	}
	// D5's pinned files: r3's, with Datastore.Audit added to
	// ForgeHarnessSpace so the pool token can list the harness storage's
	// content (PVE drops volumes failing check_volume_access from /content).
	// Bootstrap's A-ACC generates its grants from the ACL rows and the roles.
	for name, want := range map[string]string{
		"d5r3-expected-acl-rows.json":        "54baf98e3212a3f07a6da631b45e0f950f5501794baee36e9a7afe7e81ad5d0d",
		"d5r3-expected-roles.json":           "5e29e48c43d246019b0588c7e2928bbd23b822aacd36b6ebc7ad2effb3a6869b",
		"d5r3-expected-tree-post-build.json": "3cc6724ff18af278311bd04cefe75cf657f178f77093d2c241c23dae528ead5b",
	} {
		b, err := os.ReadFile("testdata/permissions/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != want {
			t.Errorf("%s sha256 = %s, want %s", name, got, want)
		}
	}
}
