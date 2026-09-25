package pve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// pveforge-validator-pool-membership. Fixtures are source-derived:
// pve-manager Pool.pm c7d5332 (GET /pools?poolid=), pve-storage Config.pm
// (GET /storage) and /cluster/nextid — NOT live-captured.

// poolAns is GET /pools?poolid=p listing members (raw JSON objects).
func poolAns(poolid string, members ...string) answer {
	return data(`[{"poolid":"` + poolid + `","members":[` + strings.Join(members, ",") + `]}]`)
}

func vmMember(n int) string {
	return fmt.Sprintf(`{"id":"qemu/%d","node":"n1","type":"qemu","vmid":%d}`, n, n)
}

func stMember(id string) string {
	return fmt.Sprintf(`{"id":"storage/n1/%s","node":"n1","type":"storage","storage":"%s"}`, id, id)
}

// poolRow is a resolvable pool grant on /pool/p (Pool.Audit held) over
// tree, which always holds /pool/p itself.
func poolRow(tree string) vcase {
	return vcase{
		want:  []Grant{pin("/pool/p", false, "Pool.Audit", "VM.Audit")},
		tree:  data(`{"/pool/p":{"Pool.Audit":0,"VM.Audit":0}` + tree + `}`),
		paths: map[string]answer{"/pool/p": pathAns("/pool/p", `{"Pool.Audit":0,"VM.Audit":0}`)},
	}
}

func TestValidateTokenGrants_PoolMembership(t *testing.T) {
	resolved := []string{"tree", "path:/pool/p", "pools:p", "tree", "pools:p"}
	cases := map[string]vcase{}

	r := poolRow(`,"/vms/100":{"VM.Audit":0},"/vms/777":{"VM.Audit":0}`)
	r.pools = map[string][]answer{"p": {poolAns("p", vmMember(100))}}
	r.nextid = map[string]answer{"777": vmidTaken(777)}
	r.expect, r.names, r.seq = ErrScopeTooWide, []string{"at /vms/777 the token holds VM.Audit,"}, append(resolved, "nextid:777")
	r.requests = 6
	cases["P1 a direct 0-flag grant on a non-member, existing VM"] = r

	r = poolRow(`,"/storage/sx":{"VM.Audit":0}`)
	r.pools = map[string][]answer{"p": {poolAns("p", stMember("s1"))}}
	withSX := data(`[{"storage":"s1","type":"dir"},{"storage":"sx","type":"dir"}]`)
	r.storage = &withSX
	r.expect, r.names, r.requests = ErrScopeTooWide, []string{"at /storage/sx the token holds VM.Audit,"}, 6
	cases["P2 a direct 0-flag grant on a non-member, existing storage"] = r

	r = poolRow(`,"/storage/s1":{"VM.Audit":0},"/vms/100":{"VM.Audit":0}`)
	r.pools = map[string][]answer{"p": {poolAns("p", vmMember(100), stMember("s1"))}}
	r.expect, r.requests, r.seq = nil, 5, resolved
	cases["P0s a guest and a storage member"] = r

	cases["P4 a propagating pool grant stays on the fallback (known limit 1)"] = vcase{
		want:   []Grant{pin("/pool/p", true, "Pool.Audit", "VM.Audit")},
		tree:   data(`{"/pool/p":{"Pool.Audit":1,"VM.Audit":1},"/vms/777":{"VM.Audit":0}}`),
		paths:  map[string]answer{"/pool/p": pathAns("/pool/p", `{"Pool.Audit":1,"VM.Audit":1}`)},
		expect: nil, requests: 2, seq: []string{"tree", "path:/pool/p"},
	}

	for name, a := range map[string]answer{
		"403":                {http.StatusForbidden, "raw\nbody line two\x1b" + strings.Repeat("x", 5000)},
		"401":                {http.StatusUnauthorized, `{"data":null}`},
		"500":                {http.StatusInternalServerError, `{"errors":"boom"}`},
		"null":               data(`null`),
		"empty list":         data(`[]`),
		"two entries":        data(`[{"poolid":"p","members":[]},{"poolid":"p","members":[]}]`),
		"another poolid":     data(`[{"poolid":"q","members":[]}]`),
		"members absent":     data(`[{"poolid":"p"}]`),
		"members null":       data(`[{"poolid":"p","members":null}]`),
		"a null member":      data(`[{"poolid":"p","members":[null]}]`),
		"an unknown type":    data(`[{"poolid":"p","members":[{"type":"sdn","id":"x"}]}]`),
		"vmid 0":             data(`[{"poolid":"p","members":[{"type":"qemu","vmid":0}]}]`),
		"vmid a string":      data(`[{"poolid":"p","members":[{"type":"qemu","vmid":"100"}]}]`),
		"vmid fractional":    data(`[{"poolid":"p","members":[{"type":"qemu","vmid":100.5}]}]`),
		"a bad storage id":   data(`[{"poolid":"p","members":[{"type":"storage","storage":"-x"}]}]`),
		"storage id missing": data(`[{"poolid":"p","members":[{"type":"storage"}]}]`),
	} {
		r = poolRow(`,"/vms/100":{"VM.Audit":0}`)
		r.pools = map[string][]answer{"p": {a}}
		r.expect, r.requests = ErrUnverifiableRead, 3
		cases["P5 members read: "+name] = r
	}

	r = poolRow(`,"/vms/100":{"VM.Audit":0},"/vms/101":{"VM.Audit":0}`)
	r.pools = map[string][]answer{"p": {poolAns("p", vmMember(100)), poolAns("p", vmMember(101))}}
	r.expect, r.requests, r.seq = nil, 5, resolved
	cases["P6 a member in only one of the two reads"] = r

	cases["P7 a propagating grant at exactly /pool confers on members"] = vcase{
		want:   []Grant{pin("/pool", true, "VM.Audit")},
		tree:   data(`{"/pool":{"VM.Audit":1},"/vms/100":{"VM.Audit":0}}`),
		paths:  map[string]answer{"/pool": pathAns("/pool", `{"VM.Audit":1}`)},
		expect: nil, requests: 2,
	}

	r = poolRow(`,"/vms/100":{"VM.Audit":0},"/vms/777":{"VM.Audit":0}`)
	r.pools = map[string][]answer{"p": {poolAns("p", vmMember(100))}}
	r.nextid = map[string]answer{"777": vmidFreeAns(777)}
	r.expect, r.names, r.requests = ErrUnverifiableRead, []string{"/vms/777", "orphaned pool entry"}, 6
	cases["P9 a non-member VM absent from the cluster: no verdict"] = r

	r = poolRow(`,"/storage/sy":{"VM.Audit":0}`)
	r.pools = map[string][]answer{"p": {poolAns("p", vmMember(100))}}
	withoutSY := data(`[{"storage":"s1","type":"dir"}]`)
	r.storage = &withoutSY
	r.expect, r.names, r.requests = ErrUnverifiableRead, []string{"/storage/sy"}, 6
	cases["P9s a non-member storage not in the storage list: no verdict"] = r

	// c4: a definite ErrScopeTooWide on a later path wins over an earlier
	// path that could not be settled.
	r = poolRow(`,"/vms/777":{"VM.Audit":0},"/vms/888":{"VM.Audit":0}`)
	r.pools = map[string][]answer{"p": {poolAns("p")}}
	r.nextid = map[string]answer{"777": vmidFreeAns(777), "888": vmidTaken(888)}
	r.expect, r.names, r.requests = ErrScopeTooWide, []string{"at /vms/888"}, 7
	r.seq = append(resolved, "nextid:777", "nextid:888")
	cases["C4 an orphan then an existing non-member: the verdict wins"] = r

	// b1: every existence-read failure is flattened, never a verdict — a
	// 401/403 above all, and its body is never carried.
	for name, a := range map[string]answer{
		"403":  {http.StatusForbidden, "raw\nbody line two\x1b" + strings.Repeat("x", 5000)},
		"401":  {http.StatusUnauthorized, `{"data":null}`},
		"500":  {http.StatusInternalServerError, `{"errors":"boom"}`},
		"null": data(`null`),
	} {
		r = poolRow(`,"/vms/777":{"VM.Audit":0}`)
		r.pools = map[string][]answer{"p": {poolAns("p")}}
		r.nextid = map[string]answer{"777": a}
		r.expect, r.names, r.requests = ErrUnverifiableRead, []string{"/vms/777"}, 6
		cases["B1 existence check (nextid): "+name] = r

		r = poolRow(`,"/storage/sy":{"VM.Audit":0}`)
		r.pools = map[string][]answer{"p": {poolAns("p")}}
		st := a
		r.storage = &st
		r.expect, r.names, r.requests = ErrUnverifiableRead, []string{"/storage/sy"}, 6
		cases["B1 existence check (storage list): "+name] = r
	}

	// The resolution's own reads failing, each classified as the same read
	// is elsewhere: the ?path= read and the tree read as today (a 403 is a
	// verdict, as it is on the first read), a members read flattened.
	r = poolRow(`,"/vms/100":{"VM.Audit":0}`)
	r.paths = map[string]answer{"/pool/p": {http.StatusForbidden, `{"data":null}`}}
	r.expect, r.requests = ErrNotAuthorized, 2
	cases["R1 the early ?path= read refused"] = r

	r = poolRow(`,"/vms/100":{"VM.Audit":0}`)
	r.pools = map[string][]answer{"p": {poolAns("p", vmMember(100))}}
	r.trees = []answer{{http.StatusInternalServerError, `{"errors":"boom"}`}}
	r.expect, r.requests = ErrUnverifiableRead, 4
	cases["R2 the second tree read fails: no verdict"] = r

	// Ruling on finding 4: the first tree read succeeded, so a 401/403 on the
	// second is transient or a change in flight — never ErrNotAuthorized.
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		r = poolRow(`,"/vms/100":{"VM.Audit":0}`)
		r.pools = map[string][]answer{"p": {poolAns("p", vmMember(100))}}
		r.trees = []answer{{code, "raw\nbody line two\x1b" + strings.Repeat("x", 5000)}}
		r.expect, r.names, r.requests = ErrUnverifiableRead, []string{fmt.Sprintf("PVE answered HTTP %d", code)}, 4
		cases[fmt.Sprintf("R2b the second tree read refused (%d): no verdict", code)] = r
	}
	r = poolRow(`,"/vms/100":{"VM.Audit":0}`)
	r.pools = map[string][]answer{"p": {poolAns("p", vmMember(100))}}
	r.trees = []answer{data(`{"/pool/p":{"A":2}}`)}
	r.expect, r.requests = ErrUnverifiableRead, 4
	cases["R2c the second tree read does not decode: no verdict"] = r

	r = poolRow(`,"/vms/100":{"VM.Audit":0}`)
	r.pools = map[string][]answer{"p": {poolAns("p", vmMember(100))}}
	r.trees = []answer{data(`{}`)}
	r.expect, r.names, r.requests = ErrUnverifiableRead, []string{"second read"}, 4
	cases["R3 the second tree read is empty: no verdict"] = r

	r = poolRow(`,"/vms/100":{"VM.Audit":0}`)
	r.pools = map[string][]answer{"p": {poolAns("p", vmMember(100)), {http.StatusForbidden, `{"data":null}`}}}
	r.expect, r.requests = ErrUnverifiableRead, 5
	cases["R4 the second members read refused"] = r

	r = poolRow(`,"/vms/100":{"VM.Audit":0}`)
	r.pools = map[string][]answer{"p": {data(`[{"poolid":"p","members":[{"vmid":100}]}]`)}}
	r.expect, r.requests = ErrUnverifiableRead, 3
	cases["P5 members read: a member without a type"] = r

	r = poolRow(`,"/vms/777":{"VM.Audit":0}`)
	r.pools = map[string][]answer{"p": {poolAns("p")}}
	badList := data(`[{"storage":"s1"},{"type":"dir"}]`)
	r.storage = &badList
	r.tree = data(`{"/pool/p":{"Pool.Audit":0,"VM.Audit":0},"/storage/sy":{"VM.Audit":0}}`)
	r.expect, r.names, r.requests = ErrUnverifiableRead, []string{"/storage/sy"}, 6
	cases["B1 existence check (storage list): an entry without a storage id"] = r

	// A storage path whose id PVE could never have issued: no check can be
	// made, so no verdict.
	r = poolRow(`,"/storage/x":{"VM.Audit":0}`)
	r.pools = map[string][]answer{"p": {poolAns("p")}}
	r.expect, r.names, r.requests = ErrUnverifiableRead, []string{"/storage/x", "not a guest or storage path"}, 5
	cases["P9x a non-member path that is not a valid guest or storage id"] = r

	// A propagate-0 grant at exactly /pool confers nothing on pool members:
	// PVE derives a member's pool roles from roles("/pool/<x>"), which
	// inherits a /pool grant only when it propagates.
	cases["P7b a propagate-0 grant at exactly /pool does not confer on members"] = vcase{
		want:   []Grant{pin("/pool", false, "VM.Audit")},
		tree:   data(`{"/pool":{"VM.Audit":0},"/vms/100":{"VM.Audit":0}}`),
		paths:  map[string]answer{"/pool": pathAns("/pool", `{"VM.Audit":0}`)},
		expect: ErrScopeTooWide, names: []string{"at /vms/100 the token holds VM.Audit,"}, requests: 2,
	}

	// Pool.Audit held on the pool but not requested: the grant is not
	// resolvable, so the unresolved pool clause stands and /pools is never
	// read — even though PVE's ?path= answer shows Pool.Audit.
	cases["P3b Pool.Audit held but not requested: the fallback, no /pools read"] = vcase{
		want:   []Grant{pin("/pool/p", false, "VM.Audit")},
		tree:   data(`{"/pool/p":{"VM.Audit":0},"/vms/777":{"VM.Audit":0}}`),
		paths:  map[string]answer{"/pool/p": pathAns("/pool/p", `{"Pool.Audit":0,"VM.Audit":0}`)},
		expect: nil, requests: 2, seq: []string{"tree", "path:/pool/p"},
	}

	// A guest path that is not canonical (/vms/0690) is no vmid PVE issues:
	// no existence check is made, and no verdict is given.
	r = poolRow(`,"/vms/0690":{"VM.Audit":0}`)
	r.pools = map[string][]answer{"p": {poolAns("p")}}
	r.expect, r.names, r.requests = ErrUnverifiableRead, []string{"/vms/0690", "not a guest or storage path"}, 5
	r.seq = resolved
	cases["P9v a non-canonical guest path: no existence check"] = r

	// The storage list is read once, however many storage paths need it.
	r = poolRow(`,"/storage/sa":{"VM.Audit":0},"/storage/sb":{"VM.Audit":0}`)
	r.pools = map[string][]answer{"p": {poolAns("p")}}
	oneList := data(`[{"storage":"s1","type":"dir"}]`)
	r.storage = &oneList
	r.expect, r.names, r.requests = ErrUnverifiableRead, []string{"/storage/sa"}, 6
	r.seq = append(resolved, "storage")
	cases["P9c two storage paths, one storage list read"] = r

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) { runVCase(t, tc) })
	}
}

// The rows above check errors.Is(err, ErrUnverifiableRead) and no
// ErrNoGrants/ErrWrongScope/ErrScopeTooWide; this pins, on the same
// fixtures, that ErrNotAuthorized is not in the chain either — the b1
// property bootstrap's isVerdict depends on.
func TestValidatePool_NeverAVerdict(t *testing.T) {
	for name, tc := range map[string]vcase{
		"members 403": func() vcase {
			r := poolRow(`,"/vms/100":{"VM.Audit":0}`)
			r.pools = map[string][]answer{"p": {{http.StatusForbidden, `{"data":null}`}}}
			return r
		}(),
		"members 401": func() vcase {
			r := poolRow(`,"/vms/100":{"VM.Audit":0}`)
			r.pools = map[string][]answer{"p": {{http.StatusUnauthorized, `{"data":null}`}}}
			return r
		}(),
		"nextid 403": func() vcase {
			r := poolRow(`,"/vms/777":{"VM.Audit":0}`)
			r.pools = map[string][]answer{"p": {poolAns("p")}}
			r.nextid = map[string]answer{"777": {http.StatusForbidden, `{"data":null}`}}
			return r
		}(),
		"storage 403": func() vcase {
			r := poolRow(`,"/storage/sy":{"VM.Audit":0}`)
			r.pools = map[string][]answer{"p": {poolAns("p")}}
			a := answer{http.StatusForbidden, `{"data":null}`}
			r.storage = &a
			return r
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			pr := &permRouter{t: t, tree: tc.tree, paths: tc.paths, pools: tc.pools, nextid: tc.nextid, storage: tc.storage}
			err := ValidateTokenGrants(context.Background(), testClient(t, newFakeAPIServer(t, pr.serve)), tc.want)
			if !errors.Is(err, ErrUnverifiableRead) {
				t.Fatalf("want ErrUnverifiableRead, got %v", err)
			}
			for _, v := range []error{ErrNotAuthorized, ErrScopeTooWide, ErrWrongScope, ErrNoGrants} {
				if errors.Is(err, v) {
					t.Errorf("the error carries the verdict %v: %v", v, err)
				}
			}
			if !strings.Contains(err.Error(), "PVE answered HTTP 40") {
				t.Errorf("want the status named, got %v", err)
			}
		})
	}
}

// unverifiable never wraps its cause: a wrapped ErrNotAuthorized, or any
// sentinel, is gone from the chain; the text is one bounded line.
func TestUnverifiable_NeverWraps(t *testing.T) {
	for _, cause := range []error{
		fmt.Errorf("read: %w", ErrNotAuthorized),
		fmt.Errorf("read: %w", ErrScopeTooWide),
		errors.New("line one\nline two " + strings.Repeat("é", 400)),
		errors.New("x" + strings.Repeat("é", 400)), // a cut inside a rune backs off
	} {
		err := unverifiable("read x", cause)
		if !errors.Is(err, ErrUnverifiableRead) || errors.Is(err, ErrNotAuthorized) || errors.Is(err, ErrScopeTooWide) || errors.Unwrap(errors.Unwrap(err)) != nil {
			t.Errorf("unverifiable(%q) = %v: want ErrUnverifiableRead only", cause, err)
		}
		if strings.ContainsAny(err.Error(), "\n\r") || len(err.Error()) > 400 {
			t.Errorf("not one bounded line: %q", err.Error())
		}
	}
}

// P8: a privilege held at 0 is held (pool-derived privileges carry 0).
func TestDecodePrivSet_ZeroIsHeld(t *testing.T) {
	set, err := decodePrivSet([]byte(`{"A":0,"B":false,"C":1}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"A", "B", "C"} {
		if _, ok := set[p]; !ok {
			t.Errorf("%s dropped from %v", p, set)
		}
	}
	if set["A"] || !set["C"] {
		t.Errorf("flags wrong: %v", set)
	}
}

// PoolMembers' paths: /vms/<n> for every guest type, /storage/<id> for a
// storage; extra fields allowed; an empty pool is an empty (non-nil) set.
func TestDecodePoolMembers(t *testing.T) {
	got, err := decodePoolMembers([]byte(`[{"poolid":"p","comment":"c","members":[`+
		`{"type":"qemu","vmid":100,"id":"qemu/100","extra":1},{"type":"lxc","vmid":200},{"type":"openvz","vmid":300},{"type":"storage","storage":"nfs.a-1"}]}]`), "p")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/storage/nfs.a-1", "/vms/100", "/vms/200", "/vms/300"}
	if keys := sortedKeys(got); strings.Join(keys, " ") != strings.Join(want, " ") {
		t.Errorf("members = %v, want %v", keys, want)
	}
	if empty, err := decodePoolMembers([]byte(`[{"poolid":"p","members":[]}]`), "p"); err != nil || empty == nil || len(empty) != 0 {
		t.Errorf("an empty pool = %v, %v; want an empty set", empty, err)
	}
	for _, id := range []string{"a", "-a", "a-", "1a", "a b"} {
		if _, err := decodePoolMembers([]byte(`[{"poolid":"p","members":[{"type":"storage","storage":"`+id+`"}]}]`), "p"); !errors.Is(err, ErrUnverifiableRead) {
			t.Errorf("storage id %q accepted", id)
		}
	}
}
