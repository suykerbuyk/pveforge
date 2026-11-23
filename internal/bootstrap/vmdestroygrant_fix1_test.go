package bootstrap

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// Fix round 1 of `acl enable-vm-destroy`: pool members, role-only, the roster
// token re-read under the lock, a leading '-', and fixtures for four mutants
// the first round's fake could not distinguish.

// fix1Cases extend T7's table (each row asserts the acl-modify count, a
// refusal writing nothing, the roster hash and INV-2 against the fake's
// independent port of PVE's role walk, which now includes pools).
func fix1Cases() []enableCase {
	row := func(f *grantFake, path, role string, prop bool) { f.addRow(path, role, "token", liveToken, prop) }
	return []enableCase{
		// ---- pool members (grok Finding 1, rejected on a proof the rows below make) ----
		{name: "pool: /vms/100 member, the token's pool role holds a privilege outside D: refused pre-write", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.pools["p1"] = fakePool{vms: []int{100}}
			f.setRole("PoolX", "Datastore.Audit")
			row(f, "/pool/p1", "PoolX", false)
			return f, liveToken
		}, wantErr: ErrUpgradeWouldNotConverge, contains: "/pool/p1"},
		{name: "pool: role inside D (VM.Audit) on a /vms/100 member: upgraded, /vms/100 predicted == actual", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.pools["p1"] = fakePool{vms: []int{100}}
			f.setRole("PoolOK", "VM.Audit")
			row(f, "/pool/p1", "PoolOK", false)
			return f, liveToken
		}, aclWrites: 1, outcome: EnableUpgraded},
		{name: "pool: no row of its own on /pool/p1 (it inherits / and so R): upgraded", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.pools["p1"] = fakePool{vms: []int{100, 101}}
			return f, liveToken
		}, aclWrites: 1, outcome: EnableUpgraded},
		{name: "pool: storage member /storage/local with a Datastore.Audit pool role: refused pre-write", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.pools["p2"] = fakePool{storage: []string{"local"}}
			f.setRole("StorOK", "Datastore.Audit")
			row(f, "/pool/p2", "StorOK", false)
			return f, liveToken
		}, wantErr: ErrUpgradeWouldNotConverge, contains: "/pool/p2"},
		{name: "pool: SDN vnet member with an SDN.Use pool role: refused pre-write", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.pools["p3"] = fakePool{vnets: []string{"localnetwork/vmbr0"}}
			f.setRole("NetUse", "SDN.Use")
			row(f, "/pool/p3", "NetUse", false)
			return f, liveToken
		}, wantErr: ErrUpgradeWouldNotConverge, contains: "/pool/p3"},
		{name: "pool: storage and vnet members with roles inside D: upgraded", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.pools["p2"] = fakePool{storage: []string{"local"}, vnets: []string{"localnetwork/vmbr0"}}
			f.setRole("PoolOK", "VM.Audit")
			row(f, "/pool/p2", "PoolOK", false)
			return f, liveToken
		}, aclWrites: 1, outcome: EnableUpgraded},

		// ---- fixtures for mutants MA, MC, MG (imp2 F4) ----
		{name: "MA: a propagate-0 ancestor row (/vms) does NOT block /vms/100 inheriting /: upgraded", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.setRole("VMOnly", vmAdmin23...)
			row(f, "/vms", "VMOnly", false)
			f.addRow("/vms/100", "PVEVMAdmin", "user", "bob@pve", false) // puts /vms/100 in the tree
			return f, liveToken
		}, aclWrites: 1, outcome: EnableUpgraded},
		{name: "MC: the owner holds the role with propagate 0: the token's flags are ANDed down, refused pre-write", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.acls = nil
			f.tokens["alice@pve!tok1"] = true
			f.setRole("OwnerRole", vmD...)
			f.addRow("/", "OwnerRole", "user", "alice@pve", false)
			f.addRow("/", "PVEVMAdmin", "token", "alice@pve!tok1", true)
			return f, "alice@pve!tok1"
		}, wantErr: ErrUpgradeWouldNotConverge, contains: "alice@pve"},
		{name: "MG: PVEVMAdmin@/ propagate 0 with a row on each other default path: the grant would newly propagate VM privileges", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.acls = nil
			f.setRole("VMOnly", vmAdmin23...)
			row(f, "/", "PVEVMAdmin", false)
			for _, p := range defaultTopPaths[1:] {
				row(f, p, "VMOnly", false)
			}
			return f, liveToken
		}, wantErr: ErrNotVMAdminToken, contains: "VM.Allocate"},
	}
}

// The pool claim, proved on the fake: a pool-member path where the token
// holds a pool role outside D is ALREADY in the token's pre-write tree (the
// token holds PVEVMAdmin there through / propagate 1, so the path is never
// empty), which is why the prediction sees it and refuses before any write.
func TestEnable_PoolMemberPathsArePresentBeforeTheWrite(t *testing.T) {
	f := newGrantFake()
	f.pools["p1"] = fakePool{vms: []int{100}, storage: []string{"local"}, vnets: []string{"localnetwork/vmbr0"}}
	f.setRole("PoolX", "Datastore.Audit", "SDN.Use")
	f.addRow("/pool/p1", "PoolX", "token", liveToken, false)
	before := f.effective(liveToken)
	for _, p := range []string{"/vms/100", "/storage/local", "/sdn/zones/localnetwork/vmbr0"} {
		set, ok := before[p]
		if !ok || len(set) == 0 {
			t.Fatalf("%s is absent from the pre-write tree: the rejection of the pool blocker would be wrong", p)
		}
		if _, held := set["VM.Allocate"]; !held {
			t.Errorf("%s: the token does not hold PVEVMAdmin there (the C1 premise): %v", p, set)
		}
	}
	// held at flag 0 (pool roles never propagate)
	if flag, held := before["/vms/100"]["Datastore.Audit"]; !held || flag {
		t.Fatalf("the pool role's privilege is not in /vms/100's pre-write set at flag 0: %v", before["/vms/100"])
	}
	// And a path absent pre-write cannot appear post-write for a token that
	// passes C1: with no pool role of its own the pool roles are the token's
	// roles on /pool/p1, inherited from / (PVEVMAdmin, then R): inside D.
	g := newGrantFake()
	g.pools["p1"] = fakePool{vms: []int{100}}
	pre := g.effective(liveToken)
	r := newEnableRun(t, g)
	if _, err := r.do(); err != nil {
		t.Fatal(err)
	}
	post := g.effective(liveToken)
	for p := range post {
		if _, ok := pre[p]; !ok {
			t.Errorf("%s is present after the grant and absent before it", p)
		}
	}
	if _, ok := post["/vms/100"]; !ok {
		t.Fatal("vacuous: /vms/100 is not in the post-write tree")
	}
}

// ---- imp2 F1: a role id that starts with '-' ----

func TestEnable_LeadingDashRoleRefusedBeforeAnyDial(t *testing.T) {
	for _, name := range []string{"-x", "--delete", "-", "--roles", "-ForgeX"} {
		f := newGrantFake()
		r := newEnableRun(t, f)
		r.req.Role = name
		_, err := r.do()
		if !errors.Is(err, ErrRoleName) || !strings.Contains(err.Error(), "'-'") {
			t.Errorf("%q: want ErrRoleName naming the dash, got %v", name, err)
		}
		if r.tr.reconnectCalls != 0 || len(f.commands) != 0 {
			t.Errorf("%q: the host was reached (dials %d, commands %q)", name, r.tr.reconnectCalls, f.commands)
		}
	}
	// The screen refuses it too, with matching argv: a screen that checked only
	// the argv shape would accept "--delete" as a role.
	for _, bad := range []enableParams{{role: "--delete", privs: vmD, tokenID: liveToken}, {role: "-x", privs: vmD, tokenID: liveToken}} {
		for _, argv := range [][]string{enableRoleArgv(bad), enableACLArgv(bad)} {
			if _, err := screenEnableArgv(argv, bad); err == nil {
				t.Errorf("screen accepted role %q: %q", bad.role, argv)
			}
		}
	}
	if err := checkVMDestroyRole("a-b"); err != nil {
		t.Errorf("an interior dash was refused: %v", err)
	}
}

// ---- imp2 F2: --role-only ----

func TestEnable_RoleOnlyNeverTouchesTheToken(t *testing.T) {
	// A rebuilt node: the roster still holds the old token record, PVE knows no
	// such token (no token, no ACL rows).
	rebuilt := func() *grantFake {
		f := newGrantFake()
		f.tokens = map[string]bool{}
		f.acls = nil
		return f
	}
	t.Run("without the flag the stale token is a token to upgrade, and is refused", func(t *testing.T) {
		f := rebuilt()
		_, err := newEnableRun(t, f).do()
		if !errors.Is(err, ErrNotVMAdminToken) || len(f.mutating()) != 0 {
			t.Fatalf("err %v, writes %q", err, f.mutating())
		}
	})
	t.Run("--role-only creates the role and the log holds no acl modify, no token read", func(t *testing.T) {
		f := rebuilt()
		r := newEnableRun(t, f)
		r.req.RoleOnly = true
		res, err := r.do()
		if err != nil {
			t.Fatal(err)
		}
		if res.Outcome != EnableRoleOnly || res.TokenID != "" || !res.RoleCreated {
			t.Fatalf("%+v", res)
		}
		if f.count(cmdRoleAdd) != 1 || f.count(cmdACLModify) != 0 || f.count("pveum user permissions") != 0 || f.count("pveum acl list") != 0 {
			t.Fatalf("log %q", f.commands)
		}
		if !slices.Equal(f.roles[DefaultVMDestroyRole], vmD) {
			t.Fatalf("role %v", f.roles[DefaultVMDestroyRole])
		}
	})
	t.Run("--role-only on a token that could be upgraded still only creates the role", func(t *testing.T) {
		f := newGrantFake()
		r := newEnableRun(t, f)
		r.req.RoleOnly = true
		if _, err := r.do(); err != nil {
			t.Fatal(err)
		}
		if f.count(cmdACLModify) != 0 || len(f.acls) != 1 {
			t.Fatalf("log %q acls %v", f.commands, f.acls)
		}
	})
	t.Run("--role-only does not compare the roster's token (it never uses it)", func(t *testing.T) {
		f := rebuilt()
		r := newEnableRun(t, f)
		r.req.RoleOnly = true
		r.own = "root@pam!something-else" // the run's token differs from the roster's
		if _, err := r.do(); err != nil {
			t.Fatalf("a role-only run refused over a token it never uses: %v", err)
		}
	})
}

// ---- imp2 F3: the roster's token id, re-read under the lock ----

func TestEnable_RosterTokenChangedWhileWaitingForTheLock(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, r *enableRun){
		"rotated to another id": func(t *testing.T, r *enableRun) {
			if err := roster.WriteTokenAuth(r.roster, "qa-pve-01", roster.TokenWrite{TokenID: "root@pam!rotated", SecretPlaintext: []byte("s")}, roster.NewPassphrase("roster-pass")); err != nil {
				t.Fatal(err)
			}
		},
		"cleared": func(t *testing.T, r *enableRun) {
			if err := roster.ClearTokenAuth(r.roster, "qa-pve-01"); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newGrantFake()
			r := newEnableRun(t, f)
			key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "bootstrap", ID: "token"}
			unlock, err := lock.Mutation(context.Background(), r.roster, key)
			if err != nil {
				t.Fatal(err)
			}
			var res *EnableVMDestroyResult
			var runErr error
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, runErr = r.do()
			}()
			time.Sleep(300 * time.Millisecond) // the verb is waiting on the lock
			if n := len(f.commands); n != 0 {
				t.Errorf("the verb touched the host (%d commands) while another holder had the lock", n)
			}
			change(t, r) // a bootstrap, holding the lock, rotates the token
			_ = unlock()
			wg.Wait()
			if !errors.Is(runErr, ErrTokenChangedUnderLock) || res != nil {
				t.Fatalf("want ErrTokenChangedUnderLock, got %+v, %v", res, runErr)
			}
			if len(f.commands) != 0 {
				t.Fatalf("the verb touched the host after refusing: %q", f.commands)
			}
			noVerdict(t, name, runErr)
		})
	}
	// Unchanged: the same token under the lock proceeds.
	f := newGrantFake()
	if _, err := newEnableRun(t, f).do(); err != nil {
		t.Fatalf("an unchanged token was refused: %v", err)
	}
	// A roster that gained a token the run did not know about is also a change.
	g := newGrantFake()
	r := newEnableRun(t, g)
	r.setOwn("")
	r.own = ""
	if err := roster.WriteTokenAuth(r.roster, "qa-pve-01", roster.TokenWrite{TokenID: liveToken, SecretPlaintext: []byte("s")}, roster.NewPassphrase("roster-pass")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.do(); !errors.Is(err, ErrTokenChangedUnderLock) {
		t.Fatalf("a token that appeared under the lock: want ErrTokenChangedUnderLock, got %v", err)
	}
}

// ---- imp2 F4: direct fixtures for the two comparison helpers ----

func TestEnable_WidenedByCountsAFlagGain(t *testing.T) {
	before := map[string]map[string]bool{"/": {"VM.Audit": false, "Sys.Audit": true}}
	after := map[string]map[string]bool{"/": {"VM.Audit": true, "Sys.Audit": true}}
	if got := widenedBy(before, after); !slices.Equal(got, []string{"VM.Audit"}) {
		t.Fatalf("a 0 -> 1 propagation gain is a widening: got %v", got)
	}
	if got := widenedBy(after, before); len(got) != 0 {
		t.Fatalf("losing propagation is not a widening: got %v", got)
	}
	if got := widenedBy(before, before); len(got) != 0 {
		t.Fatalf("no change: got %v", got)
	}
}

func TestEnable_TreeDiffSeesAPropagationDifference(t *testing.T) {
	a := map[string]map[string]bool{"/": {"VM.Audit": true}, "/vms": {}}
	p := map[string]map[string]bool{"/": {"VM.Audit": false}}
	d := treeDiff(a, p)
	if d == "" || !strings.Contains(d, "propagation") || !strings.Contains(d, "VM.Audit") {
		t.Fatalf("a flag-only difference must be reported: %q", d)
	}
	if d := treeDiff(map[string]map[string]bool{"/": {"A": true}, "/x": {}}, map[string]map[string]bool{"/": {"A": true}}); d != "" {
		t.Fatalf("an empty path is not a difference: %q", d)
	}
	if d := treeDiff(map[string]map[string]bool{"/": {"A": true}}, map[string]map[string]bool{"/": {"A": true, "B": true}}); d == "" {
		t.Fatal("a privilege only one side holds must be reported")
	}
}

// An own row on a path that is also a pool member, in a pool whose /pool/<id>
// roles the token inherits from /. After the grant, compile_acl_path adds the
// pool's roles (now PVEVMAdmin AND R) at flag 0 on that member path, so
// Sys.Audit appears there at flag 0 where the prediction (an override path is
// "unchanged") says nothing. The write is correct: the success condition after
// the write is the INVARIANT (the validator accepts the actual tree against
// /:R::1, and the widening is at most Sys.Audit), not prediction exactness. So
// the verb succeeds and notes the difference, naming the path, instead of
// telling the operator to delete a good grant. (Fix round 1 pinned the old
// behaviour here as a known gap; fix round 2 flips it.)
func TestEnable_OverrideRowOnAPoolMemberPathSucceedsWithANote(t *testing.T) {
	f := newGrantFake()
	f.pools["p1"] = fakePool{vms: []int{100}}
	f.setRole("VMOnly", vmAdmin23...)
	f.addRow("/vms/100", "VMOnly", "token", liveToken, false)
	before := f.effective(liveToken)
	if _, ok := before["/vms/100"]; !ok {
		t.Fatal("vacuous: /vms/100 is not in the pre-write tree")
	}
	r := newEnableRun(t, f)
	res, err := r.do()
	if err != nil {
		t.Fatalf("a correct grant was reported as an error: %v", err)
	}
	if res.Outcome != EnableUpgraded || f.count(cmdACLModify) != 1 || f.count("pveum acl delete") != 0 {
		t.Fatalf("outcome %q, log %q", res.Outcome, f.mutating())
	}
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "/vms/100") || !strings.Contains(res.Notes[0], "Sys.Audit") {
		t.Fatalf("want one informational note naming /vms/100 and Sys.Audit, got %q", res.Notes)
	}
	after := f.effective(liveToken)
	if flag, held := after["/vms/100"]["Sys.Audit"]; !held || flag {
		t.Fatalf("the fake no longer shows the flag-0 Sys.Audit gain on /vms/100: %v", after["/vms/100"])
	}
	if got := widenedBy(before, after); !slices.Equal(got, []string{"Sys.Audit"}) {
		t.Fatalf("widened by %v, want exactly [Sys.Audit]", got)
	}
	// ...and what the verb accepted is a tree bootstrap accepts too.
	if err := judgeAgainstRole(after, DefaultVMDestroyRole, vmD); err != nil {
		t.Fatalf("/:R::1 rejects the tree the verb accepted: %v", err)
	}
	noVerdict(t, "note", err)
}

// Half (2) of the post-write invariant on its own: a privilege INSIDE D that
// the token did not hold before appears somewhere in the window (an Empty role
// on /vms/100 is given VM.Allocate by a concurrent root editor). The validator
// half accepts it (D confers it); only the net-widening half sees it.
func TestEnable_InRunWindow_WideningInsideDIsStillRefused(t *testing.T) {
	f := newGrantFake()
	f.setRole(DefaultVMDestroyRole, vmD...)
	f.setRole("Empty")
	f.addRow("/vms/100", "Empty", "token", liveToken, false)
	if _, ok := f.effective(liveToken)["/vms/100"]; ok {
		t.Fatal("vacuous: /vms/100 already holds something before the grant")
	}
	f.before = func(cmd string) {
		if strings.HasPrefix(cmd, cmdACLModify+" ") {
			f.setRole("Empty", "VM.Allocate")
		}
	}
	_, err := newEnableRun(t, f).do()
	if !errors.Is(err, ErrPostWriteInvariant) || !strings.Contains(err.Error(), "VM.Allocate") || !strings.Contains(err.Error(), "pveum acl delete") {
		t.Fatalf("want ErrPostWriteInvariant naming VM.Allocate and the repair, got %v", err)
	}
	if f.count("pveum acl delete") != 0 {
		t.Fatal("the verb deleted an ACL")
	}
	noVerdict(t, "inside D", err)
}

// vm destroy's status read needs Sys.Audit at /nodes/<node>. A token with its
// own override row on a node path is not reached by the new role there: the
// upgrade succeeds (the grant is correct), but a note names the path and
// points at doctor. No refusal, no extra write.
func TestEnable_NoteWhereSysAuditIsNotEffectiveOnANodePath(t *testing.T) {
	f := newGrantFake()
	f.setRole("VMOnly", vmAdmin23...)
	f.addRow("/nodes/pve1", "VMOnly", "token", liveToken, false)
	if _, ok := f.effective(liveToken)["/nodes/pve1"]; !ok {
		t.Fatal("vacuous: /nodes/pve1 is not in the pre-write tree")
	}
	r := newEnableRun(t, f)
	res, err := r.do()
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != EnableUpgraded || f.count(cmdACLModify) != 1 || len(f.mutating()) != 2 {
		t.Fatalf("outcome %q, writes %q: the note must not add a write or a refusal", res.Outcome, f.mutating())
	}
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "[/nodes/pve1]") || !strings.Contains(res.Notes[0], "pveforge doctor qa-pve-01") || !strings.Contains(res.Notes[0], "vm destroy will refuse") {
		t.Fatalf("want one note naming /nodes/pve1 and doctor, got %q", res.Notes)
	}
	// The same fact, STRUCTURED: callers never match the note's text.
	if len(res.AuditNotEffective) != 1 || res.AuditNotEffective[0] != "/nodes/pve1" {
		t.Fatalf("AuditNotEffective = %q, want [/nodes/pve1]", res.AuditNotEffective)
	}
	// Path B (nothing overrides the node paths) carries no such note.
	g := newGrantFake()
	res, err = newEnableRun(t, g).do()
	if err != nil || len(res.Notes) != 0 || len(res.AuditNotEffective) != 0 {
		t.Fatalf("path B: %+v, %v", res, err)
	}
	if got := nodePathsLackingAudit(map[string]map[string]bool{"/nodes": {"Sys.Audit": false}, "/nodes/a": {"VM.Audit": true}, "/vms": {}}); len(got) != 1 || got[0] != "/nodes/a" {
		t.Fatalf("nodePathsLackingAudit = %v (a flag-0 Sys.Audit counts as held; non-node paths are ignored)", got)
	}
}
