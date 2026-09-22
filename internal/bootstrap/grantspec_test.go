package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// ---- U-A: explicit, repeatable grants; bootstrap fails closed ----

// dirEntries lists the names in the roster's directory (the lock lives
// beside the roster).
func dirEntries(t *testing.T, rosterPath string) []string {
	t.Helper()
	es, err := os.ReadDir(filepath.Dir(rosterPath))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// A-T1: no grant at all is refused before the roster is written, the lock
// is taken or SSH is touched. Not a verdict.
func TestRun_AT1_NoGrantFailsClosed(t *testing.T) {
	path := newTestRoster(t, "")
	opts := baseOptions(path)
	opts.Grants = nil // explicitly: baseOptions carries today's grant
	before, entries := rosterBytes(t, path), dirEntries(t, path)
	tr := &fakeTransport{installFingerprint: "SHA256:abc", session: &fakeSession{}}
	v := &fakeValidator{}
	res, err := Run(context.Background(), opts, tr, v)
	if !errors.Is(err, ErrInvalidGrant) || res != nil || isVerdict(err) {
		t.Fatalf("want ErrInvalidGrant and no result, got %+v, %v", res, err)
	}
	if tr.installCalls+tr.dialCalls+tr.reconnectCalls != 0 || len(tr.session.attempted) != 0 || v.calls != 0 {
		t.Fatal("SSH or the API was touched")
	}
	if !reflect.DeepEqual(rosterBytes(t, path), before) || !reflect.DeepEqual(dirEntries(t, path), entries) {
		t.Fatalf("the roster or its directory changed (a lock was taken?): %v -> %v", entries, dirEntries(t, path))
	}
}

// A-T1b: the grant check runs before validateOptions (the observable part
// of "first"; defaultHostNodeFromRoster swallows its errors).
func TestRun_AT1b_GrantCheckedBeforeOptions(t *testing.T) {
	opts := baseOptions(newTestRoster(t, ""))
	opts.Grants = nil
	opts.Host = ""
	_, err := Run(context.Background(), opts, &fakeTransport{session: &fakeSession{}}, &fakeValidator{})
	if !errors.Is(err, ErrInvalidGrant) || strings.Contains(err.Error(), "host is required") {
		t.Fatalf("want ErrInvalidGrant before the host check, got %v", err)
	}
}

// threeRoles answers pveum role list for the A-T2/A-T4 grants.
const threeRoles = `[{"privs":"A","roleid":"R1","special":0},{"privs":"B","roleid":"R2","special":0},{"privs":"C","roleid":"R3","special":0}]`

func mustParse(t *testing.T, specs ...string) []Grant {
	t.Helper()
	g, err := ParseGrants(specs)
	if err != nil {
		t.Fatalf("ParseGrants(%q): %v", specs, err)
	}
	return g
}

func aclCommands(s *fakeSession) []string {
	var out []string
	for _, c := range s.commands {
		if strings.HasPrefix(c, "pveum acl modify") {
			out = append(out, c)
		}
	}
	return out
}

// A-T2: several grants, mixed propagate and pinning, are issued exactly, in
// order, and validated as that same list; the surviving token reports them.
func TestRun_AT2_SeveralGrantsIssuedExactly(t *testing.T) {
	opts := baseOptions(newTestRoster(t, ""))
	opts.Grants = mustParse(t, "/pool/p:R1", "/storage/s:R2:B:1", "/sdn/zones/z:R3::0")
	session := &fakeSession{byCmd: map[string]fakeRunResult{"pveum role list": {res: RunResult{Stdout: threeRoles}}}}
	v := &fakeValidator{}
	res, err := Run(context.Background(), opts, &fakeTransport{installFingerprint: "SHA256:abc", session: session}, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	wantCmds := []string{
		"pveum acl modify '/pool/p' --tokens 'root@pam!pveforge' --roles 'R1' --propagate 0",
		"pveum acl modify '/storage/s' --tokens 'root@pam!pveforge' --roles 'R2' --propagate 1",
		"pveum acl modify '/sdn/zones/z' --tokens 'root@pam!pveforge' --roles 'R3' --propagate 0",
	}
	if got := aclCommands(session); !reflect.DeepEqual(got, wantCmds) {
		t.Fatalf("acl commands = %q", got)
	}
	want := []Grant{
		{Path: "/pool/p", Role: "R1"},
		{Path: "/storage/s", Role: "R2", Propagate: true, Privs: []string{"B"}},
		{Path: "/sdn/zones/z", Role: "R3"},
	}
	if len(v.wants) != 1 || !reflect.DeepEqual(v.wants[0], want) {
		t.Fatalf("wants = %#v", v.wants)
	}
	if res.TokenOutcome != OutcomeMinted || !reflect.DeepEqual(res.Grants, want) {
		t.Fatalf("result = %+v", res)
	}
}

// A-T3: propagate defaults to 0, on the wire and in the validated want.
func TestRun_AT3_PropagateDefaultsToZero(t *testing.T) {
	opts := baseOptions(newTestRoster(t, ""))
	opts.Grants = mustParse(t, "/pool/p:R1")
	session := &fakeSession{byCmd: map[string]fakeRunResult{"pveum role list": {res: RunResult{Stdout: threeRoles}}}}
	v := &fakeValidator{}
	if _, err := Run(context.Background(), opts, &fakeTransport{installFingerprint: "SHA256:abc", session: session}, v); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := aclCommands(session); len(got) != 1 || !strings.HasSuffix(got[0], " --propagate 0") {
		t.Fatalf("acl commands = %q", got)
	}
	if v.wants[0][0].Propagate {
		t.Fatal("the validated want propagates")
	}
}

// A-T4: the normalized path reaches the wire, the validator and the
// result, from a raw grant path (MG7, MG16).
func TestRun_AT4_NormalizedPathEverywhere(t *testing.T) {
	opts := baseOptions(newTestRoster(t, ""))
	opts.Grants = []Grant{{Path: "//pool//p/", Role: "R1"}}
	session := &fakeSession{byCmd: map[string]fakeRunResult{"pveum role list": {res: RunResult{Stdout: threeRoles}}}}
	v := &fakeValidator{}
	res, err := Run(context.Background(), opts, &fakeTransport{installFingerprint: "SHA256:abc", session: session}, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := aclCommands(session); len(got) != 1 || !strings.HasPrefix(got[0], "pveum acl modify '/pool/p' ") {
		t.Fatalf("acl commands = %q", got)
	}
	if v.wants[0][0].Path != "/pool/p" || len(res.Grants) != 1 || res.Grants[0].Path != "/pool/p" {
		t.Fatalf("wants = %#v, result grants = %#v", v.wants, res.Grants)
	}
}

// A-T5 / A-T4b: the --grant parser.
func TestParseGrants_AT5(t *testing.T) {
	thirteen := "Pool.Audit,VM.Allocate,VM.Audit,VM.Config.CDROM,VM.Config.CPU,VM.Config.Cloudinit,VM.Config.Disk,VM.Config.HWType,VM.Config.Memory,VM.Config.Network,VM.Config.Options,VM.PowerMgmt,VM.Snapshot"
	for spec, want := range map[string]Grant{
		"/pool/p:R":              {Path: "/pool/p", Role: "R"},
		"/pool/p:R:A,B":          {Path: "/pool/p", Role: "R", Privs: []string{"A", "B"}},
		"/pool/p:R::1":           {Path: "/pool/p", Role: "R", Propagate: true},
		"/pool/p:R::0":           {Path: "/pool/p", Role: "R"},
		"/pool/p:R:A:1":          {Path: "/pool/p", Role: "R", Privs: []string{"A"}, Propagate: true},
		"/:R:" + thirteen + ":0": {Path: "/", Role: "R", Privs: strings.Split(thirteen, ",")},
		"pool/p/:R":              {Path: "/pool/p", Role: "R"},
	} {
		got, err := ParseGrants([]string{spec})
		if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], want) {
			t.Errorf("ParseGrants(%q) = %#v, %v; want %#v", spec, got, err, want)
		}
		if err == nil && got[0].Privs == nil && want.Privs != nil || err == nil && want.Privs == nil && got[0].Privs != nil {
			t.Errorf("%q: pinned/unpinned confused: %#v", spec, got[0].Privs)
		}
	}
	for spec, sentinel := range map[string]error{
		"/pool/p":            ErrInvalidGrant,
		"/pool/p:R:A:1:x":    ErrInvalidGrant,
		":R":                 ErrInvalidGrant,
		"/pool/p:":           ErrInvalidGrant,
		"/pool/p:R:A:2":      ErrInvalidGrant,
		"/pool/p:R:A:yes":    ErrInvalidGrant,
		"/pool/p:R:A:true":   ErrInvalidGrant,
		"/pool/p:R::":        ErrInvalidGrant, // an empty 4th field is refused, not 0
		"/pool/p:R:A,,B":     ErrInvalidGrant,
		"/pool/p:R:A,A":      ErrInvalidGrant,
		"/pool/p:R:A B":      ErrInvalidGrant,
		"/pool/p:bad role":   ErrInvalidGrant,
		"/foo:R":             ErrInvalidACLPath, // R6h's rows: PVE's check_path whitelist
		"0:R":                ErrInvalidACLPath,
		"/vms/99:R":          ErrInvalidACLPath,
		"/pool/p\nx:R":       ErrInvalidACLPath,
		"/storage/a;b:R::1":  ErrInvalidACLPath,
		"/pool/a/b/c/d:R::0": ErrInvalidACLPath,
	} {
		_, err := ParseGrants([]string{spec})
		if !errors.Is(err, sentinel) || strings.ContainsAny(err.Error(), "\n\r") {
			t.Errorf("ParseGrants(%q): want %v on one line, got %v", spec, sentinel, err)
		}
	}
	for _, p := range []string{"0", "1"} {
		_, err := ParseGrants([]string{"/pool/p:R:" + p})
		if !errors.Is(err, ErrInvalidGrant) || !strings.Contains(err.Error(), "use PATH:ROLE::"+p) {
			t.Errorf("/pool/p:R:%s: want the propagate hint, got %v", p, err)
		}
	}
	// The hint never misfires on a real privilege.
	if _, err := ParseGrants([]string{"/pool/p:R:A1"}); err != nil {
		t.Errorf("/pool/p:R:A1: %v", err)
	}
	// No spec at all: the fail-closed hint, from ParseGrants itself.
	for _, specs := range [][]string{nil, {}} {
		_, err := ParseGrants(specs)
		if !errors.Is(err, ErrInvalidGrant) || !strings.Contains(err.Error(), "requires at least one --grant PATH:ROLE[:PRIVS[:PROPAGATE]]") {
			t.Errorf("ParseGrants(%#v): want the hint, got %v", specs, err)
		}
	}
}

// A-T5b: two specs that normalize to one path are refused before SSH.
func TestAT5b_DuplicateAfterNormalization(t *testing.T) {
	if _, err := ParseGrants([]string{"//pool/p:R", "/pool/p:S"}); !errors.Is(err, ErrInvalidGrant) || !strings.Contains(err.Error(), "two grants on path /pool/p") {
		t.Fatalf("ParseGrants: %v", err)
	}
	opts := baseOptions(newTestRoster(t, ""))
	opts.Grants = []Grant{{Path: "//pool/p", Role: "R"}, {Path: "/pool/p", Role: "S"}}
	tr := &fakeTransport{installFingerprint: "SHA256:abc", session: &fakeSession{}}
	if _, err := Run(context.Background(), opts, tr, &fakeValidator{}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("Run: %v", err)
	}
	if tr.installCalls+tr.dialCalls+tr.reconnectCalls != 0 || len(tr.session.attempted) != 0 {
		t.Fatal("SSH was touched")
	}
}

// MG8: normalization copies Privs; the caller's slice is never shared.
func TestNormalizeGrants_CopiesPrivs(t *testing.T) {
	in := []Grant{{Path: "/pool/p", Role: "R", Privs: []string{"A", "B"}}}
	out, err := normalizeGrants(in)
	if err != nil {
		t.Fatal(err)
	}
	out[0].Privs[0] = "X"
	if in[0].Privs[0] != "A" {
		t.Fatal("normalizeGrants shares the caller's Privs")
	}
}

// pinRun runs a reconnect whose held token is present on PVE and whose
// skip-check WOULD be a verdict (so a remove follows if anything gets that
// far), with the given role list and grants.
func pinRun(t *testing.T, roleList string, grants []Grant) (error, *fakeSession, *fakeValidator, bool) {
	t.Helper()
	s := seedRoster(t, heldID, "")
	s.opts.Grants = grants
	before := rosterBytes(t, s.path)
	session := &fakeSession{pve: newFakePVE("pveforge"), byCmd: map[string]fakeRunResult{"pveum role list": {res: RunResult{Stdout: roleList}}}}
	v := &fakeValidator{errs: []error{fmt.Errorf("%w", ErrScopeTooWide), nil}}
	_, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, v)
	return err, session, v, !reflect.DeepEqual(before, rosterBytes(t, s.path))
}

func assertPinRefused(t *testing.T, err error, session *fakeSession, v *fakeValidator, changed bool, path string) {
	t.Helper()
	if !errors.Is(err, ErrPinnedPrivsMismatch) || isVerdict(err) || !strings.Contains(err.Error(), "at "+path+":") {
		t.Fatalf("want ErrPinnedPrivsMismatch at %s (not a verdict), got %v", path, err)
	}
	if v.calls != 0 || len(session.mutating()) != 0 || session.ran("pveum user token list") || changed {
		t.Fatalf("the run got past the pin check: calls=%d commands=%v changed=%v", v.calls, session.commands, changed)
	}
}

// A-T6: a pin that is not exactly its role is refused before anything is
// removed, whichever way it differs (MG11, MG12, MG12b, MG17).
func TestRun_AT6_PinMustEqualRole(t *testing.T) {
	const roleAB = `[{"privs":"A,B","roleid":"R","special":0}]`
	for name, privs := range map[string][]string{
		"a pin a strict subset of the role":        {"A"},
		"b pin a strict superset of the role":      {"A", "B", "C"},
		"d same size, different members (A,C/A,B)": {"A", "C"},
	} {
		t.Run(name, func(t *testing.T) {
			err, session, v, changed := pinRun(t, roleAB, []Grant{{Path: "/pool/p", Role: "R", Privs: privs}})
			assertPinRefused(t, err, session, v, changed, "/pool/p")
		})
	}
	t.Run("c equal sets in a different order proceed", func(t *testing.T) {
		err, _, v, _ := pinRun(t, roleAB, []Grant{{Path: "/pool/p", Role: "R", Privs: []string{"B", "A"}}})
		if err != nil || v.calls == 0 {
			t.Fatalf("want the run to proceed past the pin check, got %v (validator calls %d)", err, v.calls)
		}
	})
}

// A-T7: each pin is compared with ITS OWN role (MG13): two roles with
// disjoint privileges.
func TestRun_AT7_PinCheckedPerGrant(t *testing.T) {
	const roles = `[{"privs":"A1,A2","roleid":"RoleA","special":0},{"privs":"B1,B2","roleid":"RoleB","special":0}]`
	ok := []Grant{
		{Path: "/pool/p", Role: "RoleA", Privs: []string{"A1", "A2"}},
		{Path: "/storage/s", Role: "RoleB", Privs: []string{"B1", "B2"}},
	}
	err, _, v, _ := pinRun(t, roles, ok)
	if err != nil || v.calls == 0 {
		t.Fatalf("each pin equals its own role: want the run to proceed, got %v", err)
	}
	bad := []Grant{ok[0], {Path: "/storage/s", Role: "RoleB", Privs: []string{"B1"}}}
	err, session, v, changed := pinRun(t, roles, bad)
	assertPinRefused(t, err, session, v, changed, "/storage/s")
}

// A-T8 (result side): Result.Grants is the validated want exactly when a
// token survives: minted, reused, and also when the meta persist then
// fails (R6, MG16c); never after a failed run (F3, MG16b).
func TestRun_AT8_GrantsOnlyWhenATokenSurvives(t *testing.T) {
	want := []Grant{{Path: "/", Role: "PVEVMAdmin", Propagate: true}}
	failMeta := func(t *testing.T) {
		orig := persistTargetMetaFn
		persistTargetMetaFn = func(Options) error { return errors.New("meta write failed") }
		t.Cleanup(func() { persistTargetMetaFn = orig })
	}
	minted := func(t *testing.T) (*Result, error) {
		return Run(context.Background(), baseOptions(newTestRoster(t, "")), &fakeTransport{installFingerprint: "SHA256:abc", session: &fakeSession{}}, &fakeValidator{})
	}
	reused := func(t *testing.T) (*Result, error) {
		s := seedRoster(t, heldID, "")
		return Run(context.Background(), s.opts, &fakeTransport{session: &fakeSession{pve: newFakePVE("pveforge")}}, &fakeValidator{})
	}
	t.Run("minted", func(t *testing.T) {
		res, err := minted(t)
		if err != nil || res.TokenOutcome != OutcomeMinted || !reflect.DeepEqual(res.Grants, want) {
			t.Fatalf("%+v, %v", res, err)
		}
	})
	t.Run("reused", func(t *testing.T) {
		res, err := reused(t)
		if err != nil || res.TokenOutcome != OutcomeReused || !reflect.DeepEqual(res.Grants, want) {
			t.Fatalf("%+v, %v", res, err)
		}
	})
	t.Run("minted, then the meta persist fails", func(t *testing.T) {
		failMeta(t)
		res, err := minted(t)
		if err == nil || res == nil || res.TokenOutcome != OutcomeMinted || !reflect.DeepEqual(res.Grants, want) {
			t.Fatalf("%+v, %v", res, err)
		}
	})
	t.Run("reused, then the meta persist fails", func(t *testing.T) {
		failMeta(t)
		res, err := reused(t)
		if err == nil || res == nil || res.TokenOutcome != OutcomeReused || !reflect.DeepEqual(res.Grants, want) {
			t.Fatalf("%+v, %v", res, err)
		}
	})
	// CR1 (RB2): a verified mint whose persist then fails (the R15
	// duplicate-block shape) leaves no token: discarded, no grants.
	t.Run("a verified mint whose persist fails reports no grants", func(t *testing.T) {
		path := newTestRoster(t, "")
		v := &fakeValidator{onCall: func(int) { duplicateTargetBlock(t, path) }}
		res, err := Run(context.Background(), baseOptions(path), &fakeTransport{installFingerprint: "SHA256:abc", session: &fakeSession{}}, v)
		if err == nil || res == nil || res.TokenOutcome != OutcomeDiscarded || res.Validation != ValidationVerified || res.Grants != nil {
			t.Fatalf("%+v, %v", res, err)
		}
	})
	// CR1 (RB3): the held token is revoked on a verdict and the re-mint
	// fails (R10's shape): revoked_not_replaced, no grants.
	t.Run("a revoked_not_replaced run reports no grants", func(t *testing.T) {
		s, _, tr, v := prior(t, map[string]fakeRunResult{"pveum user token add": {res: RunResult{ExitCode: 1, Stderr: "nope"}}})
		res, err := Run(context.Background(), s.opts, tr, v)
		wantRevoked(t, res, err)
		if res.Grants != nil {
			t.Fatalf("grants reported for a revoked, unreplaced token: %#v", res.Grants)
		}
	})
	t.Run("a failed run reports no grants", func(t *testing.T) {
		v := &fakeValidator{err: fmt.Errorf("%w", ErrScopeTooWide)}
		res, err := Run(context.Background(), baseOptions(newTestRoster(t, "")), &fakeTransport{installFingerprint: "SHA256:abc", session: &fakeSession{}}, v)
		if err == nil || res == nil || res.TokenOutcome != OutcomeDiscarded || res.Grants != nil {
			t.Fatalf("%+v, %v", res, err)
		}
	})
}

// FO3: the result's grants are a copy, never an alias of the run's want
// (which the validator received).
// Both survival points are covered: a one-site fix (RB4d, the reuse site
// still aliasing) must not survive.
func TestRun_ResultGrantsAreACopy(t *testing.T) {
	// pinned, so Privs is non-nil and the deep copy is observable
	const spec = "/storage/s:R2:B:1"
	roleList := map[string]fakeRunResult{"pveum role list": {res: RunResult{Stdout: threeRoles}}}
	mutateThenCompare := func(t *testing.T, res *Result, err error, v *fakeValidator, wantOutcome string) {
		t.Helper()
		if err != nil || res.TokenOutcome != wantOutcome || len(res.Grants) != 1 || len(v.wants) != 1 {
			t.Fatalf("%+v, %v", res, err)
		}
		res.Grants[0].Privs[0] = "X"
		res.Grants[0].Path = "/changed"
		if v.wants[0][0].Privs[0] != "B" || v.wants[0][0].Path != "/storage/s" {
			t.Fatalf("Result.Grants aliases the run's want: %#v", v.wants[0])
		}
	}
	t.Run("minted", func(t *testing.T) {
		opts := baseOptions(newTestRoster(t, ""))
		opts.Grants = mustParse(t, spec)
		session := &fakeSession{byCmd: roleList}
		v := &fakeValidator{}
		res, err := Run(context.Background(), opts, &fakeTransport{installFingerprint: "SHA256:abc", session: session}, v)
		mutateThenCompare(t, res, err, v, OutcomeMinted)
	})
	t.Run("reused", func(t *testing.T) {
		s := seedRoster(t, heldID, "")
		s.opts.Grants = mustParse(t, spec)
		session := &fakeSession{pve: newFakePVE("pveforge"), byCmd: roleList}
		v := &fakeValidator{}
		res, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, v)
		mutateThenCompare(t, res, err, v, OutcomeReused)
	})
}

// ---- A-ACC: the nested harness's four D5 grants, generated from the
// pinned D5 r3 fixtures (no hand-typed path/role map) ----

type d5ACLRow struct {
	Path      string `json:"path"`
	Propagate int    `json:"propagate"`
	RoleID    string `json:"roleid"`
	UGID      string `json:"ugid"`
}

func readD5(t *testing.T, name string, v interface{}) {
	t.Helper()
	b, err := os.ReadFile("../pve/testdata/permissions/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// d5Fixture returns the token's ACL rows, the grants they imply (privileges
// pinned from the roles fixture), their --grant specs, and a pveum role
// list answer built from the roles fixture (widen, when set, is appended to
// PveforgeHarness's privileges).
func d5Fixture(t *testing.T, widen string) (rows []d5ACLRow, grants []Grant, specs []string, roleList string) {
	t.Helper()
	var all []d5ACLRow
	readD5(t, "d5r3-expected-acl-rows.json", &all)
	var roles map[string][]string
	readD5(t, "d5r3-expected-roles.json", &roles)
	for _, r := range all {
		if !strings.Contains(r.UGID, "!") {
			continue
		}
		rows = append(rows, r)
		privs := roles[r.RoleID]
		if len(privs) == 0 {
			t.Fatalf("role %s has no privileges in the fixture", r.RoleID)
		}
		grants = append(grants, Grant{Path: r.Path, Role: r.RoleID, Propagate: r.Propagate == 1, Privs: append([]string{}, privs...)})
		specs = append(specs, fmt.Sprintf("%s:%s:%s:%d", r.Path, r.RoleID, strings.Join(privs, ","), r.Propagate))
	}
	ids := make([]string, 0, len(roles))
	for id := range roles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var entries []string
	for _, id := range ids {
		privs := strings.Join(roles[id], ",")
		if id == "PveforgeHarness" && widen != "" {
			privs += "," + widen
		}
		entries = append(entries, fmt.Sprintf(`{"privs":%q,"roleid":%q,"special":0}`, privs, id))
	}
	return rows, grants, specs, "[" + strings.Join(entries, ",") + "]"
}

func TestRun_AACC_D5Grants(t *testing.T) {
	rows, grants, specs, roleList := d5Fixture(t, "")
	if len(rows) != 4 {
		t.Fatalf("D5 token rows = %d, want 4", len(rows))
	}
	opts := baseOptions(newTestRoster(t, ""))
	opts.TokenID = "build"
	opts.Grants = mustParse(t, specs...)
	session := &fakeSession{byCmd: map[string]fakeRunResult{"pveum role list": {res: RunResult{Stdout: roleList}}}}
	v := &fakeValidator{}
	res, err := Run(context.Background(), opts, &fakeTransport{installFingerprint: "SHA256:abc", session: session}, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var wantCmds []string
	for _, r := range rows {
		// U-A keeps a root owner: the token NAME is the fixture's, the
		// owner is root@pam (U-C asserts the full pveforge-harness@pve!build).
		_, name, _ := strings.Cut(r.UGID, "!")
		if name != opts.TokenID {
			t.Fatalf("fixture token name %q != %q", name, opts.TokenID)
		}
		wantCmds = append(wantCmds, fmt.Sprintf("pveum acl modify '%s' --tokens 'root@pam!%s' --roles '%s' --propagate %d", r.Path, name, r.RoleID, r.Propagate))
	}
	if got := aclCommands(session); !reflect.DeepEqual(got, wantCmds) {
		t.Fatalf("acl commands:\n got %q\nwant %q", got, wantCmds)
	}
	if len(v.wants) != 1 || !reflect.DeepEqual(v.wants[0], grants) {
		t.Fatalf("wants = %#v\nwant %#v", v.wants, grants)
	}
	if !reflect.DeepEqual(res.Grants, grants) {
		t.Fatalf("result grants = %#v", res.Grants)
	}

	t.Run("PveforgeHarness widened on PVE: refused before any remove", func(t *testing.T) {
		_, grants, _, widened := d5Fixture(t, "Permissions.Modify")
		s := seedRoster(t, "root@pam!build", "")
		s.opts.TokenID = "build"
		s.opts.Grants = grants
		before := rosterBytes(t, s.path)
		session := &fakeSession{pve: newFakePVEFor(fakeDefaultOwner, "build"), byCmd: map[string]fakeRunResult{"pveum role list": {res: RunResult{Stdout: widened}}}}
		v := &fakeValidator{errs: []error{fmt.Errorf("%w", ErrScopeTooWide), nil}}
		_, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, v)
		assertPinRefused(t, err, session, v, !reflect.DeepEqual(before, rosterBytes(t, s.path)), "/pool/pveforge-harness")
	})
}
