package idempotent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"testing"
	"time"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// pveforge-post-apply-verification-and-pending, P3: the strict re-read after
// Apply (ReReader), the no-op check (NoopChecker), VMCreate's
// created-not-found, UserEnsure/GroupEnsure's read-back, and VMFieldsEnsure's
// already-set-but-pending reporting.

// --- the engine ---------------------------------------------------------

// reReadOp is a fakeOp that is also a ReReader, a PostApplier and a
// NoopChecker, counting each.
type reReadOp struct {
	fakeOp
	reReadResult string
	reReadErr    error
	reReadCalls  int
	readsAtRe    int

	postCalls int
	noopErr   error
	noopCalls int
	noopCheck func(ctx context.Context)
}

func (o *reReadOp) ReRead(context.Context) (string, error) {
	o.reReadCalls++
	o.readsAtRe = o.readCalls
	return o.reReadResult, o.reReadErr
}

func (o *reReadOp) PostApply(context.Context) error { o.postCalls++; return nil }

func (o *reReadOp) PostNoop(ctx context.Context) error {
	o.noopCalls++
	if o.noopCheck != nil {
		o.noopCheck(ctx)
	}
	return o.noopErr
}

var (
	_ ReReader    = (*reReadOp)(nil)
	_ NoopChecker = (*reReadOp)(nil)
)

// E1: Run's re-read after a successful Apply is ReRead, not Read — once, on
// the attempt whose Apply succeeded — and ReRead is never used before
// Apply, on a no-op, after a failed Apply, or on a superseded attempt.
func TestRun_ReReader_OnlyForTheReReadAfterApply(t *testing.T) {
	for name, tc := range map[string]struct {
		op        *reReadOp
		wantReads int
		wantRe    int
		wantErr   bool
	}{
		"applied": {op: &reReadOp{fakeOp: fakeOp{readResults: []string{"a"}}, reReadResult: "b"},
			wantReads: 1, wantRe: 1},
		"no-op": {op: &reReadOp{fakeOp: fakeOp{readResults: []string{"a"}, satisfiedFunc: func(string) bool { return true }}},
			wantReads: 1, wantRe: 0},
		"apply failed": {op: &reReadOp{fakeOp: fakeOp{readResults: []string{"a"}, applyErrs: []error{errors.New("boom")}}},
			wantReads: 1, wantRe: 0, wantErr: true},
		"conflict then success": {op: &reReadOp{fakeOp: fakeOp{readResults: []string{"a", "a2"},
			applyErrs: []error{fmt.Errorf("wrap: %w", ErrConflict), nil}}, reReadResult: "b"},
			wantReads: 2, wantRe: 1},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := Run(context.Background(), testRosterPath(t), testKey(), tc.op, false)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Run err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.op.readCalls != tc.wantReads || tc.op.reReadCalls != tc.wantRe {
				t.Errorf("Read called %d times, ReRead %d; want %d and %d", tc.op.readCalls, tc.op.reReadCalls, tc.wantReads, tc.wantRe)
			}
			if tc.wantRe == 1 {
				if res.After != "b" || res.AfterErr != nil {
					t.Errorf("After %q, AfterErr %v; want ReRead's b and no error", res.After, res.AfterErr)
				}
				if tc.op.readsAtRe != tc.wantReads {
					t.Errorf("ReRead ran after %d reads, want after all %d", tc.op.readsAtRe, tc.wantReads)
				}
			}
		})
	}
}

// E1: a failed ReRead is Result.AfterErr, exactly as a failed Read there
// is: the Run succeeds, After keeps Before's value, and PostApply still runs.
func TestRun_ReReader_ErrorIsAfterErr(t *testing.T) {
	cause := errors.New("status 500")
	op := &reReadOp{fakeOp: fakeOp{readResults: []string{"a"}}, reReadErr: cause}
	res, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed || !errors.Is(res.AfterErr, cause) || res.After != "a" {
		t.Errorf("Changed %t, AfterErr %v, After %q; want a change, the cause, and Before's value", res.Changed, res.AfterErr, res.After)
	}
	if op.postCalls != 1 {
		t.Errorf("PostApply called %d times, want 1", op.postCalls)
	}
}

// E2: PostNoop runs once, on the no-op path only: never after an Apply
// (PostApply is that path's check), never under force, never when the Read
// failed. Its error is Result.PostApplyErr with Changed false, advisory.
func TestRun_NoopChecker_OnlyOnTheNoopPath(t *testing.T) {
	satisfied := func(string) bool { return true }
	for name, tc := range map[string]struct {
		op        *reReadOp
		force     bool
		wantNoop  int
		wantPost  int
		wantRunEr bool
	}{
		"no-op":        {op: &reReadOp{fakeOp: fakeOp{readResults: []string{"a"}, satisfiedFunc: satisfied}}, wantNoop: 1},
		"applied":      {op: &reReadOp{fakeOp: fakeOp{readResults: []string{"a"}}}, wantPost: 1},
		"forced":       {op: &reReadOp{fakeOp: fakeOp{readResults: []string{"a"}, satisfiedFunc: satisfied}}, force: true, wantPost: 1},
		"apply failed": {op: &reReadOp{fakeOp: fakeOp{readResults: []string{"a"}, applyErrs: []error{errors.New("boom")}}}, wantRunEr: true},
		"read failed":  {op: &reReadOp{fakeOp: fakeOp{readErrs: []error{errors.New("boom")}, satisfiedFunc: satisfied}}, wantRunEr: true},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Run(context.Background(), testRosterPath(t), testKey(), tc.op, tc.force)
			if (err != nil) != tc.wantRunEr {
				t.Fatalf("Run err = %v, wantErr %v", err, tc.wantRunEr)
			}
			if tc.op.noopCalls != tc.wantNoop || tc.op.postCalls != tc.wantPost {
				t.Errorf("PostNoop called %d times, PostApply %d; want %d and %d", tc.op.noopCalls, tc.op.postCalls, tc.wantNoop, tc.wantPost)
			}
		})
	}

	cause := errors.New("pending read failed")
	op := &reReadOp{fakeOp: fakeOp{readResults: []string{"a"}, satisfiedFunc: satisfied}, noopErr: cause}
	res, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err != nil {
		t.Fatalf("a failed no-op check must not fail the Run: %v", err)
	}
	if res.Changed || !errors.Is(res.PostApplyErr, cause) || res.AfterErr != nil {
		t.Errorf("Changed %t, PostApplyErr %v, AfterErr %v; want a no-op carrying the cause", res.Changed, res.PostApplyErr, res.AfterErr)
	}
}

// E2: PostNoop runs while Run still holds the object's lock.
func TestRun_NoopChecker_RunsUnderTheLock(t *testing.T) {
	roster := testRosterPath(t)
	var lockErr error
	op := &reReadOp{
		fakeOp: fakeOp{readResults: []string{"a"}, satisfiedFunc: func(string) bool { return true }},
		noopCheck: func(context.Context) {
			unlock, err := lock.Mutation(lock.WithWait(context.Background(), 20*time.Millisecond), roster, testKey())
			if err == nil {
				_ = unlock()
			}
			lockErr = err
		},
	}
	if _, err := Run(context.Background(), roster, testKey(), op, false); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if op.noopCalls != 1 {
		t.Fatalf("PostNoop called %d times, want 1", op.noopCalls)
	}
	if lockErr == nil {
		t.Error("the object's lock was free during PostNoop; want it still held by Run")
	}
}

// --- VMCreate -----------------------------------------------------------

// missingVMErr is PVE's answer for a vmid with no config, as go-proxmox's
// typed error carries it (GetVM's path), body kept.
func missingVMErr(vmid int) error {
	return fmt.Errorf("get vm %d status: %w", vmid, &proxmox.StatusError{StatusCode: 500,
		Status: "500 Internal Server Error",
		Body:   []byte(fmt.Sprintf(`{"data":null,"message":"Configuration file 'nodes/qa-pve-01/qemu-server/%d.conf' does not exist\n"}`, vmid))})
}

// VC2: ReRead's three outcomes, and PostApply's reading of them.
func TestVMCreate_ReRead_ThreeOutcomes(t *testing.T) {
	present := &proxmox.VirtualMachine{Name: "web", VMID: 100, Status: "stopped"}
	for name, tc := range map[string]struct {
		result      *proxmox.VirtualMachine
		err         error
		wantCurrent bool
		wantErr     bool
		wantMissing bool
	}{
		"present":                        {result: present, wantCurrent: true},
		"pve's no such vm (go-proxmox)":  {err: missingVMErr(100), wantMissing: true},
		"pve's no such vm (raw request)": {err: pve.NewStatusError("raw request", 500, "500 Configuration file 'nodes/qa-pve-01/qemu-server/100.conf' does not exist", []byte(`{"data":null}`)), wantMissing: true},
		"another vmid's config missing":  {err: missingVMErr(1000), wantErr: true},
		"does not exist, no fragment":    {err: pve.NewStatusError("raw request", 500, "500 Internal Server Error", []byte(`user 'x@pve' does not exist`)), wantErr: true},
		"a 500 that is not an answer":    {err: pve.NewStatusError("raw request", 500, "500 Internal Server Error", []byte("pve says no")), wantErr: true},
		"a transport error":              {err: errors.New("dial tcp: connection refused"), wantErr: true},
		"unverifiable":                   {err: fmt.Errorf("get vm 100 status: %w", pve.ErrUnverifiableRead), wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			op := &VMCreate{Client: &fakeVMCreateClient{node: "qa-pve-01", getVMResult: tc.result, getVMErr: tc.err}, VMID: 100}
			got, err := op.ReRead(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("ReRead err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.err != nil && err != nil && !errors.Is(err, tc.err) {
				t.Errorf("ReRead err %v does not wrap the cause %v", err, tc.err)
			}
			if (got != "") != tc.wantCurrent {
				t.Errorf("ReRead = %q, want present %t", got, tc.wantCurrent)
			}
			var nf *CreatedNotFoundError
			postErr := op.PostApply(context.Background())
			if errors.As(postErr, &nf) != tc.wantMissing || (!tc.wantMissing && postErr != nil) {
				t.Errorf("PostApply = %v, want created-not-found %t", postErr, tc.wantMissing)
			}
			if tc.wantMissing && nf.VMID != 100 {
				t.Errorf("CreatedNotFoundError.VMID = %d, want 100", nf.VMID)
			}
		})
	}
	// Read before the create keeps its pinned contract: any error is
	// "absent", never an error — including the ones ReRead refuses.
	op := &VMCreate{Client: &fakeVMCreateClient{node: "qa-pve-01", getVMErr: errors.New("dial tcp: connection refused")}, VMID: 100}
	if got, err := op.Read(context.Background()); got != "" || err != nil {
		t.Errorf("Read = %q, %v; want absent and no error", got, err)
	}
}

// VC2: a finding is not kept across ReReads: absent, then present, is clean.
func TestVMCreate_ReRead_ResetsItsFinding(t *testing.T) {
	c := &fakeVMCreateClient{node: "qa-pve-01", getVMErr: missingVMErr(100)}
	op := &VMCreate{Client: c, VMID: 100}
	_, _ = op.ReRead(context.Background())
	c.getVMErr, c.getVMResult = nil, &proxmox.VirtualMachine{VMID: 100, Status: "running"}
	if _, err := op.ReRead(context.Background()); err != nil {
		t.Fatalf("ReRead: %v", err)
	}
	if err := op.PostApply(context.Background()); err != nil {
		t.Errorf("PostApply = %v after a ReRead that found the VM", err)
	}
}

// VC3: through Run, a create whose task succeeded and whose VM PVE then
// says does not exist is a success with Result.PostApplyErr a
// *CreatedNotFoundError, and no AfterErr: the re-read itself was answered.
func TestVMCreate_ViaRun_CreatedThenNotFound(t *testing.T) {
	c := &fakeVMCreateClient{node: "qa-pve-01", getVMErr: missingVMErr(100), createVMUPID: "UPID:qa-pve-01:1:2:3:qmcreate:100:root@pam:"}
	op := &VMCreate{Client: c, VMID: 100, Params: url.Values{"cores": {"2"}}}
	res, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var nf *CreatedNotFoundError
	if !res.Changed || res.AfterErr != nil || !errors.As(res.PostApplyErr, &nf) {
		t.Errorf("Changed %t, AfterErr %v, PostApplyErr %v; want a change reported created-not-found", res.Changed, res.AfterErr, res.PostApplyErr)
	}
	if c.createVMCalls != 1 || c.getVMCalls != 2 {
		t.Errorf("CreateVM %d, GetVM %d; want 1 create and 2 reads (PostApply makes none)", c.createVMCalls, c.getVMCalls)
	}
}

// VC3, end to end over the real pve.Client: PVE's 500 for a missing config,
// with the message in the body, reaches ReRead through go-proxmox with the
// body kept, and is classified — not merely an AfterErr.
func TestVMCreate_EndToEnd_CreatedThenNotFound(t *testing.T) {
	upid := uvUPID("qmcreate", uvVMID)
	missing := uvReply{500, fmt.Sprintf(`{"data":null,"message":"Configuration file 'nodes/%s/qemu-server/%d.conf' does not exist\n"}`, uvNode, uvVMID)}
	s := newUVServer(t)
	s.on("GET", fmt.Sprintf("/nodes/%s/qemu/%d/status/current", uvNode, uvVMID), missing)
	s.on("GET", fmt.Sprintf("/nodes/%s/qemu/%d/config", uvNode, uvVMID), missing)
	s.on("POST", fmt.Sprintf("/nodes/%s/qemu", uvNode), uvReply{200, fmt.Sprintf(`{"data":%q}`, upid)})
	uvTaskOK(s, upid)

	op := &VMCreate{Client: &realPVEClientAdapter{Client: s.client(), node: uvNode}, VMID: uvVMID,
		Params: url.Values{"cores": {"2"}}}
	res, err := Run(context.Background(), testRosterPath(t), uvKey(uvVMID), op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var nf *CreatedNotFoundError
	if !res.Changed || res.AfterErr != nil || !errors.As(res.PostApplyErr, &nf) {
		t.Errorf("Changed %t, AfterErr %v, PostApplyErr %v; want created-not-found", res.Changed, res.AfterErr, res.PostApplyErr)
	}
	if posts := s.count("POST", fmt.Sprintf("/nodes/%s/qemu", uvNode)); posts != 1 {
		t.Errorf("create POSTs = %d, want 1", posts)
	}
}

// --- UserEnsure and GroupEnsure ----------------------------------------

// UG1: a write PVE accepted but did not act on — the re-read does not have
// every requested value — is a *ReadBackMismatchError naming what was read
// back, advisory: the Run still succeeds.
func TestUserEnsure_PostApply_ReadBackMismatch(t *testing.T) {
	// Added, but the re-read lacks it.
	f := &fakeAccess{dropWrites: true}
	res := runUser(t, f, &UserEnsure{UserID: "alice@pve", Groups: []string{"ops"}})
	var mm *ReadBackMismatchError
	if !res.Changed || res.AfterErr != nil || !errors.As(res.PostApplyErr, &mm) || mm.Got != "absent" || mm.Kind != "user" || mm.ID != "alice@pve" {
		t.Errorf("Changed %t, AfterErr %v, PostApplyErr %v; want a mismatch reading back absent", res.Changed, res.AfterErr, res.PostApplyErr)
	}
	// Modified, but the re-read keeps the old comment.
	f = &fakeAccess{dropWrites: true, users: []pve.AccessUser{{UserID: "alice@pve", Enabled: true, Comment: "old"}}}
	res = runUser(t, f, &UserEnsure{UserID: "alice@pve", Comment: ptr("new")})
	if !errors.As(res.PostApplyErr, &mm) || mm.Got != `enable=true comment="old" email="" groups=""` {
		t.Errorf("PostApplyErr %v; want a mismatch naming the old comment", res.PostApplyErr)
	}
	// Applied as asked: clean.
	f = &fakeAccess{users: []pve.AccessUser{{UserID: "alice@pve", Enabled: true, Comment: "old"}}}
	if res = runUser(t, f, &UserEnsure{UserID: "alice@pve", Comment: ptr("new")}); res.PostApplyErr != nil {
		t.Errorf("PostApplyErr %v after a write the re-read confirms", res.PostApplyErr)
	}
}

// UG2 (Chair ruling 2): a re-read that fails is AfterErr only — never a
// false mismatch drawn from the list read before the write.
func TestUserEnsure_PostApply_FailedReReadIsNoFalseMismatch(t *testing.T) {
	cause := errors.New("list users: pve returned 500")
	for name, users := range map[string][]pve.AccessUser{
		"create": nil,
		"modify": {{UserID: "alice@pve", Enabled: true, Comment: "old"}},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeAccess{users: users, listErrAfterWrite: cause}
			res := runUser(t, f, &UserEnsure{UserID: "alice@pve", Comment: ptr("new")})
			if !res.Changed || !errors.Is(res.AfterErr, cause) || res.PostApplyErr != nil {
				t.Errorf("Changed %t, AfterErr %v, PostApplyErr %v; want the re-read's failure and no mismatch", res.Changed, res.AfterErr, res.PostApplyErr)
			}
		})
	}
}

func TestGroupEnsure_PostApply_ReadBack(t *testing.T) {
	run := func(f *fakeAccess, op *GroupEnsure) Result {
		t.Helper()
		op.Client = f
		res, err := Run(context.Background(), testRosterPath(t), lock.ObjectKey{TargetID: "t", Kind: "group", ID: op.GroupID}, op, false)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return res
	}
	var mm *ReadBackMismatchError
	res := run(&fakeAccess{dropWrites: true}, &GroupEnsure{GroupID: "ops", Comment: ptr("Ops")})
	if !errors.As(res.PostApplyErr, &mm) || mm.Got != "absent" || mm.Kind != "group" || mm.ID != "ops" {
		t.Errorf("created but absent: PostApplyErr %v", res.PostApplyErr)
	}
	res = run(&fakeAccess{dropWrites: true, groups: []pve.AccessGroup{{GroupID: "ops", Comment: "old"}}}, &GroupEnsure{GroupID: "ops", Comment: ptr("new")})
	if !errors.As(res.PostApplyErr, &mm) || mm.Got != `comment="old"` {
		t.Errorf("comment not applied: PostApplyErr %v", res.PostApplyErr)
	}
	cause := errors.New("list groups: pve returned 500")
	for name, groups := range map[string][]pve.AccessGroup{"create": nil, "modify": {{GroupID: "ops", Comment: "old"}}} {
		res = run(&fakeAccess{groups: groups, listErrAfterWrite: cause}, &GroupEnsure{GroupID: "ops", Comment: ptr("new")})
		if !errors.Is(res.AfterErr, cause) || res.PostApplyErr != nil {
			t.Errorf("%s, failed re-read: AfterErr %v, PostApplyErr %v; want no false mismatch", name, res.AfterErr, res.PostApplyErr)
		}
	}
}

// --- VMFieldsEnsure: already set, still pending --------------------------

// runFieldsNoop drives a no-op vm set of cores=4 (config already cores=4)
// through Run, with the /pending answer pending.
func runFieldsNoop(t *testing.T, op *VMFieldsEnsure, config string, client *fakeClient) Result {
	t.Helper()
	client.node = "qa-pve-01"
	client.rawRequestResults = []json.RawMessage{json.RawMessage(config)}
	op.Client, op.VMID = client, 100
	res, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Changed {
		t.Fatalf("Changed = true, want a no-op")
	}
	return res
}

// NP1: on a no-op, one /pending read, and only the requested keys PVE
// holds pending are reported — not a key someone else left pending, not a
// requested key applied at once — in the order requested. P1's findings
// (this Run's own changes) stay empty: there were none.
func TestVMFieldsEnsure_PostNoop_ReportsRequestedPendingKeys(t *testing.T) {
	client := &fakeClient{pendingResults: []json.RawMessage{json.RawMessage(
		`[{"key":"memory","value":2048,"pending":4096},{"key":"cores","value":2,"pending":4},{"key":"sockets","value":1},{"key":"numa","pending":1}]`)}}
	op := &VMFieldsEnsure{Pairs: pairs("numa", "1", "sockets", "1", "cores", "4")}
	res := runFieldsNoop(t, op, `{"digest":"d1","cores":"4","sockets":"1","numa":"1"}`, client)
	if res.PostApplyErr != nil {
		t.Fatalf("PostApplyErr: %v", res.PostApplyErr)
	}
	if !slices.Equal(op.AlreadyPending, []string{"numa", "cores"}) {
		t.Errorf("AlreadyPending = %q, want [numa cores] in requested order, not memory", op.AlreadyPending)
	}
	if op.Pending != nil || op.PendingDeletes != nil || op.AlreadyPendingDeletes != nil {
		t.Errorf("Pending %q, PendingDeletes %q, AlreadyPendingDeletes %q; want none", op.Pending, op.PendingDeletes, op.AlreadyPendingDeletes)
	}
	want := []string{"GET /nodes/qa-pve-01/qemu/100/config?", "GET /nodes/qa-pve-01/qemu/100/pending?"}
	if !slices.Equal(client.rawCalls, want) {
		t.Errorf("raw requests:\n got:  %q\n want: %q", client.rawCalls, want)
	}
}

// NP2 (ruling c2): a requested delete of a key that already reads as
// absent, whose removal PVE still holds pending, is reported; a pending
// removal the command did not ask for is not.
func TestVMFieldsEnsure_PostNoop_ReportsRequestedPendingDeletes(t *testing.T) {
	client := &fakeClient{pendingResults: []json.RawMessage{json.RawMessage(
		`[{"key":"description","value":"x","delete":1},{"key":"tags","value":"a","delete":2}]`)}}
	op := &VMFieldsEnsure{Deletes: []string{"description"}}
	res := runFieldsNoop(t, op, `{"digest":"d1","cores":"4"}`, client)
	if res.PostApplyErr != nil {
		t.Fatalf("PostApplyErr: %v", res.PostApplyErr)
	}
	if !slices.Equal(op.AlreadyPendingDeletes, []string{"description"}) || op.AlreadyPending != nil {
		t.Errorf("AlreadyPendingDeletes %q, AlreadyPending %q; want [description] and none", op.AlreadyPendingDeletes, op.AlreadyPending)
	}
}

// NP3: a requested cloud-init key not pending gets the one /cloudinit read,
// and is reported when not yet on the drive; one already pending is not
// read for or reported twice; a non-cloud-init no-op never reads it.
func TestVMFieldsEnsure_PostNoop_CloudInit(t *testing.T) {
	client := &fakeClient{cloudInitResults: []json.RawMessage{json.RawMessage(
		`[{"key":"ipconfig0","value":"ip=dhcp","pending":"ip=10.0.0.5/24"},{"key":"ciuser","value":"a","pending":"b"}]`)}}
	op := &VMFieldsEnsure{Pairs: pairs("ipconfig0", "ip=10.0.0.5/24"), Deletes: []string{"sshkeys"}}
	res := runFieldsNoop(t, op, `{"digest":"d1","ipconfig0":"ip=10.0.0.5/24"}`, client)
	if res.PostApplyErr != nil {
		t.Fatalf("PostApplyErr: %v", res.PostApplyErr)
	}
	if !slices.Equal(op.AlreadyCloudInitStale, []string{"ipconfig0"}) || op.AlreadyCloudInitStaleDeletes != nil {
		t.Errorf("AlreadyCloudInitStale %q, deletes %q; want [ipconfig0] and none (ciuser was not requested)", op.AlreadyCloudInitStale, op.AlreadyCloudInitStaleDeletes)
	}
	if client.cloudInitCalls != 1 {
		t.Errorf("cloud-init reads = %d, want 1", client.cloudInitCalls)
	}

	// Already pending: reported once, as pending, and /cloudinit not read.
	client = &fakeClient{pendingResults: []json.RawMessage{json.RawMessage(`[{"key":"ipconfig0","pending":"ip=10.0.0.5/24"}]`)}}
	op = &VMFieldsEnsure{Pairs: pairs("ipconfig0", "ip=10.0.0.5/24")}
	runFieldsNoop(t, op, `{"digest":"d1","ipconfig0":"ip=10.0.0.5/24"}`, client)
	if !slices.Equal(op.AlreadyPending, []string{"ipconfig0"}) || op.AlreadyCloudInitStale != nil || client.cloudInitCalls != 0 {
		t.Errorf("AlreadyPending %q, AlreadyCloudInitStale %q, cloud-init reads %d; want pending once and no read", op.AlreadyPending, op.AlreadyCloudInitStale, client.cloudInitCalls)
	}

	client = &fakeClient{}
	op = &VMFieldsEnsure{Pairs: pairs("cores", "4")}
	runFieldsNoop(t, op, `{"digest":"d1","cores":"4"}`, client)
	if client.cloudInitCalls != 0 || client.pendingCalls != 1 {
		t.Errorf("pending reads %d, cloud-init reads %d; want 1 and 0", client.pendingCalls, client.cloudInitCalls)
	}
}

// NP4: a no-op whose check fails carries the cause in PostApplyErr, with
// Changed false and nothing found; a /cloudinit failure is marked as such,
// keeping what /pending found.
func TestVMFieldsEnsure_PostNoop_Failures(t *testing.T) {
	cause := errors.New("pve returned 500")
	op := &VMFieldsEnsure{Pairs: pairs("cores", "4")}
	res := runFieldsNoop(t, op, `{"digest":"d1","cores":"4"}`, &fakeClient{pendingErr: cause})
	var ci *CloudInitCheckError
	if !errors.Is(res.PostApplyErr, cause) || errors.As(res.PostApplyErr, &ci) || op.AlreadyPending != nil {
		t.Errorf("PostApplyErr %v, AlreadyPending %q; want the unmarked cause and nothing found", res.PostApplyErr, op.AlreadyPending)
	}

	op = &VMFieldsEnsure{Pairs: pairs("cores", "4")}
	res = runFieldsNoop(t, op, `{"digest":"d1","cores":"4"}`, &fakeClient{pendingResults: []json.RawMessage{json.RawMessage(`{"cores":1}`)}})
	if !errors.Is(res.PostApplyErr, pve.ErrUnverifiableRead) {
		t.Errorf("PostApplyErr %v; want ErrUnverifiableRead for a /pending that is not a list", res.PostApplyErr)
	}

	op = &VMFieldsEnsure{Pairs: pairs("cores", "4", "ciuser", "a")}
	res = runFieldsNoop(t, op, `{"digest":"d1","cores":"4","ciuser":"a"}`, &fakeClient{
		pendingResults: []json.RawMessage{json.RawMessage(`[{"key":"cores","pending":4}]`)}, cloudInitErr: cause})
	if !errors.As(res.PostApplyErr, &ci) || !errors.Is(res.PostApplyErr, cause) || !slices.Equal(op.AlreadyPending, []string{"cores"}) {
		t.Errorf("PostApplyErr %v, AlreadyPending %q; want a marked cloud-init failure and cores still reported", res.PostApplyErr, op.AlreadyPending)
	}
}

// MB1 (ruling c1): a mixed batch — cores changes, memory is skipped because
// it already reads as set but is still pending — reports cores through P1's
// Pending and memory through AlreadyPending, from the one /pending read
// PostApply already makes: zero extra requests, and no PostNoop.
func TestVMFieldsEnsure_PostApply_MixedBatchReportsSkippedPendingKeys(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", rawRequestResults: []json.RawMessage{
		json.RawMessage(`{"digest":"d1","cores":"2","memory":"4096","ciuser":"a"}`),
		json.RawMessage(`{"digest":"d1","cores":"2","memory":"4096","ciuser":"a"}`),
		json.RawMessage(`{"digest":"d2","cores":"4","memory":"4096","ciuser":"a"}`),
	}, pendingResults: []json.RawMessage{json.RawMessage(
		`[{"key":"cores","value":2,"pending":4},{"key":"memory","value":2048,"pending":4096},{"key":"balloon","pending":0}]`)},
		cloudInitResults: []json.RawMessage{json.RawMessage(`[{"key":"ciuser","value":"old","pending":"a"}]`)}}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4", "memory", "4096", "ciuser", "a")}
	res, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed || res.AfterErr != nil || res.PostApplyErr != nil {
		t.Fatalf("Run = %+v, want a clean change", res)
	}
	if !slices.Equal(op.Applied, []string{"cores"}) || !slices.Equal(op.Pending, []string{"cores"}) {
		t.Errorf("Applied %q, Pending %q; want [cores] each", op.Applied, op.Pending)
	}
	if !slices.Equal(op.AlreadyPending, []string{"memory"}) {
		t.Errorf("AlreadyPending = %q, want [memory] (balloon was not requested)", op.AlreadyPending)
	}
	// The skipped cloud-init key rides on no extra read: /cloudinit is read
	// only for this Run's own cloud-init changes, of which there are none.
	if client.pendingCalls != 1 || client.cloudInitCalls != 0 || op.AlreadyCloudInitStale != nil {
		t.Errorf("pending reads %d, cloud-init reads %d, AlreadyCloudInitStale %q; want 1, 0 and none",
			client.pendingCalls, client.cloudInitCalls, op.AlreadyCloudInitStale)
	}
}

// MB1, deletes: a requested delete already absent but pending, in a batch
// where another key changed, is AlreadyPendingDeletes.
func TestVMFieldsEnsure_PostApply_MixedBatchReportsSkippedPendingDeletes(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", rawRequestResults: []json.RawMessage{
		json.RawMessage(`{"digest":"d1","cores":"2"}`),
		json.RawMessage(`{"digest":"d1","cores":"2"}`),
		json.RawMessage(`{"digest":"d2","cores":"4"}`),
	}, pendingResults: []json.RawMessage{json.RawMessage(`[{"key":"description","value":"x","delete":1}]`)}}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4"), Deletes: []string{"description"}}
	res, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err != nil || !res.Changed || res.PostApplyErr != nil {
		t.Fatalf("Run = %+v, %v", res, err)
	}
	if !slices.Equal(op.AlreadyPendingDeletes, []string{"description"}) || op.Deleted != nil || op.PendingDeletes != nil {
		t.Errorf("AlreadyPendingDeletes %q, Deleted %q, PendingDeletes %q; want [description], none, none", op.AlreadyPendingDeletes, op.Deleted, op.PendingDeletes)
	}
}

// NP5: every check resets what an earlier one found.
func TestVMFieldsEnsure_PostChecks_ResetFindings(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01"}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4"),
		AlreadyPending: []string{"x"}, AlreadyPendingDeletes: []string{"x"}, AlreadyCloudInitStale: []string{"x"}, AlreadyCloudInitStaleDeletes: []string{"x"},
		Pending: []string{"x"}, CloudInitStale: []string{"x"}}
	if err := op.PostNoop(context.Background()); err != nil {
		t.Fatalf("PostNoop: %v", err)
	}
	if op.AlreadyPending != nil || op.AlreadyPendingDeletes != nil || op.AlreadyCloudInitStale != nil || op.AlreadyCloudInitStaleDeletes != nil || op.Pending != nil || op.CloudInitStale != nil {
		t.Errorf("PostNoop kept earlier findings: %+v", op)
	}
	op.AlreadyPending = []string{"x"}
	if err := op.PostApply(context.Background()); err != nil {
		t.Fatalf("PostApply: %v", err)
	}
	if op.AlreadyPending != nil {
		t.Errorf("PostApply kept an earlier AlreadyPending %q", op.AlreadyPending)
	}
}

// NP6: a PostNoop with nothing requested makes no request (Validate refuses
// such an op before Run, so this guard is its only line of defence).
func TestVMFieldsEnsure_PostNoop_NothingRequestedNoRead(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01"}
	op := &VMFieldsEnsure{Client: client, VMID: 100}
	if err := op.PostNoop(context.Background()); err != nil {
		t.Fatalf("PostNoop: %v", err)
	}
	if len(client.rawCalls) != 0 {
		t.Errorf("PostNoop with nothing requested made requests: %q", client.rawCalls)
	}
}
