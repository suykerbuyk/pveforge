package idempotent

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// P2′ (pveforge-post-apply-verification-and-pending): after a batch that
// wrote or deleted a cloud-init key, which of this Run's own cloud-init
// changes has PVE not yet written to the VM's cloud-init drive?

// postApplyCI runs PostApply alone over op, whose Applied and Deleted the
// test sets, with /pending answering pending and /cloudinit answering ci.
func postApplyCI(t *testing.T, op *VMFieldsEnsure, pending, ci string) (*fakeClient, error) {
	t.Helper()
	client := &fakeClient{node: "qa-pve-01",
		pendingResults:   []json.RawMessage{json.RawMessage(pending)},
		cloudInitResults: []json.RawMessage{json.RawMessage(ci)}}
	op.Client = client
	op.VMID = 100
	return client, op.PostApply(context.Background())
}

// C1: through Run, a write of a cloud-init key is followed by /pending and
// then exactly one GET of the VM's /cloudinit, with no query.
func TestVMFieldsEnsure_CloudInit_ReadsTheDriveStateAfterPending(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", rawRequestResults: []json.RawMessage{
		json.RawMessage(`{"digest":"d1","ipconfig0":"ip=dhcp"}`),
		json.RawMessage(`{"digest":"d1","ipconfig0":"ip=dhcp"}`),
		json.RawMessage(`{"digest":"d2","ipconfig0":"ip=10.0.0.5/24"}`),
	}, cloudInitResults: []json.RawMessage{json.RawMessage(`[{"key":"ipconfig0","value":"ip=dhcp","pending":"ip=10.0.0.5/24"}]`)}}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("ipconfig0", "ip=10.0.0.5/24")}
	res, err := Run(context.Background(), testRosterPath(t), lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}, op, false)
	if err != nil || res.PostApplyErr != nil {
		t.Fatalf("Run = %v, PostApplyErr %v", err, res.PostApplyErr)
	}
	want := []string{
		"GET /nodes/qa-pve-01/qemu/100/config?",
		"GET /nodes/qa-pve-01/qemu/100/config?",
		"GET /nodes/qa-pve-01/qemu/100/config?",
		"GET /nodes/qa-pve-01/qemu/100/pending?",
		"GET /nodes/qa-pve-01/qemu/100/cloudinit?",
	}
	if !slices.Equal(client.rawCalls, want) {
		t.Errorf("raw requests:\n got:  %q\n want: %q", client.rawCalls, want)
	}
	if !slices.Equal(op.CloudInitStale, []string{"ipconfig0"}) {
		t.Errorf("CloudInitStale = %q, want [ipconfig0]", op.CloudInitStale)
	}
}

// C2: a Run that changed no cloud-init key never reads /cloudinit.
func TestVMFieldsEnsure_CloudInit_NoCloudInitKeyNoRead(t *testing.T) {
	op := &VMFieldsEnsure{Applied: []string{"cores", "network", "ipconfig", "netx"}, Deleted: []string{"description"}}
	client, err := postApplyCI(t, op, `[]`, `[{"key":"ipconfig0","pending":"x"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if client.cloudInitCalls != 0 || op.CloudInitStale != nil {
		t.Errorf("cloud-init reads = %d, stale = %q; want none for a Run that changed no cloud-init key", client.cloudInitCalls, op.CloudInitStale)
	}
}

// C3: only this Run's own cloud-init keys that the drive does not hold yet
// are reported, in the order applied: not one already on the drive, not one
// someone else changed, never a non-cloud-init key.
func TestVMFieldsEnsure_CloudInit_ReportsOnlyThisRunsStaleKeys(t *testing.T) {
	op := &VMFieldsEnsure{Applied: []string{"sshkeys", "cores", "ipconfig1", "ciuser"}}
	_, err := postApplyCI(t, op, `[]`, `[
		{"key":"ciuser","value":"old","pending":"new"},
		{"key":"sshkeys","value":"k"},
		{"key":"ipconfig1","value":"ip=dhcp","pending":"ip=10.0.0.6/24"},
		{"key":"nameserver","value":"1.1.1.1","pending":"9.9.9.9"},
		{"key":"cores","pending":4}
	]`)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ipconfig1", "ciuser"}; !slices.Equal(op.CloudInitStale, want) {
		t.Errorf("CloudInitStale = %q, want %q", op.CloudInitStale, want)
	}
}

// C4: a cloud-init key this Run deleted that the drive still holds
// ("delete": 1) is a stale delete; one someone else deleted is not reported.
func TestVMFieldsEnsure_CloudInit_ReportsThisRunsStaleDeletes(t *testing.T) {
	op := &VMFieldsEnsure{Deleted: []string{"ciuser", "description"}}
	_, err := postApplyCI(t, op, `[]`, `[{"key":"ciuser","value":"old","delete":1},{"key":"searchdomain","value":"x","delete":1}]`)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(op.CloudInitStaleDeletes, []string{"ciuser"}) || op.CloudInitStale != nil {
		t.Errorf("CloudInitStaleDeletes = %q, CloudInitStale = %q; want [ciuser] and none", op.CloudInitStaleDeletes, op.CloudInitStale)
	}
}

// C5: a cloud-init key /pending already reported is not reported again;
// when every cloud-init key of the Run is already pending, /cloudinit is not
// read at all.
func TestVMFieldsEnsure_CloudInit_NeverDoubleReportsAPendingKey(t *testing.T) {
	op := &VMFieldsEnsure{Applied: []string{"ipconfig0"}}
	client, err := postApplyCI(t, op, `[{"key":"ipconfig0","pending":"x"}]`, `[{"key":"ipconfig0","pending":"x"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(op.Pending, []string{"ipconfig0"}) || op.CloudInitStale != nil || client.cloudInitCalls != 0 {
		t.Errorf("Pending %q, CloudInitStale %q, cloud-init reads %d; want [ipconfig0], none, 0", op.Pending, op.CloudInitStale, client.cloudInitCalls)
	}

	op = &VMFieldsEnsure{Applied: []string{"ipconfig0", "sshkeys"}}
	client, err = postApplyCI(t, op, `[{"key":"ipconfig0","pending":"x"}]`, `[{"key":"ipconfig0","pending":"x"},{"key":"sshkeys","pending":"k"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(op.CloudInitStale, []string{"sshkeys"}) || client.cloudInitCalls != 1 {
		t.Errorf("CloudInitStale %q, reads %d; want [sshkeys] and one read", op.CloudInitStale, client.cloudInitCalls)
	}
}

// C6: a /cloudinit answer no healthy PVE gives is ErrUnverifiableRead,
// never "nothing stale", and what /pending found is kept.
func TestVMFieldsEnsure_CloudInit_UnverifiablePayload(t *testing.T) {
	for name, payload := range map[string]string{
		"null":           `null`,
		"an object":      `{"ciuser":{"pending":"x"}}`,
		"an entry null":  `[null]`,
		"no key":         `[{"pending":"x"}]`,
		"an empty key":   `[{"key":"","pending":"x"}]`,
		"delete 3":       `[{"key":"ciuser","delete":3}]`,
		"delete a word":  `[{"key":"ciuser","delete":"yes"}]`,
		"a string":       `"ciuser"`,
		"a non-string k": `[{"key":7}]`,
	} {
		t.Run(name, func(t *testing.T) {
			op := &VMFieldsEnsure{Applied: []string{"cores", "ciuser"}}
			_, err := postApplyCI(t, op, `[{"key":"cores","pending":4}]`, payload)
			if !errors.Is(err, pve.ErrUnverifiableRead) || !strings.Contains(err.Error(), "cloud-init") {
				t.Fatalf("err = %v, want ErrUnverifiableRead naming the cloud-init read", err)
			}
			if !slices.Equal(op.Pending, []string{"cores"}) || op.CloudInitStale != nil {
				t.Errorf("Pending %q, CloudInitStale %q: want /pending's finding kept, and nothing from the bad answer", op.Pending, op.CloudInitStale)
			}
		})
	}
}

// C7: a failed /cloudinit read is PostApply's error, wrapping its cause.
func TestVMFieldsEnsure_CloudInit_ReadFailure(t *testing.T) {
	cause := errors.New("connection reset")
	client := &fakeClient{node: "qa-pve-01", cloudInitErr: cause}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Applied: []string{"sshkeys"}}
	err := op.PostApply(context.Background())
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "read the cloud-init drive's state") {
		t.Fatalf("err = %v, want the cause wrapped by the cloud-init read", err)
	}
}

// C8: which keys are cloud-init keys: the named set (name — the guest's
// hostname — included), and ipconfigN or netN for a decimal N only.
func TestIsCloudInitKey(t *testing.T) {
	for _, k := range []string{"ciuser", "cipassword", "citype", "ciupgrade", "cicustom", "sshkeys", "nameserver", "searchdomain", "name", "ipconfig0", "ipconfig12", "net0", "net31"} {
		if !isCloudInitKey(k) {
			t.Errorf("%q is a cloud-init key", k)
		}
	}
	for _, k := range []string{"ipconfig", "ipconfigx", "ipconfig1a", "net", "netx", "net0a", "network", "names", "cores", "cicustomx", "Ciuser", ""} {
		if isCloudInitKey(k) {
			t.Errorf("%q is not a cloud-init key", k)
		}
	}
}

// C9: PostApply resets its cloud-init findings, so a second PostApply that
// finds nothing does not report the first one's.
func TestVMFieldsEnsure_CloudInit_ResetsItsFindings(t *testing.T) {
	op := &VMFieldsEnsure{Applied: []string{"ciuser"}}
	if _, err := postApplyCI(t, op, `[]`, `[{"key":"ciuser","pending":"x"}]`); err != nil || op.CloudInitStale == nil {
		t.Fatalf("first PostApply: %v, %q", err, op.CloudInitStale)
	}
	op.Applied = nil
	if _, err := postApplyCI(t, op, `[]`, `[{"key":"ciuser","pending":"x"}]`); err != nil || op.CloudInitStale != nil {
		t.Errorf("second PostApply: %v, CloudInitStale %q; want the first finding cleared", err, op.CloudInitStale)
	}
}

// C10 (RCI1): name, the guest's hostname on the drive, and netN, whose MAC
// is in the drive's network config, trigger the read and are reported.
func TestVMFieldsEnsure_CloudInit_NameAndNetAreCloudInitKeys(t *testing.T) {
	op := &VMFieldsEnsure{Applied: []string{"name", "net0"}}
	client, err := postApplyCI(t, op, `[]`, `[{"key":"name","value":"a","pending":"b"},{"key":"net0","value":"virtio=AA","pending":"virtio=BB"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if client.cloudInitCalls != 1 || !slices.Equal(op.CloudInitStale, []string{"name", "net0"}) {
		t.Errorf("reads %d, CloudInitStale %q; want 1 and [name net0]", client.cloudInitCalls, op.CloudInitStale)
	}
}

// C11 (RCI2): a failed or unverifiable cloud-init check is a
// *CloudInitCheckError, unwrapping to its cause, so the caller can say it
// was the drive check that went unanswered; a failed /pending read is not.
func TestVMFieldsEnsure_CloudInit_FailureIsMarked(t *testing.T) {
	var ce *CloudInitCheckError
	cause := errors.New("connection reset")
	op := &VMFieldsEnsure{Client: &fakeClient{node: "qa-pve-01", cloudInitErr: cause}, VMID: 100, Applied: []string{"sshkeys"}}
	if err := op.PostApply(context.Background()); !errors.As(err, &ce) || !errors.Is(err, cause) {
		t.Errorf("read failure = %v, want a *CloudInitCheckError wrapping the cause", err)
	}
	op = &VMFieldsEnsure{Applied: []string{"sshkeys"}}
	if _, err := postApplyCI(t, op, `[]`, `null`); !errors.As(err, &ce) || !errors.Is(err, pve.ErrUnverifiableRead) {
		t.Errorf("unverifiable answer = %v, want a *CloudInitCheckError wrapping ErrUnverifiableRead", err)
	}
	op = &VMFieldsEnsure{Client: &fakeClient{node: "qa-pve-01", rawRequestErr: cause}, VMID: 100, Applied: []string{"sshkeys"}}
	if err := op.PostApply(context.Background()); err == nil || errors.As(err, &ce) {
		t.Errorf("a failed /pending read = %v, want an error that is NOT a *CloudInitCheckError", err)
	}
}
