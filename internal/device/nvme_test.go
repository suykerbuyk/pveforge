package device

import (
	"context"
	"errors"
	"strings"
	"testing"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

func TestNVMeDrive_Validate(t *testing.T) {
	cases := []struct {
		name    string
		drive   NVMeDrive
		wantErr bool
	}{
		{"valid, no format", NVMeDrive{Serial: "SN123", Backing: "/dev/pve/vm-100-disk-1"}, false},
		{"valid, with format", NVMeDrive{Serial: "SN-123_x", Backing: "/var/lib/vz/images/100/disk.raw", Format: "raw"}, false},
		{"missing serial", NVMeDrive{Backing: "/dev/pve/vm-100-disk-1"}, true},
		{"missing backing", NVMeDrive{Serial: "SN123"}, true},
		{"serial with comma", NVMeDrive{Serial: "SN,123", Backing: "/dev/pve/vm-100-disk-1"}, true},
		{"serial with space", NVMeDrive{Serial: "SN 123", Backing: "/dev/pve/vm-100-disk-1"}, true},
		{"serial with quote", NVMeDrive{Serial: `SN"123`, Backing: "/dev/pve/vm-100-disk-1"}, true},
		{"backing with comma", NVMeDrive{Serial: "SN123", Backing: "/dev/pve/vm-100,disk-1"}, true},
		{"backing with space", NVMeDrive{Serial: "SN123", Backing: "/dev/pve/vm 100"}, true},
		{"format with comma", NVMeDrive{Serial: "SN123", Backing: "/dev/pve/vm-100-disk-1", Format: "raw,evil=1"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.drive.Validate()
			if c.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// backingCases is every Backing the check must decide, shared with the
// schema agreement test through BackingCasesForTest.
// Accepted: absolute, clean host paths (dir, LVM and zvol volumes).
// Refused: QEMU protocol syntax, a PVE volid (not a path QEMU can open),
// relative paths, "." and ".." segments, "//", a trailing '/', "/" alone,
// ':' anywhere, ',' and whitespace. Nothing sensitive is refused by name:
// the path is a trust decision for whoever configures it (Backing's doc).
var backingCases = []struct {
	Backing string
	OK      bool
}{
	{"/var/lib/vz/images/100/vm-100-disk-1.raw", true},
	{"/dev/pve/vm-100-disk-1", true},
	{"/dev/zvol/rpool/data/vm-100-disk-1", true},
	{"/etc/shadow", true},
	{"/a/.hidden", true},
	{"/a/b..c", true},
	{"nbd:qa-pve-01:10809", false},
	{"nbd://qa-pve-01/export", false},
	{"ssh://root@qa-pve-01/disk.raw", false},
	{"http://example.com/disk.raw", false},
	{"local-lvm:vm-100-disk-1", false},
	{"rel/path.raw", false},
	{"disk.raw", false},
	{"/a/../b", false},
	{"/..", false},
	{"/a/./b", false},
	{"/a/...", false},
	{"//a", false},
	{"/a//b", false},
	{"/a/", false},
	{"/", false},
	{"/a:b", false},
	{"/dev/pve/vm-100,disk-1", false},
	{"/dev/pve/vm 100", false},
	{"/dev/pve/vm\t100", false},
	{"", false},
}

func TestNVMeDrive_Validate_Backing(t *testing.T) {
	for _, c := range backingCases {
		err := NVMeDrive{Serial: "SN123", Backing: c.Backing}.Validate()
		if (err == nil) != c.OK {
			t.Errorf("Validate(backing %q) = %v, want ok=%v", c.Backing, err, c.OK)
		}
	}
}

// BackingCasesForTest exposes backingCases to the external test package
// (schema_agreement_test.go), the export_test idiom: declared in a
// _test.go file, it exists only in test builds.
var BackingCasesForTest = backingCases

func TestNVMeDrive_Apply_FragmentAndMerge(t *testing.T) {
	client := &fakeClient{
		node: "qa-pve-01",
		getVMResult: &proxmox.VirtualMachine{
			VirtualMachineConfig: &proxmox.VirtualMachineConfig{Args: "-cpu host"},
		},
	}
	drive := NVMeDrive{Serial: "SN123", Backing: "/dev/pve/vm-100-disk-1", Format: "raw"}

	if err := drive.Apply(context.Background(), client, 100); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if client.getVMCalls != 1 {
		t.Fatalf("expected exactly one GetVM call, got %d", client.getVMCalls)
	}
	if client.lastGetVMNode != "qa-pve-01" || client.lastGetVMID != 100 {
		t.Errorf("GetVM called with node=%q vmid=%d, want qa-pve-01/100", client.lastGetVMNode, client.lastGetVMID)
	}

	if client.setFieldCalls != 1 {
		t.Fatalf("expected exactly one SetVMConfigField call, got %d", client.setFieldCalls)
	}
	if client.lastVMID != 100 || client.lastField != "args" {
		t.Errorf("SetVMConfigField called with vmid=%d field=%q, want 100/args", client.lastVMID, client.lastField)
	}

	want := "-cpu host -device nvme,drive=nvme-SN123,serial=SN123 -drive file=/dev/pve/vm-100-disk-1,if=none,id=nvme-SN123,format=raw"
	if client.lastValue != want {
		t.Errorf("merged args = %q, want %q", client.lastValue, want)
	}
}

func TestNVMeDrive_Apply_NoFormat(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01"}
	drive := NVMeDrive{Serial: "SN123", Backing: "/dev/pve/vm-100-disk-1"}

	if err := drive.Apply(context.Background(), client, 100); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	want := "-device nvme,drive=nvme-SN123,serial=SN123 -drive file=/dev/pve/vm-100-disk-1,if=none,id=nvme-SN123"
	if client.lastValue != want {
		t.Errorf("args = %q, want %q", client.lastValue, want)
	}
}

func TestNVMeDrive_Apply_EmptyExistingArgs(t *testing.T) {
	client := &fakeClient{
		node: "qa-pve-01",
		getVMResult: &proxmox.VirtualMachine{
			VirtualMachineConfig: &proxmox.VirtualMachineConfig{Args: ""},
		},
	}
	drive := NVMeDrive{Serial: "SN123", Backing: "/dev/pve/vm-100-disk-1"}

	if err := drive.Apply(context.Background(), client, 100); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if strings.HasPrefix(client.lastValue, " ") {
		t.Errorf("merged args should not have a leading space when existing args was empty: %q", client.lastValue)
	}
}

func TestNVMeDrive_Apply_NilVirtualMachineConfig(t *testing.T) {
	// GetVM's result can carry a nil VirtualMachineConfig (e.g. a VM with
	// no config fetched yet in some hypothetical caller-supplied fake) —
	// Apply must not panic dereferencing it.
	client := &fakeClient{node: "qa-pve-01", getVMResult: &proxmox.VirtualMachine{}}
	drive := NVMeDrive{Serial: "SN123", Backing: "/dev/pve/vm-100-disk-1"}

	if err := drive.Apply(context.Background(), client, 100); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

func TestNVMeDrive_Apply_InvalidDrive(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01"}
	drive := NVMeDrive{Serial: "", Backing: "/dev/pve/vm-100-disk-1"}

	if err := drive.Apply(context.Background(), client, 100); err == nil {
		t.Fatal("expected an error for an invalid drive")
	}
	if client.getVMCalls != 0 {
		t.Error("should not call GetVM when validation fails")
	}
	if client.setFieldCalls != 0 {
		t.Error("should not call SetVMConfigField when validation fails")
	}
}

func TestNVMeDrive_Apply_GetVMFailure(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", getVMErr: errors.New("network down")}
	drive := NVMeDrive{Serial: "SN123", Backing: "/dev/pve/vm-100-disk-1"}

	err := drive.Apply(context.Background(), client, 100)
	if err == nil {
		t.Fatal("expected an error when GetVM fails")
	}
	if !strings.Contains(err.Error(), "network down") {
		t.Errorf("expected the underlying error to be preserved, got: %v", err)
	}
	if client.setFieldCalls != 0 {
		t.Error("should not call SetVMConfigField when GetVM failed")
	}
}

func TestNVMeDrive_Apply_SetVMConfigFieldFailure(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", setFieldErr: errors.New("only root can set 'args' config")}
	drive := NVMeDrive{Serial: "SN123", Backing: "/dev/pve/vm-100-disk-1"}

	err := drive.Apply(context.Background(), client, 100)
	if err == nil {
		t.Fatal("expected an error when SetVMConfigField fails")
	}
	if !strings.Contains(err.Error(), "only root can set") {
		t.Errorf("expected the underlying error to be preserved, got: %v", err)
	}
}

func TestIsSafeToken(t *testing.T) {
	if isSafeToken("", "") {
		t.Error("empty string should be unsafe")
	}
	if !isSafeToken("abcXYZ123", "") {
		t.Error("plain alnum should be safe")
	}
	if isSafeToken("a,b", "") {
		t.Error("comma should be unsafe by default")
	}
	if !isSafeToken("a-b_c", "-_") {
		t.Error("extra-allowed runes should be safe when included in extra")
	}
	if isSafeToken("a-b", "") {
		t.Error("dash should be unsafe when not in extra")
	}
}
