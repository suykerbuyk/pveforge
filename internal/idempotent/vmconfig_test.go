package idempotent

import (
	"strings"
	"testing"

	proxmox "github.com/luthermonson/go-proxmox"
)

func TestRequireVMConfig_NilConfig_ReturnsError(t *testing.T) {
	vm := &proxmox.VirtualMachine{}

	cfg, err := requireVMConfig(vm, 100, "vm tag ensure")
	if err == nil {
		t.Fatal("expected an error for a nil VirtualMachineConfig")
	}
	if cfg != nil {
		t.Errorf("expected a nil config returned alongside the error, got %+v", cfg)
	}
	if !strings.Contains(err.Error(), "vm tag ensure") || !strings.Contains(err.Error(), "100") {
		t.Errorf("error %q should mention the op name and vmid", err.Error())
	}
}

func TestRequireVMConfig_PresentConfig_ReturnsIt(t *testing.T) {
	want := &proxmox.VirtualMachineConfig{Tags: "prod", Digest: "d1"}
	vm := &proxmox.VirtualMachine{VirtualMachineConfig: want}

	cfg, err := requireVMConfig(vm, 100, "vm tag ensure")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != want {
		t.Errorf("requireVMConfig returned a different config than vm.VirtualMachineConfig")
	}
}
