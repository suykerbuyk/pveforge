package device

import (
	"context"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// fakeClient is a scriptable Client, shared by every resolver's tests in
// this package — no network, no pve package dependency.
type fakeClient struct {
	node string

	getVMResult *proxmox.VirtualMachine
	getVMErr    error

	setFieldErr error

	getVMCalls    int
	lastGetVMNode string
	lastGetVMID   int

	setFieldCalls int
	lastVMID      int
	lastField     string
	lastValue     string
}

func (f *fakeClient) GetVM(_ context.Context, node string, vmid int) (*proxmox.VirtualMachine, error) {
	f.getVMCalls++
	f.lastGetVMNode = node
	f.lastGetVMID = vmid
	if f.getVMErr != nil {
		return nil, f.getVMErr
	}
	if f.getVMResult != nil {
		return f.getVMResult, nil
	}
	return &proxmox.VirtualMachine{}, nil
}

func (f *fakeClient) Node() string {
	return f.node
}

func (f *fakeClient) SetVMConfigField(_ context.Context, vmid int, field, value string) error {
	f.setFieldCalls++
	f.lastVMID = vmid
	f.lastField = field
	f.lastValue = value
	return f.setFieldErr
}
