package idempotent

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/pve"
)

// Regression tests for pveforge-status-error-pin-bump (P2 of
// pveforge-read-status-swallow), at the Op layer. Each drives a REAL
// *pve.Client, so the status reaches the Op exactly as it would in
// production.
//
// A bare "Read refuses" assertion is not enough here: on
// v0.8.2-pveforge.0, P1's unverifiable-read guards already refuse the same
// 595 {"data":null} fixtures, so such a test is green on both pins. What
// only .1 delivers is that the refusal names the status. Each test
// therefore asserts that the error carries the status line AND is not
// pve.ErrUnverifiableRead.

// uvStatus595 is the res.Status Go's HTTP/1.1 server sends for PVE's
// private 595 code, which a *proxmox.StatusError reports as its Error().
const uvStatus595 = "595 status code 595"

func requireStatus595Cause(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a refusal naming %q, got a nil error", uvStatus595)
	}
	if !strings.Contains(err.Error(), uvStatus595) {
		t.Errorf("error %q does not name the status %q", err, uvStatus595)
	}
	if errors.Is(err, pve.ErrUnverifiableRead) {
		t.Errorf("error %q is ErrUnverifiableRead: the status never reached the Op, only its null payload did", err)
	}
}

// statusGetVMClient serves GetVM and Node from a real *pve.Client and
// leaves every other method of the embedded interface nil: these tests only
// ever call an Op's Read.
type statusGetVMClient struct {
	Client
	pc *pve.Client
}

func (c *statusGetVMClient) Node() string { return uvNode }
func (c *statusGetVMClient) GetVM(ctx context.Context, node string, vmid int) (*proxmox.VirtualMachine, error) {
	return c.pc.GetVM(ctx, node, vmid)
}

type statusShutdownClient struct {
	VMShutdownClient
	pc *pve.Client
}

func (c *statusShutdownClient) Node() string { return uvNode }
func (c *statusShutdownClient) GetVM(ctx context.Context, node string, vmid int) (*proxmox.VirtualMachine, error) {
	return c.pc.GetVM(ctx, node, vmid)
}

// VMTagEnsure never uses the run status, but a status/current read that
// PVE could not answer still makes the whole VM read unusable, and the
// refusal must say why.
func TestVMTagEnsure_Read_StatusOnly595RefusesNamingTheStatus(t *testing.T) {
	s := newUVServer(t)
	s.on("GET", fmt.Sprintf("/nodes/%s/qemu/%d/status/current", uvNode, uvVMID), uvReply{595, uvNull})
	s.on("GET", fmt.Sprintf("/nodes/%s/qemu/%d/config", uvNode, uvVMID), uvReply{200, `{"data":{"digest":"d","tags":"web"}}`})

	op := &VMTagEnsure{Client: &statusGetVMClient{pc: s.client()}, VMID: uvVMID, Tag: "db"}
	_, err := op.Read(context.Background())
	requireStatus595Cause(t, err)
}

// VMShutdown never uses the config, but a config read PVE could not answer
// must not let a shutdown decide anything, and the refusal must say why.
func TestVMShutdown_Read_ConfigOnly595RefusesNamingTheStatus(t *testing.T) {
	s := newUVServer(t)
	s.on("GET", fmt.Sprintf("/nodes/%s/qemu/%d/status/current", uvNode, uvVMID), uvReply{200, fmt.Sprintf(`{"data":{"vmid":%d,"status":"running"}}`, uvVMID)})
	s.on("GET", fmt.Sprintf("/nodes/%s/qemu/%d/config", uvNode, uvVMID), uvReply{595, uvNull})

	op := &VMShutdown{Client: &statusShutdownClient{pc: s.client()}, VMID: uvVMID}
	_, err := op.Read(context.Background())
	requireStatus595Cause(t, err)
}

// P2-5: VMCreate.Read's documented contract is that ANY GetVM error reads
// as absent, leaving PVE's own create call authoritative. A status error
// must not change that: the create is still issued, exactly once.
func TestVMCreate_EndToEnd_StatusErrorGetVMIsAbsentAndCreates(t *testing.T) {
	for _, code := range []int{404, 595} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			upid := uvUPID("qmcreate", uvVMID)
			s := newUVServer(t)
			s.on("GET", fmt.Sprintf("/nodes/%s/qemu/%d/status/current", uvNode, uvVMID), uvReply{code, uvNull})
			s.on("GET", fmt.Sprintf("/nodes/%s/qemu/%d/config", uvNode, uvVMID), uvReply{code, uvNull})
			s.on("POST", fmt.Sprintf("/nodes/%s/qemu", uvNode), uvReply{200, fmt.Sprintf(`{"data":%q}`, upid)})
			uvTaskOK(s, upid)

			op := &VMCreate{Client: &realPVEClientAdapter{Client: s.client(), node: uvNode}, VMID: uvVMID,
				Params: url.Values{"cores": {"2"}}}
			res, err := Run(context.Background(), testRosterPath(t), uvKey(uvVMID), op, false)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if posts := s.count("POST", fmt.Sprintf("/nodes/%s/qemu", uvNode)); posts != 1 {
				t.Fatalf("expected exactly 1 create POST, got %d (Changed=%v)", posts, res.Changed)
			}
			if !res.Changed {
				t.Error("expected Changed=true")
			}
		})
	}
}
