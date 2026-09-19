package pve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// Regression tests for pveforge-status-error-pin-bump (P2 of
// pveforge-read-status-swallow). go-proxmox v0.8.2-pveforge.1 returns a
// typed *proxmox.StatusError for every non-2xx answer, where .0 decoded a
// 404/502-504/595-599 {"data":null} body into a zero value with a nil
// error. P1's unverifiable-read guards caught most of those zero values on
// .0, so "the read refused" is green on both pins; what only .1 delivers is
// that the refusal names the STATUS, not an unverifiable payload. Every
// cause-agnostic assertion here therefore checks both halves: the error
// text carries the HTTP status line, and it is not ErrUnverifiableRead.

// statusLine is the res.Status Go's own HTTP/1.1 server sends for code,
// which is what a *proxmox.StatusError's Error() reports: the reason phrase
// for a registered code, "status code N" for PVE's private 59x codes.
func statusLine(code int) string {
	if text := http.StatusText(code); text != "" {
		return fmt.Sprintf("%d %s", code, text)
	}
	return fmt.Sprintf("%d status code %d", code, code)
}

// requireStatusCause fails unless err is a refusal whose cause is the HTTP
// status itself: the error names the status line, and it is not the
// unverifiable-payload refusal P1 produces for the same fixture on .0.
func requireStatusCause(t *testing.T, err error, code int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a refusal naming %q, got a nil error", statusLine(code))
	}
	if !strings.Contains(err.Error(), statusLine(code)) {
		t.Errorf("error %q does not name the status %q", err, statusLine(code))
	}
	if errors.Is(err, ErrUnverifiableRead) {
		t.Errorf("error %q is ErrUnverifiableRead: the status never reached the caller, only its null payload did", err)
	}
}

// statusReadCase is one go-proxmox-backed read (a c.pc call site), the path
// that is made to fail, and any healthy routes the read needs first.
type statusReadCase struct {
	name    string
	path    string
	healthy map[string]string // path -> 200 body, served alongside
	read    func(ctx context.Context, c *Client) error
}

// statusReadCases covers every c.pc call site in internal/pve: the 14
// c.pc.Get lines, both c.pc.Nodes calls, both Cluster.Resources reads, and
// Task.Ping behind WaitForTask. A new c.pc read belongs in this table.
func statusReadCases() []statusReadCase {
	const upid = "UPID:n1:00001234:00005678:12345678:qmstart:4242:root@pam:"
	return []statusReadCase{
		{"GetNode", "/nodes/n1/status", nil, func(ctx context.Context, c *Client) error {
			_, err := c.GetNode(ctx, "n1")
			return err
		}},
		{"GetNodes", "/nodes", nil, func(ctx context.Context, c *Client) error {
			_, err := c.GetNodes(ctx)
			return err
		}},
		{"ListNodes", "/nodes", nil, func(ctx context.Context, c *Client) error {
			_, err := c.ListNodes(ctx)
			return err
		}},
		{"FindByTag", "/cluster/resources", nil, func(ctx context.Context, c *Client) error {
			_, err := c.FindByTag(ctx, "web")
			return err
		}},
		{"TagStillClaimed", "/cluster/resources", nil, func(ctx context.Context, c *Client) error {
			_, err := c.TagStillClaimed(ctx, "web", 4242)
			return err
		}},
		{"storageContentWithType", "/nodes/n1/storage/local/content", nil, func(ctx context.Context, c *Client) error {
			_, err := c.storageContentWithType(ctx, "n1", "local")
			return err
		}},
		{"GetNetworkInterface", "/nodes/n1/network/vmbr7", nil, func(ctx context.Context, c *Client) error {
			_, err := c.GetNetworkInterface(ctx, "n1", "vmbr7")
			return err
		}},
		{"GetNetworkInterfaces", "/nodes/n1/network", nil, func(ctx context.Context, c *Client) error {
			_, err := c.GetNetworkInterfaces(ctx, "n1")
			return err
		}},
		{"ListSnapshots", "/nodes/n1/qemu/4242/snapshot", nil, func(ctx context.Context, c *Client) error {
			_, err := c.ListSnapshots(ctx, "n1", 4242)
			return err
		}},
		{"NextVMID/unpinned", "/cluster/nextid", nil, func(ctx context.Context, c *Client) error {
			_, err := c.NextVMID(ctx, 0)
			return err
		}},
		{"vmidFree", "/cluster/nextid", nil, func(ctx context.Context, c *Client) error {
			_, err := c.vmidFree(ctx, 4242)
			return err
		}},
		{"GetStorage", "/nodes/n1/storage/local/status", nil, func(ctx context.Context, c *Client) error {
			_, err := c.GetStorage(ctx, "n1", "local")
			return err
		}},
		{"GetStorages", "/nodes/n1/storage", nil, func(ctx context.Context, c *Client) error {
			_, err := c.GetStorages(ctx, "n1")
			return err
		}},
		{"GetStorageConfigPath", "/storage/local", nil, func(ctx context.Context, c *Client) error {
			_, err := c.GetStorageConfigPath(ctx, "local")
			return err
		}},
		{"GetStorageVolumes", "/nodes/n1/storage/local/content", nil, func(ctx context.Context, c *Client) error {
			_, err := c.GetStorageVolumes(ctx, "n1", "local")
			return err
		}},
		{"GetVM/status", "/nodes/n1/qemu/4242/status/current", map[string]string{
			"/nodes/n1/qemu/4242/config": `{"data":{"digest":"d","name":"web"}}`,
		}, func(ctx context.Context, c *Client) error {
			_, err := c.GetVM(ctx, "n1", 4242)
			return err
		}},
		{"GetVM/config", "/nodes/n1/qemu/4242/config", map[string]string{
			"/nodes/n1/qemu/4242/status/current": `{"data":{"vmid":4242,"status":"running"}}`,
		}, func(ctx context.Context, c *Client) error {
			_, err := c.GetVM(ctx, "n1", 4242)
			return err
		}},
		{"GetVMs", "/nodes/n1/qemu", nil, func(ctx context.Context, c *Client) error {
			_, err := c.GetVMs(ctx, "n1")
			return err
		}},
		{"WaitForTask", "/nodes/n1/tasks/*", nil, func(ctx context.Context, c *Client) error {
			return c.WaitForTask(ctx, "n1", upid)
		}},
	}
}

// TestStatusReads_NonSuccessStatusReachesTheCaller is P2-1's cause-agnostic
// half: every c.pc read answered 404 or 595 {"data":null} must refuse with
// the status itself. On v0.8.2-pveforge.0 each row either succeeded
// silently or refused as ErrUnverifiableRead.
func TestStatusReads_NonSuccessStatusReachesTheCaller(t *testing.T) {
	for _, tc := range statusReadCases() {
		for _, code := range []int{404, 595} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, code), func(t *testing.T) {
				// WaitForTask retries a 595 poll; keep its sleeps short.
				withTaskTimings(t, time.Millisecond, time.Second)
				s := newRouteServer(t)
				for p, b := range tc.healthy {
					s.on("GET", p, 200, b)
				}
				s.on("GET", tc.path, code, nullData)
				requireStatusCause(t, tc.read(context.Background(), s.client()), code)
			})
		}
	}
}

// TestStatusReads_StatusErrorIsTyped is P2-1's typed half: the same reads
// hand callers a *proxmox.StatusError carrying the code, and
// proxmox.IsNotFound is true for the 404 only. PVE reports a missing object
// as a 500, so a 404 here means a wrong path or a proxy, never "absent".
func TestStatusReads_StatusErrorIsTyped(t *testing.T) {
	for _, tc := range statusReadCases() {
		for _, code := range []int{404, 595} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, code), func(t *testing.T) {
				withTaskTimings(t, time.Millisecond, time.Second)
				s := newRouteServer(t)
				for p, b := range tc.healthy {
					s.on("GET", p, 200, b)
				}
				s.on("GET", tc.path, code, nullData)
				err := tc.read(context.Background(), s.client())
				var se *proxmox.StatusError
				if !errors.As(err, &se) {
					t.Fatalf("expected a *proxmox.StatusError in the chain, got %v", err)
				}
				if se.StatusCode != code {
					t.Errorf("StatusCode = %d, want %d", se.StatusCode, code)
				}
				if got := proxmox.IsNotFound(err); got != (code == 404) {
					t.Errorf("proxmox.IsNotFound = %v for a %d", got, code)
				}
			})
		}
	}
}
