package pve

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// StopVM issues PVE's stop-VM call — POST /nodes/{node}/qemu/{vmid}/status/stop
// — a hard, immediate stop (distinct from a graceful shutdown, which this
// project has no separate command for yet — see pveforge-vm-lifecycle-ops's
// own per-child breakdown). VMDestroy's Apply calls this as a best-effort
// step before the hard destroy below: PVE refuses to destroy a running VM,
// so a caller destroying a VM that happens to already be stopped, or that
// PVE won't stop for some transient reason, must not be blocked by that —
// see VMDestroy's own doc comment (internal/idempotent/vmdestroy.go) on why
// the stop step never fails Apply.
//
// Goes through RawRequest, like CreateVM, so PVE's own diagnostic text on
// a rejection reaches the caller verbatim: go-proxmox's error for a
// non-2xx has only the HTTP status line as its text, whose reason phrase
// HTTP/2 erases (through v0.8.2-pveforge.0 it discarded the body of a
// 500/501 outright).
//
// Returns the UPID of the PVE task the stop call kicks off, for the caller
// to hand to WaitForTask.
func (c *Client) StopVM(ctx context.Context, node string, vmid int) (string, error) {
	if node == "" {
		return "", fmt.Errorf("stop vm %d: node is required", vmid)
	}

	raw, err := c.RawRequest(ctx, http.MethodPost, fmt.Sprintf("/nodes/%s/qemu/%d/status/stop", url.PathEscape(node), vmid), nil)
	if err != nil {
		return "", fmt.Errorf("stop vm %d: %w", vmid, err)
	}

	upid, err := decodeUPIDScalar(raw)
	if err != nil {
		return "", fmt.Errorf("stop vm %d: %w", vmid, err)
	}
	return upid, nil
}

// DestroyVM issues PVE's destroy-VM call — DELETE /nodes/{node}/qemu/{vmid}
// — via RawRequest rather than go-proxmox's own VirtualMachine.Delete, so
// that PVE's diagnostic text on a destroy-time rejection (typically a 500)
// reaches the caller verbatim: go-proxmox's error for a non-2xx, a
// *proxmox.StatusError since v0.8.2-pveforge.1 (through .0 the body of a
// 500/501 was discarded outright), has only the HTTP status line as its
// text, whose reason phrase HTTP/2 erases.
//
// purge, when true, sends PVE's own "purge=1" parameter: beyond deleting
// the VM's own config and disks, purge additionally strips the destroyed
// vmid from cluster-level config objects that reference it BY ID but live
// outside the VM's own config file — backup-job vmid lists, replication
// job config, HA resource config. It does NOT delete backup archives, and
// does NOT touch storage volumes beyond the VM's own disks (those follow
// their own separate PVE-side lifecycle). VMDestroy's Apply always passes
// purge=true: an unpurged destroy would leave dangling vmid references in
// those cluster objects behind — exactly the silent-partial-success class
// this project's other Ops (VMFieldsEnsure, VMTagEnsure) already go out of
// their way to avoid — with no current caller needing a knob to disable it.
//
// Returns the UPID of the PVE task the destroy call kicks off, for the
// caller to hand to WaitForTask.
func (c *Client) DestroyVM(ctx context.Context, node string, vmid int, purge bool) (string, error) {
	if node == "" {
		return "", fmt.Errorf("destroy vm %d: node is required", vmid)
	}

	params := url.Values{}
	if purge {
		params.Set("purge", "1")
	}

	raw, err := c.RawRequest(ctx, http.MethodDelete, fmt.Sprintf("/nodes/%s/qemu/%d", url.PathEscape(node), vmid), params)
	if err != nil {
		return "", fmt.Errorf("destroy vm %d: %w", vmid, err)
	}

	upid, err := decodeUPIDScalar(raw)
	if err != nil {
		return "", fmt.Errorf("destroy vm %d: %w", vmid, err)
	}
	return upid, nil
}

// TagStillClaimed reports whether any QEMU VM OTHER than excludeVMID still
// carries tag, via the same underlying primitive FindByTag uses
// (GET /cluster/resources through (&proxmox.Cluster{}).New(c.pc), never
// c.pc.Cluster(ctx) — see FindByTag's own doc comment on why) rather than
// FindByTag itself: FindByTag's own reviewed 0/1/many contract has no way
// to express "ignore this one specific match," which is exactly what a
// post-destroy recheck needs — a just-destroyed VM can still appear in
// /cluster/resources briefly (cache lag), and this recheck must tolerate
// that instead of treating it as a real finding.
//
// Tag matching mirrors FindByTag exactly: an exact semicolon-split element
// match against a resource's Tags, never a substring match (the "qng" vs
// "qng-template" false-positive class FindByTag's own doc comment warns
// against), restricted to Type == "qemu" resources.
//
// A true result is informational, not an error condition this function
// itself judges — VMDestroy's caller decides what a genuine duplicate-tag
// finding means for their workflow. This function only answers the
// narrow, tolerant question its name asks.
func (c *Client) TagStillClaimed(ctx context.Context, tag string, excludeVMID int) (bool, error) {
	if tag == "" {
		return false, fmt.Errorf("tag still claimed: tag is required")
	}

	cluster := (&proxmox.Cluster{}).New(c.pc)
	resources, err := cluster.Resources(ctx, "vm")
	if err != nil {
		return false, fmt.Errorf("tag still claimed %q: %w", tag, err)
	}
	if resources == nil {
		return false, fmt.Errorf("tag still claimed %q: %w: resource list payload was null", tag, ErrUnverifiableRead)
	}
	if i := nullEntry(resources); i >= 0 {
		return false, fmt.Errorf("tag still claimed %q: %w: resource list entry %d is null", tag, ErrUnverifiableRead, i)
	}

	exclude := uint64(excludeVMID)
	for _, r := range resources {
		if r.Type != "qemu" || r.VMID == exclude {
			continue
		}
		for _, t := range strings.Split(r.Tags, proxmox.TagSeperator) {
			if t == tag {
				return true, nil
			}
		}
	}
	return false, nil
}
