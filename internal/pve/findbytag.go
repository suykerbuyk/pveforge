package pve

import (
	"context"
	"errors"
	"fmt"
	"strings"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// ErrNotFound indicates FindByTag's tag matched no cluster resource.
//
// Not to be confused with proxmox.ErrNotFound, which a *proxmox.StatusError
// matches for an HTTP 404. A 404 on /cluster/resources makes FindByTag
// return an error matching proxmox.ErrNotFound, NOT this sentinel: that
// read failed (a wrong path or a proxy — PVE itself reports a missing
// object as a 500), which says nothing about whether any resource carries
// the tag. The two mean different things and are deliberately not unified.
var ErrNotFound = errors.New("no resource matches the given tag")

// ErrAmbiguousTag indicates FindByTag's tag matched more than one cluster
// resource, so the caller's assumption that a tag identifies a single VM
// does not hold — the caller must disambiguate rather than have FindByTag
// guess.
var ErrAmbiguousTag = errors.New("tag matches more than one resource")

// FindByTag looks up the single QEMU VM in the cluster carrying tag as one
// of its (semicolon-separated) tags, via GET /cluster/resources.
//
// Deliberately builds the cluster handle with (&proxmox.Cluster{}).New(c.pc)
// rather than c.pc.Cluster(ctx): the latter makes an unconditional, unrelated
// GET /cluster/status call before returning (see go-proxmox's cluster.go),
// doubling round-trips and widening the failure surface for a lookup that
// has nothing to do with cluster status. Cluster.New is the exported,
// no-API-call constructor.
//
// Server-side "type=vm" also returns LXC containers, so results are
// filtered client-side to Type == "qemu" — matching every other
// internal/pve VM call, which is QEMU-only. A tag match is an exact element
// match against a resource's semicolon-split Tags, never a substring match:
// a lookup for tag "qng" must not match a resource tagged
// "qng-template;other".
//
// Three-way result: zero matches wraps ErrNotFound, exactly one match
// returns that resource, and more than one wraps ErrAmbiguousTag.
func (c *Client) FindByTag(ctx context.Context, tag string) (*proxmox.ClusterResource, error) {
	if tag == "" {
		return nil, fmt.Errorf("find by tag: tag is required")
	}
	if strings.Contains(tag, proxmox.TagSeperator) {
		return nil, fmt.Errorf("find by tag: tag %q contains the tag separator %q", tag, proxmox.TagSeperator)
	}

	cluster := (&proxmox.Cluster{}).New(c.pc)
	resources, err := cluster.Resources(ctx, "vm")
	if err != nil {
		return nil, fmt.Errorf("find by tag %q: %w", tag, err)
	}
	if resources == nil {
		return nil, fmt.Errorf("find by tag %q: %w: resource list payload was null", tag, ErrUnverifiableRead)
	}
	if i := nullEntry(resources); i >= 0 {
		return nil, fmt.Errorf("find by tag %q: %w: resource list entry %d is null", tag, ErrUnverifiableRead, i)
	}

	var matches []*proxmox.ClusterResource
	for _, r := range resources {
		if r.Type != "qemu" {
			continue
		}
		for _, t := range strings.Split(r.Tags, proxmox.TagSeperator) {
			if t == tag {
				matches = append(matches, r)
				break
			}
		}
	}

	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("find by tag %q: %w", tag, ErrNotFound)
	case 1:
		return matches[0], nil
	default:
		return nil, fmt.Errorf("find by tag %q: %d matches: %w", tag, len(matches), ErrAmbiguousTag)
	}
}
