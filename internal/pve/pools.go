package pve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

// storageIDRE is PVE's storage id format, pve-storage-id, which pve-common's
// parse_id checks as m/^[a-z][a-z0-9\-\_\.]*[a-z0-9]\z/i.
var storageIDRE = regexp.MustCompile(`(?i)^[a-z][a-z0-9_.-]*[a-z0-9]$`)

// PoolMembers reads GET /pools?poolid=<poolid> and returns the ACL paths of
// the pool's members: /vms/<vmid> for a guest (qemu, lxc or openvz) and
// /storage/<id> for a storage. The answer is decoded strictly: it must be
// exactly one entry whose poolid is the one asked for, with a members array
// (an empty pool has members: []), and every member must be an object of a
// known type with a positive integer vmid or a storage id in PVE's format.
// Anything else is ErrUnverifiableRead — never an empty membership. Extra
// fields are allowed.
//
// Source-derived (pve-manager API2/Pool.pm), NOT live-captured: the method
// is user => 'all' and, when poolid is given, its Pool.Audit check discards
// its own result (Pool.pm:97, harness task F10), so any authenticated
// caller reads any named pool; members is always set when poolid is given.
// PVE builds the list from user.cfg but skips a guest absent from the
// cluster vmlist, so it can be a subset of what the permission tree derives
// from pool membership: an orphaned pool entry, whose VM config is gone
// while user.cfg still lists it (a hand-deleted config or a corrupted
// cluster filesystem; a destroy that dies mid-way leaves its config, so the
// VM still lists as a member).
func (c *Client) PoolMembers(ctx context.Context, poolid string) (map[string]bool, error) {
	raw, err := c.RawRequest(ctx, http.MethodGet, "/pools", url.Values{"poolid": {poolid}})
	if err != nil {
		return nil, fmt.Errorf("read members of pool %s: %w", poolid, err)
	}
	members, err := decodePoolMembers(raw, poolid)
	if err != nil {
		return nil, fmt.Errorf("read members of pool %s: %w", poolid, err)
	}
	return members, nil
}

func decodePoolMembers(raw json.RawMessage, poolid string) (map[string]bool, error) {
	var pools []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &pools); err != nil || pools == nil {
		return nil, fmt.Errorf("%w: the pool list is not a JSON array", ErrUnverifiableRead)
	}
	if len(pools) != 1 || pools[0] == nil {
		return nil, fmt.Errorf("%w: the pool list has %d entries, not the one pool asked for", ErrUnverifiableRead, len(pools))
	}
	var got string
	if err := json.Unmarshal(pools[0]["poolid"], &got); err != nil || got != poolid {
		return nil, fmt.Errorf("%w: the pool list's entry is not the pool asked for", ErrUnverifiableRead)
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(pools[0]["members"], &entries); err != nil || entries == nil {
		return nil, fmt.Errorf("%w: the pool entry carries no members array", ErrUnverifiableRead)
	}
	out := make(map[string]bool, len(entries))
	for i, e := range entries {
		if e == nil {
			return nil, fmt.Errorf("%w: member %d is not an object", ErrUnverifiableRead, i)
		}
		var typ string
		if err := json.Unmarshal(e["type"], &typ); err != nil {
			return nil, fmt.Errorf("%w: member %d has no type", ErrUnverifiableRead, i)
		}
		switch typ {
		case "qemu", "lxc", "openvz":
			// A JSON number only: json.Number would also take a quoted "690".
			var n json.Number
			if v := e["vmid"]; len(v) == 0 || v[0] == '"' || json.Unmarshal(v, &n) != nil {
				return nil, fmt.Errorf("%w: guest member %d has no numeric vmid", ErrUnverifiableRead, i)
			}
			vmid, err := strconv.Atoi(n.String())
			if err != nil || vmid <= 0 {
				return nil, fmt.Errorf("%w: guest member %d has a vmid that is not a positive integer", ErrUnverifiableRead, i)
			}
			out["/vms/"+strconv.Itoa(vmid)] = true
		case "storage":
			var id string
			if err := json.Unmarshal(e["storage"], &id); err != nil || !storageIDRE.MatchString(id) {
				return nil, fmt.Errorf("%w: storage member %d has no valid storage id", ErrUnverifiableRead, i)
			}
			out["/storage/"+id] = true
		default:
			return nil, fmt.Errorf("%w: member %d has an unknown type", ErrUnverifiableRead, i)
		}
	}
	return out, nil
}

// StorageIDs reads GET /storage, the cluster's storage configuration list,
// and returns the ids it lists. PVE filters it by the CALLER's privileges:
// from pve-storage API2/Storage/Config.pm (index, user => 'all'), an entry
// is listed only if the caller holds Datastore.Audit or
// Datastore.AllocateSpace on /storage/<id> (check_any). So a storage the
// caller cannot see is absent from the answer, exactly as one that does not
// exist. Decoded strictly: not an array, null, a null entry or an entry
// without a valid storage id is ErrUnverifiableRead. Source-derived, not
// live-captured.
func (c *Client) StorageIDs(ctx context.Context) (map[string]bool, error) {
	raw, err := c.RawRequest(ctx, http.MethodGet, "/storage", nil)
	if err != nil {
		return nil, fmt.Errorf("read storage list: %w", err)
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || entries == nil {
		return nil, fmt.Errorf("read storage list: %w: not a JSON array", ErrUnverifiableRead)
	}
	out := make(map[string]bool, len(entries))
	for i, e := range entries {
		var id string
		if e == nil || json.Unmarshal(e["storage"], &id) != nil || !storageIDRE.MatchString(id) {
			return nil, fmt.Errorf("read storage list: %w: entry %d has no valid storage id", ErrUnverifiableRead, i)
		}
		out[id] = true
	}
	return out, nil
}
