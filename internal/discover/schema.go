// Package discover is pveforge-discoverability-schema's (PRD §3.5)
// two-layer schema/discovery library: every noun and verb pveforge
// exposes should be walkable top-down without static documentation.
//
// Layer 1, PVE's own generic object model (nodes, VMs, storage,
// network), is exposed by proxying PVE's own static API-doc schema tree
// (apidoc.js — the same doc-generation artifact both `pvesh usage` and
// the web API-viewer are ultimately built from) — see PVEObjectSchema,
// ParseAPITree, and pve.Client.APIDocTree. Deliberately a passthrough,
// not a translation into Schema below or any other dialect: PRD §3.5
// calls for "expose/proxy this schema rather than hand-authoring a
// parallel one," and a translation layer would itself be a second,
// hand-maintained schema representation that could drift from PVE's
// actual (version-dependent) shape — exactly the risk that instruction
// exists to avoid.
//
// Layer 1 was originally designed around a live per-path HTTP OPTIONS
// request instead (mirroring what was assumed to be pvesh's own
// mechanism); that assumption was verified FALSE against a live PVE
// 9.2.11 cluster on 2026-09-14 — PVE's API daemon rejects HTTP OPTIONS
// unconditionally, for every path, before auth or routing ever runs. See
// pve.Client.APIDocTree's doc comment for the full evidence and the
// corrected mechanism this package now uses instead.
//
// Layer 2, pveforge's own bespoke device-semantic resolvers (currently
// just device.NVMeDrive), is invisible to Proxmox's schema — to Proxmox,
// args: is just an opaque string — so it has to be hand-authored (see
// NVMeDriveSchema). It's described using the Schema type below, which
// happens to reuse PVE's own OPTIONS vocabulary (type/description/
// optional/default/enum/pattern): not because the two layers are
// required to share one identical dialect (they don't; layer 1 is
// whatever PVE returns, unreshaped), but because that vocabulary is
// already reasonable and self-explanatory, and reusing it is cheaper
// than inventing a second one for layer 2 alone.
package discover

// Schema is the field-level vocabulary layer 2's hand-authored
// descriptions use (see NVMeDriveSchema). Layer 1 (PVEObjectSchema) does
// NOT use this type — it returns PVE's own response shape verbatim.
type Schema struct {
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
	// Pattern is a regex a string value must match, when set — see
	// nvme.go's allowedExtraToPattern for how NVMeDriveSchema derives
	// these from device.NVMeDrive's own validation constants rather than
	// restating them independently.
	Pattern    string            `json:"pattern,omitempty"`
	Optional   bool              `json:"optional,omitempty"`
	Default    any               `json:"default,omitempty"`
	Enum       []any             `json:"enum,omitempty"`
	Properties map[string]Schema `json:"properties,omitempty"`
	Required   []string          `json:"required,omitempty"`
}
