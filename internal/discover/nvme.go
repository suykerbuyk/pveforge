package discover

import (
	"strings"

	"github.com/suykerbuyk/pveforge/internal/device"
)

// NVMeDriveSchema is pveforge's own hand-authored description of
// device.NVMeDrive — layer 2 of PRD §3.5's discoverability model: this
// device-semantic intent is invisible to Proxmox's own schema, since to
// Proxmox args: is just an opaque string, so its shape has to be authored
// by hand rather than inherited from PVE's OPTIONS introspection
// (contrast PVEObjectSchema, layer 1).
//
// Hand-authored rather than reflection/struct-tag-generated: with exactly
// one resolver in existence, designing a general convention now would
// very likely be shaped around NVMeDrive's own particular fields and need
// an awkward redesign the moment a second resolver (BMC, PCIe — still
// just PRD examples, not built) arrives with a different shape — see
// pveforge-discoverability-schema's own recorded decision. Revisit once
// there are 2-3 real resolvers to generalize from.
//
// Pattern fields are DERIVED from device.NVMeSerialAllowedExtra/
// NVMeBackingAllowedExtra/NVMeFormatAllowedExtra (internal/device/
// nvme.go) via allowedExtraToPattern, rather than restated as independent
// regexes — those constants are exactly what NVMeDrive.Validate itself
// checks against, so this schema can never silently drift from the real
// validation logic as long as both read the same constants.
var NVMeDriveSchema = Schema{
	Type:        "object",
	Description: "An emulated NVMe drive attached via the args: raw-QEMU escape hatch (Proxmox has no first-class NVMe bus type).",
	Properties: map[string]Schema{
		"serial": {
			Type:        "string",
			Description: "The drive's emulated serial number, surfaced inside the guest OS.",
			Pattern:     allowedExtraToPattern(device.NVMeSerialAllowedExtra),
		},
		"backing": {
			Type:        "string",
			Description: `The QEMU -drive file= target: a PVE volid (e.g. "local-lvm:vm-100-disk-1") or a raw host path.`,
			Pattern:     allowedExtraToPattern(device.NVMeBackingAllowedExtra),
		},
		"format": {
			Type:        "string",
			Description: `The QEMU -drive format= value (e.g. "raw", "qcow2"). PVE/QEMU infer it when unset.`,
			Optional:    true,
			Pattern:     allowedExtraToPattern(device.NVMeFormatAllowedExtra),
		},
	},
	Required: []string{"serial", "backing"},
}

// DeviceSchemas is the complete set of layer-2 hand-authored schemas,
// keyed by resolver type name.
//
// DELIBERATELY BRITTLE, on purpose: this must be updated by hand the
// moment a second device-semantic resolver is added to internal/device —
// there is no reflection/registry mechanism generating this list (see
// NVMeDriveSchema's own doc comment on why). TestDeviceSchemas_OneEntry
// (nvme_test.go) asserts this map has exactly one entry today; that
// assertion is meant to force a conscious, visible update when it no
// longer holds, rather than let a new resolver silently go undescribed.
var DeviceSchemas = map[string]Schema{
	"NVMeDrive": NVMeDriveSchema,
}

// allowedExtraToPattern turns an isSafeToken-style "extra allowed
// characters" string (device.NVMeSerialAllowedExtra and siblings) into
// the equivalent ^[...]+$ regex: ASCII letters and digits are always
// allowed (isSafeToken's own baseline), plus whatever's in extra.
//
// Every character from extra is escaped with a backslash before being
// placed in the character class, including '-' (alongside the always-
// special '\', ']', '^') — purely as defense-in-depth for inputs this
// function doesn't see today, not a fix for an active bug: verified
// (regexp.MatchString, both by hand and in
// TestAllowedExtraToPattern_TrailingHyphenIsLiteral) that Go's RE2
// already parses a single trailing '-' straight after a completed range
// like "0-9" as a literal hyphen, not as a second range operator reaching
// back into the already-consumed '9' — there being only one '-' in either
// of NVMeSerialAllowedExtra/NVMeBackingAllowedExtra, it can't complete a
// second "atom-atom" triple no matter where it sits. Escaping it anyway
// costs nothing and removes any need to reason about ordering if extra
// ever gained a second '-' or a different arrangement.
func allowedExtraToPattern(extra string) string {
	var b strings.Builder
	b.WriteString("^[A-Za-z0-9")
	for _, r := range extra {
		if strings.ContainsRune(`\^]-`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteString("]+$")
	return b.String()
}
