package outer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// snapnameRE ports lib.sh:134 HARNESS_SNAPNAME_RE: a snapshot name starts
// with a letter and is letters/digits/_/- thereafter. Anchored here.
var snapnameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)

// ValidSnapshotName reports whether name matches the harness snapshot-name
// shape (lib.sh:134).
func ValidSnapshotName(name string) bool { return snapnameRE.MatchString(name) }

// fieldAllowed is the per-verb field allow-list, a port of
// _harness_field_allowed (lib.sh:306-311). It is fail-closed: only the exact
// (set, key) pairs the shell permits return true. The create/config sets use
// the separate three-tier screen below (ScreenCreate / ScreenConfig), the port
// of _harness_screen_fields (lib.sh:375-411) that U-BUILD owns.
func fieldAllowed(set, key string) bool {
	switch set + " " + key {
	case "snapshot snapname",
		"snapshot vmstate",
		"snapshot description",
		"rollback start",
		"start timeout",
		"stop timeout",
		"shutdown timeout",
		"shutdown forceStop",
		"destroy purge",
		"destroy destroy-unreferenced-disks":
		return true
	}
	return false
}

// AllowedField is the exported gate over fieldAllowed, so the cobra leaves
// screen every parameter they send against lib.sh's allow-list before
// issuing it.
func AllowedField(set, key string) bool { return fieldAllowed(set, key) }

// ---- create / config field screen (U-BUILD), a faithful mirror of
// _harness_config_field / _harness_disk_ok / _harness_net_ok /
// _harness_screen_fields (lib.sh:289-411). It operates on the WHOLE field set:
// an object of single-line STRING values, the control-char check on the whole
// key=value token, the key pattern, class dispatch, delete= reclassification,
// and the disk-option refusals. Nothing here is a new allow-list entry; any
// value this accepts that lib.sh rejects is a widening (operator-binding).

// Field classes, mirroring _harness_config_field's return codes (lib.sh:289-297).
const (
	classPlain   = 0 // a plain config field (lib.sh:291,293)
	classDisk    = 1 // scsi<N> / ide<N> (lib.sh:295) → DiskOK
	classRefused = 2 // anything not named (lib.sh:296)
	classNet     = 3 // net<N> (lib.sh:294) → NetOK
)

var (
	// configKeyRE is the key pattern _harness_screen_fields enforces on every
	// field (lib.sh:380): a leading lowercase letter, then [A-Za-z0-9_-].
	configKeyRE = regexp.MustCompile(`^[a-z][A-Za-z0-9_-]*$`)
	ipconfigRE  = regexp.MustCompile(`^ipconfig[0-9]+$`)   // lib.sh:293
	netIfaceRE  = regexp.MustCompile(`^net[0-9]+$`)        // lib.sh:294
	diskIfaceRE = regexp.MustCompile(`^(scsi|ide)[0-9]+$`) // lib.sh:295
	// isoRE / importRE: the two narrow disk exceptions (lib.sh:328,344).
	diskISORE    = regexp.MustCompile(`^local:iso/[A-Za-z0-9_-][A-Za-z0-9._-]*\.iso$`)
	diskImportRE = regexp.MustCompile(`^local:import/[A-Za-z0-9_-][A-Za-z0-9._-]*\.(qcow2|raw)$`)
	diskSizeRE   = regexp.MustCompile(`^([0-9]+|cloudinit)$`) // lib.sh:334
)

// plainConfigField is the fixed name-list of _harness_config_field (lib.sh:291),
// the unused-but-allowed names kept exactly (dropping them would be a tightening).
var plainConfigField = map[string]bool{
	"name": true, "cores": true, "sockets": true, "cpu": true, "memory": true,
	"balloon": true, "ostype": true, "machine": true, "bios": true, "boot": true,
	"agent": true, "serial0": true, "vga": true, "scsihw": true, "nameserver": true,
	"searchdomain": true, "ciuser": true, "sshkeys": true, "delete": true,
}

// CreateFieldClass mirrors _harness_config_field (lib.sh:289-297): the class a
// create/config field key falls into. classRefused for anything not named.
func CreateFieldClass(key string) int {
	if plainConfigField[key] {
		return classPlain
	}
	if ipconfigRE.MatchString(key) {
		return classPlain
	}
	if netIfaceRE.MatchString(key) {
		return classNet
	}
	if diskIfaceRE.MatchString(key) {
		return classDisk
	}
	return classRefused
}

// DiskOK mirrors _harness_disk_ok (lib.sh:319-352): a disk value may name only
// the required storage (a new allocation <storage>:<GiB|cloudinit>), the
// installer ISO on local as a cdrom, or a cloud image imported from
// local:import into a disk on the required storage. Its options are refused
// unless they are import-from (checked), or a bare ?*=* option that is ignored;
// file=/volume=/*=*:* and a bare token are refused.
func DiskOK(value, storage string) bool {
	first := value
	rest := ""
	if i := strings.IndexByte(value, ','); i >= 0 {
		first = value[:i]
		rest = value[i+1:]
	}
	first = strings.TrimPrefix(first, "file=") // lib.sh:324
	switch {
	case first == "none": // lib.sh:326
	case strings.HasPrefix(first, "local:iso/"): // lib.sh:327-329
		if !diskISORE.MatchString(first) || !strings.Contains(","+value+",", ",media=cdrom,") {
			return false
		}
	case strings.Contains(first, ":"): // lib.sh:330-335 — a new allocation on the required storage
		store := first[:strings.IndexByte(first, ':')]
		spec := first[strings.IndexByte(first, ':')+1:]
		if storage == "" || store != storage || !diskSizeRE.MatchString(spec) {
			return false
		}
	default: // lib.sh:336
		return false
	}
	// Option loop (lib.sh:338-351). Empty options are NOT dropped: lib.sh's loop
	// hits the `*)` arm on a bare/empty token and dies 2, so `S:8,,media=cdrom`
	// must be refused (a trailing comma, `S:8,`, leaves no option — allowed).
	for _, opt := range splitDiskOptions(rest) {
		switch {
		case strings.HasPrefix(opt, "import-from="): // lib.sh:343-346
			v := strings.TrimPrefix(opt, "import-from=")
			if !diskImportRE.MatchString(v) || storage == "" || diskStorage(first) != storage {
				return false
			}
		case strings.HasPrefix(opt, "file="), strings.HasPrefix(opt, "volume="), isKVColon(opt): // lib.sh:347
			return false
		case isIgnorableOpt(opt): // ?*=* (lib.sh:348)
		default: // lib.sh:349
			return false
		}
	}
	return true
}

// diskStorage returns the storage id of a disk's first token (before ':'); "" if none.
func diskStorage(first string) string {
	if i := strings.IndexByte(first, ':'); i >= 0 {
		return first[:i]
	}
	return ""
}

// isKVColon reports `*=*:*` (lib.sh:347): an option whose value holds a ':'
// (e.g. volume=other:vm-1-disk-0 written without the volume= prefix).
func isKVColon(opt string) bool {
	i := strings.IndexByte(opt, '=')
	return i > 0 && strings.Contains(opt[i+1:], ":")
}

// isIgnorableOpt reports `?*=*` (lib.sh:348): at least one char, then '=', then
// anything — an option shape lib.sh ignores. A bare token (no '=') is refused.
func isIgnorableOpt(opt string) bool {
	i := strings.IndexByte(opt, '=')
	return i >= 1
}

// NetOK mirrors _harness_net_ok (lib.sh:355-369): a NIC names exactly one
// bridge=, whose value is one of bridges (space-separated HARNESS_BRIDGES);
// every other option is ignored. A `bridge =x` (space) is not a bridge= option.
func NetOK(value, bridges string) bool {
	count := 0
	for _, opt := range splitNonEmpty(value, ',') {
		if strings.HasPrefix(opt, "bridge=") {
			count++
			br := strings.TrimPrefix(opt, "bridge=")
			if !strings.Contains(" "+bridges+" ", " "+br+" ") {
				return false
			}
		}
	}
	return count == 1
}

func splitNonEmpty(s string, sep byte) []string {
	var out []string
	for _, p := range strings.Split(s, string(sep)) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitDiskOptions mirrors _harness_disk_ok's option walk (lib.sh:338-341):
// `while [ -n "$rest" ]; do opt=${rest%%,*}; rest=${rest#"$opt"}; rest=${rest#,}`.
// It KEEPS interior empty options (so a bare/empty token reaches the `*)` refusal)
// but, like the shell's while-loop, yields nothing for an empty or trailing-comma
// remainder (`S:8,` → no option).
func splitDiskOptions(rest string) []string {
	var out []string
	for rest != "" {
		opt := rest
		if i := strings.IndexByte(rest, ','); i >= 0 {
			opt = rest[:i]
			rest = rest[i+1:]
		} else {
			rest = ""
		}
		out = append(out, opt)
	}
	return out
}

// ScreenCreate is the create leg of _harness_screen_fields + harness_vm_create's
// jq pre-check (lib.sh:375-411,799): the params must be an object of single-line
// STRING values; each key=value token is refused for a control character; each
// key matches the config key pattern; then class dispatch (plain ok; disk →
// DiskOK; net → NetOK; refused → die), and delete= reclassification. The create
// leg does NOT require created-by-run for a class-1 disk (lib.sh:391).
func ScreenCreate(obj map[string]json.RawMessage, storage, bridges string) error {
	for key, raw := range obj {
		// lib.sh:799 requires every value be a JSON STRING. A bare `null`
		// unmarshals into a Go string as "" (no error), so check the raw token
		// is a string (starts with '"') BEFORE unmarshal — else `{"name":null}`
		// would widen past the screen.
		if t := bytes.TrimSpace(raw); len(t) == 0 || t[0] != '"' {
			return fmt.Errorf("create params must be an object of single-line strings: field %q is not a string", key)
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("create params must be an object of single-line strings: field %q is not a string", key)
		}
		if err := screenField(key, value, storage, bridges, true, false); err != nil {
			return err
		}
	}
	return nil
}

// ScreenConfig is the config leg of _harness_screen_fields (lib.sh:375-411):
// the same per-field screen as create, PLUS the created-by-run gate on a class-1
// disk (lib.sh:391) — the eject (put config) runs it with createdByRun=true.
func ScreenConfig(fields map[string]string, storage, bridges string, createdByRun bool) error {
	for key, value := range fields {
		if err := screenField(key, value, storage, bridges, false, createdByRun); err != nil {
			return err
		}
	}
	return nil
}

// screenField is one field of _harness_screen_fields (lib.sh:378-410): the
// whole-token control-char check, the key pattern, class dispatch, and delete=
// reclassification. isCreate selects the create leg (no created-by-run gate on a
// class-1 disk, lib.sh:391).
func screenField(key, value, storage, bridges string, isCreate, createdByRun bool) error {
	if strings.ContainsFunc(key+"="+value, func(r rune) bool { return r < 0x20 || r == 0x7f }) { // lib.sh:379 whole token
		return fmt.Errorf("a field holds a control character")
	}
	if !configKeyRE.MatchString(key) { // lib.sh:380
		return fmt.Errorf("%q is not a field=value pair", key+"="+value)
	}
	switch CreateFieldClass(key) {
	case classPlain:
	case classDisk: // lib.sh:390-392
		if !isCreate && !createdByRun {
			return fmt.Errorf("disk %s may be set only on a VM this run created", key)
		}
		if !DiskOK(value, storage) {
			return fmt.Errorf("disk %s=%s is not a new allocation on the required storage %q, the installer ISO, or an import from local:import", key, value, storage)
		}
	case classNet: // lib.sh:394
		if !NetOK(value, bridges) {
			return fmt.Errorf("NIC %s=%s must name exactly one bridge, one of: %s", key, value, bridges)
		}
	default: // lib.sh:395 classRefused
		return fmt.Errorf("field %s is not allowed here", key)
	}
	if key == "delete" { // lib.sh:397-409 — reclassify each named item
		for _, item := range splitDeleteItems(value) {
			switch CreateFieldClass(item) {
			case classPlain, classNet: // lib.sh:404
				if item == "delete" {
					return fmt.Errorf("delete=%s is not allowed", value)
				}
			case classDisk: // lib.sh:405-406
				if !createdByRun {
					return fmt.Errorf("disk %s may be deleted only on a VM this run created", item)
				}
			default: // lib.sh:407
				return fmt.Errorf("delete of field %s is not allowed", item)
			}
		}
	}
	return nil
}

// splitDeleteItems splits a delete= value on space, comma and semicolon
// (lib.sh:401 IFS=' ,;'), dropping empties.
func splitDeleteItems(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == ',' || r == ';' })
}
