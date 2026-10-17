package outer

import "regexp"

// snapnameRE ports lib.sh:134 HARNESS_SNAPNAME_RE: a snapshot name starts
// with a letter and is letters/digits/_/- thereafter. Anchored here.
var snapnameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)

// ValidSnapshotName reports whether name matches the harness snapshot-name
// shape (lib.sh:134).
func ValidSnapshotName(name string) bool { return snapnameRE.MatchString(name) }

// fieldAllowed is the per-verb field allow-list, a port of
// _harness_field_allowed (lib.sh:302-310). It is fail-closed: only the exact
// (set, key) pairs the shell permits return true. U-CORE's verbs use the
// snapshot / rollback / start / stop / shutdown / destroy sets; the create
// set (and its disk/net screening, _harness_disk_ok/_net_ok) belongs to the
// VM-create path, which U-CORE does not ship (it is U-BUILD's).
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
