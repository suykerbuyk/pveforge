package outer

import (
	"encoding/json"
	"strings"
	"testing"
)

// These tests PIN the create/config screen by calling it DIRECTLY (the §0C gap:
// harness_build_test.go asserts only the positive create shape; the field-screen
// refusals live here). Each case is a value lib.sh rejects — a mutant that opens
// the screen turns the matching case green→red.

// obj builds a ScreenCreate object (all values JSON strings) from a Go map.
func obj(fields map[string]string) map[string]json.RawMessage {
	m := make(map[string]json.RawMessage, len(fields))
	for k, v := range fields {
		b, _ := json.Marshal(v)
		m[k] = b
	}
	return m
}

// nodeCreate / nfsCreate are the real build create matrices (build.sh:365-382),
// the positive control: they must pass ScreenCreate.
func nodeCreate() map[string]string {
	return map[string]string{
		"name": "pvh-n1", "ostype": "l26", "cpu": "host", "cores": "4", "memory": "16384",
		"bios": "seabios", "scsihw": "virtio-scsi-single",
		"scsi0": "pveforge-harness:128",
		"ide2":  "local:iso/pvh-n1-auto.iso,media=cdrom",
		"net0":  "virtio=02:00:00:00:00:90,bridge=vmbr0,firewall=0",
		"boot":  "order=scsi0;ide2",
	}
}
func nfsCreate() map[string]string {
	return map[string]string{
		"name": "pvh-nfs", "ostype": "l26", "cpu": "host", "cores": "2", "memory": "2048",
		"bios": "seabios", "scsihw": "virtio-scsi-single",
		"scsi0": "pveforge-harness:0,import-from=local:import/debian-13-genericcloud-amd64.qcow2",
		"scsi1": "pveforge-harness:200", "ide2": "pveforge-harness:cloudinit",
		"net0": "virtio=02:00:00:00:00:92,bridge=vmbr0,firewall=0",
		"boot": "order=scsi0", "agent": "1",
		"ipconfig0": "ip=192.0.2.92/24,gw=192.0.2.1", "nameserver": "192.0.2.53",
		"searchdomain": "pvh.example.invalid", "ciuser": "pvh",
		"sshkeys": "ssh-ed25519%20AAAA%20nested",
	}
}

func TestScreenCreate_PositiveMatrices(t *testing.T) {
	for name, fields := range map[string]map[string]string{"node": nodeCreate(), "nfs": nfsCreate()} {
		if err := ScreenCreate(obj(fields), "pveforge-harness", "vmbr0"); err != nil {
			t.Errorf("%s create matrix refused by the screen: %v", name, err)
		}
	}
}

func TestScreenCreate_Refusals(t *testing.T) {
	base := nodeCreate()
	with := func(mut func(map[string]string)) map[string]json.RawMessage {
		f := nodeCreate()
		mut(f)
		return obj(f)
	}
	cases := map[string]map[string]json.RawMessage{
		// (a) an unknown field is class 2.
		"unknown field hookscript": with(func(f map[string]string) { f["hookscript"] = "x" }),
		"unknown field lock":       with(func(f map[string]string) { f["lock"] = "backup" }),
		"tags in the create body":  with(func(f map[string]string) { f["tags"] = "x" }),
		// (b) the key pattern: a leading uppercase.
		"uppercase key Tags":  with(func(f map[string]string) { f["Tags"] = "x" }),
		"uppercase key SCSI0": with(func(f map[string]string) { f["SCSI0"] = "pveforge-harness:8" }),
		// (f) disk option refusals.
		"disk file= option":   with(func(f map[string]string) { f["scsi0"] = "pveforge-harness:8,file=local:iso/evil.iso" }),
		"disk volume= option": with(func(f map[string]string) { f["scsi0"] = "pveforge-harness:8,volume=other:vm-1-disk-0" }),
		"disk *=*:* option":   with(func(f map[string]string) { f["scsi0"] = "pveforge-harness:8,serial=a:b" }),
		// (g) import-from storage mismatch (distinct from a bad path).
		"import-from off-storage disk": with(func(f map[string]string) { f["scsi0"] = "other:0,import-from=local:import/x.qcow2" }),
		// (h) a disk off the required storage.
		"disk off storage": with(func(f map[string]string) { f["scsi0"] = "local-lvm:8" }),
		// (i) a net on a bridge not in HARNESS_BRIDGES.
		"net off bridge": with(func(f map[string]string) { f["net0"] = "virtio=02:00:00:00:00:90,bridge=vmbr9,firewall=0" }),
	}
	for name, o := range cases {
		if err := ScreenCreate(o, "pveforge-harness", "vmbr0"); err == nil {
			t.Errorf("%s: screen accepted a value lib.sh rejects (widening)", name)
		}
	}
	_ = base

	// (c) a non-string JSON value.
	if err := ScreenCreate(map[string]json.RawMessage{"cores": json.RawMessage(`4`)}, "pveforge-harness", "vmbr0"); err == nil {
		t.Error("screen accepted a non-string value")
	}
	// (d) a control character — in the KEY (backstopped by the key pattern) and
	// in the VALUE (a newline that would let one value read as two fields; only
	// the whole-token control-char check catches this).
	if err := ScreenCreate(map[string]json.RawMessage{"na\nme": json.RawMessage(`"x"`)}, "pveforge-harness", "vmbr0"); err == nil {
		t.Error("screen accepted a control character in the key")
	}
	if err := ScreenCreate(map[string]json.RawMessage{"name": json.RawMessage(`"x\ny"`)}, "pveforge-harness", "vmbr0"); err == nil {
		t.Error("screen accepted a control character in a value")
	}
}

func TestScreenConfig_DeleteReclassificationAndCreatedByRun(t *testing.T) {
	// The eject fields pass the config leg when created-by-run.
	eject := map[string]string{"ide2": "none,media=cdrom", "boot": "order=scsi0"}
	if err := ScreenConfig(eject, "pveforge-harness", "vmbr0", true); err != nil {
		t.Errorf("eject fields refused on the config leg: %v", err)
	}
	// (j) a class-1 disk on the config leg requires created-by-run.
	if err := ScreenConfig(map[string]string{"ide2": "none,media=cdrom"}, "pveforge-harness", "vmbr0", false); err == nil {
		t.Error("config leg accepted a disk on a VM this run did not create")
	}
	// (e) delete= reclassification: a class-2 item and the literal delete item.
	if err := ScreenConfig(map[string]string{"delete": "hookscript"}, "pveforge-harness", "vmbr0", true); err == nil {
		t.Error("delete=hookscript accepted")
	}
	if err := ScreenConfig(map[string]string{"delete": "delete"}, "pveforge-harness", "vmbr0", true); err == nil {
		t.Error("delete=delete accepted")
	}
	// A disk delete item needs created-by-run.
	if err := ScreenConfig(map[string]string{"delete": "scsi1"}, "pveforge-harness", "vmbr0", false); err == nil {
		t.Error("delete of a disk accepted on a VM this run did not create")
	}
	// A plain delete item (e.g. ide2 the whole drive) is allowed with created-by-run.
	if err := ScreenConfig(map[string]string{"delete": "ide2"}, "pveforge-harness", "vmbr0", true); err != nil {
		t.Errorf("delete=ide2 refused for a created VM: %v", err)
	}
}

// TestScreenCreate_NullRejected (C1): a JSON null value unmarshals into a Go
// string as "" with no error, so it must be rejected by the raw-token check —
// lib.sh:799 requires type=="string". Reverting the raw[0]!='"' guard re-accepts it.
func TestScreenCreate_NullRejected(t *testing.T) {
	for _, raw := range []string{`null`, `4`, `true`, `[]`, `{}`} {
		if err := ScreenCreate(map[string]json.RawMessage{"name": json.RawMessage(raw)}, "pveforge-harness", "vmbr0"); err == nil {
			t.Errorf("ScreenCreate accepted a non-string value %s (lib.sh:799 requires a string)", raw)
		}
	}
	// A real quoted string still passes.
	if err := ScreenCreate(map[string]json.RawMessage{"name": json.RawMessage(`"pvh-n1"`)}, "pveforge-harness", "vmbr0"); err != nil {
		t.Errorf("ScreenCreate refused a valid string value: %v", err)
	}
}

// TestScreenCreate_KeyPatternErrorText (C3): an uppercase key is refused either
// way (class-2 backstops it), so the key pattern is pinned by its ERROR TEXT —
// dropping configKeyRE changes the message from "is not a field=value pair" to
// the class refusal, which this assertion catches.
func TestScreenCreate_KeyPatternErrorText(t *testing.T) {
	err := ScreenCreate(map[string]json.RawMessage{"Tags": json.RawMessage(`"x"`)}, "pveforge-harness", "vmbr0")
	if err == nil || !strings.Contains(err.Error(), "is not a field=value pair") {
		t.Errorf("uppercase key error = %v, want the key-pattern message %q", err, "is not a field=value pair")
	}
}

// TestScreenCreate_CreateLegSkipsCreatedByRun is the control for (j): the CREATE
// leg must NOT require created-by-run on a class-1 disk (lib.sh:391) — else the
// shell's own create would be refused.
func TestScreenCreate_CreateLegSkipsCreatedByRun(t *testing.T) {
	if err := ScreenCreate(obj(map[string]string{"name": "x", "scsi0": "pveforge-harness:8"}), "pveforge-harness", "vmbr0"); err != nil {
		t.Errorf("create leg refused a disk (it must not require created-by-run): %v", err)
	}
}

func TestDiskOK_And_NetOK(t *testing.T) {
	// DiskOK positive forms (incl. a trailing comma — lib.sh's while-loop yields
	// no option for it, so it stays allowed).
	for _, v := range []string{
		"pveforge-harness:128", "pveforge-harness:0,import-from=local:import/x.qcow2",
		"pveforge-harness:cloudinit", "local:iso/pvh-n1-auto.iso,media=cdrom",
		"none,media=cdrom", "file=none", "pveforge-harness:8,",
	} {
		if !DiskOK(v, "pveforge-harness") {
			t.Errorf("DiskOK(%q) = false, want true", v)
		}
	}
	// DiskOK refusals, incl. C2: an empty (double-comma) option — lib.sh's `*)`
	// arm die-2s on it; splitNonEmpty used to drop it (a widening).
	for _, v := range []string{
		"local-lvm:8", "pveforge-harness:8,file=x", "pveforge-harness:8,volume=o:vm-1-disk-0",
		"pveforge-harness:8,serial=a:b", "other:0,import-from=local:import/x.qcow2",
		"local:iso/x.iso" /* no media=cdrom */, "pveforge-harness:xyz", "pveforge-harness:8,bare",
		"pveforge-harness:8,,media=cdrom", "pveforge-harness:0,,import-from=local:import/x.qcow2",
	} {
		if DiskOK(v, "pveforge-harness") {
			t.Errorf("DiskOK(%q) = true, want false", v)
		}
	}
	// C2 (net): lib.sh's _harness_net_ok has NO default arm — it IGNORES a double
	// comma (counts one bridge → OK). Refusing it would be a TIGHTENING away from
	// lib.sh, so NetOK must still ACCEPT it (faithful mirror; grok's C2 net claim
	// was wrong, imp2 F1 correct).
	if !NetOK("virtio=aa,bridge=vmbr0,,firewall=0", "vmbr0") {
		t.Error("NetOK rejected a double-comma net value lib.sh accepts (would be a tightening)")
	}
	// NetOK: exactly one bridge in the set.
	if !NetOK("virtio=aa,bridge=vmbr0,firewall=0", "vmbr0") {
		t.Error("NetOK rejected a valid vmbr0 nic")
	}
	for _, v := range []string{"virtio=aa,bridge=vmbr9", "virtio=aa", "bridge=vmbr0,bridge=vmbr0"} {
		if NetOK(v, "vmbr0") {
			t.Errorf("NetOK(%q) = true, want false", v)
		}
	}
}
