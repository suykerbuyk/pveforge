package roster

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"
)

// TestDecode_KeySpelling: a key spelled other than exactly as a roster
// field is refused at load, wherever it is written, and the error names the
// key and its line. go-toml alone would take it (see the premise check).
func TestDecode_KeySpelling(t *testing.T) {
	const head = "[[targets]]\nid = \"a\"\nhost = \"h\"\nnode = \"n\"\n"
	cases := []struct {
		name, doc, want string
	}{
		{"export, case variant", head + "Export = \"token\"\n", `roster line 5: key "Export" must be spelled "export"`},
		{"export, closed then reopened by a second spelling", head + "export = \"\"\nExport = \"token\"\n", `roster line 6: key "Export" must be spelled "export"`},
		{"host_key_fingerprint, overridden by a second spelling", head + "\n[targets.ssh]\nuser = \"root\"\nhost_key_fingerprint = \"SHA256:pinned\"\nHost_Key_Fingerprint = \"SHA256:other\"\n", `roster line 9: key "Host_Key_Fingerprint" must be spelled "host_key_fingerprint"`},
		{"host_key_fingerprint, dotted", head + "ssh.HOST_KEY_FINGERPRINT = \"SHA256:other\"\n", `roster line 5: key "HOST_KEY_FINGERPRINT" must be spelled "host_key_fingerprint"`},
		{"host_key_fingerprint, inline table", head + "ssh = { user = \"root\", Host_key_fingerprint = \"SHA256:other\" }\n", `roster line 5: key "Host_key_fingerprint" must be spelled "host_key_fingerprint"`},
		{"table header", "[[Targets]]\nid = \"a\"\nhost = \"h\"\nnode = \"n\"\n", `roster line 1: key "Targets" must be spelled "targets"`},
		{"subtable header", head + "\n[targets.Token]\nid = \"x\"\n", `roster line 6: key "Token" must be spelled "token"`},
		{"inline array of targets", "targets = [{ id = \"a\", host = \"h\", node = \"n\", eXport = \"token\" }]\n", `roster line 1: key "eXport" must be spelled "export"`},
		{"unknown key", head + "exprot = \"token\"\n", `roster line 5: key "exprot" is not a roster key in [targets]`},
		{"unknown top-level key", "comment = \"x\"\n", `roster line 1: key "comment" is not a roster key at the top level`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode([]byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Decode = %v, want an error containing %q", err, tc.want)
			}
		})
	}
	// Every key spelled exactly, in every form, still loads.
	withTestWorkFactor(t)
	enc := sampleArmored(t, "s", "pw")
	ok := "[[targets]]\nid = \"a\"\nhost = \"h\"\nnode = \"n\"\napi_port = 8006\ninsecure_tls = true\nexport = \"token\"\n" +
		"ssh = { user = \"root\", host_key_fingerprint = \"SHA256:x\", private_key_enc = '''" + enc + "''' }\n" +
		"[[targets]]\nid = \"b\"\nhost = \"h\"\nnode = \"n\"\n[targets.token]\nid = \"u@pve!t\"\nsecret_enc = '''\n" + enc + "'''\n" +
		"[targets.ssh]\nuser = \"root\"\npublic_key = \"k\"\nhost_key_fingerprint = \"SHA256:y\"\nprivate_key_enc = '''\n" + enc + "'''\n"
	if _, err := Decode([]byte(ok)); err != nil {
		t.Errorf("a roster spelled exactly: %v", err)
	}
}

// TestDecode_KeySpelling_Premise: go-toml on its own matches keys
// case-insensitively and lets the last spelling win, which is what
// checkKeys closes. If go-toml ever stops doing this, the check is still
// right, but this test says the premise changed.
func TestDecode_KeySpelling_Premise(t *testing.T) {
	var r Roster
	doc := "[[targets]]\nid = \"a\"\nhost = \"h\"\nnode = \"n\"\nexport = \"\"\nExport = \"token\"\n\n[targets.ssh]\nhost_key_fingerprint = \"SHA256:pinned\"\nHost_Key_Fingerprint = \"SHA256:other\"\n"
	if err := toml.Unmarshal([]byte(doc), &r); err != nil {
		t.Fatalf("go-toml refuses the document itself: %v", err)
	}
	if got := r.Targets[0].Export; got != ExportToken {
		t.Errorf("go-toml read export as %q; the premise was %q", got, ExportToken)
	}
	if got := r.Targets[0].SSH.HostKeyFingerprint; got != "SHA256:other" {
		t.Errorf("go-toml read host_key_fingerprint as %q; the premise was the second spelling", got)
	}
}

// TestRosterKeys_MatchTheTypes: rosterKeys lists exactly the toml tags of
// Roster, Target, TokenAuth and SSHAuth, so a field added to the types
// cannot be refused at load, and a key dropped from them cannot linger.
func TestRosterKeys_MatchTheTypes(t *testing.T) {
	tags := func(v any) []string {
		var out []string
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			out = append(out, strings.Split(rt.Field(i).Tag.Get("toml"), ",")[0])
		}
		slices.Sort(out)
		return out
	}
	for table, v := range map[string]any{"": Roster{}, "targets": Target{}, "targets.token": TokenAuth{}, "targets.ssh": SSHAuth{}} {
		got := slices.Clone(rosterKeys[table])
		slices.Sort(got)
		if want := tags(v); !slices.Equal(got, want) {
			t.Errorf("rosterKeys[%q] = %q, the type's toml tags are %q", table, got, want)
		}
	}
	if len(rosterKeys) != 4 {
		t.Errorf("rosterKeys has %d tables, want 4", len(rosterKeys))
	}
}
