package main

import (
	"encoding/json"
	"runtime/debug"
	"strings"
	"testing"
)

func bi(version string, settings map[string]string, deps ...*debug.Module) *debug.BuildInfo {
	b := &debug.BuildInfo{GoVersion: "go1.27.4", Main: debug.Module{Path: "github.com/suykerbuyk/pveforge", Version: version}, Deps: deps}
	for k, v := range settings {
		b.Settings = append(b.Settings, debug.BuildSetting{Key: k, Value: v})
	}
	return b
}

var cleanVCS = map[string]string{"vcs": "git", "vcs.revision": strings.Repeat("a", 40), "vcs.time": "2026-11-23T00:00:00Z", "vcs.modified": "false", "CGO_ENABLED": "0", "-trimpath": "true"}

func with(m map[string]string, kv ...string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

// AC-V1..V4: the pure function, with the near-misses. The end-to-end builds in a
// throwaway repository (internal/sourceguard TestRelease_*) show how the real
// toolchain stamps each of these; this table is the logic.
func TestVersion_Table(t *testing.T) {
	yes, no := true, false
	replaced := &debug.Module{Path: "example.com/dep", Version: "v1.0.0", Replace: &debug.Module{Path: "../dep"}}
	cases := []struct {
		name         string
		in           *debug.BuildInfo
		ok           bool
		release      bool
		prerelease   bool
		stamped      bool
		dirty        *bool
		static       bool
		commit       string
		wantCommitTS string
	}{
		{"clean tag", bi("v0.1.0", cleanVCS), true, true, false, true, &no, true, strings.Repeat("a", 40), "2026-11-23T00:00:00Z"},
		{"untagged pseudo-version", bi("v0.0.0-20261123000000-091ac6186a82", cleanVCS), true, false, false, true, &no, true, strings.Repeat("a", 40), "2026-11-23T00:00:00Z"},
		{"tagged and dirty", bi("v0.1.0+dirty", with(cleanVCS, "vcs.modified", "true")), true, false, false, true, &yes, true, strings.Repeat("a", 40), "2026-11-23T00:00:00Z"},
		{"+incompatible", bi("v2.0.0+incompatible", cleanVCS), true, false, false, true, &no, true, strings.Repeat("a", 40), "2026-11-23T00:00:00Z"},
		{"release candidate", bi("v0.1.0-rc.1", cleanVCS), true, false, true, true, &no, true, strings.Repeat("a", 40), "2026-11-23T00:00:00Z"},
		{"-beta is not a pveforge prerelease", bi("v0.1.0-beta.1", cleanVCS), true, false, false, true, &no, true, strings.Repeat("a", 40), "2026-11-23T00:00:00Z"},
		{"-alpha is not a pveforge prerelease", bi("v0.1.0-alpha.1", cleanVCS), true, false, false, true, &no, true, strings.Repeat("a", 40), "2026-11-23T00:00:00Z"},
		{"-rc without a number", bi("v0.1.0-rc", cleanVCS), true, false, false, true, &no, true, strings.Repeat("a", 40), "2026-11-23T00:00:00Z"},
		{"-rc.1.2", bi("v0.1.0-rc.1.2", cleanVCS), true, false, false, true, &no, true, strings.Repeat("a", 40), "2026-11-23T00:00:00Z"},
		{"two-part version", bi("v0.1", cleanVCS), true, false, false, true, &no, true, strings.Repeat("a", 40), "2026-11-23T00:00:00Z"},
		{"no v", bi("0.1.0", cleanVCS), true, false, false, true, &no, true, strings.Repeat("a", 40), "2026-11-23T00:00:00Z"},
		{"a replace anywhere", bi("v0.1.0", cleanVCS, replaced), true, false, false, true, &no, true, strings.Repeat("a", 40), "2026-11-23T00:00:00Z"},
		{"the version says dirty, vcs.modified says clean: fail closed", bi("v0.1.0+dirty", cleanVCS), true, false, false, true, &yes, true, strings.Repeat("a", 40), "2026-11-23T00:00:00Z"},
		{"vcs.modified says dirty while the version string is plain: not release", bi("v0.1.0", with(cleanVCS, "vcs.modified", "true")), true, false, false, true, &yes, true, strings.Repeat("a", 40), "2026-11-23T00:00:00Z"},
		{"stamped but no vcs.modified: not release", bi("v0.1.0", map[string]string{"vcs": "git", "vcs.revision": "b"}), true, false, false, true, nil, false, "b", ""},
		{"unstamped export", bi("(devel)", map[string]string{"CGO_ENABLED": "0"}), true, false, false, false, nil, true, "", ""},
		{"empty version", bi("", nil), true, false, false, false, nil, false, "", ""},
		{"no build info at all", nil, false, false, false, false, nil, false, "", ""},
		{"dynamic build", bi("v0.1.0", with(cleanVCS, "CGO_ENABLED", "1")), true, true, false, true, &no, false, strings.Repeat("a", 40), "2026-11-23T00:00:00Z"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := versionInfo(c.in, c.ok)
			if r.Release != c.release || r.Prerelease != c.prerelease || r.Stamped != c.stamped || r.Static != c.static || r.Commit != c.commit || r.CommitTime != c.wantCommitTS {
				t.Errorf("got release=%v prerelease=%v stamped=%v static=%v commit=%q time=%q, want %v %v %v %v %q %q", r.Release, r.Prerelease, r.Stamped, r.Static, r.Commit, r.CommitTime, c.release, c.prerelease, c.stamped, c.static, c.commit, c.wantCommitTS)
			}
			switch {
			case c.dirty == nil && r.Dirty != nil:
				t.Errorf("dirty=%v printed for a build with no VCS verdict (it must be absent)", *r.Dirty)
			case c.dirty != nil && (r.Dirty == nil || *r.Dirty != *c.dirty):
				t.Errorf("dirty = %v, want %v", r.Dirty, *c.dirty)
			}
			if r.SchemaVersion != schemaVersion {
				t.Errorf("schema_version = %d", r.SchemaVersion)
			}
		})
	}
}

// AC-V2: an unstamped build must say so and must never print dirty=false.
func TestVersion_UnstampedPrintsNoDirtyField(t *testing.T) {
	r := versionInfo(bi("(devel)", map[string]string{"CGO_ENABLED": "0"}), true)
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), `"dirty"`) {
		t.Fatalf("an unstamped build printed a dirty field: %s", b)
	}
	if !strings.Contains(string(b), `"stamped":false`) {
		t.Fatalf("an unstamped build did not say stamped=false: %s", b)
	}
	// the control: a stamped clean build does print dirty=false
	c, _ := json.Marshal(versionInfo(bi("v0.1.0", cleanVCS), true))
	if !strings.Contains(string(c), `"dirty":false`) {
		t.Fatalf("a clean stamped build must print dirty=false: %s", c)
	}
}

// AC-V5: the flag and the command print the same kv; both exit 0; -o json has
// the same keys. The flag test also proves the root wiring (a deleted wiring
// line makes `--version` an unknown flag).
func TestVersion_FlagAndCommandAgree(t *testing.T) {
	c1, flagOut, flagErr := runRootArgs("--version")
	c2, cmdOut, cmdErr := runRootArgs("version")
	if c1 != 0 || c2 != 0 {
		t.Fatalf("exit statuses %d, %d (stderr %q, %q), want 0, 0", c1, c2, flagErr, cmdErr)
	}
	if flagOut != cmdOut {
		t.Fatalf("--version and `version` differ:\n%s\n---\n%s", flagOut, cmdOut)
	}
	for _, k := range []string{"version=", "release=", "stamped=", "go=", "static=", "schema_version="} {
		if !strings.Contains(flagOut, k) {
			t.Errorf("kv output lacks %s:\n%s", k, flagOut)
		}
	}
	c3, jsonOut, _ := runRootArgs("version", "-o", "json")
	if c3 != 0 {
		t.Fatalf("version -o json exit %d", c3)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(jsonOut), &m); err != nil {
		t.Fatalf("version -o json is not JSON: %v", err)
	}
	for _, k := range []string{"version", "stamped", "release", "prerelease", "go", "goos", "goarch", "static", "trimpath", "schema_version"} {
		if _, ok := m[k]; !ok {
			t.Errorf("json lacks %q", k)
		}
	}
}

// AC-V6: the schema's contract block is the same function's report.
func TestVersion_SchemaCarriesTheSameReport(t *testing.T) {
	code, out, errOut := runRootArgs("schema")
	if code != 0 {
		t.Fatalf("schema exit %d: %s", code, errOut)
	}
	var s commandSchema
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(s.Contract)
	want, _ := json.Marshal(&contractSchema{Pveforge: readVersion()})
	if s.Contract == nil || string(got) != string(want) {
		t.Fatalf("schema contract %s differs from readVersion() %s", got, want)
	}
	if s.SchemaVersion != schemaVersion {
		t.Fatalf("schemaVersion = %d", s.SchemaVersion)
	}
}
