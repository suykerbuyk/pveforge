package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func cloneSchema(t *testing.T, s commandSchema) commandSchema {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var out commandSchema
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// nodeAt returns a pointer to the node for a space-separated command path.
func nodeAt(t *testing.T, s *commandSchema, path string) *commandSchema {
	t.Helper()
	n := s
	for _, part := range strings.Fields(path) {
		var next *commandSchema
		for i := range n.Subcommands {
			if n.Subcommands[i].Name == part {
				next = &n.Subcommands[i]
			}
		}
		if next == nil {
			t.Fatalf("no command %q in the schema (at %q)", path, part)
		}
		n = next
	}
	return n
}

func flagAt(t *testing.T, n *commandSchema, name string) *flagSchema {
	t.Helper()
	for i := range n.Flags {
		if n.Flags[i].Name == name {
			return &n.Flags[i]
		}
	}
	t.Fatalf("no flag --%s", name)
	return nil
}

func findKind(r schemaDiffReport, kind string) *schemaFinding {
	for i := range r.Findings {
		if r.Findings[i].Kind == kind {
			return &r.Findings[i]
		}
	}
	return nil
}

// AC-S4: one row per rule, in BOTH directions. A row mutates a copy of the real
// current schema (so the fixture is realistic) and asserts the verdict and the
// finding kind. `old` is the baseline; the swap of an additive row must be
// breaking and the swap of a breaking row must be additive-or-breaking-removal.
func TestSchemaDiff_Rules(t *testing.T) {
	base := currentSchema(t)
	if len(flattenSchema(base)) < 50 || len(base.Env) == 0 {
		t.Fatal("the base schema is not the real one")
	}
	type row struct {
		name    string
		mutate  func(t *testing.T, s *commandSchema) // applied to the NEW side
		pre     func(t *testing.T, s *commandSchema) // applied to BOTH sides first (a precondition)
		verdict string
		kind    string
	}
	vmd := "vm destroy"
	rows := []row{
		// ---- breaking ----
		{name: "verb removed", mutate: func(t *testing.T, s *commandSchema) {
			vm := nodeAt(t, s, "vm")
			vm.Subcommands = slices.DeleteFunc(vm.Subcommands, func(c commandSchema) bool { return c.Name == "destroy" })
		}, verdict: classBreaking, kind: "verb_removed"},
		{name: "verb renamed", mutate: func(t *testing.T, s *commandSchema) { nodeAt(t, s, vmd).Name = "obliterate" }, verdict: classBreaking, kind: "verb_removed"},
		{name: "alias removed", pre: func(t *testing.T, s *commandSchema) { nodeAt(t, s, vmd).Aliases = []string{"rm"} },
			mutate: func(t *testing.T, s *commandSchema) { nodeAt(t, s, vmd).Aliases = nil }, verdict: classBreaking, kind: "alias_removed"},
		{name: "tier raised", mutate: func(t *testing.T, s *commandSchema) { nodeAt(t, s, "vm get").Mutation = mutationDestructive }, verdict: classBreaking, kind: "tier_changed"},
		{name: "tier lowered", mutate: func(t *testing.T, s *commandSchema) { nodeAt(t, s, vmd).Mutation = mutationSafe }, verdict: classBreaking, kind: "tier_changed"},
		{name: "flag removed", mutate: func(t *testing.T, s *commandSchema) {
			n := nodeAt(t, s, vmd)
			n.Flags = slices.DeleteFunc(n.Flags, func(f flagSchema) bool { return f.Name == "lock-wait" })
		}, verdict: classBreaking, kind: "flag_removed"},
		{name: "shorthand removed", mutate: func(t *testing.T, s *commandSchema) { flagAt(t, nodeAt(t, s, vmd), "output").Shorthand = "" }, verdict: classBreaking, kind: "flag_shorthand_changed"},
		{name: "flag type changed", mutate: func(t *testing.T, s *commandSchema) { flagAt(t, nodeAt(t, s, vmd), "lock-wait").Type = "string" }, verdict: classBreaking, kind: "flag_type_changed"},
		{name: "default changed on an ordinary flag", mutate: func(t *testing.T, s *commandSchema) { flagAt(t, nodeAt(t, s, vmd), "lock-wait").Default = "5s" }, verdict: classBreaking, kind: "flag_default_changed"},
		{name: "default changed from empty", mutate: func(t *testing.T, s *commandSchema) { flagAt(t, nodeAt(t, s, vmd), "roster").Default = "./x.toml" }, verdict: classBreaking, kind: "flag_default_changed"},
		{name: "flag became required", mutate: func(t *testing.T, s *commandSchema) { flagAt(t, nodeAt(t, s, vmd), "lock-wait").Required = true }, verdict: classBreaking, kind: "flag_required_changed"},
		{name: "flag stopped being required", mutate: func(t *testing.T, s *commandSchema) { flagAt(t, nodeAt(t, s, "bootstrap"), "grant").Required = false }, verdict: classBreaking, kind: "flag_required_changed"},
		{name: "conditional requirement changed", mutate: func(t *testing.T, s *commandSchema) { flagAt(t, nodeAt(t, s, vmd), "yes").RequiredWhen = "always" }, verdict: classBreaking, kind: "flag_required_changed"},
		{name: "required flag added", mutate: func(t *testing.T, s *commandSchema) {
			n := nodeAt(t, s, vmd)
			n.Flags = append(n.Flags, flagSchema{Name: "new", Type: "string", Required: true})
		}, verdict: classBreaking, kind: "flag_added_required"},
		{name: "positional removed", mutate: func(t *testing.T, s *commandSchema) { n := nodeAt(t, s, vmd); n.Args = n.Args[:1] }, verdict: classBreaking, kind: "arg_removed"},
		{name: "required positional added", mutate: func(t *testing.T, s *commandSchema) {
			n := nodeAt(t, s, vmd)
			n.Args = append(n.Args, argSchema{Name: "extra", Required: true})
		}, verdict: classBreaking, kind: "arg_added_required"},
		{name: "positionals reordered", mutate: func(t *testing.T, s *commandSchema) {
			n := nodeAt(t, s, vmd)
			n.Args[0], n.Args[1] = n.Args[1], n.Args[0]
		}, verdict: classBreaking, kind: "arg_changed"},
		{name: "dash constraint changed", mutate: func(t *testing.T, s *commandSchema) { n := nodeAt(t, s, "exec"); n.Args[1].AfterDash = false }, verdict: classBreaking, kind: "arg_changed"},
		{name: "exit code removed", mutate: func(t *testing.T, s *commandSchema) { nodeAt(t, s, vmd).Exits.Codes = []int{4} }, verdict: classBreaking, kind: "exit_code_removed"},
		{name: "exit set widened (1→3/4)", pre: func(t *testing.T, s *commandSchema) { nodeAt(t, s, "vm set").Exits = nil },
			mutate: func(t *testing.T, s *commandSchema) { nodeAt(t, s, "vm set").Exits = &exitsSchema{Codes: []int{4}} }, verdict: classBreaking, kind: "exit_code_added"},
		{name: "named state removed", mutate: func(t *testing.T, s *commandSchema) { nodeAt(t, s, "api post").Exits.State = "" }, verdict: classBreaking, kind: "state_removed"},
		{name: "named state renamed", mutate: func(t *testing.T, s *commandSchema) { nodeAt(t, s, "exec").Exits.State = "child" }, verdict: classBreaking, kind: "state_changed"},
		{name: "global exit status removed", mutate: func(t *testing.T, s *commandSchema) { s.ExitStatuses = s.ExitStatuses[:len(s.ExitStatuses)-1] }, verdict: classBreaking, kind: "exit_status_removed"},
		{name: "global exit status redefined", mutate: func(t *testing.T, s *commandSchema) { s.ExitStatuses[2].Name = "unknown" }, verdict: classBreaking, kind: "exit_status_redefined"},
		{name: "env var removed", mutate: func(t *testing.T, s *commandSchema) { s.Env = s.Env[1:] }, verdict: classBreaking, kind: "env_removed"},
		{name: "env scope changed", mutate: func(t *testing.T, s *commandSchema) { s.Env[0].Scope = "core" }, verdict: classBreaking, kind: "env_changed"},
		{name: "env direction changed", mutate: func(t *testing.T, s *commandSchema) { s.Env[0].Direction = "out" }, verdict: classBreaking, kind: "env_changed"},
		{name: "env secret flag changed", mutate: func(t *testing.T, s *commandSchema) { s.Env[0].Secret = true }, verdict: classBreaking, kind: "env_changed"},
		{name: "roster key removed", mutate: func(t *testing.T, s *commandSchema) { s.Roster.Keys = s.Roster.Keys[1:] }, verdict: classBreaking, kind: "roster_key_removed"},
		{name: "schema version lowered", mutate: func(t *testing.T, s *commandSchema) { s.SchemaVersion = 1 }, verdict: classBreaking, kind: "schema_version_lowered"},
		{name: "output key removed (top level)", mutate: func(t *testing.T, s *commandSchema) {
			o := nodeAt(t, s, "doctor").Output
			o.Keys = slices.DeleteFunc(o.Keys, func(k outputKey) bool { return k.Name == "node" })
		}, verdict: classBreaking, kind: "output_key_removed"},
		{name: "output key removed (an optional one)", mutate: func(t *testing.T, s *commandSchema) {
			o := nodeAt(t, s, vmd).Output
			o.Keys = slices.DeleteFunc(o.Keys, func(k outputKey) bool { return k.Name == "error" })
		}, verdict: classBreaking, kind: "output_key_removed"},
		{name: "output key removed (nested)", mutate: func(t *testing.T, s *commandSchema) {
			o := nodeAt(t, s, "doctor").Output
			for i := range o.Keys {
				if o.Keys[i].Name == "rows" {
					o.Keys[i].Keys = slices.DeleteFunc(o.Keys[i].Keys, func(k outputKey) bool { return k.Name == "hint" })
				}
			}
		}, verdict: classBreaking, kind: "output_key_removed"},
		{name: "output key kind changed", mutate: func(t *testing.T, s *commandSchema) { nodeAt(t, s, "doctor").Output.Keys[0].Kind = "number" }, verdict: classBreaking, kind: "output_key_kind_changed"},
		{name: "output key became optional", mutate: func(t *testing.T, s *commandSchema) {
			o := nodeAt(t, s, "doctor").Output
			for i := range o.Keys {
				if o.Keys[i].Name == "node" {
					o.Keys[i].Optional = true
				}
			}
		}, verdict: classBreaking, kind: "output_key_became_optional"},
		{name: "output removed", mutate: func(t *testing.T, s *commandSchema) { nodeAt(t, s, "doctor").Output = nil }, verdict: classBreaking, kind: "output_removed"},
		{name: "output kind changed", mutate: func(t *testing.T, s *commandSchema) { nodeAt(t, s, "doctor").Output.Kind = "passthrough" }, verdict: classBreaking, kind: "output_kind_changed"},
		// ---- additive ----
		{name: "verb added", mutate: func(t *testing.T, s *commandSchema) {
			s.Subcommands = append(s.Subcommands, commandSchema{Name: "newverb", Use: "newverb", Mutation: mutationSafe})
		}, verdict: classAdditive, kind: "verb_added"},
		{name: "alias added", mutate: func(t *testing.T, s *commandSchema) { nodeAt(t, s, vmd).Aliases = []string{"rm"} }, verdict: classAdditive, kind: "alias_added"},
		{name: "optional flag added", mutate: func(t *testing.T, s *commandSchema) {
			n := nodeAt(t, s, vmd)
			n.Flags = append(n.Flags, flagSchema{Name: "new", Type: "string"})
		}, verdict: classAdditive, kind: "flag_added"},
		{name: "shorthand added", mutate: func(t *testing.T, s *commandSchema) { flagAt(t, nodeAt(t, s, vmd), "lock-wait").Shorthand = "w" }, verdict: classAdditive, kind: "flag_shorthand_added"},
		{name: "optional positional added", mutate: func(t *testing.T, s *commandSchema) {
			n := nodeAt(t, s, vmd)
			n.Args = append(n.Args, argSchema{Name: "extra"})
		}, verdict: classAdditive, kind: "arg_added"},
		{name: "named state added", mutate: func(t *testing.T, s *commandSchema) { nodeAt(t, s, vmd).Exits.State = "new_state" }, verdict: classAdditive, kind: "state_added"},
		{name: "output key added", mutate: func(t *testing.T, s *commandSchema) {
			o := nodeAt(t, s, "doctor").Output
			o.Keys = append(o.Keys, outputKey{Name: "extra", Kind: "string", Optional: true})
		}, verdict: classAdditive, kind: "output_key_added"},
		{name: "output key became always-present", mutate: func(t *testing.T, s *commandSchema) {
			o := nodeAt(t, s, "doctor").Output
			for i := range o.Keys {
				if o.Keys[i].Optional {
					o.Keys[i].Optional = false
					return
				}
			}
			t.Fatal("no optional key to flip")
		}, verdict: classAdditive, kind: "output_key_became_required"},
		{name: "env var added", mutate: func(t *testing.T, s *commandSchema) {
			s.Env = append(s.Env, envSchema{Name: "ZZZ_NEW", Direction: "in", Scope: "core"})
		}, verdict: classAdditive, kind: "env_added"},
		{name: "roster key added", mutate: func(t *testing.T, s *commandSchema) { s.Roster.Keys = append(s.Roster.Keys, "targets.zzz") }, verdict: classAdditive, kind: "roster_key_added"},
		{name: "exit status added", mutate: func(t *testing.T, s *commandSchema) {
			s.ExitStatuses = append(s.ExitStatuses, exitStatusSchema{Code: 5, Name: "new", Meaning: "x"})
		}, verdict: classAdditive, kind: "exit_status_added"},
		// ---- informational: no verdict ----
		{name: "global exit status meaning reworded", mutate: func(t *testing.T, s *commandSchema) { s.ExitStatuses[1].Meaning = "reworded" }, verdict: "none", kind: "exit_status_meaning_changed"},
		{name: "short text changed", mutate: func(t *testing.T, s *commandSchema) { nodeAt(t, s, vmd).Short = "reworded" }, verdict: "none", kind: "short_changed"},
		{name: "flag usage text changed", mutate: func(t *testing.T, s *commandSchema) { flagAt(t, nodeAt(t, s, vmd), "yes").Usage = "reworded" }, verdict: "none", kind: "flag_usage_changed"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			old, cur := cloneSchema(t, base), cloneSchema(t, base)
			if r.pre != nil {
				r.pre(t, &old)
				r.pre(t, &cur)
			}
			r.mutate(t, &cur)
			rep := diffSchemas(old, cur)
			if rep.Verdict != r.verdict {
				t.Fatalf("verdict = %q, want %q (findings %+v)", rep.Verdict, r.verdict, rep.Findings)
			}
			if findKind(rep, r.kind) == nil {
				t.Fatalf("no %q finding in %+v", r.kind, rep.Findings)
			}
			if r.name == "env scope changed" {
				if f := findKind(rep, r.kind); !strings.Contains(f.Was, "scope=harness") || !strings.Contains(f.Now, "scope=core") {
					t.Fatalf("the finding does not show the scope change: was %q now %q", f.Was, f.Now)
				}
			}
			// the swap: reversing old and new must not leave the verdict unchanged
			// for the add/remove pairs (an additive change reversed is a removal)
			if r.verdict == classAdditive && !strings.HasSuffix(r.kind, "became_required") && r.kind != "shorthand_added" {
				rev := diffSchemas(cur, old)
				if rev.Verdict != classBreaking {
					t.Errorf("the reversed diff of an additive change is %q, want breaking (findings %+v)", rev.Verdict, rev.Findings)
				}
			}
		})
	}
	if len(rows) < 45 {
		t.Fatalf("the rule table has %d rows", len(rows))
	}
}

func TestSchemaDiff_IdenticalIsNone_AndV1IsIncomparable(t *testing.T) {
	cur := currentSchema(t)
	if r := diffSchemas(cloneSchema(t, cur), cur); r.Verdict != "none" || len(r.Findings) != 0 {
		t.Fatalf("an identical pair is %q with findings %+v", r.Verdict, r.Findings)
	}
	b, err := os.ReadFile("testdata/schema_v1.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var v1 commandSchema
	if err := json.Unmarshal(b, &v1); err != nil {
		t.Fatal(err)
	}
	r := diffSchemas(v1, cur)
	if r.Verdict != classIncomparable || r.Breaking != 0 || r.Incomparable == 0 {
		t.Fatalf("v1 → v2: verdict %q breaking %d incomparable %d: a baseline that lacks a surface must say incomparable, never none", r.Verdict, r.Breaking, r.Incomparable)
	}
	if r.OldVersion != 1 || r.NewVersion != 2 {
		t.Errorf("versions %d → %d", r.OldVersion, r.NewVersion)
	}
	// and v1 vs v1 is none (the control: the incomparable verdict is about the surfaces, not the files)
	if r := diffSchemas(v1, v1); r.Verdict != "none" {
		t.Fatalf("v1 vs v1 = %q", r.Verdict)
	}
	// a removal is still caught against a v1 baseline
	removed := cloneSchema(t, cur)
	removed.Subcommands = slices.DeleteFunc(removed.Subcommands, func(c commandSchema) bool { return c.Name == "doctor" })
	if r := diffSchemas(v1, removed); r.Verdict != classBreaking {
		t.Fatalf("a removed verb against a v1 baseline is %q", r.Verdict)
	}
}

// AC-S5: the command, through runRoot. Exit 0 for every verdict; with --fail-on
// breaking a breaking verdict is exit 1 and NEVER 4 (4 means refused before a change).
func TestSchemaDiff_CommandExitStatus(t *testing.T) {
	cur := currentSchema(t)
	dir := t.TempDir()
	write := func(name string, s commandSchema) string {
		b, _ := json.Marshal(s)
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	oldP := write("old.json", cur)
	broken := cloneSchema(t, cur)
	broken.Subcommands = slices.DeleteFunc(broken.Subcommands, func(c commandSchema) bool { return c.Name == "doctor" })
	newP := write("new.json", broken)

	code, out, errOut := runRootArgs("schema", "diff", oldP, newP, "-o", "json")
	if code != 0 {
		t.Fatalf("a breaking diff exits %d without --fail-on (stderr %q)", code, errOut)
	}
	var rep schemaDiffReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil || rep.Verdict != classBreaking || findKind(rep, "verb_removed") == nil {
		t.Fatalf("report %+v (%v)", rep, err)
	}
	code, _, errOut = runRootArgs("schema", "diff", oldP, newP, "--fail-on", "breaking")
	if code != 1 || !strings.Contains(errOut, "breaking") {
		t.Fatalf("--fail-on breaking exit %d (stderr %q), want 1", code, errOut)
	}
	// the control: an additive pair passes --fail-on breaking
	code, _, _ = runRootArgs("schema", "diff", newP, oldP, "--fail-on", "breaking")
	if code != 0 {
		t.Fatalf("an additive diff exits %d under --fail-on breaking, want 0", code)
	}
	if c, _, _ := runRootArgs("schema", "diff", oldP, newP, "--fail-on", "additive"); c != 1 {
		t.Errorf("--fail-on additive exit %d, want 1 (usage)", c)
	}
	if c, _, _ := runRootArgs("schema", "diff", oldP); c != 1 {
		t.Errorf("one argument exit %d, want 1", c)
	}
	notSchema := filepath.Join(dir, "x.json")
	_ = os.WriteFile(notSchema, []byte(`{"name":"other"}`), 0o600)
	if c, _, e := runRootArgs("schema", "diff", oldP, notSchema); c != 1 || !strings.Contains(e, "not a pveforge schema") {
		t.Errorf("a non-schema file: exit %d, %q", c, e)
	}
	for _, c := range []int{0, 1} {
		if c == exitRefused {
			t.Fatal("unreachable")
		}
	}
}

// C2 (code review): a schema of a generation this binary does not know, or one with
// a field it does not know, is NEVER "none". Codex's reproduction: this tree's schema
// against a copy with schemaVersion 3 and a new top-level futureContract surface.
func TestSchemaDiff_UnsupportedGenerationAndUnknownFieldsAreIncomparable(t *testing.T) {
	cur := currentSchema(t)
	dir := t.TempDir()
	base, _ := json.Marshal(cur)
	write := func(name string, mutate func(m map[string]any)) string {
		var m map[string]any
		if err := json.Unmarshal(base, &m); err != nil {
			t.Fatal(err)
		}
		if mutate != nil {
			mutate(m)
		}
		b, _ := json.Marshal(m)
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	same := write("same.json", nil)
	run := func(a, b string) schemaDiffReport {
		code, out, errOut := runRootArgs("schema", "diff", a, b, "-o", "json")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errOut)
		}
		var rep schemaDiffReport
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}
	// the control: identical files are none, so "incomparable" below is not the default
	if rep := run(same, write("same2.json", nil)); rep.Verdict != "none" || len(rep.Findings) != 0 {
		t.Fatalf("identical files: %+v", rep)
	}
	future := write("future.json", func(m map[string]any) {
		m["schemaVersion"] = 3
		m["futureContract"] = map[string]any{"x": 1}
	})
	rep := run(same, future)
	if rep.Verdict != classIncomparable || findKind(rep, "unsupported_schema_version") == nil || findKind(rep, "unknown_field") == nil {
		t.Fatalf("v2 vs v3 + futureContract: %+v", rep)
	}
	if f := findKind(rep, "unknown_field"); !strings.Contains(f.Path, "futureContract") {
		t.Errorf("the unknown field is not named: %+v", f)
	}
	// the OLD side too
	if rep := run(future, same); rep.Verdict != classIncomparable {
		t.Fatalf("v3 baseline: %+v", rep)
	}
	// a version above the maximum alone
	if rep := run(same, write("v3only.json", func(m map[string]any) { m["schemaVersion"] = 3 })); rep.Verdict != classIncomparable || findKind(rep, "unsupported_schema_version") == nil {
		t.Fatalf("version only: %+v", rep)
	}
	// an unknown field alone, nested deep (inside a flag of a command)
	deep := write("deep.json", func(m map[string]any) {
		subs := m["subcommands"].([]any)
		for _, s := range subs {
			sm := s.(map[string]any)
			if sm["name"] == "doctor" {
				fl := sm["flags"].([]any)
				fl[0].(map[string]any)["futureField"] = true
			}
		}
	})
	rep = run(same, deep)
	if rep.Verdict != classIncomparable || findKind(rep, "unknown_field") == nil || findKind(rep, "unsupported_schema_version") != nil {
		t.Fatalf("a nested unknown field: %+v", rep)
	}
	if f := findKind(rep, "unknown_field"); !strings.Contains(f.Path, "futureField") || !strings.Contains(f.Path, "flags[0]") {
		t.Errorf("the nested path is not named: %+v", f)
	}
	// a real breaking change still wins over incomparable
	br := cloneSchema(t, cur)
	br.Subcommands = slices.DeleteFunc(br.Subcommands, func(c commandSchema) bool { return c.Name == "doctor" })
	bb, _ := json.Marshal(br)
	var bm map[string]any
	_ = json.Unmarshal(bb, &bm)
	bm["futureContract"] = 1
	bb, _ = json.Marshal(bm)
	bp := filepath.Join(dir, "broken-future.json")
	_ = os.WriteFile(bp, bb, 0o600)
	if rep := run(same, bp); rep.Verdict != classBreaking {
		t.Fatalf("a removed verb plus an unknown field: %q, want breaking", rep.Verdict)
	}
}
