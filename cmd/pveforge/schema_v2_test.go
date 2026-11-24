package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func currentSchema(t *testing.T) commandSchema {
	t.Helper()
	code, out, errOut := runRootArgs("schema")
	if code != 0 {
		t.Fatalf("schema exit %d: %s", code, errOut)
	}
	var s commandSchema
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// AC-S1: the v2 surfaces exist and are total.
func TestSchema_V2SurfacesAreTotal(t *testing.T) {
	s := currentSchema(t)
	if s.SchemaVersion != 2 || s.Contract == nil || s.Roster == nil {
		t.Fatalf("schemaVersion %d, contract %v, roster %v", s.SchemaVersion, s.Contract, s.Roster)
	}
	nodes := flattenSchema(s)
	var tiered, nonSafe, withExits, withArgs int
	for p, n := range nodes {
		if n.Mutation == "" {
			continue
		}
		tiered++
		if n.Mutation != mutationSafe {
			nonSafe++
			if n.Exits == nil {
				t.Errorf("%s (%s) has no exits row (AC-W1)", p, n.Mutation)
			}
		}
		if n.Exits != nil {
			withExits++
		}
		if strings.Contains(n.Use, "<") && len(n.Args) == 0 {
			t.Errorf("%s: Use %q has positional arguments but the schema has no args", p, n.Use)
		}
		if len(n.Args) > 0 {
			withArgs++
		}
	}
	if tiered < 55 || nonSafe < 36 || withExits < len(verbExits) {
		t.Fatalf("floors: %d tiered, %d non-safe, %d with exits (registry %d)", tiered, nonSafe, withExits, len(verbExits))
	}
	if d := nodes["doctor"].Exits; d == nil || !slices.Equal(d.Codes, []int{4}) {
		t.Errorf("doctor exits = %+v, want [4]", d)
	}
	if e := nodes["exec"].Exits; e == nil || e.State != stateChildStatus {
		t.Errorf("exec exits = %+v, want the named state %s", e, stateChildStatus)
	}
	if e := nodes["api post"].Exits; e == nil || e.State != stateUnobservedDispatch {
		t.Errorf("api post exits = %+v, want the named state %s", e, stateUnobservedDispatch)
	}
	if e := nodes["exec"]; len(e.Args) != 3 || !e.Args[1].AfterDash || e.Args[0].AfterDash {
		t.Errorf("exec args = %+v: the dash constraint is lost", e.Args)
	}
	if len(s.Env) != len(envTable()) || len(s.ExitStatuses) != 6 {
		t.Errorf("env %d, exit statuses %d", len(s.Env), len(s.ExitStatuses))
	}
}

// AC-S1 (args): the Use-line grammar must agree with what cobra's own Args
// validator accepts, so a Use that drifts from the validator fails here.
func TestSchema_ArgsAgreeWithCobraArgs(t *testing.T) {
	root := newRootCmd()
	checked := 0
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, ch := range c.Commands() {
			walk(ch)
			if !ch.Runnable() || ch.HasSubCommands() || ch.Args == nil || ch.Name() == "exec" || ch.Name() == "help" || ch.Name() == "completion" {
				continue
			}
			args := parseUseArgs(ch.Use)
			req := 0
			variadic := false
			for _, a := range args {
				if a.Required {
					req++
				}
				if a.Variadic {
					variadic = true
				}
			}
			mk := func(n int) []string {
				out := make([]string, n)
				for i := range out {
					out[i] = "x"
				}
				return out
			}
			if err := ch.Args(ch, mk(req)); err != nil {
				t.Errorf("%s: Use %q says %d required positional(s) but Args refuses exactly that many: %v", ch.CommandPath(), ch.Use, req, err)
			}
			if req > 0 {
				if err := ch.Args(ch, mk(req-1)); err == nil {
					t.Errorf("%s: Use %q says %d required but Args accepts %d", ch.CommandPath(), ch.Use, req, req-1)
				}
			}
			if !variadic && len(args) == req {
				if err := ch.Args(ch, mk(req+1)); err == nil {
					t.Errorf("%s: Use %q takes exactly %d but Args accepts %d", ch.CommandPath(), ch.Use, req, req+1)
				}
			}
			checked++
		}
	}
	walk(root)
	if checked < 40 {
		t.Fatalf("checked only %d commands: the walk is not seeing the tree", checked)
	}
	// the parser itself: grammar rows (and a planted malformed Use is not silently empty)
	got := parseUseArgs("create <target-id> <name> --type <type> [--data key=value ...] [field=value ...] <rest>...")
	want := []argSchema{{Name: "target-id", Required: true}, {Name: "name", Required: true}, {Name: "field=value", Variadic: true}, {Name: "rest", Required: true, Variadic: true}}
	if !slices.Equal(got, want) {
		t.Errorf("parseUseArgs = %+v, want %+v", got, want)
	}
}

// requirementLiteralRE finds the error and help literals that state a flag
// requirement. Each must be a known one (below), so a new hand-checked
// requirement cannot ship without a row in runtimeRequiredFlags.
var requirementLiteralRE = regexp.MustCompile(`\b(is|are) required\b|\(required|\bneeds --|\bNeeds --|requires --|; required\b|required (key|for|unless)`)

// knownRequirementLiterals maps a distinctive substring of such a literal to the
// (command path, flag) rows it is held by.
var knownRequirementLiterals = map[string][][2]string{
	"storage create: --type is required":                                           {{"storage create", "type"}},
	"--destroy-task is required":                                                   {{"harness vm gone", "destroy-task"}},
	"needs --yes too":                                                              {{"vm destroy", "yes"}},
	"(needs --witness-marker)":                                                     {{"vm snapshot rollback", "witness-marker"}},
	"(required unless the target already exists in the roster)":                    {{"bootstrap", "host"}, {"bootstrap", "node"}},
	"--host and --node are required for a target":                                  {{"roster import-token", "host"}, {"roster import-token", "node"}},
	"needs --host-key-fingerprint":                                                 {{"bootstrap", "host-key-fingerprint"}},
	"so --no-ssh-key is required":                                                  {{"bootstrap", "no-ssh-key"}},
	"(required when there is no terminal to ask on)":                               {{"acl enable-vm-destroy", "yes"}},
	"confirm this irreversible destroy (required":                                  {{"vm destroy", "yes"}, {"harness vm destroy", "yes"}},
	"the destroy task's UPID (required)":                                           {{"harness vm gone", "destroy-task"}},
	"the full token id, <user>@<realm>!<token name> (required)":                    {{"roster import-token", "token-id"}},
	"PATH and ROLE are required":                                                   {{"bootstrap", "grant"}, {"roster import-token", "grant"}},
	"Needs --host-key-fingerprint with the NEW key":                                {{"bootstrap", "host-key-fingerprint"}},
	"needs --data pool=<zpool>":                                                    {{"storage create", "data"}},
	"a type with a known required key missing":                                     nil, // a PVE field of the raw create body, not a flag
	"at least one is required, there is no default":                                {{"bootstrap", "grant"}},
	"the PVE storage type to create (zfspool, dir, lvmthin, nfs, ...); required":   {{"storage create", "type"}},
	"the target's API host (defaults to the roster's, required for a new target)":  {{"roster import-token", "host"}},
	"the target's node name (defaults to the roster's, required for a new target)": {{"roster import-token", "node"}},
	"bootstrap: host is required":                                                  {{"bootstrap", "host"}},
	"bootstrap: node is required":                                                  {{"bootstrap", "node"}},
	// not flags: a group's help requirement, a positional, an environment or prompt value, the roster template's comment
	"a subcommand is required":                       nil,
	"Only the id, host":                              nil,
	"list node qemu VMIDs as root: node is required": nil,
	"bootstrap: target id is required":               nil,
	"bootstrap: token id is required":                nil,
	"bootstrap: roster path is required":             nil,
	"bootstrap: PVE password is required":            nil,
	"bootstrap: roster passphrase is required":       nil,
	"as bootstrap --no-ssh-key does":                 nil, // describes --no-ssh-key itself
}

func TestSchema_RequirednessSweep(t *testing.T) {
	s := currentSchema(t)
	nodes := flattenSchema(s)
	holds := func(path, flag string) bool {
		n, ok := nodes[path]
		if !ok {
			return false
		}
		for _, f := range n.Flags {
			if f.Name == flag {
				return f.Required || f.RequiredWhen != ""
			}
		}
		return false
	}
	// every table row names a real command and flag
	for path, rows := range runtimeRequiredFlags {
		n, ok := nodes[path]
		if !ok {
			t.Errorf("runtimeRequiredFlags names a command that does not exist: %q", path)
			continue
		}
		for _, r := range rows {
			if !slices.ContainsFunc(n.Flags, func(f flagSchema) bool { return f.Name == r.Flag }) {
				t.Errorf("runtimeRequiredFlags: %s has no flag --%s", path, r.Flag)
			}
		}
	}
	// the source sweep: cmd/pveforge, internal/bootstrap and the flag help
	var literals []string
	for _, dir := range []string{".", "../../internal/bootstrap"} {
		fset := token.NewFileSet()
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			af, err := parser.ParseFile(fset, f, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(af, func(n ast.Node) bool {
				bl, ok := n.(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					return true
				}
				v, err := strconv.Unquote(bl.Value)
				if err == nil && requirementLiteralRE.MatchString(v) {
					literals = append(literals, v)
				}
				return true
			})
		}
	}
	if len(literals) < 8 {
		t.Fatalf("the sweep found only %d requirement literals: it is not seeing the source", len(literals))
	}
	matched := map[string]bool{}
	for _, lit := range literals {
		known := false
		for key := range knownRequirementLiterals {
			if strings.Contains(lit, key) {
				known = true
				matched[key] = true
			}
		}
		if !known {
			t.Errorf("a requirement the schema does not know about: %.140q\n\tadd a row to runtimeRequiredFlags and a key to knownRequirementLiterals (or reword the text)", lit)
		}
	}
	for key, rows := range knownRequirementLiterals {
		if !matched[key] {
			t.Errorf("knownRequirementLiterals key %q matches no literal in the source: stale", key)
		}
		for _, r := range rows {
			if !holds(r[0], r[1]) {
				t.Errorf("%q says --%s of %q is required, but the schema does not say so", key, r[1], r[0])
			}
		}
	}
	// and the flags cobra marks required are in the schema as required
	for _, p := range []string{"network bridge create", "network bridge destroy"} {
		if !holds(p, "management-bridge") {
			t.Errorf("%s --management-bridge (cobra required) is not required in the schema", p)
		}
	}
}

// AC-S3: the exit-status table has ONE owner: the README table, the schema
// table and the constants runRoot assigns are one set.
func TestSchema_ExitStatusesAreOneSet(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(readme), "## Exit status")
	if !ok {
		t.Fatal("README has no Exit status section")
	}
	section, _, _ := strings.Cut(after, "\n## ")
	row := regexp.MustCompile("(?m)^\\| `([0-9]+)` \\|")
	var readmeCodes []int
	for _, m := range row.FindAllStringSubmatch(section, -1) {
		n, _ := strconv.Atoi(m[1])
		readmeCodes = append(readmeCodes, n)
	}
	var schemaCodes []int
	for _, e := range exitStatusTable() {
		schemaCodes = append(schemaCodes, e.Code)
	}
	sort.Ints(readmeCodes)
	sort.Ints(schemaCodes)
	if !slices.Equal(readmeCodes, schemaCodes) {
		t.Fatalf("README exit codes %v != schema exitStatuses %v", readmeCodes, schemaCodes)
	}
	if !slices.Contains(schemaCodes, exitOutcomeUnknown) || !slices.Contains(schemaCodes, exitRefused) {
		t.Fatalf("the schema table lacks the code constants %d and %d", exitOutcomeUnknown, exitRefused)
	}
	// every status a verb row can name is in the table
	for p, v := range verbExits {
		for _, c := range v.Exits {
			if !slices.Contains(schemaCodes, c) {
				t.Errorf("%s: exit %d is not in the exit-status table", p, c)
			}
		}
	}
}

func TestSchema_RosterKeysAndEnvAreHeldToGoldens(t *testing.T) {
	if got, want := rosterKeys(), readLines(t, "testdata/roster_keys.golden"); !slices.Equal(got, want) {
		t.Errorf("roster keys changed (a removed or renamed key is a breaking change):\n got %v\nwant %v", got, want)
	}
	var names []string
	for _, e := range envTable() {
		names = append(names, e.Name)
	}
	if want := readLines(t, "../../internal/sourceguard/testdata/env_names.golden"); !slices.Equal(names, want) {
		t.Errorf("the schema env names differ from the scan's golden:\n got %v\nwant %v", names, want)
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("env table is not sorted")
	}
	for _, e := range envTable() {
		switch e.Scope {
		case "core", "proxy", "harness", "harness-secrets", "exec-child":
		default:
			t.Errorf("env %s has scope %q", e.Name, e.Scope)
		}
	}
}

// AC-S2: schema v2 is a strict superset of the v1 contract (captured from the
// pre-release tree f731f9e): every v1 command, flag and field is still there
// with the same value.
func TestSchema_V1IsASubset(t *testing.T) {
	b, err := os.ReadFile("testdata/schema_v1.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var v1 commandSchema
	if err := json.Unmarshal(b, &v1); err != nil {
		t.Fatal(err)
	}
	cur := currentSchema(t)
	oldNodes, newNodes := flattenSchema(v1), flattenSchema(cur)
	if len(oldNodes) < 50 {
		t.Fatalf("the v1 golden has %d commands: it is not the v1 schema", len(oldNodes))
	}
	for p, on := range oldNodes {
		nn, ok := newNodes[p]
		if !ok {
			t.Errorf("v1 command %q is gone", p)
			continue
		}
		if on.Mutation != nn.Mutation || on.Name != nn.Name || !slices.Equal(on.Aliases, nn.Aliases) {
			t.Errorf("%s: v1 fields changed: %+v vs %+v", p, on, nn)
		}
		nf := map[string]flagSchema{}
		for _, f := range nn.Flags {
			nf[f.Name] = f
		}
		for _, f := range on.Flags {
			g, ok := nf[f.Name]
			if !ok || g.Type != f.Type || g.Default != f.Default || g.Shorthand != f.Shorthand {
				t.Errorf("%s --%s: v1 flag changed or gone (%+v vs %+v)", p, f.Name, f, g)
			}
		}
	}
	// the control: the difference is real (new commands exist), so the subset check
	// is not comparing a file with itself
	if _, ok := newNodes["version"]; !ok {
		t.Errorf("the version command is missing")
	}
	if _, ok := oldNodes["version"]; ok {
		t.Errorf("the v1 golden already has `version`: it is not the pre-release schema")
	}
}

// the schema is deterministic and carries no wall clock.
func TestSchema_IsDeterministic(t *testing.T) {
	_, a, _ := runRootArgs("schema")
	_, b, _ := runRootArgs("schema")
	if a != b {
		t.Fatal("two runs of `pveforge schema` differ")
	}
}
