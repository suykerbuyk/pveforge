package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
)

// `pveforge schema diff <old.json> <new.json>` classifies the change between
// two `pveforge schema` outputs (two releases) as breaking or additive, so a
// consumer that pinned a release can detect a contract break mechanically
// (contract plan §3.4). It is local: no roster, no host. The rules are the
// table in the plan; every row has a fixture in both directions.

const (
	classBreaking      = "breaking"
	classAdditive      = "additive"
	classInformational = "informational"
	classIncomparable  = "incomparable"
)

// maxSchemaFile bounds a schema file read for the diff.
const maxSchemaFile = 32 << 20

type schemaFinding struct {
	Class string `json:"class"`
	Kind  string `json:"kind"`
	Path  string `json:"path"`
	Was   string `json:"was,omitempty"`
	Now   string `json:"now,omitempty"`
}

type schemaDiffReport struct {
	Verdict       string          `json:"verdict"`
	Breaking      int             `json:"breaking"`
	Additive      int             `json:"additive"`
	Informational int             `json:"informational"`
	Incomparable  int             `json:"incomparable"`
	OldVersion    int             `json:"old_schema_version"`
	NewVersion    int             `json:"new_schema_version"`
	Findings      []schemaFinding `json:"findings,omitempty"`
}

// diffSchemas compares two decoded schemas. old is the baseline.
func diffSchemas(old, cur commandSchema) schemaDiffReport {
	d := &differ{oldV: schemaGen(old), newV: schemaGen(cur)}
	// A comparison is only as good as the diff's own knowledge of the format: a
	// schema of a generation newer than this binary understands, or one carrying
	// a field this binary does not know, can hold a contract surface nothing here
	// compares. That is never "none": it is incomparable (fail closed).
	for _, side := range []struct {
		name string
		v    int
		s    commandSchema
	}{{"baseline", d.oldV, old}, {"candidate", d.newV, cur}} {
		if side.v > schemaVersion {
			d.add(classIncomparable, "unsupported_schema_version", side.name, strconv.Itoa(side.v), "this binary compares schema versions up to "+strconv.Itoa(schemaVersion))
		}
		for _, u := range side.s.unknown {
			d.add(classIncomparable, "unknown_field", side.name+": "+u, "", "")
		}
	}
	d.diffRoot(old, cur)
	oldNodes, newNodes := flattenSchema(old), flattenSchema(cur)
	for _, p := range sortedKeys(oldNodes) {
		on := oldNodes[p]
		nn, ok := newNodes[p]
		if !ok {
			d.add(classBreaking, "verb_removed", p, "present", "absent")
			continue
		}
		d.diffNode(p, on, nn)
	}
	for _, p := range sortedKeys(newNodes) {
		if _, ok := oldNodes[p]; !ok {
			d.add(classAdditive, "verb_added", p, "", "present")
		}
	}
	return d.report()
}

// schemaGen is a schema's version: files before releases carry none (version 1).
func schemaGen(s commandSchema) int {
	if s.SchemaVersion == 0 {
		return 1
	}
	return s.SchemaVersion
}

type differ struct {
	oldV, newV int
	findings   []schemaFinding
}

func (d *differ) add(class, kind, path, was, now string) {
	d.findings = append(d.findings, schemaFinding{Class: class, Kind: kind, Path: path, Was: was, Now: now})
}

func (d *differ) report() schemaDiffReport {
	r := schemaDiffReport{OldVersion: d.oldV, NewVersion: d.newV, Findings: d.findings}
	for _, f := range d.findings {
		switch f.Class {
		case classBreaking:
			r.Breaking++
		case classAdditive:
			r.Additive++
		case classInformational:
			r.Informational++
		case classIncomparable:
			r.Incomparable++
		}
	}
	switch {
	case r.Breaking > 0:
		r.Verdict = classBreaking
	case r.Incomparable > 0:
		r.Verdict = classIncomparable
	case r.Additive > 0:
		r.Verdict = classAdditive
	default:
		r.Verdict = "none"
	}
	return r
}

// v2only reports whether the baseline lacks a v2 surface (so a comparison of it
// cannot say "unchanged").
func (d *differ) oldLacks() bool { return d.oldV < 2 && d.newV >= 2 }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// flattenSchema maps every command path (without the root) to its node.
func flattenSchema(root commandSchema) map[string]commandSchema {
	out := map[string]commandSchema{}
	var walk func(n commandSchema, prefix string)
	walk = func(n commandSchema, prefix string) {
		for _, c := range n.Subcommands {
			p := strings.TrimSpace(prefix + " " + c.Name)
			out[p] = c
			walk(c, p)
		}
	}
	walk(root, "")
	return out
}

func (d *differ) diffRoot(old, cur commandSchema) {
	if d.newV < d.oldV && d.oldV <= schemaVersion {
		d.add(classBreaking, "schema_version_lowered", "schemaVersion", strconv.Itoa(d.oldV), strconv.Itoa(d.newV))
	}
	// global flags
	d.diffFlags("", old.GlobalFlags, cur.GlobalFlags)
	// root-only v2 surfaces
	if d.oldLacks() {
		for _, s := range []string{"exitStatuses", "env", "roster"} {
			d.add(classIncomparable, "surface_missing_in_baseline", s, "", "")
		}
	} else {
		d.diffExitStatuses(old.ExitStatuses, cur.ExitStatuses)
		d.diffEnv(old.Env, cur.Env)
		d.diffRosterKeys(old.Roster, cur.Roster)
	}
}

func (d *differ) diffNode(p string, on, nn commandSchema) {
	if on.Mutation != nn.Mutation {
		// ANY tier change is breaking, in both directions (contract plan C3/C6).
		d.add(classBreaking, "tier_changed", p, on.Mutation, nn.Mutation)
	}
	d.diffAliases(p, on.Aliases, nn.Aliases)
	if on.Short != nn.Short {
		d.add(classInformational, "short_changed", p, on.Short, nn.Short)
	}
	d.diffFlags(p, on.Flags, nn.Flags)
	if d.oldLacks() {
		if on.Runnable() {
			d.add(classIncomparable, "surface_missing_in_baseline", p+" args/exits/output", "", "")
		}
		return
	}
	d.diffArgs(p, on.Args, nn.Args)
	d.diffExits(p, on.Exits, nn.Exits)
	d.diffOutput(p, on.Output, nn.Output)
}

// Runnable is a schema node that carries a mutation tier (a runnable command).
func (c commandSchema) Runnable() bool { return c.Mutation != "" || len(c.Subcommands) == 0 }

func (d *differ) diffAliases(p string, old, cur []string) {
	for _, a := range old {
		if !slices.Contains(cur, a) {
			d.add(classBreaking, "alias_removed", p, a, "")
		}
	}
	for _, a := range cur {
		if !slices.Contains(old, a) {
			d.add(classAdditive, "alias_added", p, "", a)
		}
	}
}

func (d *differ) diffFlags(p string, old, cur []flagSchema) {
	om, nm := map[string]flagSchema{}, map[string]flagSchema{}
	for _, f := range old {
		om[f.Name] = f
	}
	for _, f := range cur {
		nm[f.Name] = f
	}
	for _, name := range sortedKeys(om) {
		of := om[name]
		fp := strings.TrimSpace(p + " --" + name)
		nf, ok := nm[name]
		if !ok {
			d.add(classBreaking, "flag_removed", fp, "present", "absent")
			continue
		}
		if of.Shorthand != nf.Shorthand {
			if of.Shorthand != "" {
				d.add(classBreaking, "flag_shorthand_changed", fp, of.Shorthand, nf.Shorthand)
			} else {
				d.add(classAdditive, "flag_shorthand_added", fp, "", nf.Shorthand)
			}
		}
		if of.Type != nf.Type {
			d.add(classBreaking, "flag_type_changed", fp, of.Type, nf.Type)
		}
		if of.Default != nf.Default {
			// ANY default change is breaking, on every flag.
			d.add(classBreaking, "flag_default_changed", fp, of.Default, nf.Default)
		}
		if d.oldLacks() {
			if nf.Required || nf.RequiredWhen != "" {
				d.add(classIncomparable, "flag_requiredness_unknown_in_baseline", fp, "", reqText(nf))
			}
		} else if of.Required != nf.Required || of.RequiredWhen != nf.RequiredWhen {
			d.add(classBreaking, "flag_required_changed", fp, reqText(of), reqText(nf))
		}
		if of.Usage != nf.Usage {
			d.add(classInformational, "flag_usage_changed", fp, "", "")
		}
	}
	for _, name := range sortedKeys(nm) {
		if _, ok := om[name]; ok {
			continue
		}
		nf := nm[name]
		fp := strings.TrimSpace(p + " --" + name)
		if nf.Required {
			d.add(classBreaking, "flag_added_required", fp, "", reqText(nf))
		} else {
			d.add(classAdditive, "flag_added", fp, "", reqText(nf))
		}
	}
}

func reqText(f flagSchema) string {
	switch {
	case f.Required:
		return "required"
	case f.RequiredWhen != "":
		return "conditional: " + f.RequiredWhen
	}
	return "optional"
}

func argText(a argSchema) string {
	s := a.Name
	if !a.Required {
		s = "[" + s + "]"
	}
	if a.Variadic {
		s += "..."
	}
	if a.AfterDash {
		s = "-- " + s
	}
	return s
}

func (d *differ) diffArgs(p string, old, cur []argSchema) {
	n := min(len(old), len(cur))
	for i := 0; i < n; i++ {
		if old[i] != cur[i] {
			d.add(classBreaking, "arg_changed", fmt.Sprintf("%s arg %d", p, i+1), argText(old[i]), argText(cur[i]))
		}
	}
	for i := n; i < len(old); i++ {
		d.add(classBreaking, "arg_removed", fmt.Sprintf("%s arg %d", p, i+1), argText(old[i]), "")
	}
	for i := n; i < len(cur); i++ {
		if cur[i].Required {
			d.add(classBreaking, "arg_added_required", fmt.Sprintf("%s arg %d", p, i+1), "", argText(cur[i]))
		} else {
			d.add(classAdditive, "arg_added", fmt.Sprintf("%s arg %d", p, i+1), "", argText(cur[i]))
		}
	}
}

func exitText(e *exitsSchema) string {
	if e == nil {
		return "none"
	}
	return fmt.Sprintf("%v %s", e.Codes, e.State)
}

func (d *differ) diffExits(p string, old, cur *exitsSchema) {
	var oc, nc []int
	var os, ns string
	if old != nil {
		oc, os = old.Codes, old.State
	}
	if cur != nil {
		nc, ns = cur.Codes, cur.State
	}
	for _, c := range oc {
		if !slices.Contains(nc, c) {
			d.add(classBreaking, "exit_code_removed", p, exitText(old), exitText(cur))
		}
	}
	for _, c := range nc {
		if !slices.Contains(oc, c) {
			// a widened exit set changes a consumer keyed on the old statuses
			// (contract plan D3): breaking
			d.add(classBreaking, "exit_code_added", p, exitText(old), exitText(cur))
		}
	}
	switch {
	case os != "" && ns == "":
		d.add(classBreaking, "state_removed", p, os, ns)
	case os != "" && ns != os:
		d.add(classBreaking, "state_changed", p, os, ns)
	case os == "" && ns != "":
		d.add(classAdditive, "state_added", p, "", ns)
	}
}

func (d *differ) diffExitStatuses(old, cur []exitStatusSchema) {
	om := map[int]exitStatusSchema{}
	for _, e := range old {
		om[e.Code] = e
	}
	nm := map[int]exitStatusSchema{}
	for _, e := range cur {
		nm[e.Code] = e
	}
	for _, e := range old {
		n, ok := nm[e.Code]
		switch {
		case !ok:
			d.add(classBreaking, "exit_status_removed", strconv.Itoa(e.Code), e.Name, "")
		case n.Name != e.Name:
			d.add(classBreaking, "exit_status_redefined", strconv.Itoa(e.Code), e.Name, n.Name)
		case n.Meaning != e.Meaning:
			// wording: informational, like a changed `short` (docs/releasing.md)
			d.add(classInformational, "exit_status_meaning_changed", strconv.Itoa(e.Code), "", "")
		}
	}
	for _, e := range cur {
		if _, ok := om[e.Code]; !ok {
			d.add(classAdditive, "exit_status_added", strconv.Itoa(e.Code), "", e.Name)
		}
	}
}

func envText(e envSchema) string {
	return fmt.Sprintf("%s secret=%t scope=%s child=%s", e.Direction, e.Secret, e.Scope, e.ExecChild)
}

func (d *differ) diffEnv(old, cur []envSchema) {
	om, nm := map[string]envSchema{}, map[string]envSchema{}
	for _, e := range old {
		om[e.Name] = e
	}
	for _, e := range cur {
		nm[e.Name] = e
	}
	for _, name := range sortedKeys(om) {
		n, ok := nm[name]
		switch {
		case !ok:
			d.add(classBreaking, "env_removed", name, envText(om[name]), "")
		case n != om[name]:
			// direction, secret, scope and the exec-child handling are all contract
			d.add(classBreaking, "env_changed", name, envText(om[name]), envText(n))
		}
	}
	for _, name := range sortedKeys(nm) {
		if _, ok := om[name]; !ok {
			d.add(classAdditive, "env_added", name, "", envText(nm[name]))
		}
	}
}

func (d *differ) diffRosterKeys(old, cur *rosterSchema) {
	var ok, nk []string
	if old != nil {
		ok = old.Keys
	}
	if cur != nil {
		nk = cur.Keys
	}
	for _, k := range ok {
		if !slices.Contains(nk, k) {
			d.add(classBreaking, "roster_key_removed", k, "present", "absent")
		}
	}
	for _, k := range nk {
		if !slices.Contains(ok, k) {
			d.add(classAdditive, "roster_key_added", k, "", "present")
		}
	}
}

func (d *differ) diffOutput(p string, old, cur *outputSchema) {
	switch {
	case old == nil && cur == nil:
		return
	case old == nil:
		d.add(classAdditive, "output_added", p, "", cur.Kind)
		return
	case cur == nil:
		d.add(classBreaking, "output_removed", p, old.Kind, "")
		return
	}
	if old.Kind != cur.Kind {
		d.add(classBreaking, "output_kind_changed", p, old.Kind, cur.Kind)
		return
	}
	d.diffKeys(p, old.Keys, cur.Keys)
}

func (d *differ) diffKeys(p string, old, cur []outputKey) {
	nm := map[string]outputKey{}
	for _, k := range cur {
		nm[k.Name] = k
	}
	om := map[string]outputKey{}
	for _, k := range old {
		om[k.Name] = k
	}
	for _, k := range old {
		kp := p + " ." + k.Name
		n, ok := nm[k.Name]
		if !ok {
			// a removed key is ALWAYS breaking: optional or not, nested or not
			d.add(classBreaking, "output_key_removed", kp, k.Kind, "")
			continue
		}
		if k.Kind != n.Kind {
			d.add(classBreaking, "output_key_kind_changed", kp, k.Kind, n.Kind)
		}
		if !k.Optional && n.Optional {
			// a key that was always present may now be absent
			d.add(classBreaking, "output_key_became_optional", kp, "always", "optional")
		}
		if k.Optional && !n.Optional {
			d.add(classAdditive, "output_key_became_required", kp, "optional", "always")
		}
		d.diffKeys(kp, k.Keys, n.Keys)
	}
	for _, k := range cur {
		if _, ok := om[k.Name]; !ok {
			d.add(classAdditive, "output_key_added", p+" ."+k.Name, "", k.Kind)
		}
	}
}

// readSchemaFile reads one schema file, bounded.
func readSchemaFile(path string) (commandSchema, error) {
	var s commandSchema
	f, err := os.Open(path)
	if err != nil {
		return s, fmt.Errorf("schema diff: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSchemaFile+1))
	if err != nil {
		return s, fmt.Errorf("schema diff: read %s: %w", path, err)
	}
	if len(b) > maxSchemaFile {
		return s, fmt.Errorf("schema diff: %s is larger than %d bytes", path, maxSchemaFile)
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("schema diff: %s is not a pveforge schema: %w", path, err)
	}
	if s.Name != "pveforge" {
		return s, fmt.Errorf("schema diff: %s is not a pveforge schema (root name %q)", path, s.Name)
	}
	// json.Unmarshal drops fields it does not know: find them, so a surface this
	// binary cannot compare is reported, never silently ignored.
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil {
		return s, fmt.Errorf("schema diff: %s: %w", path, err)
	}
	unknownKeys(generic, reflect.TypeOf(s), "", &s.unknown)
	sort.Strings(s.unknown)
	return s, nil
}

// unknownKeys appends the path of every JSON object key in v that the Go type t
// does not declare (by its json tag), at any depth.
func unknownKeys(v any, t reflect.Type, path string, out *[]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch x := v.(type) {
	case map[string]any:
		if t.Kind() != reflect.Struct {
			return
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			if tag == "-" || (tag == "" && !f.IsExported()) {
				continue
			}
			name, _, _ := strings.Cut(tag, ",")
			if name == "" {
				name = f.Name
			}
			fields[name] = f.Type
		}
		for k, child := range x {
			ft, known := fields[k]
			if !known {
				*out = append(*out, strings.TrimPrefix(path+"."+k, "."))
				continue
			}
			unknownKeys(child, ft, path+"."+k, out)
		}
	case []any:
		if t.Kind() != reflect.Slice {
			return
		}
		for i, e := range x {
			unknownKeys(e, t.Elem(), fmt.Sprintf("%s[%d]", path, i), out)
		}
	}
}

func newSchemaDiffCmd() *cobra.Command {
	var failOn string
	var resolveFormat func() (kvjson.Format, error)
	cmd := &cobra.Command{
		Use:   "diff <old.json> <new.json> [--fail-on breaking]",
		Short: "Classify the change between two `pveforge schema` outputs as breaking or additive",
		Long: `Compare two files written by "pveforge schema" (two releases) and print a verdict:
none, additive, breaking, or incomparable (a file lacks a surface the other has,
carries a schemaVersion newer than this binary compares, or holds a JSON field
this binary does not know: nothing can be said about that part, so the verdict is
never "none"). Every removed verb, flag,
shorthand, alias, environment variable, output key or roster key is breaking;
so is any change of a flag's type or default, any change of requiredness, ANY
change of a command's mutation tier, a changed or removed argument, and any
change of a verb's exit statuses or named states (a verb gaining exit status 3
or 4 included). Added verbs, optional flags, optional arguments, output keys,
environment variables and roster keys are additive. Wording changes are
informational.

The exit status is 0 whatever the verdict, unless --fail-on breaking is given:
then a breaking verdict is exit 1. (Exit 4 is reserved for a refusal before a
change; this command changes nothing.)`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := resolveFormat()
			if err != nil {
				return err
			}
			if failOn != "" && failOn != classBreaking {
				return fmt.Errorf("schema diff: --fail-on %q: the only value is %q", failOn, classBreaking)
			}
			old, err := readSchemaFile(args[0])
			if err != nil {
				return err
			}
			cur, err := readSchemaFile(args[1])
			if err != nil {
				return err
			}
			rep := diffSchemas(old, cur)
			for i := range rep.Findings {
				f := &rep.Findings[i]
				f.Path, f.Was, f.Now = boundErrText(f.Path), boundErrText(f.Was), boundErrText(f.Now)
			}
			rerr := kvjson.Render(cmd.OutOrStdout(), format, rep)
			if failOn == classBreaking && rep.Verdict == classBreaking {
				return fmt.Errorf("schema diff: the change is breaking (%d breaking finding(s))", rep.Breaking)
			}
			return rerr
		},
	}
	resolveFormat = addOutputFlag(cmd)
	cmd.Flags().StringVar(&failOn, "fail-on", "", `exit 1 when the verdict is this: "breaking"`)
	markSafe(cmd)
	return cmd
}
