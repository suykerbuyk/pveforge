package main

import (
	"reflect"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// The contract surfaces `pveforge schema` publishes beyond the command tree
// (contract plan §3.3). Each is data a consumer diffs between releases with
// `pveforge schema diff`; each is held to the code by a test, never by prose.

// ---- semantic requiredness ----------------------------------------------

// requiredFlag is one flag a command refuses to run without although cobra does
// not know it (or knows it only conditionally). When == "" means always;
// otherwise it is a short statement of the condition. Flags cobra marks
// required (MarkFlagRequired) need no row here: the schema reads the
// annotation. TestSchema_RequirednessSweep holds this table to the command
// tree's help text and to the error literals the commands carry, so a new
// hand-checked requirement cannot ship without a row (or a reasoned exemption).
type requiredFlag struct {
	Flag string
	When string
}

var runtimeRequiredFlags = map[string][]requiredFlag{
	"bootstrap": {
		{Flag: "grant"},
		{Flag: "host", When: "the target is not in the roster yet"},
		{Flag: "node", When: "the target is not in the roster yet"},
		{Flag: "no-ssh-key", When: "the target holds a token but no SSH key"},
		{Flag: "host-key-fingerprint", When: "a password session captures a TLS pin and --ssh-tofu is not given, or --reprovisioned is given"},
	},
	"roster import-token": {
		{Flag: "grant"},
		{Flag: "host", When: "the target is not in the roster yet"},
		{Flag: "node", When: "the target is not in the roster yet"},
	},
	"storage create":        {{Flag: "type"}, {Flag: "data", When: "--type zfspool is given (pool=<zpool>)"}},
	"vm destroy":            {{Flag: "yes", When: "a destroy would be dispatched (checked after the reads)"}},
	"harness vm destroy":    {{Flag: "yes"}},
	"harness vm gone":       {{Flag: "destroy-task"}},
	"acl enable-vm-destroy": {{Flag: "yes", When: "a write is planned and there is no terminal to ask on"}},
	"vm snapshot rollback":  {{Flag: "witness-marker", When: "--witness-command is given"}},
}

// requiredOf is the schema's requiredness of flag f of cmd: cobra's required
// annotation, or the table's unconditional row, is "required"; a conditional
// row is requiredWhen.
func requiredOf(cmd *cobra.Command, f *pflag.Flag) (required bool, when string) {
	if len(f.Annotations[cobra.BashCompOneRequiredFlag]) > 0 && f.Annotations[cobra.BashCompOneRequiredFlag][0] == "true" {
		return true, ""
	}
	path := strings.TrimPrefix(cmd.CommandPath(), cmd.Root().Name()+" ")
	for _, r := range runtimeRequiredFlags[path] {
		if r.Flag == f.Name {
			if r.When == "" {
				return true, ""
			}
			return false, r.When
		}
	}
	return false, ""
}

// ---- positional arguments -------------------------------------------------

// argSchema is one positional argument, parsed from the command's Use line by
// one grammar (parseUseArgs): <x> required, [x] optional, x... variadic, and
// "--" separating the arguments handed to another program (exec).
type argSchema struct {
	Name      string `json:"name"`
	Required  bool   `json:"required"`
	Variadic  bool   `json:"variadic,omitempty"`
	AfterDash bool   `json:"afterDash,omitempty"`
}

// useUnits splits a Use line (after the command name) into units at depth 0:
// a [..] or (..) group is one unit.
func useUnits(use string) []string {
	var units []string
	var cur strings.Builder
	depth := 0
	flush := func() {
		if cur.Len() > 0 {
			units = append(units, cur.String())
			cur.Reset()
		}
	}
	for _, r := range use {
		switch {
		case r == '[' || r == '(':
			// a group starts a new unit only at the start of one; inside a
			// token (PATH:ROLE[:PRIVS]) it only extends the token
			if depth == 0 && cur.Len() == 0 {
				flush()
			}
			depth++
			cur.WriteRune(r)
		case r == ']' || r == ')':
			cur.WriteRune(r)
			depth--
			if depth == 0 && (strings.HasPrefix(cur.String(), "[") || strings.HasPrefix(cur.String(), "(")) {
				flush()
			}
		case r == ' ' && depth == 0:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return units
}

// parseUseArgs returns the positional arguments of a Use line. Flags (--x and
// the one value token after a named flag, and any [--...] or (--...) group) are
// skipped.
func parseUseArgs(use string) []argSchema {
	units := useUnits(use)
	if len(units) > 0 {
		units = units[1:] // the command name
	}
	var out []argSchema
	afterDash := false
	for i := 0; i < len(units); i++ {
		u := units[i]
		switch {
		case u == "--":
			afterDash = true
		case strings.HasPrefix(u, "--"):
			// a named flag: its value is the next unit unless that is another
			// flag or a group
			if i+1 < len(units) {
				n := units[i+1]
				if !strings.HasPrefix(n, "--") && !strings.HasPrefix(n, "[") && !strings.HasPrefix(n, "(") {
					i++
				}
			}
		case strings.HasPrefix(u, "("):
			// a choice group of flags
		case strings.HasPrefix(u, "[--"):
			// an optional flag group
		case strings.HasPrefix(u, "["):
			inner := strings.TrimSuffix(strings.TrimPrefix(u, "["), "]")
			out = append(out, argOf(inner, false, afterDash))
		default:
			out = append(out, argOf(u, true, afterDash))
		}
	}
	return out
}

func argOf(raw string, required, afterDash bool) argSchema {
	variadic := strings.Contains(raw, "...")
	name := strings.TrimSpace(strings.ReplaceAll(raw, "...", ""))
	name = strings.TrimSuffix(strings.TrimPrefix(name, "<"), ">")
	return argSchema{Name: strings.TrimSpace(name), Required: required, Variadic: variadic, AfterDash: afterDash}
}

// ---- exits ----------------------------------------------------------------

// exitsSchema is the part of a command's exit-status contract beyond 0, 1 and
// the signals: the reserved statuses it can return and its named state.
type exitsSchema struct {
	Codes []int  `json:"codes"`
	State string `json:"state,omitempty"`
}

// readOnlyExits are the safe-tier commands that exit with a reserved status:
// doctor refuses (4) when a privilege is missing, unknown or not checked.
var readOnlyExits = map[string]verbExit{
	"doctor": {Exits: []int{4}},
}

func exitsOf(path string) *exitsSchema {
	v, ok := verbExits[path]
	if !ok {
		v, ok = readOnlyExits[path]
	}
	if !ok {
		return nil
	}
	codes := append([]int(nil), v.Exits...)
	sort.Ints(codes)
	return &exitsSchema{Codes: codes, State: v.State}
}

// exitStatusSchema is one row of the global exit-status table. The README table,
// this table and runRoot's constants are held to each other by one test
// (TestSchema_ExitStatusesAreOneSet).
type exitStatusSchema struct {
	Code    int    `json:"code"`
	Name    string `json:"name"`
	Meaning string `json:"meaning"`
}

func exitStatusTable() []exitStatusSchema {
	return []exitStatusSchema{
		{0, "success", "the command completed, including one that completed with a printed warning"},
		{1, "failure", "the command failed (including a usage error); also a failure after a change was made, and a lost response on a synchronous write, which is not proof that nothing changed"},
		{exitOutcomeUnknown, "outcome_unknown", "a change was dispatched and its outcome was not observed"},
		{exitRefused, "refused", "refused before anything was changed on a PVE host or in the roster file"},
		{130, "interrupted_sigint", "interrupted by SIGINT"},
		{143, "interrupted_sigterm", "interrupted by SIGTERM"},
	}
}

// ---- environment ----------------------------------------------------------

// envSchema is one environment variable pveforge reads, sets, or strips. The
// SET of names is held to the code by a type-checked scan of every environment
// access in the module (internal/sourceguard TestRelease_EnvSetIsExact, against
// testdata/env_names.golden); the metadata is this table.
type envSchema struct {
	Name      string `json:"name"`
	Direction string `json:"direction"`           // in: read; out: set for a child
	Secret    bool   `json:"secret"`              // the value is a credential
	Scope     string `json:"scope"`               // core, proxy, harness, harness-secrets, exec-child
	ExecChild string `json:"execChild,omitempty"` // removed or set, for `pveforge exec`'s child
}

func envTable() []envSchema {
	return []envSchema{
		{Name: "ALL_PROXY", Direction: "in", Scope: "harness"},
		{Name: "HARNESS_CREATED_FILE", Direction: "in", Scope: "harness"},
		{Name: "HARNESS_PROBE_MIN_FREE_GIB", Direction: "in", Scope: "harness"},
		{Name: "HARNESS_RESET_MIN_FREE_GIB", Direction: "in", Scope: "harness"},
		{Name: "HARNESS_STORAGE", Direction: "in", Scope: "harness"},
		{Name: "HTTPS_PROXY", Direction: "in", Scope: "proxy"},
		{Name: "HTTP_PROXY", Direction: "in", Scope: "proxy"},
		{Name: "NO_PROXY", Direction: "in", Scope: "proxy"},
		{Name: "PVEFORGE_HARNESS_AGE_IDENTITY", Direction: "in", Secret: true, Scope: "harness-secrets"},
		{Name: "PVEFORGE_HARNESS_AGE_IDENTITY_FILE", Direction: "in", Scope: "harness-secrets"},
		{Name: "PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD", Direction: "in", Secret: true, Scope: "harness-secrets"},
		{Name: "PVEFORGE_HARNESS_OUTER_ROSTERS", Direction: "in", Scope: "harness"},
		{Name: "PVEFORGE_HARNESS_ROSTER", Direction: "in", Scope: "harness"},
		{Name: "PVEFORGE_PVE_AUTHORIZATION", Direction: "out", Secret: true, Scope: "exec-child", ExecChild: "set"},
		{Name: "PVEFORGE_PVE_PASSWORD", Direction: "in", Secret: true, Scope: "core", ExecChild: "removed"},
		{Name: "PVEFORGE_ROSTER", Direction: "in", Scope: "core"},
		{Name: "PVEFORGE_ROSTER_PASSPHRASE", Direction: "in", Secret: true, Scope: "core", ExecChild: "removed"},
		{Name: "all_proxy", Direction: "in", Scope: "harness"},
		{Name: "http_proxy", Direction: "in", Scope: "proxy"},
		{Name: "https_proxy", Direction: "in", Scope: "proxy"},
		{Name: "no_proxy", Direction: "in", Scope: "proxy"},
	}
}

// ---- roster keys ----------------------------------------------------------

// rosterSchema lists the roster file's toml keys. They are generated by
// reflection over the roster types and held to a golden list by a test, so a
// rename shows in the diff of two releases.
type rosterSchema struct {
	Keys []string `json:"keys"`
}

func rosterKeys() []string {
	var out []string
	var walk func(t reflect.Type, prefix string)
	walk = func(t reflect.Type, prefix string) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("toml")
			if tag == "" || tag == "-" {
				continue
			}
			name := strings.Split(tag, ",")[0]
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			out = append(out, path)
			walk(f.Type, path)
		}
	}
	walk(reflect.TypeOf(roster.Roster{}), "")
	sort.Strings(out)
	return out
}

// ---- the contract block ---------------------------------------------------

// contractSchema is the build identity the schema describes: the same
// versionReport `pveforge version` prints, from the same function.
type contractSchema struct {
	Pveforge versionReport `json:"pveforge"`
}
