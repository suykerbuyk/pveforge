package netguard

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// modulePackageDirs walks the module for directories holding .go files,
// skipping testdata (whose probe packages are deliberately badly behaved and
// are not linked into anything). Derived rather than hardcoded so a package
// added later is swept without anyone remembering to add it.
func modulePackageDirs(t *testing.T) []string {
	t.Helper()
	var dirs []string
	err := filepath.WalkDir(moduleRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", ".git", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		dir := filepath.Dir(path)
		if len(dirs) == 0 || dirs[len(dirs)-1] != dir {
			dirs = append(dirs, dir)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", moduleRoot, err)
	}
	sort.Strings(dirs)
	dirs = slicesCompact(dirs)
	return dirs
}

func slicesCompact(s []string) []string {
	out := s[:0]
	var prev string
	for i, v := range s {
		if i == 0 || v != prev {
			out = append(out, v)
		}
		prev = v
	}
	return out
}

// TestNoPreInstallDialerAnywhereInTheModule sweeps every package in the
// module, not just the six that wire a TestMain.
//
// The per-package guard answers "does THIS package build a dialer too early".
// That is not the whole question: Go initialises every package linked into a
// test binary before that binary's TestMain, so a package-level client in
// internal/roster — which wires no seam and needs none, because it does not
// dial — would be constructed before internal/pve's TestMain and would escape
// internal/pve's own guard entirely. One package's omission would silently
// weaken another package's guarantee.
//
// This is the module-wide answer. It is cheap (a parse, no build) and it is
// self-maintaining: the directory list is derived from the tree.
func TestNoPreInstallDialerAnywhereInTheModule(t *testing.T) {
	dirs := modulePackageDirs(t)
	// Anti-vacuity: sweeping nothing, or sweeping a subtree, would pass
	// forever. The module has twelve packages today.
	if len(dirs) < 12 {
		t.Fatalf("swept only %d package directories from %s, expected at least 12 — wrong root?\n%v",
			len(dirs), moduleRoot, dirs)
	}
	var sawPve, sawRoster bool
	for _, dir := range dirs {
		sawPve = sawPve || strings.HasSuffix(dir, "internal/pve")
		sawRoster = sawRoster || strings.HasSuffix(dir, "internal/roster")
		t.Run(filepath.Base(dir), func(t *testing.T) {
			AssertNoPreInstallDialerIn(t, dir)
		})
	}
	// ...and it reached the packages that matter, not twelve unrelated ones.
	if !sawPve || !sawRoster {
		t.Errorf("the sweep did not reach internal/pve (%t) and internal/roster (%t); it looked at the wrong tree:\n%v",
			sawPve, sawRoster, dirs)
	}
}

// TestEverySeedCanActuallyFire is the meta-guard, and it exists because the
// absence of it cost a real hole.
//
// DefaultTransport and DefaultClient were once listed in the CALLS map, which
// is consulted only for a CallExpr's callee name. A bare http.DefaultTransport
// is a SelectorExpr and never a call, so neither seed could match anything
// under any input: two entries that made the guard look complete while
// matching nothing. The suite was green throughout, because a seed that never
// fires is indistinguishable from a seed with no violations to find — the
// same vacuity this whole unit is built around, turned on the guard itself.
//
// So every seed, in every map, must be demonstrably capable of producing a
// finding. A seed that cannot is either dead or misfiled, and either way it
// fails here rather than quietly widening the hole.
func TestEverySeedCanActuallyFire(t *testing.T) {
	// One synthetic package-level construction per seed, in the syntactic
	// position that seed is supposed to match.
	cases := map[string]string{}
	for name := range dialerSeedCalls {
		cases[name] = "var x, _ = pkg." + name + "()\n"
	}
	for name := range dialerSeedValues {
		cases[name] = "var x = pkg." + name + "\n"
	}
	for name := range dialerSeedTypes {
		cases[name+"{}"] = "var x = &pkg." + name + "{}\n"
	}
	if len(cases) == 0 {
		t.Fatal("no seeds to check, so this guard proved nothing")
	}

	// A REQUIRED-MEMBERSHIP FLOOR, declared independently of the maps.
	//
	// The loop below proves every seed that EXISTS can fire. It cannot prove a
	// seed still exists, because it iterates the maps themselves: delete an
	// entry and the loop simply checks one thing less and stays green. That is
	// this repo's standing "a green suite cannot detect a DELETED test,
	// because deleting it makes the suite greener" failure, pointed at the
	// seed list — and it is not hypothetical here. Mutant C6 removed
	// DefaultTransport from dialerSeedValues and SURVIVED this test until this
	// floor was added.
	//
	// So the floor is a second, separate declaration of what must be present.
	// It is deliberate duplication: the check and the thing checked need
	// different observers. Adding a seed needs no change here; REMOVING one
	// requires deleting it in two places, which is a review conversation
	// rather than an accident.
	for _, req := range []struct {
		set  map[string]bool
		name string
		what string
	}{
		{dialerSeedCalls, "NewClient", "dialerSeedCalls"},
		{dialerSeedCalls, "Dial", "dialerSeedCalls"},
		{dialerSeedCalls, "DialWithPassword", "dialerSeedCalls"},
		{dialerSeedValues, "DefaultTransport", "dialerSeedValues"},
		{dialerSeedValues, "DefaultClient", "dialerSeedValues"},
		{dialerSeedTypes, "Transport", "dialerSeedTypes"},
	} {
		if !req.set[req.name] {
			t.Errorf("%s no longer contains %q. That seed closed a measured hole; "+
				"removing it reopens one silently, because every other check here "+
				"iterates the map and would simply stop looking.", req.what, req.name)
		}
	}

	for want, decl := range cases {
		t.Run(want, func(t *testing.T) {
			dir := t.TempDir()
			src := "package p\n\nimport pkg \"net/http\"\n\n" + decl + "\nvar _ = x\n"
			if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
			findings, scanned, err := scanPreInstallDialers(dir)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if scanned != 1 {
				t.Fatalf("scanned %d files, want 1", scanned)
			}
			if len(findings) == 0 {
				t.Fatalf("seed %q produced NO finding against:\n%s\n"+
					"It is dead — nothing can ever match it — or it is in the wrong map "+
					"(calls are matched as a CallExpr callee, values as a bare "+
					"Ident/SelectorExpr, types as a CompositeLit type).", want, src)
			}
			if findings[0].Name != want {
				t.Errorf("seed %q matched, but reported as %q", want, findings[0].Name)
			}
		})
	}
}

// TestPreInstallScan_CatchesTheCapturedTransportIdioms pins the three forms
// that survived the dead-seed defect, including the one the Chair's break-test
// found: the exact expression internal/pve/client.go:103 uses, which is the
// line most likely to be copied into a package-level initialiser by someone
// building a customised client.
func TestPreInstallScan_CatchesTheCapturedTransportIdioms(t *testing.T) {
	for name, decl := range map[string]string{
		"clone_of_default_transport": "var c = &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}\n",
		"bare_default_transport":     "var x = http.DefaultTransport\n",
		"bare_default_client":        "var x = http.DefaultClient\n",
		"default_transport_as_field": "var c = &http.Client{Transport: http.DefaultTransport}\n",
		"transport_literal":          "var c = &http.Client{Transport: &http.Transport{}}\n",
		"via_helper":                 "func mk() *http.Transport { return http.DefaultTransport.(*http.Transport).Clone() }\n\nvar c = &http.Client{Transport: mk()}\n",
		"in_init":                    "var c *http.Client\n\nfunc init() { c = &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()} }\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			src := "package p\n\nimport \"net/http\"\n\n" + decl + "\nvar _ = c\n"
			src = strings.Replace(src, "var _ = c\n", "", 1)
			if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
			findings, _, err := scanPreInstallDialers(dir)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if len(findings) == 0 {
				t.Fatalf("this pre-install capture was NOT caught:\n%s", src)
			}
		})
	}
}

// TestPreInstallScan_AllowsWhatIsActuallySafe is the accept side. A guard
// that flagged everything would pass every test above and make the module
// unbuildable, so the things that are genuinely fine have to be pinned too.
func TestPreInstallScan_AllowsWhatIsActuallySafe(t *testing.T) {
	for name, decl := range map[string]string{
		// Nil Transport: resolves http.DefaultTransport at REQUEST time, so
		// it meets the swap Install performs later.
		"client_with_nil_transport": "var c = &http.Client{Timeout: time.Second}\n",
		// A bare dialer captures nothing and is inert until used. This is
		// netguard's own loopbackDialer shape.
		"bare_net_dialer": "var d = &net.Dialer{Timeout: time.Second}\n",
		// Built inside a function, which runs after TestMain.
		"constructed_in_a_func": "func get() *http.Client { return &http.Client{Transport: http.DefaultTransport} }\n",
		// A plain value.
		"unrelated_var": "var n = 22\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			src := "package p\n\nimport (\n\t\"net\"\n\t\"net/http\"\n\t\"time\"\n)\n\n" + decl +
				"\nvar _, _, _ = net.IPv4zero, http.MethodGet, time.Second\n"
			if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
			findings, _, err := scanPreInstallDialers(dir)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("false positive on safe code: %v\n%s", findings, src)
			}
		})
	}
}
