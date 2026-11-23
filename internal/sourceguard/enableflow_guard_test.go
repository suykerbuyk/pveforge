package sourceguard

import (
	"slices"
	"testing"
)

// Source pins for the operator flow of `acl enable-vm-destroy` (plan
// .build/chair/enable-flow-plan.md, T7/T11/F4): the verb's verdict is doctor's
// code path, never a second computation (ruling G5, the same shape as M14e for
// vm destroy's status read), and everything the verb prints goes through one
// renderer. Non-vacuity as in enablegrant_guard_test.go: the walk parsed a
// floor of files and Reached the guarded ones, and every target DOES match real
// code elsewhere, so a target that silently matches nothing is caught.

const (
	flowConfirmFile = "cmd/pveforge/confirm.go"
	flowDoctorFile  = "cmd/pveforge/doctor.go"
	flowPVEPkg      = "github.com/suykerbuyk/pveforge/internal/pve"
	flowFmtPkg      = "fmt"
	flowKVPkg       = "github.com/suykerbuyk/pveforge/internal/kvjson"
)

func verdictConstTargets() []Target {
	var out []Target
	for _, n := range []string{"VerdictHeld", "VerdictMissing", "VerdictUnknown", "VerdictNotChecked"} {
		out = append(out, Target{ImportPath: flowPVEPkg, Name: n})
	}
	return out
}

func TestEnableFlow_T7_TheVerdictIsDoctorsCodePath(t *testing.T) {
	probes := []Target{
		{AnyQualifier: true, Name: "CheckVerb"},
		{AnyQualifier: true, Name: "NodeStatusRead"},
		{AnyQualifier: true, Name: "ClusterNodes"},
	}
	verdictFn := Target{Name: "doctorVerdict"}
	all := slices.Concat(probes, verdictConstTargets(), []Target{verdictFn})
	res, err := NonTestReferences(Scope{Root: "../.."}, all)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Parsed) < 100 {
		t.Fatalf("the walk parsed only %d files", len(res.Parsed))
	}
	for _, f := range []string{enableCmdFile, flowConfirmFile, flowDoctorFile} {
		if !res.Reached(f) {
			t.Fatalf("the walk never parsed %s", f)
		}
	}
	// (a) the verb's files decide no row and read nothing themselves.
	for _, f := range []string{enableCmdFile, flowConfirmFile} {
		for _, r := range refsIn(res, f, slices.Concat(probes, verdictConstTargets())) {
			t.Errorf("%s makes its own verdict read or decides a row: %s", f, r)
		}
	}
	// (b) doctorVerdict is called from exactly doctor's command and the verb's
	// finish, once each.
	var sites []string
	for file, refs := range res.Refs {
		for _, r := range refs {
			if r.Target == verdictFn && r.Func != "doctorVerdict" {
				sites = append(sites, file+":"+r.Func)
			}
		}
	}
	slices.Sort(sites)
	if want := []string{enableCmdFile + ":enableFlow.finish", flowDoctorFile + ":newDoctorCmd"}; !slices.Equal(sites, want) {
		t.Errorf("doctorVerdict is called from %v, want exactly %v", sites, want)
	}
	// (c) CheckVerb is reached from one non-test file of the command package, in
	// doctorVerdict.
	var cv []string
	for file, refs := range res.Refs {
		for _, r := range refs {
			if r.Target == probes[0] && len(file) > 11 && file[:11] == "cmd/pveforg" {
				cv = append(cv, file+":"+r.Func)
			}
		}
	}
	if want := []string{flowDoctorFile + ":doctorVerdict"}; !slices.Equal(cv, want) {
		t.Errorf("CheckVerb is called from %v in cmd/pveforge, want exactly %v", cv, want)
	}
	// (d) non-vacuity: the row words and the reads are real code in doctor.go /
	// internal/pve, and doctorVerdict is real in both callers.
	if len(refsIn(res, flowDoctorFile, verdictConstTargets())) == 0 {
		t.Error("no Verdict constant in doctor.go: the pin would pass on a typo")
	}
	if len(res.Refs["internal/pve/vmdestroyreq.go"]) == 0 {
		t.Error("nothing matched in internal/pve/vmdestroyreq.go")
	}
	for _, tg := range []Target{probes[1]} {
		if len(refsIn(res, "internal/pve/inflight.go", []Target{tg})) == 0 {
			t.Errorf("%s matches nothing in internal/pve/inflight.go", tg)
		}
	}
}

// F4 / T11: nothing the verb prints bypasses the renderer. The cmd file spells
// no fmt.Fprint*; confirm.go writes only the fixed prompt (and the newline
// after it) inside askYesNo; and the cmd file does call kvjson.Render.
func TestEnableFlow_T11_EverythingPrintedGoesThroughKVJSON(t *testing.T) {
	fprint := []Target{
		{ImportPath: flowFmtPkg, Name: "Fprintf"}, {ImportPath: flowFmtPkg, Name: "Fprint"},
		{ImportPath: flowFmtPkg, Name: "Fprintln"}, {ImportPath: flowFmtPkg, Name: "Printf"},
		{ImportPath: flowFmtPkg, Name: "Println"}, {ImportPath: flowFmtPkg, Name: "Print"},
	}
	render := Target{ImportPath: flowKVPkg, Name: "Render"}
	res, err := NonTestReferences(Scope{Root: "../.."}, slices.Concat(fprint, []Target{render}))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{enableCmdFile, flowConfirmFile} {
		if !res.Reached(f) {
			t.Fatalf("the walk never parsed %s", f)
		}
	}
	for _, r := range refsIn(res, enableCmdFile, fprint) {
		t.Errorf("the verb prints outside kvjson: %s", r)
	}
	for _, r := range refsIn(res, flowConfirmFile, fprint) {
		if r.Func != "askYesNo" {
			t.Errorf("confirm.go prints outside askYesNo: %s", r)
		}
	}
	// the prompt writer is real, and the verb renders (so the first loop is not
	// reading a file that prints nothing at all).
	if len(refsIn(res, flowConfirmFile, fprint)) == 0 {
		t.Error("confirm.go prints nothing: the prompt is not where the pin looks")
	}
	if n := len(refsIn(res, enableCmdFile, []Target{render})); n < 3 {
		t.Errorf("acl_enable.go calls kvjson.Render %d times, want at least 3 (dry run, plan, report)", n)
	}
	if len(refsIn(res, "cmd/pveforge/doctor.go", []Target{render})) == 0 {
		t.Error("kvjson.Render matches nothing in doctor.go: the target is vacuous")
	}
}

// INV-1 over the new file too (F4): confirm.go reaches none of the token
// phase's remove/mint machinery and spells no forbidden pveum command. The
// original guard is left as it was; this extends it.
func TestEnableFlow_INV1_ConfirmFileIsInsideTheGuard(t *testing.T) {
	idents, lits := forbiddenIdents(), forbiddenLiterals()
	res, err := NonTestReferences(Scope{Root: "../.."}, slices.Concat(idents, lits))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reached(flowConfirmFile) {
		t.Fatalf("the walk never parsed %s", flowConfirmFile)
	}
	for _, r := range refsIn(res, flowConfirmFile, slices.Concat(idents, lits)) {
		t.Errorf("INV-1: %s", r)
	}
}
