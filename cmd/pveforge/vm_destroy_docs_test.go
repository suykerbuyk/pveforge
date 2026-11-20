package main

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

// Drift pins for what the docs promise about `vm destroy`. The numeric exit
// set is held by TestREADME_ExitStatusesMatchTheCode, which cannot see this
// prose or the situation table; these are what hold them.

func readDoc(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// docSection is the text after the line starting heading, up to the next
// heading of the same or a higher level.
func docSection(t *testing.T, text, heading string) string {
	t.Helper()
	i := strings.Index(text, "\n"+heading)
	if i < 0 {
		t.Fatalf("no heading %q", heading)
	}
	body := text[i+1+len(heading):]
	level := strings.Index(heading, " ")
	for l := level; l >= 1; l-- {
		if j := strings.Index(body, "\n"+strings.Repeat("#", l)+" "); j >= 0 {
			body = body[:j]
		}
	}
	return body
}

var tableCellTicks = regexp.MustCompile("`")

// tableRows returns the cells of every markdown table row in body that starts
// with a backticked cell, backticks removed.
func tableRows(body string) [][]string {
	var rows [][]string
	for _, l := range strings.Split(body, "\n") {
		if !strings.HasPrefix(l, "| `") {
			continue
		}
		var cells []string
		for _, c := range strings.Split(strings.Trim(l, "|"), "|") {
			cells = append(cells, strings.TrimSpace(tableCellTicks.ReplaceAllString(c, "")))
		}
		rows = append(rows, cells)
	}
	return rows
}

// destroyScenarios drives the verb to ONE situation each, the same fixtures the
// behavioural tests use. B9 needs a real signal and is driven by
// TestVMDestroy_B9_RealSignalsAfterDispatch.
func destroyScenarios(t *testing.T) map[string]func() dRes {
	short := func() { t.Cleanup(pve.SetTaskTimingsForTests(time.Millisecond, 100*time.Millisecond)) }
	run := func(mut func(*pvefake.VMREST)) func() dRes {
		return func() dRes { return newDEnv(t, mut).runYes() }
	}
	retry := func(rows []pvefake.TaskRow, mut func(*pvefake.VMREST)) func() dRes {
		return func() dRes { return retryEnv(t, rows, mut).runYes() }
	}
	running := func(s *pvefake.VMREST) { s.VMStatus = `{"status":"running"}` }
	script := func(key string, rep pvefake.Reply, also func(*pvefake.VMREST)) func(*pvefake.VMREST) {
		return func(s *pvefake.VMREST) {
			if also != nil {
				also(s)
			}
			s.Script = map[string][]pvefake.Reply{key: {rep}}
		}
	}
	stop := "POST /nodes/" + dNode + "/qemu/691/status/stop"
	del := "DELETE /nodes/" + dNode + "/qemu/691"
	pending := func(kind string) func(*pvefake.VMREST) {
		return func(s *pvefake.VMREST) { s.Tasks = []pvefake.TaskRow{dRunning(kind, 7)} }
	}
	return map[string]func() dRes{
		"B1":          run(nil),
		"B1-unclean":  run(func(s *pvefake.VMREST) { s.ReflectEnd = "WARNINGS: 1" }),
		"task-failed": run(func(s *pvefake.VMREST) { s.ReflectEnd = "ERROR: x" }),
		"B2": func() dRes {
			e := newDEnv(t, func(s *pvefake.VMREST) { s.ReflectEnd = "" })
			short()
			return e.runYes()
		},
		"B3":                     run(script("GET /nodes/"+dNode+"/tasks/"+dUPID("qmdestroy", 1)+"/status", pvefake.Reply{Code: 595, Message: "x"}, nil)),
		"B1-unproven":            run(func(s *pvefake.VMREST) { s.NextIDFree = false }),
		"dispatch-unconfirmed":   run(script(del, pvefake.Reply{Body: "null"}, nil)),
		"stop-unknown":           run(script(stop, pvefake.Reply{Code: 502, Message: "x"}, running)),
		"stop-failed":            run(script(stop, pvefake.Reply{Code: 500, Message: "x"}, running)),
		"dispatch-refused":       run(func(s *pvefake.VMREST) { s.DestroyCode = 500 }),
		"B4":                     run(pending("qmdestroy")),
		"B4b":                    run(pending("qmigrate")),
		"B4c":                    run(pending("qmstop")),
		"B4d":                    func() dRes { return newDEnv(t, nil).run() },
		"B5-gone":                retry([]pvefake.TaskRow{dRow("qmdestroy", 3, "OK")}, nil),
		"B5-unclean":             retry([]pvefake.TaskRow{dRow("qmdestroy", 3, "WARNINGS: 1")}, nil),
		"B5-elsewhere":           retry([]pvefake.TaskRow{dRow("qmdestroy", 3, "OK")}, func(s *pvefake.VMREST) { s.NextIDFree = false }),
		"B5-absent-without-task": retry(nil, nil),
		"B10":                    run(func(s *pvefake.VMREST) { s.NodeStatus = 403 }),
	}
}

// T-README: every situation the README documents is DRIVEN through the verb and
// must exit what the README says with the outcome it says — the situation
// column, not only the four outcome words (a README that documents B5-gone as 4
// and B5-elsewhere as 0 must fail). The blind spot, stated: the prose in the
// "Meaning" column is not checked, and B9 is driven by its own process test.
func TestREADME_VMDestroyOutcomesMatchTheVerb(t *testing.T) {
	sec := docSection(t, readDoc(t, "../../README.md"), "## `vm destroy`")
	outcomes := map[string]bool{"ok": true, "failed": true, "unknown": true, "refused": true}
	scen := destroyScenarios(t)
	seen := map[string]bool{}
	gotOutcomeExit := map[string]int{}
	for _, c := range tableRows(sec) {
		if len(c) < 3 || c[0] == "outcome" || c[0] == "situation" {
			continue
		}
		if outcomes[c[0]] && !strings.HasPrefix(c[1], "B") {
			n, err := strconv.Atoi(c[1])
			if err != nil {
				t.Fatalf("outcome row %v: exit %q", c, c[1])
			}
			gotOutcomeExit[c[0]] = n
			continue
		}
		sit, outcome, exits := c[0], c[1], regexp.MustCompile(`\d+`).FindAllString(c[2], -1)
		seen[sit] = true
		if sit == "B9" {
			if outcome != "unknown" || len(exits) != 2 || exits[0] != "130" || exits[1] != "143" {
				t.Errorf("B9 row %v", c)
			}
			continue
		}
		run, ok := scen[sit]
		if !ok {
			t.Errorf("the README documents situation %q, which no scenario drives", sit)
			continue
		}
		r := run()
		if r.str("situation") != sit || r.str("outcome") != outcome || len(exits) != 1 || strconv.Itoa(r.code) != exits[0] {
			t.Errorf("README row %v, but the verb gave exit %d outcome %q situation %q:\n%s", c, r.code, r.str("outcome"), r.str("situation"), r.stdout)
		}
	}
	for sit := range scen {
		if !seen[sit] {
			t.Errorf("situation %q is driven but the README has no row for it", sit)
		}
	}
	for outcome, want := range map[string]int{"ok": exitOK, "failed": exitFailed, "unknown": exitOutcomeUnknown, "refused": exitRefused} {
		if got, ok := gotOutcomeExit[outcome]; !ok || got != want {
			t.Errorf("README outcome table: %s exits %d (present %v), code says %d", outcome, got, ok, want)
		}
	}
	// And the reason set is a closed list with no duplicates.
	list := regexp.MustCompile("(?s)`deadline`.*?`stop-failed`").FindString(sec)
	if list == "" {
		t.Fatal("the README lists no reason set")
	}
	seenReason := map[string]bool{}
	for _, m := range regexp.MustCompile("`([a-z-]+)`").FindAllStringSubmatch(list, -1) {
		if seenReason[m[1]] {
			t.Errorf("reason %q is listed twice", m[1])
		}
		seenReason[m[1]] = true
	}
	if len(seenReason) != 10 {
		t.Errorf("README reason set has %d entries, want the 10 the code defines: %v", len(seenReason), seenReason)
	}
}

const (
	exitOK     = 0
	exitFailed = 1
)

// T-PROSE: the prose the numeric exit-set test cannot see.
func TestDocs_NoStaleExitFourClaim(t *testing.T) {
	fold := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	readme, prd := fold(readDoc(t, "../../README.md")), fold(readDoc(t, "../../docs/prd.md"))
	if strings.Contains(readme, "No command exits 4 yet") {
		t.Error("the README still says no command exits 4")
	}
	rows := map[string]string{}
	for _, l := range strings.Split(readDoc(t, "../../README.md"), "\n") {
		for _, n := range []string{"3", "4"} {
			if strings.HasPrefix(l, "| `"+n+"` |") {
				rows[n] = l
			}
		}
	}
	for _, n := range []string{"3", "4"} {
		if !strings.Contains(rows[n], "`vm destroy`") {
			t.Errorf("the README's exit-%s row does not name `vm destroy`: %q", n, rows[n])
		}
	}
	if strings.Contains(rows["3"], "Other commands that wait on a task report the same condition in their error text and exit `1`") {
		t.Errorf("the exit-3 row still says other commands (which now include vm destroy) exit 1: %q", rows["3"])
	}
	bullet := prd[strings.Index(prd, "**Exit status.**"):]
	bullet = bullet[:strings.Index(bullet, "**Task waits.**")]
	if strings.Contains(bullet, "no command yet") {
		t.Errorf("the PRD's exit-status bullet still says no command refuses yet: %q", bullet)
	}
	if !strings.Contains(bullet, "`vm destroy`") {
		t.Errorf("the PRD's exit-status bullet does not name `vm destroy`: %q", bullet)
	}
}

// T-GUIDE: the guide's GRANT PROCEDURE (not the file) names exactly the
// privileges the verb refuses with, and all three a destroy needs.
func TestGuide_VMDestroyPrivilegeMatchesTheRefusal(t *testing.T) {
	guide := docSection(t, readDoc(t, "../../docs/operations/secrets-and-keys.md"), "### 11. Granting what `vm destroy` needs")
	probe := newDEnv(t, func(s *pvefake.VMREST) { s.NodeStatus = 403 }).runYes()
	member := retryEnv(t, []pvefake.TaskRow{dRow("qmdestroy", 3, "OK")}, func(s *pvefake.VMREST) { s.ClusterNodesStatus = 403 }).runYes()
	for name, r := range map[string]dRes{"probe 403": probe, "member list 403": member} {
		priv := r.str("privilege")
		if priv == "" {
			t.Fatalf("%s: the refusal carries no privilege: %s", name, r.stdout)
		}
		if !strings.Contains(guide, strings.ReplaceAll(priv, dNode, "<node>")) {
			t.Errorf("%s: the refusal names %q, which the grant procedure does not", name, priv)
		}
	}
	for _, priv := range []string{"Sys.Audit", "VM.Allocate", "VM.PowerMgmt"} {
		if !strings.Contains(guide, priv) {
			t.Errorf("the grant procedure does not name %s", priv)
		}
	}
	// The custom role is PVEVMAdmin's list (read live from PVE 9.2.11) plus
	// Sys.Audit: 24 privileges, no more, no fewer.
	m := regexp.MustCompile(`pveum role add PVEForgeVMAdminAudit --privs "([^"]+)"`).FindStringSubmatch(guide)
	if m == nil {
		t.Fatal("the grant procedure has no `pveum role add` line")
	}
	privs := strings.Split(m[1], ",")
	if len(privs) != 24 || privs[len(privs)-1] != "Sys.Audit" || strings.Count(m[1], "Sys.Audit") != 1 {
		t.Errorf("the custom role has %d privileges, want PVEVMAdmin's 23 plus Sys.Audit: %v", len(privs), privs)
	}
}
