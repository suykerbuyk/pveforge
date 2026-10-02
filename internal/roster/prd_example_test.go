package roster

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

// The PRD (docs/prd.md §4) shows an annotated roster, and §4.1 states the
// work factor secrets are sealed at. Both are this package's facts, so they
// are held here: cmd/pveforge's PRD tests cannot reach checkKeys or the
// work-factor pin, which are unexported.

// prdRosterExample returns the fenced ```toml block of the PRD's §4.
func prdRosterExample(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../docs/prd.md")
	if err != nil {
		t.Fatal(err)
	}
	_, sec, ok := strings.Cut(string(b), "\n## 4. ")
	if !ok {
		t.Fatal(`docs/prd.md has no "## 4. " section`)
	}
	if i := strings.Index(sec, "\n### "); i >= 0 {
		sec = sec[:i]
	}
	_, block, ok := strings.Cut(sec, "```toml\n")
	if !ok {
		t.Fatal("docs/prd.md §4 has no ```toml block")
	}
	block, _, ok = strings.Cut(block, "```")
	if !ok {
		t.Fatal("docs/prd.md §4's ```toml block is not closed")
	}
	// The block is indented as part of a list item; TOML does not mind.
	return block
}

// TestPRD_RosterExampleUsesOnlyRosterKeys: every key in the PRD's example
// roster is one a roster may hold, spelled exactly, checked by the same
// checkKeys that refuses a real roster's unknown key; and the two
// provenance values are ones Load accepts, by its own checks. The rest is
// not loaded: the example's placeholder secrets and pins would not survive
// a full load.
func TestPRD_RosterExampleUsesOnlyRosterKeys(t *testing.T) {
	block := prdRosterExample(t)
	if err := checkKeys([]byte(block)); err != nil {
		t.Errorf("docs/prd.md §4's example roster: %v", err)
	}
	// Anti-vacuity: the example shows every table, and checkKeys really is
	// reading it (a key it does not know is refused).
	for _, table := range []string{"[[targets]]", "[targets.token]", "[targets.ssh]", "[targets.tls]"} {
		if !strings.Contains(block, table) {
			t.Errorf("docs/prd.md §4's example roster has no %s table", table)
		}
	}
	if err := checkKeys([]byte(block + "\nbogus_key = 1\n")); err == nil {
		t.Error("checkKeys accepted the example with an unknown key added: it is not reading the block")
	}
	for _, v := range []struct {
		key   string
		check func(string) error
	}{
		{"host_key_source", checkHostKeySource},
		{"source", func(s string) error { _, err := tlspin.ParseSource(s); return err }},
	} {
		ms := regexp.MustCompile(`(?m)^\s*`+v.key+`\s*=\s*"([^"]*)"`).FindAllStringSubmatch(block, -1)
		if len(ms) != 1 {
			t.Errorf("docs/prd.md §4's example roster sets %s %d times, want once", v.key, len(ms))
			continue
		}
		if err := v.check(ms[0][1]); err != nil {
			t.Errorf("docs/prd.md §4's example roster: %s = %q: %v", v.key, ms[0][1], err)
		}
	}
}

// TestPRD_WorkFactorMatchesTheCode: the work factor the PRD states is the
// one kdf_guard_test.go pins production to.
func TestPRD_WorkFactorMatchesTheCode(t *testing.T) {
	b, err := os.ReadFile("../../docs/prd.md")
	if err != nil {
		t.Fatal(err)
	}
	ms := regexp.MustCompile(`work factor logN ([0-9]+)`).FindAllStringSubmatch(strings.Join(strings.Fields(string(b)), " "), -1)
	if len(ms) == 0 {
		t.Fatal(`docs/prd.md no longer states "work factor logN N"`)
	}
	for _, m := range ms {
		if v, _ := strconv.Atoi(m[1]); v != productionScryptWorkFactor {
			t.Errorf("docs/prd.md says %q, but production seals at logN %d", m[0], productionScryptWorkFactor)
		}
	}
}
