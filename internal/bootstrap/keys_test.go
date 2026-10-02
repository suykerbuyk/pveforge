package bootstrap

import (
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

func genLine(t *testing.T, comment string) string {
	t.Helper()
	kp, err := sshexec.GenerateEd25519Keypair(comment)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(kp.AuthorizedKeyLine)
}

// TestKeyReport: held means the exact line; a same-comment key is a stray
// with the command for its own bytes; keys that are not pveforge's, lines
// that do not parse, comments and blanks are never listed; a key two
// rosters hold names both.
func TestKeyReport(t *testing.T) {
	held, stray := genLine(t, "pveforge@a"), genLine(t, "pveforge@a")
	other := genLine(t, "root@admin")
	notOurs := genLine(t, "xpveforge@a")
	r1 := &roster.Roster{Targets: []roster.Target{{ID: "a", SSH: &roster.SSHAuth{PublicKey: held + "\n"}}, {ID: "b"}}}
	r2 := &roster.Roster{Targets: []roster.Target{{ID: "a2", SSH: &roster.SSHAuth{PublicKey: held}}}}
	lines := []string{"", "# comment", other, notOurs, "not a key pveforge@a", held, stray + "\r", "   "}
	got := KeyReport(lines, []RosterKeys{RosterKeysOf("r1.toml", r1), RosterKeysOf("r2.toml", r2)})
	if len(got) != 2 {
		t.Fatalf("listed %d keys, want 2: %+v", len(got), got)
	}
	if k := got[0]; k.Stray || strings.Join(k.HeldBy, ",") != "r1.toml:a,r2.toml:a2" || k.RemoveCommand != "" {
		t.Errorf("the held key: %+v", k)
	}
	if k := got[1]; !k.Stray || len(k.HeldBy) != 0 || k.RemoveCommand != sshexec.ManualKeyRemovalCommand(stray+"\r") {
		t.Errorf("the stray: %+v; want the command for the file's own bytes", k)
	}
	if got := KeyReport(nil, nil); got == nil || len(got) != 0 {
		t.Errorf("no lines: %#v, want an empty, non-nil list", got)
	}
}
