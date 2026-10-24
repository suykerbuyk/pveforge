package bootstrap

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// PveforgeKeyCommentPrefix begins the comment of every key pveforge
// installs (pveforge@<target-id>).
const PveforgeKeyCommentPrefix = "pveforge@"

// AuthorizedKeysReadCmd reads root's authorized_keys, and nothing else. A
// missing file reads as an empty one: no key at all, so none of pveforge's.
// A file that is there but cannot be read is an error, never "no keys":
// on PVE a dangling symlink means pmxcfs is down, and reporting no strays
// then would be false.
const AuthorizedKeysReadCmd = `f=~/.ssh/authorized_keys; if [ -e "$f" ] || [ -L "$f" ]; then cat "$f"; fi`

// AuthorizedKeys reads root's authorized_keys on the node, as root, and
// returns its lines. It writes nothing. On PVE the file is
// /etc/pve/priv/authorized_keys, shared by the cluster, so any node's copy
// is every node's.
func (a *RootAccess) AuthorizedKeys(ctx context.Context) ([]string, error) {
	res, err := a.rootRun(ctx, AuthorizedKeysReadCmd)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("read root's authorized_keys: exit %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return strings.Split(res.Stdout, "\n"), nil
}

// RosterKeys is one roster's SSH public keys, for KeyReport: Path names
// the roster, Held maps each target's public key (its wire-format blob,
// whatever options or comment a line carries) to the targets holding it,
// and Unparsed names each target whose public_key does not parse.
type RosterKeys struct {
	Path     string
	Held     map[string][]string
	Unparsed []string
}

// RosterKeysOf lists the SSH public keys r's targets hold. A target whose
// public_key does not parse is never skipped silently: it is listed in
// Unparsed, since its key may be live on the node, and a line that is its
// key must never read as a stray with a removal command.
func RosterKeysOf(path string, r *roster.Roster) RosterKeys {
	rk := RosterKeys{Path: path, Held: map[string][]string{}}
	for _, t := range r.Targets {
		if t.SSH == nil {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(t.SSH.PublicKey)))
		if err != nil {
			rk.Unparsed = append(rk.Unparsed, t.ID)
			continue
		}
		blob := string(pub.Marshal())
		rk.Held[blob] = append(rk.Held[blob], t.ID)
	}
	return rk
}

// KeyLine is one pveforge key in root's authorized_keys.
type KeyLine struct {
	Comment     string `json:"comment"`
	Fingerprint string `json:"fingerprint"`
	// HeldBy names each "<roster>:<target>" whose public_key is this key
	// (the same key, whatever options the line carries), among the rosters
	// checked.
	HeldBy []string `json:"held_by"`
	// Stray: no roster checked holds it.
	Stray bool `json:"stray"`
	// RemoveCommand, for a stray, removes exactly this line, options
	// included, when run as root on the node. pveforge never runs it.
	RemoveCommand string `json:"remove_command,omitempty"`
	// RemoveCommandWithheld says why a stray has no RemoveCommand: a roster
	// checked holds a public_key that does not parse (Unverifiable), so this
	// line may be that target's live key; or its line holds a carriage
	// return (a CRLF file), which no whole-line match can name exactly.
	RemoveCommandWithheld string `json:"remove_command_withheld,omitempty"`
}

// Unverifiable names each "<roster>:<target>" among rosters whose
// public_key does not parse. While any is listed, KeyReport cannot tell
// whether a line is that target's key, and gives no stray a removal
// command.
func Unverifiable(rosters []RosterKeys) []string {
	out := []string{}
	for _, rk := range rosters {
		for _, id := range rk.Unparsed {
			out = append(out, rk.Path+":"+id)
		}
	}
	return out
}

// KeyReport lists every line of root's authorized_keys whose comment begins
// pveforge@, and which of rosters hold it (the same key, compared by its
// blob with each target's public_key, so a line with options still reads
// as held). A line nothing holds is a stray, with the
// exact manual removal command. Any other line (not parsable as a key, or
// without a pveforge@ comment) is not pveforge's to judge and is never
// listed. It changes nothing.
//
// A key held by a roster NOT among rosters reads as a stray here: another
// person's roster, or one on another machine, may still use it. While a
// roster checked holds a public_key that does not parse (Unverifiable), no
// stray gets a removal command.
func KeyReport(lines []string, rosters []RosterKeys) []KeyLine {
	out := []KeyLine{}
	unverifiable := Unverifiable(rosters)
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil || !strings.HasPrefix(comment, PveforgeKeyCommentPrefix) {
			continue
		}
		k := KeyLine{Comment: comment, Fingerprint: ssh.FingerprintSHA256(pub), HeldBy: []string{}}
		blob := string(pub.Marshal())
		for _, rk := range rosters {
			for _, id := range rk.Held[blob] {
				k.HeldBy = append(k.HeldBy, rk.Path+":"+id)
			}
		}
		if len(k.HeldBy) == 0 {
			k.Stray = true
			// The file's own bytes: the command matches the whole line exactly.
			if len(unverifiable) > 0 {
				k.RemoveCommandWithheld = "a roster target's public_key does not parse (" + strings.Join(unverifiable, ", ") + "), so whether this line is its live key cannot be told; fix that public_key, then report again"
			} else if cmd, err := sshexec.ManualKeyRemovalCommand(raw); err != nil {
				k.RemoveCommandWithheld = "its line holds a carriage return (a CRLF file), so no whole-line match can name it exactly; remove it by hand"
			} else {
				k.RemoveCommand = cmd
			}
		}
		out = append(out, k)
	}
	return out
}
