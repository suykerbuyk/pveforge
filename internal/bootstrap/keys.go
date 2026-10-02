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

// authorizedKeysReadCmd reads root's authorized_keys. A missing file is an
// empty one: no key at all, so none of pveforge's.
const authorizedKeysReadCmd = "cat ~/.ssh/authorized_keys 2>/dev/null || true"

// AuthorizedKeys reads root's authorized_keys on the node, as root, and
// returns its lines. It writes nothing. On PVE the file is
// /etc/pve/priv/authorized_keys, shared by the cluster, so any node's copy
// is every node's.
func (a *RootAccess) AuthorizedKeys(ctx context.Context) ([]string, error) {
	res, err := a.rootRun(ctx, authorizedKeysReadCmd)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("read root's authorized_keys: exit %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return strings.Split(res.Stdout, "\n"), nil
}

// RosterKeys is one roster's SSH public keys, for KeyReport: Path names
// the roster, Held maps each target's exact public_key line to its id.
type RosterKeys struct {
	Path string
	Held map[string][]string
}

// RosterKeysOf lists the SSH public keys r's targets hold.
func RosterKeysOf(path string, r *roster.Roster) RosterKeys {
	rk := RosterKeys{Path: path, Held: map[string][]string{}}
	for _, t := range r.Targets {
		if t.SSH != nil && strings.TrimSpace(t.SSH.PublicKey) != "" {
			line := strings.TrimSpace(t.SSH.PublicKey)
			rk.Held[line] = append(rk.Held[line], t.ID)
		}
	}
	return rk
}

// KeyLine is one pveforge key in root's authorized_keys.
type KeyLine struct {
	Comment     string `json:"comment"`
	Fingerprint string `json:"fingerprint"`
	// HeldBy names each "<roster>:<target>" whose public_key is exactly
	// this line, among the rosters checked.
	HeldBy []string `json:"held_by"`
	// Stray: no roster checked holds it.
	Stray bool `json:"stray"`
	// RemoveCommand, for a stray, removes exactly this line when run as
	// root on the node. pveforge never runs it.
	RemoveCommand string `json:"remove_command,omitempty"`
}

// KeyReport lists every line of root's authorized_keys whose comment begins
// pveforge@, and which of rosters hold it (the exact line, compared with
// each target's public_key). A line nothing holds is a stray, with the
// exact manual removal command. Any other line (not parsable as a key, or
// without a pveforge@ comment) is not pveforge's to judge and is never
// listed. It changes nothing.
//
// A key held by a roster NOT among rosters reads as a stray here: another
// person's roster, or one on another machine, may still use it.
func KeyReport(lines []string, rosters []RosterKeys) []KeyLine {
	out := []KeyLine{}
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
		for _, rk := range rosters {
			for _, id := range rk.Held[line] {
				k.HeldBy = append(k.HeldBy, rk.Path+":"+id)
			}
		}
		if len(k.HeldBy) == 0 {
			k.Stray = true
			// The file's own bytes: the command matches the whole line exactly.
			k.RemoveCommand = sshexec.ManualKeyRemovalCommand(raw)
		}
		out = append(out, k)
	}
	return out
}
