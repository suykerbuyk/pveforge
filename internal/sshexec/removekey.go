package sshexec

import (
	"errors"
	"fmt"
	"strings"
)

// RemoveKeyExitNotExactlyOne is the exit status of RemoveAuthorizedKeyScript
// when the file does not hold the line exactly once, and
// RemoveKeyExitChanged when the file changed while the script was reading
// it; in both cases nothing was written.
const (
	RemoveKeyExitNotExactlyOne = 3
	RemoveKeyExitChanged       = 4
)

// ErrInvalidKeyLine: a line given to RemoveAuthorizedKeyScript or
// ManualKeyRemovalCommand is empty, or holds a newline or a carriage
// return, so no whole-line match could mean exactly that one line.
var ErrInvalidKeyLine = errors.New("not a single authorized_keys line")

// checkKeyLine refuses a line no whole-line match could mean exactly.
func checkKeyLine(line string) error {
	switch {
	case strings.TrimSpace(line) == "":
		return fmt.Errorf("%w: it is empty", ErrInvalidKeyLine)
	case strings.ContainsAny(line, "\r\n"):
		return fmt.Errorf("%w: it holds a line break (\\n or \\r)", ErrInvalidKeyLine)
	}
	return nil
}

// removeKeyCommands is the removal program: SIMPLE COMMANDS ONLY (no if,
// then or fi, and no comment lines), so that joined with "\n" or with "; "
// it is the same program. RemoveAuthorizedKeyScript joins it with "\n";
// ManualKeyRemovalCommand with "; ", as one line an operator can paste.
//
//   - snap and new exist before either trap can read them: under set -u an
//     unset $new would abort the EXIT trap, turning exit 3 into 2 and
//     leaving the snapshot behind.
//   - dash runs no EXIT trap when it is killed, and sshexec hangs up a
//     session it abandons: the HUP INT TERM trap exits, so the EXIT trap
//     runs and no authorized_keys.tmp.* is left beside the target (on PVE
//     in /etc/pve/priv, replicated to every node).
//   - f is the RESOLVED target. On PVE ~/.ssh/authorized_keys is a symlink
//     to /etc/pve/priv/authorized_keys, shared by the whole cluster; the
//     new file is created beside the target, on the same filesystem, and
//     renamed onto it, as PVE's own PVE::Tools::file_set_contents writes
//     it. The symlink itself is never touched, and a reader sees the old
//     file or the new one, never a truncated one.
//   - The match is the WHOLE line, byte for byte (grep -xF): never a
//     comment, a prefix or a pattern.
//   - The cmp is the last command before the rename (see the accepted
//     risk on RemoveAuthorizedKeyScript).
func removeKeyCommands(line string) []string {
	q := ShellQuote(line)
	return []string{
		"set -eu",
		"snap= new=",
		`trap 'rm -f "$snap" "$new"' EXIT`,
		"trap 'exit 129' HUP INT TERM",
		"f=$(readlink -f ~/.ssh/authorized_keys)",
		"snap=$(mktemp)",
		`cat "$f" > "$snap"`,
		fmt.Sprintf(`n=$(grep -cxF -- %s "$snap" || true)`, q),
		fmt.Sprintf(`[ "$n" = 1 ] || { echo "found $n"; exit %d; }`, RemoveKeyExitNotExactlyOne),
		`new=$(mktemp "$f.tmp.XXXXXX")`,
		fmt.Sprintf(`grep -vxF -- %s "$snap" > "$new" || [ $? -eq 1 ]`, q),
		fmt.Sprintf(`cmp -s "$f" "$snap" || { echo changed; exit %d; }`, RemoveKeyExitChanged),
		`mv -f -- "$new" "$f"`,
		"echo removed",
	}
}

// RemoveAuthorizedKeyScript returns a POSIX sh script that removes line (a
// complete "ssh-ed25519 AAAA... comment" authorized_keys line) from root's
// ~/.ssh/authorized_keys, and nothing else. It is for one case only: a
// bootstrap run that installed line and then failed before the roster held
// it (operator ruling T2k, 2026-09-26). It must never be given a line the
// caller did not itself install in that run. A line that is empty or holds
// a line break is refused (ErrInvalidKeyLine).
//
// It refuses unless the line appears exactly once, printing how many it
// found (exit RemoveKeyExitNotExactlyOne), and writes nothing if the file
// changed while it read it (exit RemoveKeyExitChanged). Every failure
// leaves the target byte for byte as it was: a failed mktemp (pmxcfs
// read-only, quorum lost), a failed write, a failed rename, a missing file
// or a dangling symlink. It prints "removed" on success. See
// removeKeyCommands for how.
//
// ACCEPTED RISK (Chair, T2k plan review, finding 5): a line another writer
// appends between the final cmp and the rename is lost. That writer could
// be PVE's own ssh_merge_keys (pvecm updatecerts), which takes no lock, or
// another node's install; a lost node key breaks inter-node SSH until the
// next pvecm updatecerts. The window is the gap between two commands, PVE's
// own writer takes the same risk, and no lock helps.
//
// LIVE CHECK OWED on the nested harness before this is relied on: an
// O_EXCL create of authorized_keys.tmp.XXXXXX in /etc/pve/priv; the rename
// seen from the other node; the symlink kept; root logins during the
// rename; a failure at mktemp with quorum lost; and a HUP mid-run leaving
// no .tmp. file in /etc/pve/priv.
func RemoveAuthorizedKeyScript(line string) (string, error) {
	if err := checkKeyLine(line); err != nil {
		return "", err
	}
	return strings.Join(removeKeyCommands(line), "\n") + "\n", nil
}

// ManualKeyRemovalCommand is the command an operator runs as root ON the
// node to remove line by hand: the same program as
// RemoveAuthorizedKeyScript (the same whole-line match, exactly-once and
// changed-meanwhile checks, and rename), as one line, `sh -c '<program>'`,
// for a line pveforge will not remove itself (a stray from an earlier run,
// or a removal that failed). A line that is empty or holds a line break is
// refused (ErrInvalidKeyLine).
func ManualKeyRemovalCommand(line string) (string, error) {
	if err := checkKeyLine(line); err != nil {
		return "", err
	}
	return "sh -c " + ShellQuote(strings.Join(removeKeyCommands(line), "; ")), nil
}
