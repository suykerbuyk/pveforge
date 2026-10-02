package sshexec

import "fmt"

// RemoveKeyExitNotExactlyOne is the exit status of RemoveAuthorizedKeyScript
// when the file does not hold the line exactly once, and
// RemoveKeyExitChanged when the file changed while the script was reading
// it; in both cases nothing was written.
const (
	RemoveKeyExitNotExactlyOne = 3
	RemoveKeyExitChanged       = 4
)

// RemoveAuthorizedKeyScript returns a POSIX sh script that removes line (a
// complete "ssh-ed25519 AAAA... comment" authorized_keys line) from root's
// ~/.ssh/authorized_keys, and nothing else. It is for one case only: a
// bootstrap run that installed line and then failed before the roster held
// it (operator ruling T2k, 2026-09-26). It must never be given a line the
// caller did not itself install in that run.
//
//   - The match is the WHOLE line, byte for byte (grep -xF): never a
//     comment, a prefix or a pattern, so no other key can match, even one
//     with the same pveforge@<target> comment.
//   - It refuses unless the line appears exactly once, and prints how many
//     it found (exit RemoveKeyExitNotExactlyOne).
//   - It rewrites the file IN PLACE (cat > file). On PVE ~/.ssh/
//     authorized_keys is a symlink to /etc/pve/priv/authorized_keys, shared
//     by the whole cluster; sed -i or mv would replace the symlink with a
//     plain file and silently unshare root's keys. Never change that.
//   - It snapshots the file, filters the snapshot, and writes only if the
//     file still equals the snapshot (exit RemoveKeyExitChanged otherwise),
//     so a key another process appended meanwhile is not dropped. A write
//     racing the last comparison is still possible; the window is the
//     comparison itself.
//
// It prints "removed" on success. The snapshot and the filtered copy hold
// public keys only, and are removed on every exit.
//
// LIVE CHECK OWED on the nested harness before this is relied on: that the
// in-place rewrite keeps ~/.ssh/authorized_keys a symlink and reaches the
// other node; that pmxcfs accepts the truncate-and-write; and that root
// logins made during the rewrite survive it.
func RemoveAuthorizedKeyScript(line string) string {
	q := ShellQuote(line)
	return fmt.Sprintf(`set -e
f=~/.ssh/authorized_keys
snap=$(mktemp)
out=$(mktemp)
trap 'rm -f "$snap" "$out"' EXIT
cat "$f" > "$snap"
n=$(grep -cxF -- %s "$snap" || true)
if [ "$n" != 1 ]; then
  echo "found $n"
  exit %d
fi
grep -vxF -- %s "$snap" > "$out" || [ $? -eq 1 ]
if ! cmp -s "$f" "$snap"; then
  echo changed
  exit %d
fi
cat "$out" > "$f"
echo removed
`, q, RemoveKeyExitNotExactlyOne, q, RemoveKeyExitChanged)
}

// ManualKeyRemovalCommand is the command an operator runs as root ON the
// node to remove line by hand: the same whole-line, in-place removal, for
// a line pveforge will not remove itself (a stray from an earlier run, or a
// removal that failed).
func ManualKeyRemovalCommand(line string) string {
	q := ShellQuote(line)
	return fmt.Sprintf(`t=$(mktemp) && grep -vxF -- %s ~/.ssh/authorized_keys > "$t"; [ $? -le 1 ] && cat "$t" > ~/.ssh/authorized_keys; rm -f "$t"`, q)
}
