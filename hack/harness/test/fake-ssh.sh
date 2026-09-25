#!/usr/bin/env bash
# Offline stand-in for ssh, used only by
# internal/sourceguard/harness_d5_test.go and harness_cluster_test.go. Every
# argument of each call is appended to $FAKE_SSH_DIR/ssh.log, one line per
# call, so a test can see the options as well as the command. The last
# argument is the remote command, answered from resp/<key> (stdout) and
# rc/<key> (exit status, default 0), where <key> is the command with every
# byte outside [A-Za-z0-9._-] turned into "_". `true` needs no answer file;
# any other command without one exits 99.
#
# For the cluster script (each is inert unless the test made it):
#   - a command whose first line is "# key: <name>" is answered by <name>;
#   - host/<host>/{resp,rc,err}/ answer for one host (the argument before the
#     command, "_"-mapped like a key) before the shared resp/ and rc/;
#   - <key>.<n> answers the n-th call of that key on that host, counted from
#     1, before <key>;
#   - err/<key> is written to stderr;
#   - with a calls/ directory, each call's argv is also written to
#     calls/<n>, NUL-separated (a multi-line command stays one argument);
#   - with a stdin/ directory, each call's stdin is saved to stdin/<n>.
set -u
F=${FAKE_SSH_DIR:?}
cmd=${*: -1}
printf '%s\n' "$*" >>"$F/ssh.log"
k=$(printf '%s' "$cmd" | tr -c 'A-Za-z0-9._-' '_')
first=${cmd%%$'\n'*}
if [[ $first =~ ^\#\ key:\ ([A-Za-z0-9._-]+)$ ]]; then
	k=${BASH_REMATCH[1]}
fi
if [ -d "$F/calls" ] || [ -d "$F/stdin" ] || [ -d "$F/host" ]; then
	seq=1
	[ -f "$F/seq" ] && seq=$(($(cat "$F/seq") + 1))
	printf '%s' "$seq" >"$F/seq"
	[ ! -d "$F/calls" ] || printf '%s\0' "$@" >"$F/calls/$(printf '%04d' "$seq")"
	[ ! -d "$F/stdin" ] || cat >"$F/stdin/$(printf '%04d' "$seq")"
fi
h=
if [ "$#" -ge 2 ]; then
	h=$(printf '%s' "${*: -2:1}" | tr -c 'A-Za-z0-9._-' '_')
fi
n=1
if [ -d "$F/host" ]; then
	mkdir -p "$F/count"
	[ -f "$F/count/$h.$k" ] && n=$(($(cat "$F/count/$h.$k") + 1))
	printf '%s' "$n" >"$F/count/$h.$k"
fi
# pick prints the first existing answer file of kind for this call.
pick() { # kind
	local d
	for d in "$F/host/$h/$1" "$F/$1"; do
		[ -n "$h" ] || [ "$d" = "$F/$1" ] || continue
		if [ -f "$d/$k.$n" ]; then
			printf '%s' "$d/$k.$n"
			return
		elif [ -f "$d/$k" ]; then
			printf '%s' "$d/$k"
			return
		fi
	done
}
rc=0
f=$(pick rc)
[ -z "$f" ] || rc=$(cat "$f")
f=$(pick err)
[ -z "$f" ] || cat "$f" >&2
f=$(pick resp)
if [ -n "$f" ]; then
	cat "$f"
elif [ "$cmd" != true ]; then
	echo "fake ssh: no answer for '$cmd'" >&2
	exit 99
fi
exit "$rc"
