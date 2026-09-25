#!/usr/bin/env bash
# Offline stand-in for ssh, used only by
# internal/sourceguard/harness_d5_test.go. Every argument of each call is
# appended to $FAKE_SSH_DIR/ssh.log, one line per call, so a test can see the
# options as well as the command. The last argument is the remote command,
# answered from resp/<key> (stdout) and rc/<key> (exit status, default 0),
# where <key> is the command with every byte outside [A-Za-z0-9._-] turned
# into "_". `true` needs no answer file; any other command without one exits
# 99.
set -u
F=${FAKE_SSH_DIR:?}
cmd=${*: -1}
printf '%s\n' "$*" >>"$F/ssh.log"
k=$(printf '%s' "$cmd" | tr -c 'A-Za-z0-9._-' '_')
rc=0
[ -f "$F/rc/$k" ] && rc=$(cat "$F/rc/$k")
if [ -f "$F/resp/$k" ]; then
	cat "$F/resp/$k"
elif [ "$cmd" != true ]; then
	echo "fake ssh: no answer for '$cmd'" >&2
	exit 99
fi
exit "$rc"
