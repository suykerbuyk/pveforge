#!/usr/bin/env bash
# Offline stand-in for pveforge, used only by
# internal/sourceguard/harness_scripts_test.go. It appends each call's argv to
# $FAKE_PVEFORGE_DIR/argv.log, one line per call, and answers from files the
# test wrote: resp/<key> is a call's stdout and rc/<key> its exit status
# (default 0), where <key> is "<verb> <path>[ <field=value>...]" (or
# "vm create <vmid>") with every byte outside [A-Za-z0-9._-] turned into "_".
# A read with no resp file, or any call it does not know, exits 99.
set -u
F=${FAKE_PVEFORGE_DIR:?}
printf '%s\n' "$*" >>"$F/argv.log"
# lib.sh names the roster with --roster on every call and unsets
# PVEFORGE_ROSTER, so a default roster can never reach pveforge.
if [ -n "${PVEFORGE_ROSTER+set}" ]; then
	echo "fake pveforge: PVEFORGE_ROSTER reached pveforge" >&2
	exit 98
fi
key() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }
answer() { # key default-stdout
	local k rc=0
	k=$(key "$1")
	[ -f "$F/rc/$k" ] && rc=$(cat "$F/rc/$k")
	if [ -f "$F/resp/$k" ]; then
		cat "$F/resp/$k"
	elif [ -n "$2" ]; then
		printf '%s\n' "$2"
	else
		echo "fake pveforge: no answer for '$1'" >&2
		exit 99
	fi
	exit "$rc"
}
if [ "${1:-}" = vm ] && [ "${2:-}" = create ]; then
	answer "vm create ${4:-}" "${3:-}: vm ${4:-} created"
fi
if [ "${1:-}" = api ]; then
	verb=${2:-} path=${3:-} k="${2:-} ${3:-}"
	shift 3
	while [ "$#" -gt 0 ]; do
		if [ "$1" = --data ]; then
			k="$k $2"
			shift
		fi
		shift
	done
	case "$verb" in
	get) answer "$k" "" ;;
	put) answer "$k" null ;;
	post | delete) answer "$k" '"UPID:fake"' ;;
	esac
fi
echo "fake pveforge: unexpected call: $*" >&2
exit 99
