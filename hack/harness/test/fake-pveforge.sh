#!/usr/bin/env bash
# Offline stand-in for pveforge, used only by the tests in
# internal/sourceguard (harness_scripts_test.go, harness_probe_test.go). It
# appends each call's argv to $FAKE_PVEFORGE_DIR/argv.log, one line per call,
# and answers from files the test wrote: resp/<key> is a call's stdout and
# rc/<key> its exit status (default 0), where <key> is
# "<verb> <path>[ <field=value>...]" (or "vm create <vmid>") with every byte
# outside [A-Za-z0-9._-] turned into "_".
# A read with no resp file, or any call it does not know, exits 99.
#
# Sequences (for the capability probe): the n-th call of a key (counted from
# 1, per key) answers from resp/<key>.<n> and rc/<key>.<n> when they exist,
# else from resp/<key> and rc/<key> as above. err/<key>[.<n>] is written to
# stderr, as pveforge's error text; kill/<key>[.<n>] names a signal (TERM,
# INT, HUP) sent to the calling script before answering, or "group:<signal>"
# to send it to the whole process group, as a terminal's Ctrl-C does.
# block/<key>[.<n>] makes the call touch $F/blocked and then wait for a line
# on the fifo $F/block.fifo before answering, so a test can act mid-run. With
# none of these files present, every answer is exactly what it always was.
#
# For nested.sh (inert unless the test made an env/ directory): each call's
# environment is saved to env/<n>, n its line in argv.log. `roster init
# <path>` (key "roster init") writes an empty roster at <path>, mode 0600,
# unless its status is non-zero; `bootstrap <id>` and `network bridge create
# <id> <iface>` answer under the keys "bootstrap <id>" and "network bridge
# create <id> <iface>".
set -u
F=${FAKE_PVEFORGE_DIR:?}
printf '%s\n' "$*" >>"$F/argv.log"
if [ -d "$F/env" ]; then
	env >"$F/env/$(wc -l <"$F/argv.log" | tr -d ' ')"
fi
# lib.sh names the roster with --roster on every call and unsets
# PVEFORGE_ROSTER, so a default roster can never reach pveforge.
if [ -n "${PVEFORGE_ROSTER+set}" ]; then
	echo "fake pveforge: PVEFORGE_ROSTER reached pveforge" >&2
	exit 98
fi
key() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }
# pick prints the path of the n-th variant of dir/k, else of dir/k, else nothing.
pick() { # dir k n
	if [ -f "$F/$1/$2.$3" ]; then
		printf '%s' "$F/$1/$2.$3"
	elif [ -f "$F/$1/$2" ]; then
		printf '%s' "$F/$1/$2"
	fi
}
answer() { # key default-stdout
	local k n=1 rc=0 f sig
	k=$(key "$1")
	mkdir -p "$F/count"
	[ -f "$F/count/$k" ] && n=$(($(cat "$F/count/$k") + 1))
	printf '%s' "$n" >"$F/count/$k"
	f=$(pick block "$k" "$n")
	if [ -n "$f" ]; then
		: >"$F/blocked"
		read -r _ <"$F/block.fifo"
	fi
	f=$(pick kill "$k" "$n")
	if [ -n "$f" ]; then
		sig=$(cat "$f")
		case $sig in
		group:*) kill -s "${sig#group:}" 0 ;;
		*) kill -s "$sig" "$PPID" ;;
		esac
	fi
	f=$(pick rc "$k" "$n")
	[ -n "$f" ] && rc=$(cat "$f")
	f=$(pick err "$k" "$n")
	[ -n "$f" ] && cat "$f" >&2
	f=$(pick resp "$k" "$n")
	if [ -n "$f" ]; then
		cat "$f"
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
if [ "${1:-}" = roster ] && [ "${2:-}" = init ] && [ "$#" = 3 ]; then
	k=$(key "roster init")
	rc=0
	f=$(pick rc "$k" 1)
	[ -z "$f" ] || rc=$(cat "$f")
	if [ "$rc" = 0 ]; then
		(umask 077 && echo "# fake nested roster" >"$3")
	fi
	answer "roster init" "Initialized empty roster at $3"
fi
if [ "${1:-}" = bootstrap ] && [ "$#" -ge 2 ]; then
	answer "bootstrap $2" ""
fi
if [ "${1:-}" = network ] && [ "${2:-}" = bridge ] && [ "${3:-}" = create ] && [ "$#" -ge 5 ]; then
	answer "network bridge create $4 $5" "$4: bridge $5 created"
fi
echo "fake pveforge: unexpected call: $*" >&2
exit 99
