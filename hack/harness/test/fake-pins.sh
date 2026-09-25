#!/usr/bin/env bash
# Offline stand-in for cmd/pveforge-harness-pins, used only by
# internal/sourceguard/harness_nested_test.go. Each call appends
# "pins <roster> <target>" to $FAKE_PVEFORGE_DIR/argv.log and its environment
# to pins.env. It answers from pins/<target>.<n> (the n-th call for that
# target, from 1) or pins/<target>, exit 0; an answer "absent" or no answer
# file exits 3 (no such target), "unreadable" exits 1. pins/<target>.rc makes
# every call for it exit with that status.
set -u
F=${FAKE_PVEFORGE_DIR:?}
printf 'pins %s %s\n' "$1" "$2" >>"$F/argv.log"
env >>"$F/pins.env"
mkdir -p "$F/count"
n=1
[ -f "$F/count/pins.$2" ] && n=$(($(cat "$F/count/pins.$2") + 1))
printf '%s' "$n" >"$F/count/pins.$2"
if [ -f "$F/pins/$2.rc" ]; then
	exit "$(cat "$F/pins/$2.rc")"
fi
for f in "$F/pins/$2.$n" "$F/pins/$2"; do
	if [ -f "$f" ]; then
		case "$(cat "$f")" in
		absent) exit 3 ;;
		unreadable) exit 1 ;;
		esac
		cat "$f"
		exit 0
	fi
done
exit 3
