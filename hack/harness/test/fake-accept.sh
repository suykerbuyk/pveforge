#!/usr/bin/env bash
# Offline stand-in for cmd/pveforge-harness-accept, used only by
# internal/sourceguard/harness_nested_test.go. Each call appends
# "accept <args>" to $FAKE_PVEFORGE_DIR/argv.log (so the order against
# pveforge's calls shows), saves its environment to accept.env, and exits
# with the status in accept.rc (default 0).
set -u
F=${FAKE_PVEFORGE_DIR:?}
printf 'accept %s\n' "$*" >>"$F/argv.log"
env >"$F/accept.env"
rc=0
[ ! -f "$F/accept.rc" ] || rc=$(cat "$F/accept.rc")
exit "$rc"
