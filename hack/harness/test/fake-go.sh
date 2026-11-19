#!/usr/bin/env bash
# Offline stand-in for `go`, used only by the tests in internal/sourceguard,
# for lib.sh's binary-provenance check (harness_init runs
# `go version -m -- <binary>`). It answers that ONE argv and exits 99 for any
# other, so a call the tests did not foresee is loud.
#
# With $FAKE_PVEFORGE_DIR set it appends its argv, one line, to go.log there;
# go.out is the answer (default: a clean build of FAKEREV, in the tab-separated
# shape real `go version -m` prints) and go.rc the exit status (default 0).
set -u
F=${FAKE_PVEFORGE_DIR:-}
[ -n "$F" ] && printf '%s\n' "$*" >>"$F/go.log"
if [ "${1:-}" != version ] || [ "${2:-}" != -m ] || [ "${3:-}" != -- ] || [ $# -ne 4 ]; then
	echo "fake go: unexpected argv: $*" >&2
	exit 99
fi
if [ -n "$F" ] && [ -f "$F/go.out" ]; then
	cat "$F/go.out"
else
	printf '%s\tgo1.27.4\n\tpath\tgithub.com/suykerbuyk/pveforge/cmd/pveforge\n\tbuild\tvcs=git\n\tbuild\tvcs.revision=%s\n\tbuild\tvcs.time=2026-11-19T00:00:00Z\n\tbuild\tvcs.modified=false\n' "$4" "1111111111111111111111111111111111111111"
fi
rc=0
[ -n "$F" ] && [ -f "$F/go.rc" ] && rc=$(cat "$F/go.rc")
exit "$rc"
