#!/usr/bin/env bash
# Offline stand-in for `git`, used only by the tests in internal/sourceguard,
# for lib.sh's binary-provenance check (harness_init runs
# `git -C <checkout> rev-parse HEAD`). It answers that ONE argv and exits 99
# for any other. The clean export `make gate` tests in has no .git, so the
# tests control HEAD here instead.
#
# With $FAKE_PVEFORGE_DIR set it appends its argv, one line, to git.log there;
# git.head is the answer (default: the revision fake-go.sh reports) and git.rc
# the exit status (default 0, with no output when non-zero).
set -u
F=${FAKE_PVEFORGE_DIR:-}
[ -n "$F" ] && printf '%s\n' "$*" >>"$F/git.log"
if [ "${1:-}" != -C ] || [ "${3:-}" != rev-parse ] || [ "${4:-}" != HEAD ] || [ $# -ne 4 ]; then
	echo "fake git: unexpected argv: $*" >&2
	exit 99
fi
rc=0
[ -n "$F" ] && [ -f "$F/git.rc" ] && rc=$(cat "$F/git.rc")
if [ "$rc" -ne 0 ]; then
	echo "fatal: not a git repository" >&2
	exit "$rc"
fi
if [ -n "$F" ] && [ -f "$F/git.head" ]; then
	cat "$F/git.head"
else
	echo 1111111111111111111111111111111111111111
fi
