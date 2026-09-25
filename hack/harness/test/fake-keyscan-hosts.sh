#!/usr/bin/env bash
# Offline stand-in for ssh-keyscan, used only by
# internal/sourceguard/harness_build_test.go: records its argv
# (keyscan.log under $FAKE_PVEFORGE_DIR) and prints keyscan/<host>, the
# host's keys as the test wrote them, exiting with keyscan/<host>.rc
# (default 0).
set -u
F=${FAKE_PVEFORGE_DIR:?}
printf '%s\n' "$*" >>"$F/keyscan.log"
h=${*: -1}
rc=0
[ -f "$F/keyscan/$h.rc" ] && rc=$(cat "$F/keyscan/$h.rc")
[ -f "$F/keyscan/$h" ] && cat "$F/keyscan/$h"
exit "$rc"
