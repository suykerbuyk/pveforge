#!/usr/bin/env bash
# Offline stand-in for ssh-keyscan, used only by
# internal/sourceguard/harness_d5_test.go: prints $FAKE_SSH_DIR/keyscan.txt,
# the host keys the test generated, whatever host it is asked about.
set -u
F=${FAKE_SSH_DIR:?}
printf '%s\n' "$*" >>"$F/keyscan.log"
cat "$F/keyscan.txt"
