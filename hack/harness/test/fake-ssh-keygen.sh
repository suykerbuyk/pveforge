#!/usr/bin/env bash
# Offline stand-in for ssh-keygen, used only by
# internal/sourceguard/harness_build_test.go: records its argv
# (ssh-keygen.argv under $FAKE_PVEFORGE_DIR) and writes a fixed key pair at
# the -f path, the private half mode 0600.
set -u
F=${FAKE_PVEFORGE_DIR:?}
printf '%s\n' "$@" -- >>"$F/ssh-keygen.argv"
f=
prev=
for a in "$@"; do
	[ "$prev" != -f ] || f=$a
	prev=$a
done
[ -n "$f" ] || exit 98
(
	umask 077
	echo "fake private key" >"$f"
)
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeNestedKeyFakeNestedKeyFakeNestedKey0 pveforge-harness-nested" >"$f.pub"
