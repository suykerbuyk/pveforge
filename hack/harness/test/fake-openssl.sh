#!/usr/bin/env bash
# Offline stand-in for openssl, used only by
# internal/sourceguard/harness_build_test.go: `openssl passwd -6 -stdin`
# only. It records its argv (openssl.argv), environment (openssl.env) and
# stdin (openssl.stdin) under $FAKE_PVEFORGE_DIR, and prints a fixed SHA-512
# crypt hash, or openssl.out when the test wrote one.
set -u
F=${FAKE_PVEFORGE_DIR:?}
printf '%s\n' "$@" >>"$F/openssl.argv"
env >>"$F/openssl.env"
cat >>"$F/openssl.stdin"
[ "$*" = "passwd -6 -stdin" ] || {
	echo "fake openssl: unexpected call: $*" >&2
	exit 98
}
if [ -f "$F/openssl.out" ]; then
	cat "$F/openssl.out"
	exit 0
fi
printf '%s\n' '$6$fakesalt$FakeHashFakeHashFakeHashFakeHashFakeHashFakeHashFakeHashFakeHashFakeHashFakeHashFake12'
