#!/usr/bin/env bash
# Offline stand-in for podman, used only by
# internal/sourceguard/harness_build_test.go for prepare-iso.sh. Each call's
# argv goes to $FAKE_PVEFORGE_DIR/podman.log (one argument per line, then a
# "--" line) and its environment to podman.env. It "prepares" each node's ISO
# by writing /work/<node>-auto.iso (the -v mount of /work) from the node's
# answer file, then exits with the status in podman.rc (default 0).
set -u
F=${FAKE_PVEFORGE_DIR:?}
printf '%s\n' "$@" -- >>"$F/podman.log"
env >>"$F/podman.env"
rc=0
[ -f "$F/podman.rc" ] && rc=$(cat "$F/podman.rc")
[ "$rc" = 0 ] || exit "$rc"
work=
prev=
for a in "$@"; do
	if [ "$prev" = -v ] && [ "${a#*:}" = /work ]; then
		work=${a%:/work}
	fi
	prev=$a
done
[ -n "$work" ] || {
	echo "fake podman: no -v <dir>:/work" >&2
	exit 98
}
for n in pvh-n1 pvh-n2; do
	{
		echo "fake installer ISO for $n"
		cat "$work/$n.toml"
	} >"$work/$n-auto.iso"
done
