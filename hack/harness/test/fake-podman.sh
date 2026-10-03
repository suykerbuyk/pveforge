#!/usr/bin/env bash
# Offline stand-in for podman, used only by
# internal/sourceguard/harness_build_test.go for prepare-iso.sh. Each call's
# argv goes to $FAKE_PVEFORGE_DIR/podman.log (one argument per line, then a
# "--" line) and its environment to podman.env. It "prepares" each node's ISO
# by writing /work/<node>-auto.iso (the -v mount of /work) from the node's
# answer file, then exits with the status in podman.rc (default 0). The umask
# it ran under goes to podman.umask. podman.iso, when present, says what it
# leaves instead: "none" writes no ISO, and "symlink" makes pvh-n1's ISO a
# symlink to $FAKE_PVEFORGE_DIR/victim.
#
# With podman.exec present it instead RUNS the container script, as the
# container would: the -v mounts become the host directories they name, the
# container's own /etc/apt and /usr/share/keyrings a directory under
# $FAKE_PVEFORGE_DIR/root, and each -e value is exported. The script then
# reaches apt-get, curl, sha512sum and proxmox-auto-install-assistant through
# PATH, where the test puts stand-ins (fake-auto-install-assistant.sh).
set -u
F=${FAKE_PVEFORGE_DIR:?}
printf '%s\n' "$@" -- >>"$F/podman.log"
env >>"$F/podman.env"
umask >"$F/podman.umask"
rc=0
[ -f "$F/podman.rc" ] && rc=$(cat "$F/podman.rc")
[ "$rc" = 0 ] || exit "$rc"
work=
src=
prev=
for a in "$@"; do
	if [ "$prev" = -v ] && [ "${a#*:}" = /work ]; then
		work=${a%:/work}
	fi
	if [ "$prev" = -v ] && [ "${a#*:}" = /src:ro ]; then
		src=${a%:/src:ro}
	fi
	if [ "$prev" = -e ] && [ -f "$F/podman.exec" ]; then
		export "${a?}"
	fi
	prev=$a
done
[ -n "$work" ] || {
	echo "fake podman: no -v <dir>:/work" >&2
	exit 98
}
if [ -f "$F/podman.exec" ]; then
	[ -n "$src" ] || {
		echo "fake podman: no -v <dir>:/src:ro" >&2
		exit 98
	}
	root=$F/root
	mkdir -p "$root/etc/apt/sources.list.d" "$root/usr/share/keyrings"
	script=${!#}
	script=${script//\/work/$work}
	script=${script//\/src/$src}
	script=${script//\/etc\/apt/$root/etc/apt}
	script=${script//\/usr\/share\/keyrings/$root/usr/share/keyrings}
	exec bash -c "$script"
fi
iso=
[ -f "$F/podman.iso" ] && iso=$(cat "$F/podman.iso")
[ "$iso" != none ] || exit 0
for n in pvh-n1 pvh-n2; do
	if [ "$iso" = symlink ] && [ "$n" = pvh-n1 ]; then
		ln -s "$F/victim" "$work/$n-auto.iso"
		continue
	fi
	{
		echo "fake installer ISO for $n"
		cat "$work/$n.toml"
	} >"$work/$n-auto.iso"
done
