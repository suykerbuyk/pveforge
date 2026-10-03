#!/usr/bin/env bash
# Offline stand-in for proxmox-auto-install-assistant 9.2.8, run by
# fake-podman.sh's exec mode for internal/sourceguard/harness_build_test.go.
# Like the real tool, it exits 0 even when a step fails. Each call goes to
# $FAKE_PVEFORGE_DIR/assistant.log as "<command> <node>[ tmp=<dir>]".
#   - prepare-iso writes no ISO (an error on stderr, status 0) for a node
#     named in assistant.prepare-fails, and for every node when --tmp is
#     missing or not a directory: the real tool then stages its copy next to
#     the source ISO, which the container mounts read-only.
#   - inspect-iso prints nothing for a node named in assistant.inspect-silent,
#     and only an error (status 0) for an ISO that does not exist.
set -u
F=${FAKE_PVEFORGE_DIR:?}
cmd=$1
shift
case $cmd in
validate-answer)
	echo "validate-answer $(basename "$1" .toml)" >>"$F/assistant.log"
	echo "The answer file was parsed successfully, no errors found!"
	;;
prepare-iso)
	answer= out= tmp=
	while [ $# -gt 0 ]; do
		case $1 in
		--answer-file) answer=$2 && shift ;;
		--output) out=$2 && shift ;;
		--tmp) tmp=$2 && shift ;;
		esac
		shift
	done
	node=$(basename "$out" -auto.iso)
	echo "prepare-iso $node tmp=$tmp" >>"$F/assistant.log"
	if [ -z "$tmp" ] || [ ! -d "$tmp" ] || grep -qxF "$node" "$F/assistant.prepare-fails" 2>/dev/null; then
		echo "Error: Read-only file system (os error 30)" >&2
		exit 0
	fi
	{
		echo "fake prepared ISO for $node"
		cat "$answer"
	} >"$out"
	;;
inspect-iso)
	node=$(basename "$1" -auto.iso)
	echo "inspect-iso $node" >>"$F/assistant.log"
	[ -f "$1" ] || {
		echo "Error: input ISO \"$1\" does not exist" >&2
		exit 0
	}
	grep -qxF "$node" "$F/assistant.inspect-silent" 2>/dev/null && exit 0
	echo "Source ISO:    $1"
	echo "Auto-install:  enabled"
	;;
*)
	echo "fake assistant: unknown command $cmd" >&2
	exit 99
	;;
esac
