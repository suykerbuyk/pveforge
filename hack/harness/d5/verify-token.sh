#!/usr/bin/env bash
# hack/harness/d5/verify-token.sh: D5's TOKEN-side checks, read-only. Every
# read is lib.sh's harness_get: `pveforge api get` as the pool token in the
# harness roster (operator ruling 2026-09-24 (1)). It takes the harness lock,
# so it never runs in the middle of a build, reset or probe.
#
# Usage: HARNESS_EVIDENCE=<new dir> verify-token.sh <pre|post>
#   pre   before the harness VMs exist: the pool has no members.
#   post  after the build: its members are 690-692, on qa-pve-02.
# See d5/sequence.md, gate G5.
source "$(dirname "$0")/../lib.sh"
source "$(dirname "$0")/evidence.sh"

phase=${1:-}
case "$phase" in
pre | post) ;;
*) _harness_die 2 "usage: HARNESS_EVIDENCE=<new dir> verify-token.sh <pre|post>" ;;
esac
harness_init
d5_open_evidence "token-$phase"

tree=$D5_FIXTURES/d5r3-expected-tree-pre-build.json members='[]'
if [ "$phase" = post ]; then
	tree=$D5_FIXTURES/d5r3-expected-tree-post-build.json members='[690,691,692]'
fi
# The zero-privilege answer owed live at D5: a path the token holds nothing on.
readonly D5_ZERO_PATH=/storage/local-lvm

tget() { # name path [field=value ...]: the raw answer goes to t.<name>.json
	local name=$1
	shift
	# In a subshell: harness_get stops the script on a failed read, and a
	# failed read here is one red check, not the end of the run.
	# A failed read leaves no answer to check, so every check of it goes red.
	(harness_get "$@") >"$D5_EVIDENCE/t.$name.json" || {
		rm -f -- "$D5_EVIDENCE/t.$name.json"
		return 1
	}
}
tev() {
	printf '%s' "$D5_EVIDENCE/t.$1.json"
}
v3t_tree() { jq -e --slurpfile e "$tree" '. == $e[0]' "$(tev tree)"; }
v0t_role() { jq -e --arg r "$1" --slurpfile e "$D5_FIXTURES/d5r3-expected-roles.json" '(keys | sort) == ($e[0][$r] | sort)' "$(tev "role.$1")"; }
v1t_no_rows() { jq -e '. == []' "$(tev acl)"; }
v7t_members() {
	jq -e --arg p "$D5_POOL" --argjson m "$members" '
		length == 1 and .[0].poolid == $p
		and ([.[0].members[]? | select(.type == "qemu") | .vmid] | sort) == $m
		and ([.[0].members[]? | select(.type != "qemu")] | length) == 0' "$(tev pool)"
}
v7t_node() { jq -e --arg n "$D5_NODE" 'all(.[0].members[]?; .node == $n)' "$(tev pool)"; }
z0_nothing() { jq -e --arg p "$D5_ZERO_PATH" '(keys == [$p]) and (.[$p] == {})' "$(tev zero)"; }

d5_check "fetch tree" tget tree /access/permissions
d5_check "V3t the token's own tree equals the expected tree" v3t_tree
for role in $(jq -r 'keys[]' "$D5_FIXTURES/d5r3-expected-roles.json"); do
	d5_check "fetch role $role" tget "role.$role" "/access/roles/$role"
	d5_check "V0t role $role equals its pinned definition" v0t_role "$role"
done
d5_check "fetch acl" tget acl /access/acl
d5_check "V1t the token sees no ACL row (no delegation)" v1t_no_rows
d5_check "fetch pool" tget pool /pools "poolid=$D5_POOL"
d5_check "V7t the pool's members are exactly $members" v7t_members
d5_check "V7t-node every member is on $D5_NODE" v7t_node
d5_check "fetch zero" tget zero /access/permissions "path=$D5_ZERO_PATH"
d5_check "Z0 a path the token holds nothing on answers {\"$D5_ZERO_PATH\":{}}" z0_nothing
d5_finish
