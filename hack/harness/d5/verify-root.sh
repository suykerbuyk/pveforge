#!/usr/bin/env bash
# hack/harness/d5/verify-root.sh: D5's ROOT-side checks, read-only. Each PVE
# read is one `ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com '<pveum or
# pvesh read>'`; jq runs on the workstation. Nothing here writes to any host.
#
# Usage: HARNESS_EVIDENCE=<new dir> verify-root.sh <phase>
#   p0       step 0: non-interactive root ssh works (checked FIRST; steps 1-10
#            need it), nothing named for the harness exists yet, the storage
#            is active, and qa-pve-02's pinned host key (from D5_PIN_ROSTER's
#            qa-pve-02 target) is one of the keys the host serves. When all
#            pass, the P0 baseline (ACL list, roles, users, groups, pools) is
#            written once to ~/.config/pveforge/harness-outer.p0, never
#            overwritten.
#   roles    after steps 1-4: V0 and L1b.
#   owner    after steps 5-6: the pool exists and is empty; the user exists,
#            enabled, never expiring, holding no ACL row.
#   granted  after steps 7-10: the user's 4 rows, V1b, V1c, V5.
#   token    after step 11: everything, V1b included.
#   pre      any later run before the harness VMs exist.
#   post     after the build: 690-692 are the pool's members.
#   reverted after revert.md (R-V): nothing of the harness remains, and the
#            ACL list, custom roles, users, groups and pools are as P0.
# Every phase but p0 needs the P0 baseline. See d5/sequence.md.
source "$(dirname "$0")/../lib.sh"
source "$(dirname "$0")/evidence.sh"

readonly D5_HOST=root@qa-pve-02.lab.quantum.com
readonly D5_HOSTNAME=qa-pve-02.lab.quantum.com
# ACL paths the harness owns. The shared /storage/local and the vmbr0 SDN
# path are deliberately not here: others may hold rows there.
readonly D5_HARNESS_PATHS='^/(pool/pveforge-harness|storage/pveforge-harness|vms/69[0-9])($|/)'

phase=${1:-}
case "$phase" in
p0 | roles | owner | granted | token | pre | post | reverted) ;;
*) _harness_die 2 "usage: HARNESS_EVIDENCE=<new dir> verify-root.sh <p0|roles|owner|granted|token|pre|post|reverted>" ;;
esac
if [ "$phase" = p0 ]; then
	[ ! -e "$D5_P0" ] || _harness_die 2 "the P0 baseline $D5_P0 already exists; it is written once and never overwritten"
	[ -r "${D5_PIN_ROSTER:-}" ] || _harness_die 2 "p0 needs D5_PIN_ROSTER: the roster whose qa-pve-02 target pins the host key"
else
	[ -d "$D5_P0" ] || _harness_die 2 "the P0 baseline $D5_P0 does not exist; run phase p0 first"
fi
d5_open_evidence "$phase"

rx() { # remote-command: one read-only command as root
	ssh -o BatchMode=yes -o ConnectTimeout=15 "$D5_HOST" "$1"
}
fetch() { # name remote-command: the raw answer goes to <name>.json
	d5_check "fetch $1" rx_to "$1" "$2"
}
rx_to() { # a failed read leaves no answer to check, so every check of it goes red
	rx "$2" >"$D5_EVIDENCE/$1.json" || {
		rm -f -- "$D5_EVIDENCE/$1.json"
		return 1
	}
}
ev() { # name: an answer's path in the evidence
	printf '%s' "$D5_EVIDENCE/$1.json"
}

# pinned_fingerprint prints the host_key_fingerprint in the [targets.ssh]
# table of a roster's qa-pve-02 target.
pinned_fingerprint() { # roster
	awk -v want="$D5_NODE" '
		/^[[:space:]]*\[\[targets\]\][[:space:]]*$/ { sec = "target"; id = ""; next }
		/^[[:space:]]*\[targets\.ssh\][[:space:]]*$/ { sec = "ssh"; next }
		/^[[:space:]]*\[/ { sec = "other"; next }
		sec == "target" && /^[[:space:]]*id[[:space:]]*=/ { v = $0; sub(/^[^"]*"/, "", v); sub(/".*$/, "", v); id = v; next }
		sec == "ssh" && id == want && /^[[:space:]]*host_key_fingerprint[[:space:]]*=/ { v = $0; sub(/^[^"]*"/, "", v); sub(/".*$/, "", v); print v; exit }
	' "$1"
}

# The checks. Each is its own function so the evidence names it.
no_harness_role() { jq -e --arg p "$D5_ROLE_PREFIX" '[.[] | select(.roleid | startswith($p))] == []' "$(ev roles)"; }
no_harness_pool() { jq -e --arg p "$D5_POOL" '[.[] | select(.poolid == $p)] == []' "$(ev pools)"; }
no_harness_user() { jq -e --arg u "$D5_USER" '[.[] | select(.userid == $u)] == []' "$(ev users)"; }
no_harness_rows() { jq -e --arg u "$D5_USER" --arg t "$D5_TOKEN" '[.[] | select(.ugid == $u or .ugid == $t)] == []' "$(ev acl)"; }
storage_active() { jq -e '.active == 1' "$(ev storage)"; }
pin_served() { # the pin is one of the served keys' fingerprints; says which
	local pin
	pin=$(pinned_fingerprint "$D5_PIN_ROSTER")
	printf '%s\n' "$pin" >"$D5_EVIDENCE/pin.txt"
	ssh-keygen -lf "$D5_EVIDENCE/keyscan.txt" >"$D5_EVIDENCE/keyscan.fp"
	awk -v p="$pin" '$2 == p { print "pinned key type:", $NF; found = 1 } END { exit !found }' "$D5_EVIDENCE/keyscan.fp"
}
keyscan() { ssh-keyscan -T 10 "$D5_HOSTNAME" >"$D5_EVIDENCE/keyscan.txt"; }

v0_roles() { # the four roles are exactly the pinned definitions
	jq -e --arg p "$D5_ROLE_PREFIX" --slurpfile e "$D5_FIXTURES/d5r3-expected-roles.json" '
		([.[] | select(.roleid | startswith($p)) | {key: .roleid, value: (.privs | split(",") | sort)}] | from_entries)
		== ($e[0] | map_values(sort))' "$(ev roles)"
}
v0_other_roles() { # every other custom role is as P0 recorded it
	jq -e --arg p "$D5_ROLE_PREFIX" --slurpfile p0 "$D5_P0/roles.json" '
		def other: [.[] | select((.special // 0) != 1 and (.roleid | startswith($p) | not)) | {roleid, privs}] | sort_by(.roleid);
		other == ($p0[0] | other)' "$(ev roles)"
}
l1b_shape() { # pveum's shape for a custom role, recorded raw
	jq -c --arg p "$D5_ROLE_PREFIX" '.[] | select(.roleid | startswith($p))' "$(ev roles)" >"$D5_EVIDENCE/L1b.txt"
	jq -e --arg p "$D5_ROLE_PREFIX" '[.[] | select(.roleid | startswith($p))] | length == 4 and all(.[]; (.privs | type) == "string" and (.special // 0) != 1)' "$(ev roles)"
}
pool_empty() { jq -e --arg p "$D5_POOL" 'length == 1 and .[0].poolid == $p and .[0].members == []' "$(ev pool)"; }
user_created() { jq -e --arg u "$D5_USER" '[.[] | select(.userid == $u)] as $m | ($m | length) == 1 and $m[0].enable == 1 and $m[0].expire == 0' "$(ev users)"; }
v1_rows() { # the harness principals' rows are exactly the pinned ones (who: user or both)
	jq -e --arg u "$D5_USER" --arg t "$D5_TOKEN" --arg who "$1" --slurpfile e "$D5_FIXTURES/d5r3-expected-acl-rows.json" '
		([.[] | select(.ugid == $u or .ugid == $t) | {path, ugid, roleid, propagate}] | sort_by(.path, .ugid))
		== ($e[0] | map(select($who == "both" or .ugid == $u)) | sort_by(.path, .ugid))' "$(ev acl)"
}
v1b_foreign_rows() { # every other row is exactly P0's
	jq -e --arg u "$D5_USER" --arg t "$D5_TOKEN" --slurpfile p0 "$D5_P0/acl.json" '
		def other: [.[] | select(.ugid != $u and .ugid != $t)] | sort_by(.path, .ugid, .roleid);
		other == ($p0[0] | other)' "$(ev acl)"
}
v1c_no_foreign_on_harness() { # no one else holds a row on a harness-owned path
	jq -e --arg u "$D5_USER" --arg t "$D5_TOKEN" --arg re "$D5_HARNESS_PATHS" '
		[.[] | select((.path | test($re)) and .ugid != $u and .ugid != $t)] == []' "$(ev acl)"
}
v2_privsep() { jq -e --arg t "$D5_TOKENID" '[.[] | select(.tokenid == $t and .privsep == 1)] | length == 1' "$(ev tokens)"; }
v2b_no_group() { jq -e --arg u "$D5_USER" '[.[] | select((.users // "") | split(",") | index($u))] == []' "$(ev groups)"; }
tree_is() { jq -e --slurpfile e "$2" '. == $e[0]' "$(ev "$1")"; }
v4_nothing_at() { # a path-limited answer holding nothing is {"<path>":{}}
	jq -e --arg p "$1" '(keys == [$p]) and (.[$p] == {})' "$(ev "v4$(printf '%s' "$1" | tr '/' '_')")"
}
v7_members() { # the pool's members are exactly these qemu VMs, nothing else
	jq -e --arg p "$D5_POOL" --argjson m "$1" '
		length == 1 and .[0].poolid == $p
		and ([.[0].members[]? | select(.type == "qemu") | .vmid] | sort) == $m
		and ([.[0].members[]? | select(.type != "qemu")] | length) == 0' "$(ev pool)"
}

same_as_p0() { # name jq-projection: the answer, projected, equals P0's
	jq -e --slurpfile p0 "$D5_P0/$1.json" "(\$p0[0] | $2) as \$was | ($2) == \$was" "$(ev "$1")"
}

case "$phase" in
p0)
	# First: key-based root ssh, which steps 1-10 need. Nothing else is read
	# if it fails.
	if ! rx true >"$D5_EVIDENCE/S0.out" 2>&1; then
		d5_note "RED S0 ssh -o BatchMode=yes $D5_HOST true failed: steps 1-10 need non-interactive, key-based root ssh"
		D5_FAIL=1
		d5_finish
	fi
	d5_note "PASS S0 ssh -o BatchMode=yes $D5_HOST true"
	fetch acl 'pveum acl list --output-format json'
	fetch roles 'pveum role list --output-format json'
	fetch users 'pveum user list --output-format json'
	fetch groups 'pveum group list --output-format json'
	fetch pools 'pvesh get /pools --output-format json'
	fetch storage "pvesh get /nodes/$D5_NODE/storage/$D5_STORAGE/status --output-format json"
	d5_check "P1 no $D5_ROLE_PREFIX role" no_harness_role
	d5_check "P2 no pool $D5_POOL" no_harness_pool
	d5_check "P3 no user $D5_USER" no_harness_user
	d5_check "P4 no ACL row for $D5_USER or its token" no_harness_rows
	d5_check "P5 storage $D5_STORAGE active on $D5_NODE" storage_active
	d5_check "fetch keyscan" keyscan
	d5_check "K1 the pinned host key is one qa-pve-02 serves" pin_served
	if [ "$D5_FAIL" = 0 ]; then
		mkdir -m 700 -- "$D5_P0"
		for f in acl roles users groups pools; do
			install -m 600 -- "$(ev "$f")" "$D5_P0/$f.json"
		done
		d5_note "INFO P0 baseline written to $D5_P0"
	fi
	;;
roles)
	fetch roles 'pveum role list --output-format json'
	d5_check "V0 the four roles equal the pinned definitions" v0_roles
	d5_check "V0b every other custom role is as P0" v0_other_roles
	d5_check "L1b a custom role's pveum shape" l1b_shape
	;;
owner)
	fetch pool "pvesh get /pools --poolid $D5_POOL --output-format json"
	fetch users 'pveum user list --output-format json'
	fetch acl 'pveum acl list --output-format json'
	d5_check "O1 pool $D5_POOL exists and is empty" pool_empty
	d5_check "O2 user $D5_USER enabled, never expiring" user_created
	d5_check "O3 no ACL row for $D5_USER yet" no_harness_rows
	;;
granted)
	fetch acl 'pveum acl list --output-format json'
	fetch utree "pveum user permissions $D5_USER --output-format json"
	d5_check "V1u the user's 4 rows equal the pinned ones" v1_rows user
	d5_check "V1b every other row is as P0" v1b_foreign_rows
	d5_check "V1c no one else holds a row on a harness path" v1c_no_foreign_on_harness
	d5_check "V5 the user's tree equals the pre-build tree" tree_is utree "$D5_FIXTURES/d5r3-expected-tree-pre-build.json"
	;;
token | pre | post)
	tree=$D5_FIXTURES/d5r3-expected-tree-pre-build.json members='[]'
	if [ "$phase" = post ]; then
		tree=$D5_FIXTURES/d5r3-expected-tree-post-build.json members='[690,691,692]'
	fi
	fetch roles 'pveum role list --output-format json'
	fetch acl 'pveum acl list --output-format json'
	fetch groups 'pveum group list --output-format json'
	fetch tokens "pveum user token list $D5_USER --output-format json"
	fetch ttree "pveum user token permissions $D5_USER $D5_TOKENID --output-format json"
	fetch utree "pveum user permissions $D5_USER --output-format json"
	fetch pool "pvesh get /pools --poolid $D5_POOL --output-format json"
	d5_check "V0 the four roles equal the pinned definitions" v0_roles
	d5_check "V0b every other custom role is as P0" v0_other_roles
	d5_check "V1 the 8 rows equal the pinned ones" v1_rows both
	if [ "$phase" = token ]; then
		d5_check "V1b every other row is as P0" v1b_foreign_rows
	fi
	d5_check "V1c no one else holds a row on a harness path" v1c_no_foreign_on_harness
	d5_check "V2 token $D5_TOKENID has privsep" v2_privsep
	d5_check "V2b $D5_USER is in no group" v2b_no_group
	d5_check "V3 the token's tree equals the expected tree" tree_is ttree "$tree"
	d5_check "V5 the user's tree equals the expected tree" tree_is utree "$tree"
	for p in / /vms /vms/105 /vms/101 /vms/600 /nodes /nodes/$D5_NODE /storage /storage/local-lvm /storage/qa-dev-01-image-pool /sdn/zones/localnetwork/vmbr0/100 /access /pool; do
		fetch "v4$(printf '%s' "$p" | tr '/' '_')" "pveum user token permissions $D5_USER $D5_TOKENID --path $p --output-format json"
		d5_check "V4 the token holds nothing at $p" v4_nothing_at "$p"
	done
	d5_check "V7 the pool's members are exactly $members" v7_members "$members"
	;;
reverted)
	fetch acl 'pveum acl list --output-format json'
	fetch roles 'pveum role list --output-format json'
	fetch users 'pveum user list --output-format json'
	fetch groups 'pveum group list --output-format json'
	fetch pools 'pvesh get /pools --output-format json'
	d5_check "P1 no $D5_ROLE_PREFIX role" no_harness_role
	d5_check "P2 no pool $D5_POOL" no_harness_pool
	d5_check "P3 no user $D5_USER" no_harness_user
	d5_check "P4 no ACL row for $D5_USER or its token" no_harness_rows
	d5_check "RV1 the ACL list is as P0" same_as_p0 acl 'sort_by(.path, .ugid, .roleid)'
	d5_check "RV2 the custom roles are as P0" same_as_p0 roles '[.[] | select((.special // 0) != 1) | {roleid, privs}] | sort_by(.roleid)'
	d5_check "RV3 the users are as P0" same_as_p0 users '[.[].userid] | sort'
	d5_check "RV4 the groups are as P0" same_as_p0 groups '[.[].groupid] | sort'
	d5_check "RV5 the pools are as P0" same_as_p0 pools '[.[].poolid] | sort'
	;;
esac
d5_finish
