#!/usr/bin/env bash
# hack/harness/probe.sh: the outer storage capability probe
# (pveforge-harness-capability-probe, U3). Run as the pool token, through
# U7's unlock, with PVEFORGE_BIN set:
#
#   hack/harness/unlock.sh run -- hack/harness/probe.sh --storage <id> [--static-only]
#
# Two layers, every call through lib.sh:
#
#   static     the storage's node status: enabled, active on qa-pve-02, content
#              includes images, a type the harness can snapshot (zfspool or
#              lvmthin; anything else is refused by name), and room for the
#              harness (HARNESS_PROBE_MIN_FREE_GIB).
#   empirical  on VMID 690, BEFORE the build (Chair Q2 ruling): create a 1 GiB
#              disk, snapshot s1 then s2, roll back to s1 while s2 exists, and
#              record what the storage does — PVE refuses that on zfspool, a
#              named storage property, not a failure — then cascade (delete s2,
#              roll back to s1), delete both snapshots, destroy 690, verify it
#              gone, and poll until the storage shows nothing left.
#
# --static-only runs the static layer alone: at reset, 690 is the built
# pvh-n1, so no VM may be created.
#
# Output: rollback-rule=<rollback-latest-only|rollback-any> storage=<id>, and
# the same rule in ~/.config/pveforge/harness-state/rollback-rule.<id>, written
# atomically and only by a probe that completed; the reset (U5) reads it
# rather than assume. Evidence — every raw answer — goes to
# ~/.config/pveforge/harness-evidence/probe/<UTC>/.
#
# A probe that dies midway cleans up in its EXIT trap what this run created
# (snapshots, then the VM) and reports exactly what is left, with the
# commands: lib destroys only a VM this run created, so anything left needs an
# operator ask. Exit status: lib's own (2 a refusal before anything was sent,
# pveforge's passed through), 3 a storage the probe refuses, 4 a probe that
# found the storage misbehaving or could not finish.
source "${0%/*}/lib.sh"

# ---- Parameters. ----
# HARNESS_PROBE_MIN_FREE_GIB: the free space the storage must have. The
# default is D10's sizing: 472 GiB of harness disks (the nested nodes' system
# and data disks and pvh-nfs) plus 48 GiB of snapshot headroom = 520 GiB,
# against the storage's 600 G quota.
min_free_gib=${HARNESS_PROBE_MIN_FREE_GIB:-520}
storage=${HARNESS_STORAGE:-}
static_only=0
while [ "$#" -gt 0 ]; do
	case "$1" in
	--storage)
		[ "$#" -ge 2 ] || _harness_die 2 "--storage needs a value"
		storage=$2
		shift 2
		;;
	--static-only)
		static_only=1
		shift
		;;
	*) _harness_die 2 "unknown argument '$1' (usage: probe.sh --storage <id> [--static-only])" ;;
	esac
done
[[ $min_free_gib =~ ^[0-9]+$ ]] || _harness_die 2 "HARNESS_PROBE_MIN_FREE_GIB must be whole GiB, got '$min_free_gib'"

# The external tools the probe itself runs, resolved once, as lib's are.
for probe_tool in sleep date mv chmod; do
	probe_tool_path=$(type -P "$probe_tool") || _harness_die 2 "$probe_tool is not on PATH"
	[[ $probe_tool_path == /* ]] || _harness_die 2 "$probe_tool resolves to $probe_tool_path, which is not an absolute path"
	declare -gr "PROBE_TOOL_${probe_tool^^}=$probe_tool_path"
done
unset probe_tool probe_tool_path

harness_init
harness_declare_vmids 690
harness_require_storage "$storage"

readonly VMID=690
readonly S=$HARNESS_STORAGE
readonly STATUS_PATH=/nodes/$HARNESS_NODE/storage/$S/status
readonly CONTENT_PATH=/nodes/$HARNESS_NODE/storage/$S/content
readonly GONE_PATH=/nodes/$HARNESS_NODE/qemu/$VMID/status/current
readonly POLL_EVERY=5 POLL_FOR=180
readonly MIB=1048576

# say writes a line to stderr, best-effort: stderr is for the operator, and an
# unwritable one (a full disk, a hung-up terminal) never changes the outcome.
say() { # line
	printf '%s\n' "$1" >&2 2>/dev/null || :
}

stamp=$("$PROBE_TOOL_DATE" -u +%Y%m%dT%H%M%SZ) || _harness_die 2 "cannot read the clock"
evid_root=$HOME/.config/pveforge/harness-evidence/probe
"$HARNESS_TOOL_MKDIR" -p -m 700 -- "$evid_root" || _harness_die 2 "cannot create $evid_root"
# mkdir -m does not tighten a directory that already exists.
"$PROBE_TOOL_CHMOD" 700 "$evid_root" || _harness_die 2 "cannot make $evid_root private"
EVID=$evid_root/$stamp
"$HARNESS_TOOL_MKDIR" -m 700 -- "$EVID" || _harness_die 2 "cannot create the evidence directory $EVID"
readonly EVID
say "probe: evidence in $EVID"

evidence() { # name content
	printf '%s\n' "$2" >"$EVID/$1" || _harness_die 2 "cannot write evidence $1"
}
# note writes evidence best-effort: on a failure path, an unwritable evidence
# directory must never change the exit status or stop the report.
note() { # name content
	printf '%s\n' "$2" >"$EVID/$1" 2>/dev/null || :
}
refuse_storage() { # reason
	note REFUSED "storage $S: $1"
	say "probe: refusing storage $S: $1"
	exit 3
}
fail() { # reason
	note FAILED "$1"
	say "probe: $1"
	exit 4
}
jqe() { # json jq-args... : jq -e over json, output discarded
	local j=$1
	shift
	"$HARNESS_TOOL_JQ" -e "$@" <<<"$j" >/dev/null
}

# ---- Static layer. ----
status=$(harness_get "$STATUS_PATH")
evidence storage-status-before.json "$status"
jqe "$status" 'type == "object" and (.type | type == "string") and (.avail | type == "number") and (.content | type == "string")' ||
	_harness_die 1 "storage $S: the status answer has an unexpected shape"
jqe "$status" '.enabled == 1 or .enabled == true' || refuse_storage "it is not enabled"
jqe "$status" '.active == 1 or .active == true' || refuse_storage "it is not active on $HARNESS_NODE"
jqe "$status" '.content | split(",") | any(. == "images")' || refuse_storage "its content does not include images"
stype=$("$HARNESS_TOOL_JQ" -r .type <<<"$status") || _harness_die 1 "storage $S: cannot read its type"
case "$stype" in
zfspool | lvmthin) ;;
*) refuse_storage "type $stype cannot hold the harness: it needs zfspool or lvmthin (snapshots of raw disks)" ;;
esac
jqe "$status" --argjson min "$min_free_gib" '.avail >= $min * 1073741824' ||
	refuse_storage "$("$HARNESS_TOOL_JQ" -r '.avail / 1073741824 | floor' <<<"$status") GiB free, below HARNESS_PROBE_MIN_FREE_GIB=$min_free_gib"
evidence storage-type "$stype"

if [ "$static_only" = 1 ]; then
	evidence SUMMARY "static-only: storage $S ($stype) passed"
	echo "probe: storage $S ($stype) passes the static checks"
	exit 0
fi

# ---- Empirical layer. ----
# 690 must not exist yet: the probe runs only before the build.
pool=$(harness_get /pools "poolid=$HARNESS_POOL")
jqe "$pool" --argjson v "$VMID" 'type == "array" and length == 1 and (.[0].members | type == "array")' ||
	_harness_die 1 "pool $HARNESS_POOL: the answer has an unexpected shape"
if jqe "$pool" --argjson v "$VMID" 'any(.[0].members[]; .vmid == $v)'; then
	refuse_storage "VM $VMID already exists in pool $HARNESS_POOL: the probe runs only before the build"
fi
content=$(harness_get "$CONTENT_PATH" "vmid=$VMID")
evidence content-before.json "$content"
jqe "$content" 'type == "array"' || _harness_die 1 "storage $S: the content answer has an unexpected shape"
jqe "$content" 'length == 0' || refuse_storage "it already holds volumes of VM $VMID (a leftover): see content-before.json"
base_avail=$("$HARNESS_TOOL_JQ" -r .avail <<<"$status") || _harness_die 1 "storage $S: cannot read avail"

gone=0
done_ok=0
# cleanup runs on every exit: on success it does nothing; otherwise it undoes
# what this run created, in order, and reports what is left. Each step runs in
# a subshell, so one failure does not stop the report.
cleanup() {
	local rc=$?
	# Cleanup always runs to its report: lib's errexit off, a closed stderr
	# (a hung-up terminal, a pipe into head) never fatal, and a second
	# Ctrl-C, a TERM or a HUP ignored until it is done.
	set +e
	trap '' PIPE INT TERM HUP
	trap - EXIT
	if [ "$done_ok" = 1 ]; then
		exit "$rc"
	fi
	local log=$EVID/cleanup.log
	# A redirect that fails skips its command: an unwritable evidence
	# directory must cost the log, never a cleanup step.
	{ : >>"$log"; } 2>/dev/null || log=/dev/null
	say "probe: cleaning up after a failure (status $rc); see $log"
	if ! "$HARNESS_TOOL_GREP" -qxF -- "$VMID" "$HARNESS_CREATED_FILE" 2>/dev/null; then
		local members=""
		members=$( (harness_get /pools "poolid=$HARNESS_POOL") 2>>"$log") || members=""
		if [ -n "$members" ] && jqe "$members" --argjson v "$VMID" 'any(.[0].members[]?; .vmid == $v)'; then
			report_leftover "VM $VMID exists in pool $HARNESS_POOL, but this run did not record creating it (a create whose task failed after the VM appeared, or an earlier run's): lib will not touch it"
		fi
		exit "$rc"
	fi
	if [ "$gone" = 0 ]; then
		local snaps="" n
		snaps=$( (harness_vm_get "$VMID" snapshot) 2>>"$log") || snaps=""
		local names=()
		if [ -n "$snaps" ]; then
			# Newest first, "current" excluded; one name per line, never split
			# by the shell.
			mapfile -t names < <("$HARNESS_TOOL_JQ" -r '[.[] | select(.name != "current")] | sort_by(.snaptime // 0) | reverse | .[].name' <<<"$snaps" 2>>"$log")
		fi
		for n in "${names[@]}"; do
			(harness_vm_delete "$VMID" "snapshot/$n") >>"$log" 2>&1 || echo "cleanup: delete snapshot $n failed" >>"$log"
		done
		(harness_vm_destroy "$VMID" purge=1) >>"$log" 2>&1 || echo "cleanup: destroy failed" >>"$log"
		local err=""
		if err=$( { harness_get "$GONE_PATH" >/dev/null; } 2>&1); then
			report_leftover "VM $VMID still exists after cleanup"
			exit "$rc"
		fi
		if [[ $err != *"does not exist"* ]]; then
			report_leftover "VM $VMID: whether cleanup destroyed it could not be read"
			exit "$rc"
		fi
	fi
	# ZFS frees a destroyed VM's volumes asynchronously: the same bounded
	# poll as the probe's own, volumes only, before anything is called left.
	local left="" i=0
	while :; do
		left=$( (harness_get "$CONTENT_PATH" "vmid=$VMID") 2>>"$log") || left=""
		if [ -n "$left" ] && jqe "$left" 'type == "array" and length == 0'; then
			break
		fi
		# 690 verified gone means the probe's own poll already waited its
		# full bound: one read, no second wait.
		[ "$gone" = 0 ] || break
		i=$((i + 1))
		[ "$i" -le $((POLL_FOR / POLL_EVERY)) ] || break
		"$PROBE_TOOL_SLEEP" "$POLL_EVERY"
	done
	if [ -n "$left" ] && jqe "$left" 'type == "array" and length == 0'; then
		note CLEANUP "VM $VMID destroyed; storage $S lists nothing of it"
		say "probe: cleanup: VM $VMID destroyed; storage $S lists nothing of it"
	else
		report_leftover "VM $VMID is destroyed, but storage $S still lists its volumes (or could not be read)"
	fi
	exit "$rc"
}
# report_leftover says exactly what is left and the commands to remove it. It
# reads what it can; a read that fails is said to have failed.
report_leftover() { # headline
	local out conf snaps vols lock
	conf=$( (harness_vm_get "$VMID" config) 2>/dev/null) || conf=""
	snaps=$( (harness_vm_get "$VMID" snapshot) 2>/dev/null) || snaps=""
	vols=$( (harness_get "$CONTENT_PATH" "vmid=$VMID") 2>/dev/null) || vols=""
	lock=""
	[ -z "$conf" ] || lock=$("$HARNESS_TOOL_JQ" -r '.lock // ""' <<<"$conf" 2>/dev/null) || lock=""
	out="LEFTOVER: $1
  VM:        $VMID on $HARNESS_NODE, pool $HARNESS_POOL
  lock:      ${lock:-none (or unreadable)}
  snapshots: $([ -n "$snaps" ] && "$HARNESS_TOOL_JQ" -r '[.[] | select(.name != "current") | .name] | join(" ")' <<<"$snaps" 2>/dev/null || echo unreadable)
  volumes:   $([ -n "$vols" ] && "$HARNESS_TOOL_JQ" -r '[.[].volid] | join(" ")' <<<"$vols" 2>/dev/null || echo unreadable)
Removing it needs an operator ask (lib destroys only a VM this run created).
As root on $HARNESS_NODE:
  qm unlock $VMID                 # only if it carries a lock
  qm delsnapshot $VMID <name>     # each snapshot, newest first
  qm destroy $VMID --purge
  pvesm list $S --vmid $VMID      # must list nothing"
	note LEFTOVER "$out"
	say "$out"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# A closed stderr (a pipe into head, a hung-up terminal) would otherwise kill
# the shell outright on the next write, skipping cleanup.
trap 'exit 141' PIPE

harness_vm_create "$VMID" "{\"scsi0\":\"$S:1\",\"name\":\"pveforge-probe\",\"memory\":\"512\",\"cores\":\"1\"}" >"$EVID/create.out"
harness_vm_post "$VMID" snapshot snapname=s1 vmstate=0 >"$EVID/snapshot-s1.out"
harness_vm_post "$VMID" snapshot snapname=s2 vmstate=0 >"$EVID/snapshot-s2.out"

# The rollback to s1 while s2 exists. PVE runs it as a task and pveforge waits
# for it, so a refusal is a failed command: lib would stop the script, hence
# the subshell, whose stderr is classified.
rb_rc=0
rb_err=$( { harness_vm_post "$VMID" snapshot/s1/rollback >"$EVID/rollback-s1-with-s2.out"; } 2>&1) || rb_rc=$?
evidence rollback-s1-with-s2.stderr "$rb_err"
if [ "$rb_rc" = 0 ]; then
	rule=rollback-any
elif [[ $rb_err == *"is not most recent snapshot"* ]]; then
	rule=rollback-latest-only
	# Whether PVE leaves a lock after refusing is not verified live; lib
	# cannot clear one (lock is a refused field), so it is reported by name.
	conf=$(harness_vm_get "$VMID" config)
	lock=$("$HARNESS_TOOL_JQ" -r '.lock // ""' <<<"$conf") || _harness_die 1 "VM $VMID: cannot read its config"
	if [ -n "$lock" ]; then
		fail "VM $VMID carries lock '$lock' after the refused rollback: clear it as root on $HARNESS_NODE with 'qm unlock $VMID' (an operator ask), then run cleanup by hand as reported"
	fi
else
	fail "the rollback of s1 while s2 exists failed for an unrecognised reason (status $rb_rc): see rollback-s1-with-s2.stderr"
fi
evidence rollback-rule "$rule"
say "probe: storage $S ($stype): $rule"

# Cascade: delete s2, then the rollback to s1 must succeed.
harness_vm_delete "$VMID" snapshot/s2 >"$EVID/delete-s2.out"
harness_vm_post "$VMID" snapshot/s1/rollback >"$EVID/rollback-s1.out"
harness_vm_delete "$VMID" snapshot/s1 >"$EVID/delete-s1.out"
harness_vm_destroy "$VMID" purge=1 >"$EVID/destroy.out"

# Verify gone: PVE says the VM does not exist, and the pool no longer lists it.
gone_err=""
if gone_err=$( { harness_get "$GONE_PATH" >/dev/null; } 2>&1); then
	fail "VM $VMID still answers after the destroy"
fi
evidence gone.stderr "$gone_err"
[[ $gone_err == *"does not exist"* ]] || fail "reading VM $VMID after the destroy failed, but not with 'does not exist': see gone.stderr"
pool=$(harness_get /pools "poolid=$HARNESS_POOL")
jqe "$pool" --argjson v "$VMID" 'type == "array" and length == 1 and (.[0].members | type == "array") and all(.[0].members[]; .vmid != $v)' ||
	fail "pool $HARNESS_POOL still lists VM $VMID after the destroy"
gone=1

# ZFS frees space asynchronously: poll every 5 s, up to 180 s, until the
# storage lists nothing of 690 and its free space is back within 1 MiB of what
# it was before the create.
polls=$((POLL_FOR / POLL_EVERY))
i=0
while :; do
	content=$(harness_get "$CONTENT_PATH" "vmid=$VMID")
	status=$(harness_get "$STATUS_PATH")
	printf 'poll %d: content %s avail %s\n' "$i" "$content" "$("$HARNESS_TOOL_JQ" -r .avail <<<"$status")" >>"$EVID/poll.log"
	if jqe "$content" 'type == "array" and length == 0' && jqe "$status" --argjson b "$base_avail" --argjson m "$MIB" '(.avail | type == "number") and .avail >= $b - $m'; then
		break
	fi
	i=$((i + 1))
	if [ "$i" -gt "$polls" ]; then
		fail "after ${POLL_FOR}s, storage $S still lists volumes of VM $VMID or has not recovered its free space to within 1 MiB of before: see poll.log"
	fi
	"$PROBE_TOOL_SLEEP" "$POLL_EVERY"
done
evidence storage-status-after.json "$status"

# The rule, for the reset: atomically, and only now, after a complete probe.
state=$HOME/.config/pveforge/harness-state
rule_file=$state/rollback-rule.$S
"$HARNESS_TOOL_MKDIR" -p -m 700 -- "$state" || fail "cannot create $state"
"$PROBE_TOOL_CHMOD" 700 "$state" || fail "cannot make $state private"
tmp=$("$HARNESS_TOOL_MKTEMP" -p "$state" rollback-rule.XXXXXX) || fail "cannot write the rule"
printf '%s\n' "$rule" >"$tmp" || fail "cannot write the rule"
"$PROBE_TOOL_CHMOD" 600 "$tmp" || fail "cannot write the rule"
# -T: never move INTO a directory that happens to sit at the rule's path.
"$PROBE_TOOL_MV" -f -T -- "$tmp" "$rule_file" || fail "cannot write the rule to $rule_file"
got=""
if [ -f "$rule_file" ] && [ ! -L "$rule_file" ]; then
	read -r got <"$rule_file" || got=""
fi
[ "$got" = "$rule" ] || fail "the rule file $rule_file is not a regular file holding '$rule' after the write"
done_ok=1
evidence SUMMARY "storage $S ($stype): $rule; VM $VMID created, probed, destroyed and gone"
echo "rollback-rule=$rule storage=$S"
