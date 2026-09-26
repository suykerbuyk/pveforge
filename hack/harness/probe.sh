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
#              includes images, type zfspool (anything else, lvmthin included,
#              is refused by name: see below), and room for the
#              harness (HARNESS_PROBE_MIN_FREE_GIB).
#   empirical  on VMID 690, BEFORE the build (Chair Q2 ruling): create a 1 GiB
#              disk, snapshot s1 then s2, roll back to s1 while s2 exists, and
#              record what the storage does — PVE refuses that on zfspool, a
#              named storage property, not a failure — then cascade (delete s2,
#              roll back to s1), delete both snapshots, destroy 690, prove it
#              gone (lib's harness_vm_gone: its destroy task ended exactly
#              OK, /cluster/nextid answers 690, and the pool no longer lists
#              it; PVE answers a pool token 403, never "does not exist", for a
#              VM outside the pool), and wait for the storage's usage to come
#              back, which can only detect a leftover (lib).
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
for probe_tool in date mv chmod; do
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
readonly GIB=1073741824

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
zfspool) ;;
# The harness is proven on zfspool only; lvmthin support is a follow-up.
lvmthin) refuse_storage "type lvmthin is not supported: the harness is proven on zfspool only (lvmthin support is a follow-up task)" ;;
*) refuse_storage "type $stype cannot hold the harness: it needs zfspool (snapshots of raw disks)" ;;
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
# A VMID held outside the pool, on any node, is invisible to the pool token
# but still refuses the create: the cluster must hold no VM $VMID (lib).
harness_vmid_free "$VMID" "$EVID/nextid.log" 2>>"$EVID/nextid.stderr" || refuse_storage "VMID $VMID is not free in the cluster: $HARNESS_NOT_FREE"
content=$(harness_get "$CONTENT_PATH" "vmid=$VMID")
evidence content-before.json "$content"
jqe "$content" 'type == "array"' || _harness_die 1 "storage $S: the content answer has an unexpected shape"
jqe "$content" 'length == 0' || refuse_storage "it already holds volumes of VM $VMID (a leftover): see content-before.json"
# The usage every later proof compares with (lib), read before anything is
# created, from an EMPTY storage: the pool empty, and used at most 1 MiB.
jqe "$pool" '.[0].members | length == 0' || refuse_storage "pool $HARNESS_POOL is not empty: the probe runs on an empty harness storage, before the build"
harness_storage_baseline "$status" || refuse_storage "$HARNESS_NOT_FREE"

gone=0
done_ok=0
# The main path's destroy answer: cleanup proves 690 gone by that task when a
# re-destroy has nothing to say (690 already left the pool).
destroy_ans=""
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
		local ans=""
		ans=$( (harness_vm_destroy "$VMID") 2>>"$log") || echo "cleanup: destroy failed" >>"$log"
		printf 'destroy answered: %s\n' "$ans" >>"$log" 2>/dev/null
		# A re-destroy lib refused (690 already left the pool) answers
		# nothing: the main path's own destroy task is then the one to judge,
		# and its real outcome (WARNINGS, say) is what the report names.
		[ -n "$ans" ] || ans=$destroy_ans
		if ! harness_vm_gone "$VMID" "$ans" "$log" 2>>"$log"; then
			report_leftover "VM $VMID is not proven gone after cleanup: $HARNESS_NOT_FREE"
			exit "$rc"
		fi
	fi
	# ZFS frees a destroyed VM's volumes asynchronously: lib's bounded wait,
	# which can only DETECT a leftover (the destroy task above is the proof).
	# 690 proven gone means the probe's own wait already ran its full bound:
	# one read, no second wait.
	local secs=180
	[ "$gone" = 0 ] || secs=0
	if harness_storage_leftover "$secs" "$log" "$VMID" 2>>"$log"; then
		report_leftover "VM $VMID is destroyed, but the storage shows a leftover: $HARNESS_NOT_FREE"
	else
		note CLEANUP "VM $VMID destroyed: its destroy task ended OK"
		say "probe: cleanup: VM $VMID destroyed: its destroy task ended OK"
	fi
	exit "$rc"
}
# report_leftover says exactly what is left and the commands to remove it. It
# reads what it can; a read that fails is said to have failed.
report_leftover() { # headline
	local out conf snaps vols lock used
	conf=$( (harness_vm_get "$VMID" config) 2>/dev/null) || conf=""
	snaps=$( (harness_vm_get "$VMID" snapshot) 2>/dev/null) || snaps=""
	vols=$( (harness_get "$CONTENT_PATH" "vmid=$VMID") 2>/dev/null) || vols=""
	used=$( (harness_get "$STATUS_PATH") 2>/dev/null | "$HARNESS_TOOL_JQ" -r '.used // empty' 2>/dev/null) || used=""
	lock=""
	[ -z "$conf" ] || lock=$("$HARNESS_TOOL_JQ" -r '.lock // ""' <<<"$conf" 2>/dev/null) || lock=""
	out="LEFTOVER: $1
  VM:        $VMID on $HARNESS_NODE, pool $HARNESS_POOL
  lock:      ${lock:-none (or unreadable)}
  snapshots: $([ -n "$snaps" ] && "$HARNESS_TOOL_JQ" -r '[.[] | select(.name != "current") | .name] | join(" ")' <<<"$snaps" 2>/dev/null || echo unreadable)
  volumes:   $([ -n "$vols" ] && "$HARNESS_TOOL_JQ" -r '[.[].volid] | join(" ")' <<<"$vols" 2>/dev/null || echo unreadable) (the pool token is not shown a volume whose VM left the pool)
  storage:   $S used ${used:-unreadable}, baseline ${HARNESS_USED_BASE:-unread}
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
# How the storage accounts the 1 GiB disk just made, as evidence only: thick
# (a zvol's refreservation, the whole disk in `used` at once) or thin
# (pveforge-harness is 'sparse 1': a few KiB). The destroy task, not the usage,
# proves the disk gone later.
if used_after=$(harness_storage_used 2>>"$EVID/accounts.stderr"); then
	delta=$((used_after - HARNESS_USED_BASE))
	kind=thin
	[ "$delta" -lt $((GIB - HARNESS_USED_SLACK)) ] || kind=thick
	evidence accounts.txt "baseline $HARNESS_USED_BASE after-create $used_after delta $delta: $kind (evidence only)"
else
	evidence accounts.txt "baseline $HARNESS_USED_BASE after-create unreadable (evidence only)"
fi
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
destroy_ans=$(harness_vm_destroy "$VMID")
evidence destroy.out "$destroy_ans"

# Prove gone (lib): the destroy task ended exactly OK, the VMID is free in the
# whole cluster, and the pool no longer lists it. Every answer read is in
# gone.log; the reads' own errors, if any, in gone.stderr.
evidence gone.stderr ""
harness_vm_gone "$VMID" "$destroy_ans" "$EVID/gone.log" 2>>"$EVID/gone.stderr" || fail "VM $VMID is not proven gone after the destroy: $HARNESS_NOT_FREE; see gone.log"
gone=1

# ZFS frees space asynchronously: lib's wait, every 5 s for at most 180 s by
# the clock, which can only DETECT a leftover: a volume still listed, or the
# usage still above its baseline at the end.
if harness_storage_leftover 180 "$EVID/poll.log" "$VMID" 2>>"$EVID/poll.log"; then
	fail "VM $VMID is destroyed, but the storage shows a leftover: $HARNESS_NOT_FREE; see poll.log"
fi
evidence storage-status-after.json "$HARNESS_STORAGE_STATUS"

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
