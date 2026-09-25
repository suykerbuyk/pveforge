#!/usr/bin/env bash
# hack/harness/reset.sh: put the nested harness back to its golden point
# (pveforge-harness-golden-reset), under D11's standing authority: 690-692
# only, through the pool token only. Run through unlock.sh:
#
#   hack/harness/unlock.sh run -- hack/harness/reset.sh --storage <id>
#
# 1. The capability probe's static layer on the storage (its own process).
# 2. Every check before anything changes: each VM's system disk on the
#    storage, no lock (lib cannot clear one: an operator ask), exactly one
#    pvh-golden, disk-only, and no two snapshots at the same time (the
#    cascade orders by time). And the three goldens are ONE point: each
#    carries golden.sh's run stamp in its description, and the three stamps
#    are identical.
# 3. A hard stop, nodes before storage (691, 690, 692), of each VM not
#    already stopped; each then read as stopped.
# 4. The cascade: every snapshot taken after pvh-golden is deleted, newest
#    first. ZFS refuses a rollback past a newer snapshot; the cascade runs
#    whatever the storage, so every reset ends in the same state.
# 5. A rollback to pvh-golden, a start, storage first (692, 690, 691), and
#    acceptance through the nested API.
# It NEVER destroys a VM. A failure stops it where it is, and the evidence
# says which step each VM reached: ~/.config/pveforge/harness-evidence/reset/.
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/golden-reset.sh"

storage=${HARNESS_STORAGE:-}
while [ "$#" -gt 0 ]; do
	case "$1" in
	--storage)
		[ "$#" -ge 2 ] || _harness_die 2 "--storage needs a value"
		storage=$2
		shift 2
		;;
	*) _harness_die 2 "unknown argument '$1' (usage: reset.sh --storage <id>)" ;;
	esac
done
[ -n "$storage" ] || _harness_die 2 "the outer storage is required (--storage or HARNESS_STORAGE); there is no default"

gr_probe "$storage"
harness_init
harness_declare_vmids "${GR_VMIDS[@]}"
harness_require_storage "$storage"
gr_accept_bin
gr_open_evidence reset

# newer_than_golden prints, newest first, the snapshots taken after
# pvh-golden; it refuses a list with no golden, one without times, or two
# snapshots at the same time.
newer_than_golden() { # vmid snapshots-json
	"$HARNESS_TOOL_JQ" -e --arg g "$GR_GOLDEN" '
		([.[] | select(.name == $g)] | length) == 1
		and all(.[]; .snaptime | type == "number")
		and ([.[].snaptime] | length == (unique | length))' <<<"$2" >/dev/null ||
		_harness_die 2 "VM $1: the snapshots need exactly one $GR_GOLDEN, a time on each, and no two at the same time"
	"$HARNESS_TOOL_JQ" -r --arg g "$GR_GOLDEN" '
		([.[] | select(.name == $g)][0].snaptime) as $t
		| [.[] | select(.snaptime > $t)] | sort_by(.snaptime) | reverse | .[].name' <<<"$2" ||
		_harness_die 1 "VM $1: cannot order its snapshots"
}

# golden_stamp prints the run stamp in pvh-golden's description; it refuses
# a golden taken with its memory (vmstate) or carrying no stamp.
golden_stamp() { # vmid snapshots-json
	"$HARNESS_TOOL_JQ" -r -e --arg g "$GR_GOLDEN" --arg p "$GR_DESC_PREFIX" '
		[.[] | select(.name == $g)][0]
		| select((.vmstate // 0) == 0)
		| (.description // "") | rtrimstr("\n")
		| select(startswith($p)) | ltrimstr($p)
		| select(test("\\A[0-9]{8}T[0-9]{6}Z\\z"))' <<<"$2" ||
		_harness_die 2 "VM $1: $GR_GOLDEN must be disk-only (vmstate 0) and carry golden.sh's run stamp; retake it with golden.sh --replace-golden"
}

declare -A newer=() stamp=()
for vmid in "${GR_VMIDS[@]}"; do
	gr_check_vm "$vmid"
	snaps=$(gr_snapshots "$vmid") || _harness_die $? "reading VM $vmid's snapshots failed"
	gr_evidence "snapshots-before-$vmid.json" "$snaps"
	newer[$vmid]=$(newer_than_golden "$vmid" "$snaps") || _harness_die $? "VM $vmid: cannot order its snapshots"
	stamp[$vmid]=$(golden_stamp "$vmid" "$snaps") || _harness_die $? "VM $vmid: its $GR_GOLDEN is not usable"
done
for vmid in "${GR_VMIDS[@]}"; do
	[ "${stamp[$vmid]}" = "${stamp[${GR_VMIDS[0]}]}" ] ||
		_harness_die 2 "the goldens are not one point: $(for v in "${GR_VMIDS[@]}"; do printf '%s=%s ' "$v" "${stamp[$v]}"; done)(retake them with golden.sh --replace-golden)"
done
gr_step "the goldens are one point: stamp ${stamp[${GR_VMIDS[0]}]}"

for vmid in "${GR_STOP_ORDER[@]}"; do
	st=$(gr_status "$vmid") || _harness_die $? "reading VM $vmid's status failed"
	if [ "$st" != stopped ]; then
		harness_vm_post "$vmid" status/stop
	fi
	gr_confirm_stopped "$vmid"
done

for vmid in "${GR_VMIDS[@]}"; do
	while IFS= read -r snap; do
		[ -n "$snap" ] || continue
		harness_vm_delete "$vmid" "snapshot/$snap"
		gr_step "VM $vmid: snapshot $snap deleted"
	done <<<"${newer[$vmid]}"
	harness_vm_post "$vmid" "snapshot/$GR_GOLDEN/rollback"
	gr_step "VM $vmid: rolled back to $GR_GOLDEN"
done

gr_start
gr_accept 15m "after the reset"
gr_step "RESULT reset to $GR_GOLDEN"
