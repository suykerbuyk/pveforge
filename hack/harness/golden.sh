#!/usr/bin/env bash
# hack/harness/golden.sh: take the nested harness's golden point
# (pveforge-harness-golden-reset). Run through unlock.sh:
#
#   hack/harness/unlock.sh run -- hack/harness/golden.sh --storage <id> [--replace-golden]
#
# 1. The capability probe's static layer on the storage (its own process).
# 2. Every check before anything changes: each VM's system disk on the
#    storage, no lock, no pvh-golden yet (--replace-golden deletes an
#    existing one, after the shutdown), and the nested cluster accepted: a
#    golden point is never taken of a broken cluster.
# 3. A graceful shutdown, nodes before storage (691, 690, 692), each VM
#    then read as stopped.
# 4. With --replace-golden, every old pvh-golden is deleted first, and "no
#    golden exists" recorded, before any new one is taken: the three are
#    never a mix of two points.
# 5. A disk-only snapshot pvh-golden of each (vmstate=0: a cold, consistent
#    point across the cluster), each read back. All three carry this run's
#    one stamp in their description, which is how reset.sh knows they are
#    ONE point.
# 6. A start, storage first (692, 690, 691), and acceptance again.
# It never destroys a VM. A failure stops it where it is, and the evidence
# names each VM's golden as old, none or new:
# ~/.config/pveforge/harness-evidence/golden/.
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/golden-reset.sh"

storage=${HARNESS_STORAGE:-} replace=0
while [ "$#" -gt 0 ]; do
	case "$1" in
	--storage)
		[ "$#" -ge 2 ] || _harness_die 2 "--storage needs a value"
		storage=$2
		shift 2
		;;
	--replace-golden)
		replace=1
		shift
		;;
	*) _harness_die 2 "unknown argument '$1' (usage: golden.sh --storage <id> [--replace-golden])" ;;
	esac
done
[ -n "$storage" ] || _harness_die 2 "the outer storage is required (--storage or HARNESS_STORAGE); there is no default"

gr_probe "$storage"
harness_init
harness_declare_vmids "${GR_VMIDS[@]}"
harness_require_storage "$storage"
gr_accept_bin
gr_open_evidence golden

for vmid in "${GR_VMIDS[@]}"; do
	gr_check_vm "$vmid"
	snaps=$(gr_snapshots "$vmid") || _harness_die $? "reading VM $vmid's snapshots failed"
	gr_evidence "snapshots-before-$vmid.json" "$snaps"
	has=$("$HARNESS_TOOL_JQ" --arg g "$GR_GOLDEN" 'any(.[]; .name == $g)' <<<"$snaps") || _harness_die 1 "VM $vmid: cannot read its snapshots"
	if [ "$has" = true ] && [ "$replace" = 0 ]; then
		_harness_die 2 "VM $vmid already has $GR_GOLDEN; replacing the golden point needs --replace-golden"
	fi
	if [ "$has" = true ]; then
		GR_GOLDEN_STATE[$vmid]=old
	else
		GR_GOLDEN_STATE[$vmid]=none
	fi
done
gr_accept 5m "before the golden point"

for vmid in "${GR_STOP_ORDER[@]}"; do
	harness_vm_post "$vmid" status/shutdown timeout=300
	gr_confirm_stopped "$vmid"
done

if [ "$replace" = 1 ]; then
	for vmid in "${GR_VMIDS[@]}"; do
		snaps=$(gr_snapshots "$vmid") || _harness_die $? "reading VM $vmid's snapshots failed"
		has=$("$HARNESS_TOOL_JQ" --arg g "$GR_GOLDEN" 'any(.[]; .name == $g)' <<<"$snaps") || _harness_die 1 "VM $vmid: cannot read its snapshots"
		if [ "$has" = true ]; then
			harness_vm_delete "$vmid" "snapshot/$GR_GOLDEN"
			GR_GOLDEN_STATE[$vmid]=none
			gr_step "VM $vmid: the old $GR_GOLDEN deleted (--replace-golden)"
		fi
	done
	gr_step "no golden exists on ${GR_VMIDS[*]}"
fi

for vmid in "${GR_VMIDS[@]}"; do
	harness_vm_post "$vmid" snapshot "snapname=$GR_GOLDEN" vmstate=0 "description=$GR_DESC_PREFIX$GR_STAMP"
	GR_GOLDEN_STATE[$vmid]=new
	snaps=$(gr_snapshots "$vmid") || _harness_die $? "reading VM $vmid's snapshots failed"
	gr_evidence "snapshots-after-$vmid.json" "$snaps"
	"$HARNESS_TOOL_JQ" -e --arg g "$GR_GOLDEN" --arg d "$GR_DESC_PREFIX$GR_STAMP" '
		[.[] | select(.name == $g)] | length == 1 and ((.[0].vmstate // 0) == 0)
		and ((.[0].description // "") | rtrimstr("\n")) == $d' <<<"$snaps" >/dev/null ||
		gr_fail 1 "VM $vmid: $GR_GOLDEN does not read back as one disk-only snapshot stamped $GR_STAMP"
	gr_step "VM $vmid: $GR_GOLDEN taken"
done

gr_start
gr_accept 15m "after the golden point"
gr_step "RESULT golden point taken"
