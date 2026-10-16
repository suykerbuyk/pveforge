#!/usr/bin/env bash
# hack/harness/stage14-destructive-proof.sh: reproduce the epic's Stage 14
# destructive proof (pveforge-nested-pve-test-harness items 62-65) against the
# live nested `pvh` cluster. First proven live 2026-10-15.
#
#   PVEFORGE_BIN=<pveforge CLI>  HARNESS_ACCEPT_BIN=<pveforge-harness-accept> \
#   PVEFORGE_HARNESS_ROSTER=<nested roster>  PVEFORGE_HARNESS_OUTER_ROSTERS=<outer> \
#   PVEFORGE_HARNESS_AGE_IDENTITY_FILE=<age key> \
#   hack/harness/stage14-destructive-proof.sh --storage <id> [--iters N]
#
# What it proves, all read from live state (nothing destructive to the physical
# host — the nested cluster is the disposable resource, reset is its revert):
#   G0  preconditions: cluster accepted; every VM unlocked and at one golden
#       point; the storage passes reset's own static free-space floor.
#   A1  (item 62) the management-bridge guard REFUSES destroying the management
#       bridge itself; decided by n2's STATE (reachability + the bridge still
#       present), never by the CLI exit code. If the guard instead strands n2,
#       that is a real defect: this script recovers via reset and exits non-zero.
#   loop x --iters (items 63-65): break n2's management network over pinned-key
#       root SSH (vmbr0 -> `inet manual`, drop address+gateway); confirm n2 is
#       unreachable AND the cluster is still quorate via n1 + qdevice (n1-ONLY
#       read — never the accept binary, which needs n2); recover with reset.sh
#       from the OUTER pool-token API only; re-verify unlocked + at golden + the
#       break fully reverted. FAIL-CLOSED: never resets a cluster not proven
#       quorate, and aborts on any deviation.
#
# It does NOT run under unlock.sh; it wraps each secret-gated step in
# `unlock.sh run --` itself and SSHes to n2 with the plaintext nested key.
set -uo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
die2() { echo "stage14: $*" >&2; exit 2; }  # usage/precondition failure, before evidence exists

# --- constants of the nested harness topology (see hack/harness/README.md) ---
NODE=pvh-n2                       # the node whose network is broken
NODE_IP=10.20.247.91              # its management address (dropped by the break)
BRIDGE=vmbr0                      # its management bridge (also --management-bridge)
VMIDS=(690 691 692)               # pvh-n1, pvh-n2, pvh-nfs
OUTER_TARGET=qa-pve-02-harness    # outer pool-token roster target
OUTER_NODE=qa-pve-02              # outer node hosting the nested VMs
GOLDEN_SNAP=pvh-golden
KEY=${PVEFORGE_HARNESS_NESTED_KEY:-$HOME/.config/pveforge/harness-nested_ed25519}
KNOWN=${PVEFORGE_HARNESS_NESTED_KNOWN_HOSTS:-$HOME/.config/pveforge/harness-nested.known_hosts}

iters=3
storage=${HARNESS_STORAGE:-}
while [ "$#" -gt 0 ]; do
	case "$1" in
	--storage) [ "$#" -ge 2 ] || die2 "--storage needs a value"; storage=$2; shift 2 ;;
	--iters)   [ "$#" -ge 2 ] || die2 "--iters needs a value";   iters=$2;   shift 2 ;;
	*) die2 "unknown argument '$1' (usage: stage14-destructive-proof.sh --storage <id> [--iters N])" ;;
	esac
done
[ -n "$storage" ] || die2 "the outer storage is required (--storage or HARNESS_STORAGE)"
[[ $iters =~ ^[1-9][0-9]*$ ]] || die2 "--iters must be a positive integer, got '$iters'"
: "${PVEFORGE_BIN:?set PVEFORGE_BIN to the pveforge CLI}"
: "${HARNESS_ACCEPT_BIN:?set HARNESS_ACCEPT_BIN to a pveforge-harness-accept binary}"
: "${PVEFORGE_HARNESS_ROSTER:?set PVEFORGE_HARNESS_ROSTER to the nested roster path}"
: "${PVEFORGE_HARNESS_OUTER_ROSTERS:?set PVEFORGE_HARNESS_OUTER_ROSTERS}"
[ -n "${PVEFORGE_HARNESS_AGE_IDENTITY_FILE:-}${PVEFORGE_HARNESS_AGE_IDENTITY:-}" ] || \
	die2 "the harness age identity must be set (PVEFORGE_HARNESS_AGE_IDENTITY_FILE)"
[ "$(readlink -f -- "$PVEFORGE_BIN")" != "$(readlink -f -- "$HARNESS_ACCEPT_BIN")" ] || \
	die2 "PVEFORGE_BIN and HARNESS_ACCEPT_BIN must be DIFFERENT programs (CLI vs accept)"
# export so children (unlock.sh -> reset.sh / accept / pveforge) inherit them
export PVEFORGE_BIN HARNESS_ACCEPT_BIN PVEFORGE_HARNESS_ROSTER PVEFORGE_HARNESS_OUTER_ROSTERS
[ -n "${PVEFORGE_HARNESS_AGE_IDENTITY_FILE:-}" ] && export PVEFORGE_HARNESS_AGE_IDENTITY_FILE
[ -n "${PVEFORGE_HARNESS_AGE_IDENTITY:-}" ] && export PVEFORGE_HARNESS_AGE_IDENTITY
# the guard reads these; they must be unset for every pveforge/accept call here
unset PVEFORGE_ROSTER PVEFORGE_PVE_PASSWORD
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy

NESTED=$PVEFORGE_HARNESS_ROSTER
EVID=${PVEFORGE_HARNESS_EVIDENCE:-$HOME/.config/pveforge/harness-evidence}/stage14/$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p -- "$EVID"

die() { echo "stage14 ABORT: $*" | tee -a "$EVID/log" >&2; echo "STAGE14_RESULT=ABORT" | tee -a "$EVID/log"; exit 1; }
log() { echo "$@" | tee -a "$EVID/log"; }
# apiget PATH TARGET ROSTER  -> JSON on stdout. (Signature is 3 args, always.)
apiget() { "$here/unlock.sh" run -- "$PVEFORGE_BIN" api get "$1" "$2" --roster "$3" -o json; }
tcp() { timeout 3 bash -c "echo >/dev/tcp/$NODE_IP/$1" 2>/dev/null && echo OPEN || echo CLOSED; }
ssh_n2() { # runs stdin as a script on n2 over the pinned nested key; args after -- reach the remote $1..
	ssh -F /dev/null -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes \
	    -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN" \
	    -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=15 "root@$NODE_IP" bash -s -- "$@"
}

# golden_stamp: the single golden run-stamp shared by all VMIDS, or die.
golden_stamp() {
	local v snap stamp first=""
	for v in "${VMIDS[@]}"; do
		snap=$(apiget "/nodes/$OUTER_NODE/qemu/$v/snapshot" "$OUTER_TARGET" "$PVEFORGE_HARNESS_OUTER_ROSTERS") \
			|| die "snapshot read for $v failed"
		stamp=$(echo "$snap" | jq -r '.[] | select(.name=="'"$GOLDEN_SNAP"'" and (.vmstate // 0)==0) | .description' \
			| sed -n 's/.*\([0-9]\{8\}T[0-9]\{6\}Z\).*/\1/p' | head -1)
		[ -n "$stamp" ] || die "VM $v has no $GOLDEN_SNAP(vmstate:0) with a run stamp"
		[ -z "$first" ] && first=$stamp
		[ "$stamp" = "$first" ] || die "VM $v golden stamp $stamp != $first (goldens are not one point)"
	done
	echo "$first"
}

# g4_check LABEL GOLDEN : every VM unlocked + only golden+current at GOLDEN; n2 reverted.
g4_check() {
	local label=$1 golden=$2 v cfg snap
	log "## G4 ($label)"
	for v in "${VMIDS[@]}"; do
		cfg=$(apiget "/nodes/$OUTER_NODE/qemu/$v/config" "$OUTER_TARGET" "$PVEFORGE_HARNESS_OUTER_ROSTERS") || die "$label: cfg $v failed"
		echo "$cfg" | jq -e 'has("lock")|not' >/dev/null || die "$label: VM $v is LOCKED"
		snap=$(apiget "/nodes/$OUTER_NODE/qemu/$v/snapshot" "$OUTER_TARGET" "$PVEFORGE_HARNESS_OUTER_ROSTERS") || die "$label: snap $v failed"
		echo "$snap" | jq -e --arg g "$golden" \
			'any(.[]; .name=="'"$GOLDEN_SNAP"'" and (.vmstate // 0)==0 and (.description|contains($g))) and ((map(select(.name!="current" and .name!="'"$GOLDEN_SNAP"'")))|length==0)' \
			>/dev/null || die "$label: VM $v not clean-at-golden"
		log "  VM $v: unlocked & at golden"
	done
	ssh_n2 "$NODE_IP" <<-'REMOTE' || die "$label: n2 not fully reverted"
		set -e
		[ ! -e /etc/network/interfaces.new ] || { echo "interfaces.new PRESENT_BAD"; exit 1; }
		[ ! -e /etc/network/interfaces.stage14-bak ] || { echo "stage14-bak PRESENT_BAD"; exit 1; }
		grep -qE "^[[:space:]]*address $1/[0-9]+$" /etc/network/interfaces || { echo "address NOT restored (expected $1)"; exit 1; }
		echo "  n2 revert clean"
	REMOTE
	log "G4 ($label): OK"
}

# g3_check ITER : n2 unreachable AND cluster quorate via n1 + qdevice (n1-ONLY). FAIL-CLOSED.
g3_check() {
	local it=$1 st qd
	log "## G3 (iter $it): n1-only quorum, fail-closed"
	[ "$(tcp 8006)" = CLOSED ] || die "iter $it: $NODE still reachable on 8006 after break"
	st=$(apiget /cluster/status pvh-n1 "$NESTED") || die "iter $it: /cluster/status failed"
	echo "$st" | jq -e 'map(select(.type=="cluster"))[0].quorate==1' >/dev/null || die "iter $it: NOT quorate — refusing reset"
	qd=$(apiget /cluster/config/qdevice pvh-n1 "$NESTED") || die "iter $it: qdevice read failed"
	echo "$qd" | jq -e '.State=="Connected"' >/dev/null || die "iter $it: qdevice not Connected — refusing reset"
	log "G3 (iter $it): quorate=1, qdevice Connected"
}

# break_n2 : rewrite n2's $BRIDGE stanza to `inet manual` (drop address+gateway),
# back it up, and apply via a detached ifreload so it survives the SSH drop.
break_n2() {
	log "## break $NODE ($BRIDGE -> inet manual)"
	# Scope the edit to WITHIN the $BRIDGE stanza (iface line .. next blank line),
	# so address/gateway deletes cannot touch any other interface's stanza.
	ssh_n2 <<-REMOTE
		set -e
		sed -i.stage14-bak -e '/^iface $BRIDGE inet /,/^\$/{s/^\(iface $BRIDGE inet \)static\$/\1manual/;/^[[:space:]]*address /d;/^[[:space:]]*gateway /d;}' /etc/network/interfaces
		diff /etc/network/interfaces.stage14-bak /etc/network/interfaces || true
		systemd-run --no-block --collect ifreload -a
		echo ifreload-scheduled
	REMOTE
	log "ssh break returned ($? — a non-zero/reset is expected as $NODE drops)"
	sleep 6
}

# reset_recover : reset.sh from the outer API (secrets already available via unlock).
reset_recover() {
	local it=$1
	log "## reset (iter $it)"
	"$here/unlock.sh" run -- "$here/reset.sh" --storage "$storage" 2>&1 | tee -a "$EVID/log"
	[ "${PIPESTATUS[0]}" -eq 0 ] || die "iter $it: reset exit ${PIPESTATUS[0]}"
}

###########################################################################
log "### Stage 14 destructive proof — $(date -u +%Y%m%dT%H%M%SZ) — storage=$storage iters=$iters"
log "### evidence: $EVID"

# --- G0 preconditions (read-only) ---
log "## G0.1 accept (cluster whole/quorate/qdevice/shared/uptime)"
"$here/unlock.sh" run -- "$HARNESS_ACCEPT_BIN" -deadline 2m 2>&1 | tee -a "$EVID/log" || die "G0.1: cluster not accepted"
GOLDEN=$(golden_stamp); log "## G0.2 goldens are one point: $GOLDEN"
g4_check "G0 precondition" "$GOLDEN"
log "## G0.3 storage static floor"
"$here/unlock.sh" run -- "$here/probe.sh" --storage "$storage" --static-only 2>&1 | tee -a "$EVID/log" || die "G0.3: storage floor"

# --- A1 (item 62): the management-bridge guard must refuse, decided by STATE ---
log "## A1 (item 62): destroy $BRIDGE --management-bridge $BRIDGE on $NODE (guard proof, reset-armed)"
"$here/unlock.sh" run -- "$PVEFORGE_BIN" network bridge destroy "$NODE" "$BRIDGE" \
	--management-bridge "$BRIDGE" --roster "$NESTED" 2>&1 | tee -a "$EVID/log"
a1_destroy_exit=${PIPESTATUS[0]}   # the real destroy exit (no `|| true`, which would reset PIPESTATUS)
log "A1 destroy exit=$a1_destroy_exit (NOT the discriminator; state below decides)"
a1_8006=$(tcp 8006); a1_22=$(tcp 22); log "A1 state: $NODE:22=$a1_22 $NODE:8006=$a1_8006"
if [ "$a1_8006" = OPEN ] && "$here/unlock.sh" run -- "$PVEFORGE_BIN" network get "$NODE" "$BRIDGE" --roster "$NESTED" >/dev/null 2>&1; then
	log "A1: guard HELD — $BRIDGE present, $NODE reachable (the expected refuse)"
else
	log "A1: GUARD DEFECT — $NODE stranded; recovering via reset and failing"
	# Deliberate recovery of a KNOWN-stranded node: no pre-reset quorum gate here
	# (unlike the loop) because n2 is already down by assumption; reset.sh's own
	# final acceptance is the fail-closed backstop (a cluster that won't re-form
	# fails acceptance -> reset exits non-zero -> die).
	reset_recover "A1-recover"
	die "A1: the management-bridge guard did NOT refuse (item 62 FAILED) — see evidence; cluster recovered"
fi

# --- loop (items 63-65): break -> G3 -> reset -> G4 ---
for it in $(seq 1 "$iters"); do
	log "######## ITERATION $it / $iters ########"
	t0=$(date +%s)
	break_n2
	g3_check "$it"
	reset_recover "$it"
	g4_check "iter $it" "$GOLDEN"
	log "ITER $it OK — wall $(( $(date +%s) - t0 ))s"
done

log "STAGE14_RESULT=OK (item 62 guard refused; items 63-65 break->recover x$iters clean)"
