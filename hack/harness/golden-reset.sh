# shellcheck shell=bash
# hack/harness/golden-reset.sh: what golden.sh and reset.sh share
# (pveforge-harness-golden-reset). Sourced right after lib.sh, never on its
# own. The VMs are 690 pvh-n1, 691 pvh-n2, 692 pvh-nfs (D1); D11's reset
# authority covers exactly these three. Nothing here destroys a VM.

readonly GR_GOLDEN=pvh-golden
readonly GR_VMIDS=(690 691 692)
# Stop the nodes before the storage they mount, start the storage first.
readonly GR_STOP_ORDER=(691 690 692)
readonly GR_START_ORDER=(692 690 691)

# The external tools these scripts run, resolved once, as lib's are.
for gr_tool in date go; do
	gr_tool_path=$(type -P "$gr_tool") || _harness_die 2 "$gr_tool is not on PATH"
	[[ $gr_tool_path == /* ]] || _harness_die 2 "$gr_tool resolves to $gr_tool_path, which is not an absolute path"
	declare -gr "GR_TOOL_${gr_tool^^}=$gr_tool_path"
done
unset gr_tool gr_tool_path

GR_EVID=
GR_STAMP=
# Every golden's description is this prefix and its run's stamp.
readonly GR_DESC_PREFIX='pveforge harness golden point '
GR_FAILED=0
# golden.sh records here, per VM, which golden it holds: old, none or new.
declare -A GR_GOLDEN_STATE=()

# gr_say writes to stderr, best-effort: it never changes the outcome.
gr_say() { # line
	printf '%s\n' "$1" >&2 2>/dev/null || :
}

# gr_open_evidence makes this run's evidence directory:
# ~/.config/pveforge/harness-evidence/<what>/<UTC stamp>, mode 0700.
gr_open_evidence() { # what
	local root stamp
	root=$HOME/.config/pveforge/harness-evidence/$1
	stamp=$("$GR_TOOL_DATE" -u +%Y%m%dT%H%M%SZ) || _harness_die 2 "cannot read the clock"
	"$HARNESS_TOOL_MKDIR" -p -m 700 -- "$root" || _harness_die 2 "cannot create $root"
	GR_STAMP=$stamp
	readonly GR_STAMP
	GR_EVID=$root/$stamp
	"$HARNESS_TOOL_MKDIR" -m 700 -- "$GR_EVID" || _harness_die 2 "cannot create the evidence directory $GR_EVID (one run per second)"
	readonly GR_EVID
	gr_say "$1: evidence in $GR_EVID"
	trap gr_on_exit EXIT
}

# gr_on_exit makes every run's evidence end in its outcome: a failure lib
# raised (a failed rollback, delete or start, which exit through
# _harness_die) still leaves a FAILED line, with each VM's golden state when
# golden.sh ran. Best-effort: it never changes the exit status.
gr_on_exit() {
	local rc=$? vmid states=
	[ "$rc" != 0 ] || return 0
	if [ "${#GR_GOLDEN_STATE[@]}" -gt 0 ]; then
		for vmid in "${GR_VMIDS[@]}"; do
			states+=" $vmid=${GR_GOLDEN_STATE[$vmid]:-unknown}"
		done
		states="; golden state:$states"
	fi
	if [ "$GR_FAILED" = 0 ]; then
		printf 'FAILED exit %s%s\n' "$rc" "$states" >>"$GR_EVID/steps" 2>/dev/null || :
		gr_say "FAILED exit $rc$states"
	elif [ -n "$states" ]; then
		printf 'FAILED%s\n' "$states" >>"$GR_EVID/steps" 2>/dev/null || :
		gr_say "${states#; }"
	fi
	return "$rc"
}

# gr_evidence records name=content in the evidence directory.
gr_evidence() { # name content
	printf '%s\n' "$2" >"$GR_EVID/$1" || _harness_die 2 "cannot write evidence $1"
}

# gr_step records one step as done, in order.
gr_step() { # line
	printf '%s\n' "$1" >>"$GR_EVID/steps" || _harness_die 2 "cannot write evidence steps"
	gr_say "$1"
}

# gr_fail records why the run stopped, best-effort, and exits.
gr_fail() { # status reason
	GR_FAILED=1
	printf 'FAILED %s\n' "$2" >>"$GR_EVID/steps" 2>/dev/null || :
	gr_say "$2"
	exit "$1"
}

# gr_accept_bin builds the acceptance command (or takes HARNESS_ACCEPT_BIN,
# an absolute path, for a prebuilt one) and checks what it will need, all
# before anything changes.
gr_accept_bin() {
	local bin root
	[ -n "${PVEFORGE_HARNESS_ROSTER:-}" ] || _harness_die 2 "PVEFORGE_HARNESS_ROSTER must name the nested harness roster: acceptance reads the nested cluster through it"
	[ -n "${PVEFORGE_HARNESS_OUTER_ROSTERS:-}" ] || _harness_die 2 "PVEFORGE_HARNESS_OUTER_ROSTERS must list the outer rosters: acceptance refuses any overlap with them"
	if [ -n "${HARNESS_ACCEPT_BIN:-}" ]; then
		[[ $HARNESS_ACCEPT_BIN == /* ]] && [ -f "$HARNESS_ACCEPT_BIN" ] && [ -x "$HARNESS_ACCEPT_BIN" ] ||
			_harness_die 2 "HARNESS_ACCEPT_BIN must be the absolute path of an executable, got '$HARNESS_ACCEPT_BIN'"
		GR_ACCEPT=$HARNESS_ACCEPT_BIN
	else
		root=$(cd -- "${BASH_SOURCE[0]%/*}/../.." && pwd) || _harness_die 2 "cannot find the repository root"
		bin=${XDG_CACHE_HOME:-$HOME/.cache}/pveforge-harness/pveforge-harness-accept
		(cd -- "$root" && "$GR_TOOL_GO" build -o "$bin" ./cmd/pveforge-harness-accept) || _harness_die 2 "cannot build cmd/pveforge-harness-accept"
		GR_ACCEPT=$bin
	fi
	readonly GR_ACCEPT
}

# gr_accept waits for the nested cluster to be whole, up to deadline.
gr_accept() { # deadline why
	local rc=0
	gr_say "accept ($2): waiting up to $1 for the nested cluster"
	"$GR_ACCEPT" -deadline "$1" 2>>"$GR_EVID/accept.log" || rc=$?
	[ "$rc" = 0 ] || gr_fail "$rc" "accept ($2): the nested cluster was not accepted (exit $rc); see accept.log"
	gr_step "accepted ($2)"
}

# gr_probe runs the capability probe's static layer as its own process,
# before harness_init: it takes the harness lock itself, and a call from
# inside this script's lock would find it held. The free-space floor is the
# reset's, not the pre-build one: the harness's own disks now hold most of
# the quota.
gr_probe() { # storage
	local here=${BASH_SOURCE[0]%/*} rc=0
	HARNESS_PROBE_MIN_FREE_GIB=${HARNESS_RESET_MIN_FREE_GIB:-48} "$here/probe.sh" --storage "$1" --static-only || rc=$?
	[ "$rc" = 0 ] || _harness_die "$rc" "the capability probe's static layer refused storage $1 (exit $rc)"
}

# gr_config reads a VM's config.
gr_config() { # vmid
	harness_vm_get "$1" config || _harness_die $? "reading VM $1's config failed"
}

# gr_status reads a VM's run state: running or stopped.
gr_status() { # vmid
	local out st
	out=$(harness_vm_get "$1" status/current) || _harness_die $? "reading VM $1's status failed"
	st=$("$HARNESS_TOOL_JQ" -r 'if type == "object" and (.status | type == "string") then .status else "" end' <<<"$out") ||
		_harness_die 1 "VM $1: the status answer has an unexpected shape"
	[ -n "$st" ] || _harness_die 1 "VM $1: the status answer carries no status"
	printf '%s' "$st"
}

# gr_snapshots reads a VM's snapshots, without PVE's "current" entry.
gr_snapshots() { # vmid
	local out
	out=$(harness_vm_get "$1" snapshot) || _harness_die $? "reading VM $1's snapshots failed"
	"$HARNESS_TOOL_JQ" -e 'type == "array" and all(.[]; type == "object" and (.name | type == "string"))' <<<"$out" >/dev/null ||
		_harness_die 1 "VM $1: the snapshot list has an unexpected shape"
	"$HARNESS_TOOL_JQ" -c '[.[] | select(.name != "current")]' <<<"$out" || _harness_die 1 "VM $1: cannot read the snapshot list"
}

# gr_check_vm is every check made before anything changes, for one VM: its
# system disk is on the required storage, and it holds no lock (lib cannot
# clear one; lock is a refused field).
gr_check_vm() { # vmid
	local vmid=$1 cfg disk lock
	cfg=$(gr_config "$vmid") || _harness_die $? "reading VM $vmid's config failed"
	gr_evidence "config-$vmid.json" "$cfg"
	disk=$("$HARNESS_TOOL_JQ" -r '.scsi0 // "" | if type == "string" then . else "" end' <<<"$cfg") || _harness_die 1 "VM $vmid: cannot read scsi0"
	[ "${disk%%:*}" = "$HARNESS_STORAGE" ] ||
		_harness_die 2 "VM $vmid: its system disk is on '${disk%%:*}', not the required storage $HARNESS_STORAGE"
	lock=$("$HARNESS_TOOL_JQ" -r '.lock // "" | tostring' <<<"$cfg") || _harness_die 1 "VM $vmid: cannot read its lock"
	[ -z "$lock" ] ||
		_harness_die 2 "VM $vmid holds lock '$lock'; lib cannot clear it. Operator ask: qm unlock $vmid on $HARNESS_NODE, as root"
}

# gr_confirm_stopped reads that a VM is stopped after a stop or a shutdown
# task reported success: the task's outcome alone does not prove it.
gr_confirm_stopped() { # vmid
	local st
	st=$(gr_status "$1") || _harness_die $? "reading VM $1's status failed"
	[ "$st" = stopped ] || gr_fail 1 "VM $1 is '$st' after its stop reported success"
	gr_step "VM $1: stopped"
}

# gr_start starts the VMs, storage first.
gr_start() {
	local vmid
	for vmid in "${GR_START_ORDER[@]}"; do
		harness_vm_post "$vmid" status/start
		gr_step "VM $vmid: started"
	done
}
