# shellcheck shell=bash
# hack/harness/lib.sh: the base every outer-layer harness script (D5 verify,
# capability probe, build, golden/reset) sources as its FIRST statement:
#
#   #!/usr/bin/env bash
#   source "$(dirname "$0")/lib.sh"
#   harness_init
#   harness_declare_vmids 690
#
# It is the only way a harness script reaches the outer cluster, and it reaches
# it only through pveforge, as the pool token held in the harness roster
# (operator ruling 2026-09-24 (1)): `pveforge api get|put|post|delete` and, for
# a create, `pveforge vm create` (REST only, per-VM lock, never --unique-tag).
# The token never leaves pveforge and no secret is ever held by this shell.
#
# THREAT MODEL. lib defends against an ERRANT script: a bug, a typo, a wrong
# variable, a failed command, odd input. It does NOT defend against a
# DELIBERATE one: such a script can run $PVEFORGE_BIN api itself with the
# roster, rewrite lib's files or state, or shadow its tools, and nothing here
# can stop that. The backstop against a deliberate script is PVE's own ACLs
# on the pool-scoped token (D5). So lib's checks are there to turn a mistake
# into a named refusal before any request is sent, not to contain a hostile
# caller.
#
# What is fixed here, never taken from the environment: the roster target
# qa-pve-02-harness, the node qa-pve-02, the pool and tag pveforge-harness, and
# the VMIDs 690-699 (operator ruling 2026-09-24 (3)). A script declares the
# VMIDs it may touch (harness_declare_vmids); every VM operation must name one
# of them. Before changing an existing VM, lib reads that it is a qemu member
# of the pool, on qa-pve-02, and carries the tag. It destroys only a VM this
# run created. What a change may do is an allow-list, of endpoints
# (_harness_allow_endpoint) and, per endpoint, of fields
# (_harness_config_field, _harness_field_allowed); anything not named is
# refused. A disk may be set only on a VM this run created, and only on the
# storage the script required.
#
# Every lib function stops the script when anything it runs fails, whatever
# context it is called from: lib never relies on set -e, which bash turns off
# inside a function called from an if, !, || or && (so `if ! harness_vm_create
# ...` would otherwise carry on past a failed create). Each command whose
# status matters has its own `|| _harness_die`. A caller that runs a lib
# function in a subshell, $(...) or ( ... ), stops only that subshell, and sees
# its status.
#
# Exit status: 2 is a refusal made before anything was sent (a usage or policy
# error, a busy lock); 1 is an answer of an unexpected shape; any other status
# is pveforge's own, passed through unchanged (130/143 on a signal).
#
# The shell checks below catch accidental state in the environment a script
# starts with: tracing, a shadowing function or alias, a disabled builtin, a
# locale that changes what [0-9] matches, a PATH that finds a different tool
# later. The tools lib runs are resolved to absolute paths once, when lib is
# sourced.
#
# Traps are neither cleared nor tested for here, and cannot be (the Chair's O4
# ruling, 2026-09-24). A BASH_ENV file can install a DEBUG trap and then unset
# BASH_ENV, getting past the check below. But bash suspends the caller's DEBUG
# trap inside a sourced file: `trap -p DEBUG` there prints nothing, and a
# `trap - DEBUG` there is undone when the file returns (measured, bash 5.2).
# So lib.sh can neither see nor clear it. What keeps such a trap out of lib's
# own functions is that functions do not run it unless functrace (set -T) is
# on, and functrace and errtrace are refused below. A trap on the script's own
# top-level commands sees nothing secret: no secret passes through this shell.

# ---- Shell hygiene, before this file defines anything. ----
# The C locale first: under a UTF-8 locale a bracket range such as [0-9] can
# match more than ASCII digits.
LC_ALL=C
export LC_ALL
# A disabled builtin (enable -n exit, say) would make every refusal below a
# no-op, so it is checked next, and exit is re-enabled before refusing. If
# enable itself is disabled, the probe fails, which is refused too.
if ! harness_disabled_builtins=$(enable -n 2>&1) || [ -n "$harness_disabled_builtins" ]; then
	echo "harness: refusing: shell builtins are disabled: $harness_disabled_builtins" >&2
	enable exit 2>/dev/null
	exit 2
fi
unset harness_disabled_builtins
case "$-" in *x* | *v* | *a* | *T* | *E*)
	echo "harness: refusing: shell options \$-=$- include xtrace, verbose, allexport, functrace or errtrace" >&2
	exit 2
	;;
esac
if [ -n "${BASH_XTRACEFD:-}" ]; then
	echo "harness: refusing: BASH_XTRACEFD is set" >&2
	exit 2
fi
if [ -n "${BASH_ENV:-}${ENV:-}" ]; then
	echo "harness: refusing: BASH_ENV or ENV is set" >&2
	exit 2
fi
if [ -n "$(declare -F)" ]; then
	echo "harness: refusing: shell functions already defined (inherited, or defined before lib.sh was sourced)" >&2
	exit 2
fi
if [ "${BASH_SOURCE[1]:-}" != "$0" ]; then
	echo "harness: refusing: lib.sh must be sourced by the script being run, and that script must be executed, not sourced" >&2
	exit 2
fi
unalias -a
set -euo pipefail
# Fails, and so exits under set -e, on a bash older than 4.4.
shopt -s inherit_errexit
IFS=$' \t\n'

# The external tools lib runs, each resolved once, now, to an absolute path.
for harness_tool in jq grep flock sha256sum stat mktemp mkdir sleep date; do
	harness_tool_path=$(type -P "$harness_tool") || {
		echo "harness: refusing: $harness_tool is not on PATH" >&2
		exit 2
	}
	# A relative PATH entry gives a relative path, found again from wherever
	# the script later stands.
	[[ $harness_tool_path == /* ]] || {
		echo "harness: refusing: $harness_tool resolves to $harness_tool_path, which is not an absolute path" >&2
		exit 2
	}
	declare -gr "HARNESS_TOOL_${harness_tool^^}=$harness_tool_path"
done
unset harness_tool harness_tool_path

# ---- Fixed values. ----
readonly HARNESS_TARGET=qa-pve-02-harness
readonly HARNESS_NODE=qa-pve-02
readonly HARNESS_POOL=pveforge-harness
readonly HARNESS_TAG=pveforge-harness
# 690-699, matched as a string: no arithmetic, so no leading zero, sign or
# oversized number can slip through.
readonly HARNESS_VMID_RE='^69[0-9]$'
readonly HARNESS_SNAPNAME_RE='[A-Za-z][A-Za-z0-9_-]*'
# The bridges a harness VM's NIC may join. U4's topology puts every outer NIC
# (pvh-n1, pvh-n2, pvh-nfs) on vmbr0 (decision D4); the nested guests' pvhbr1
# lives inside the nested nodes, never on the outer cluster. The pool token's
# SDN.Use is granted on /sdn/zones/localnetwork/vmbr0 only (D5), so PVE would
# refuse any other bridge too; lib says so first.
readonly HARNESS_BRIDGES=vmbr0

HARNESS_INITIALIZED=0
HARNESS_STORAGE=
declare -A HARNESS_DECLARED=()

_harness_die() { # status message
	echo "harness: $2" >&2
	exit "$1"
}

# _harness_set_by_lib: lib makes each piece of its state readonly when it sets
# it, so a value a script wrote by mistake is not taken for lib's own.
_harness_set_by_lib() { # variable
	[[ $(declare -p "$1" 2>/dev/null) =~ ^declare\ -[A-Za-z-]*r ]]
}

_harness_require_init() {
	[ "$HARNESS_INITIALIZED" = 1 ] && _harness_set_by_lib HARNESS_INITIALIZED || _harness_die 2 "harness_init has not run"
}

_harness_require_args() { # function-name minimum given
	[ "$3" -ge "$2" ] || _harness_die 2 "$1 needs at least $2 arguments"
}

# harness_init checks the environment, takes the harness lock and opens this
# run's record of created VMs. It must run before anything reaches PVE.
harness_init() {
	[ "$HARNESS_INITIALIZED" = 0 ] || _harness_die 2 "harness_init ran twice"
	local bin=${PVEFORGE_BIN:-}
	case "$bin" in
	/*) ;;
	*) _harness_die 2 "PVEFORGE_BIN must be the absolute path of the pveforge binary, got '${bin}'" ;;
	esac
	[ -f "$bin" ] || _harness_die 2 "PVEFORGE_BIN $bin is not a file"
	[ -x "$bin" ] || _harness_die 2 "PVEFORGE_BIN $bin is not executable"
	[ -n "${PVEFORGE_ROSTER_PASSPHRASE:-}" ] || _harness_die 2 "PVEFORGE_ROSTER_PASSPHRASE must be set: pveforge is never left to prompt"
	[ -z "${PVEFORGE_PVE_PASSWORD+set}" ] || _harness_die 2 "PVEFORGE_PVE_PASSWORD is set: no harness script needs root's password"

	local dir=$HOME/.config/pveforge
	local roster=$dir/harness-outer.toml
	[ -f "$roster" ] || _harness_die 2 "the harness roster $roster does not exist"
	local mode
	mode=$("$HARNESS_TOOL_STAT" -c %a "$roster") || _harness_die 2 "cannot read the mode of $roster"
	[ "$mode" = 600 ] || _harness_die 2 "the harness roster $roster has mode $mode, want 600"
	if [ -n "${PVEFORGE_ROSTER:-}" ] && [ "$PVEFORGE_ROSTER" -ef "$roster" ]; then
		_harness_die 2 "PVEFORGE_ROSTER names the harness roster; the harness roster is never a default roster"
	fi
	if [ pveforge.toml -ef "$roster" ]; then
		_harness_die 2 "./pveforge.toml is the harness roster; the harness roster is never a default roster"
	fi
	unset PVEFORGE_ROSTER || _harness_die 2 "cannot unset PVEFORGE_ROSTER"

	local wait=${HARNESS_LOCK_WAIT:-0}
	[[ $wait =~ ^[0-9]+$ ]] || _harness_die 2 "HARNESS_LOCK_WAIT must be whole seconds, got '$wait'"
	exec {HARNESS_LOCK_FD}>>"$dir/harness.lock" || _harness_die 2 "cannot open $dir/harness.lock"
	"$HARNESS_TOOL_FLOCK" -w "$wait" "$HARNESS_LOCK_FD" || _harness_die 2 "another harness script holds $dir/harness.lock"

	"$HARNESS_TOOL_MKDIR" -p -m 700 -- "$dir/harness-runs" || _harness_die 2 "cannot create $dir/harness-runs"
	HARNESS_CREATED_FILE=$("$HARNESS_TOOL_MKTEMP" -p "$dir/harness-runs" created.XXXXXX) || _harness_die 2 "cannot create this run's record of created VMs"

	local sum
	sum=$("$HARNESS_TOOL_SHA256SUM" "$bin") || _harness_die 2 "cannot hash $bin"
	echo "harness: pveforge $bin sha256 ${sum%% *}; created-VM record $HARNESS_CREATED_FILE" >&2
	HARNESS_ROSTER=$roster || _harness_die 2 "cannot set HARNESS_ROSTER"
	readonly PVEFORGE_BIN HARNESS_ROSTER HARNESS_LOCK_FD HARNESS_CREATED_FILE
	HARNESS_INITIALIZED=1
	readonly HARNESS_INITIALIZED
}

# harness_declare_vmids names the only VMIDs this script may touch, all within
# 690-699. It runs once; the set is then readonly.
harness_declare_vmids() {
	_harness_require_init
	[ "${#HARNESS_DECLARED[@]}" = 0 ] || _harness_die 2 "harness_declare_vmids ran twice, or the declared set was written before it"
	[ "$#" -gt 0 ] || _harness_die 2 "harness_declare_vmids needs at least one VMID"
	local id
	for id in "$@"; do
		[[ $id =~ $HARNESS_VMID_RE ]] || _harness_die 2 "VMID '$id' is not one of 690-699"
		HARNESS_DECLARED[$id]=1
	done
	readonly -A HARNESS_DECLARED
}

# harness_require_storage takes the outer storage id; there is no default. A
# disk may be placed only there. It runs once; the value is then readonly.
harness_require_storage() {
	_harness_require_init
	[ -z "$HARNESS_STORAGE" ] || _harness_die 2 "harness_require_storage ran twice"
	local s=${1:-}
	[ -n "$s" ] || _harness_die 2 "the outer storage is required (--storage or HARNESS_STORAGE); there is no default"
	[[ $s =~ ^[a-z][a-z0-9._-]*[a-z0-9]$ ]] || _harness_die 2 "'$s' is not a PVE storage id"
	HARNESS_STORAGE=$s
	readonly HARNESS_STORAGE
}

_harness_require_declared() {
	[[ ${1:-} =~ $HARNESS_VMID_RE ]] || _harness_die 2 "VMID '${1:-}' is not one of 690-699"
	_harness_set_by_lib HARNESS_DECLARED || _harness_die 2 "harness_declare_vmids has not run"
	[ "${HARNESS_DECLARED[$1]:-}" = 1 ] || _harness_die 2 "VMID $1 was not declared by this script"
}

_harness_require_subpath() {
	[ -z "$1" ] || [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9_-]*(/[A-Za-z0-9][A-Za-z0-9_-]*)*$ ]] ||
		_harness_die 2 "'$1' is not a VM subpath"
}

# _harness_allow_endpoint: the only changes a script may make, each one named
# by what needs it (the probe, the build, golden/reset). It prints the name of
# the endpoint's field set (_harness_field_allowed). Anything else, clone,
# migrate, move_disk, resize, template, the agent and so on, is refused.
#   put    config                      build (eject ISO, boot order)
#   post   snapshot                    probe, golden
#          snapshot/<name>/rollback    probe, reset
#          status/start                build, reset
#          status/stop                 probe, reset (hard stop)
#          status/shutdown             golden (graceful stop)
#   delete snapshot/<name>             probe, reset (cascade)
_harness_allow_endpoint() { # verb subpath
	case "$1 $2" in
	"put config") echo config ;;
	"post snapshot") echo snapshot ;;
	"post status/start") echo start ;;
	"post status/stop") echo stop ;;
	"post status/shutdown") echo shutdown ;;
	*)
		if [ "$1" = post ] && [[ $2 =~ ^snapshot/${HARNESS_SNAPNAME_RE}/rollback$ ]]; then
			echo rollback
		elif [ "$1" = delete ] && [[ $2 =~ ^snapshot/${HARNESS_SNAPNAME_RE}$ ]]; then
			echo delsnap
		else
			_harness_die 2 "$1 $2 is not an allowed harness change"
		fi
		;;
	esac
}

# _harness_config_field: the config fields a VM may be given, at create or by
# put config, each named by what needs it. Anything else, hookscript,
# cicustom, vmstatestorage, template, lock, args and the rest, is refused.
#   build (U4): name cores sockets cpu memory balloon ostype machine bios boot
#               agent serial0 vga scsihw, and for pvh-nfs's cloud-init
#               ipconfig<N> nameserver searchdomain ciuser sshkeys
#   build (U4): net<N>, on a bridge in HARNESS_BRIDGES only (_harness_net_ok)
#   build (U4): delete, of other allowed fields (ejecting the ISO)
#   probe and build (U3, U4), and only on a VM this run created: the disks
#               scsi<N> (system and data disks) and ide<N> (installer ISO,
#               cloud-init drive)
# Returns 0 for a plain field, 1 for a disk, 3 for a NIC, 2 for a refused one.
_harness_config_field() { # key
	case "$1" in
	name | cores | sockets | cpu | memory | balloon | ostype | machine | bios | boot | agent | serial0 | vga | scsihw | nameserver | searchdomain | ciuser | sshkeys | delete) return 0 ;;
	esac
	[[ $1 =~ ^ipconfig[0-9]+$ ]] && return 0
	[[ $1 =~ ^net[0-9]+$ ]] && return 3
	[[ $1 =~ ^(scsi|ide)[0-9]+$ ]] && return 1
	return 2
}

# _harness_field_allowed: the fields each other endpoint may carry.
#   snapshot (probe, golden): snapname vmstate description
#   rollback (probe, reset):  start
#   start, stop (build, probe, reset): timeout
#   shutdown (golden):        timeout forceStop
#   delsnap (probe, reset):   none
#   destroy (lib itself):     purge destroy-unreferenced-disks
_harness_field_allowed() { # set key
	case "$1 $2" in
	"snapshot snapname" | "snapshot vmstate" | "snapshot description" | "rollback start" | "start timeout" | "stop timeout" | "shutdown timeout" | "shutdown forceStop" | "destroy purge" | "destroy destroy-unreferenced-disks") return 0 ;;
	esac
	return 1
}

# _harness_disk_ok: a disk field's value may name only the storage the script
# required. The two narrow exceptions are what the build needs: an installer
# ISO on local as a cdrom (local:iso/<file>.iso with media=cdrom), and a cloud
# image imported from local (import-from=local:import/<file>.qcow2 or .raw)
# into a disk on the required storage. The value is one line (the caller has
# refused control characters); its options are split by parameter expansion.
_harness_disk_ok() { # value
	local v=$1 first rest opt
	first=${v%%,*}
	rest=${v#"$first"}
	rest=${rest#,}
	first=${first#file=}
	case "$first" in
	none) ;;
	local:iso/*)
		[[ $first =~ ^local:iso/[A-Za-z0-9_-][A-Za-z0-9._-]*\.iso$ ]] && [[ ,$v, == *,media=cdrom,* ]] || return 1
		;;
	*:*)
		# A new allocation only (a size in GiB, 0 with import-from), or the
		# cloud-init drive: never an existing volume, such as another VM's disk.
		_harness_set_by_lib HARNESS_STORAGE && [ "${first%%:*}" = "$HARNESS_STORAGE" ] || return 1
		[[ ${first#*:} =~ ^([0-9]+|cloudinit)$ ]] || return 1
		;;
	*) return 1 ;;
	esac
	while [ -n "$rest" ]; do
		opt=${rest%%,*}
		rest=${rest#"$opt"}
		rest=${rest#,}
		case "$opt" in
		import-from=*)
			[[ ${opt#import-from=} =~ ^local:import/[A-Za-z0-9_-][A-Za-z0-9._-]*\.(qcow2|raw)$ ]] || return 1
			_harness_set_by_lib HARNESS_STORAGE && [ "${first%%:*}" = "$HARNESS_STORAGE" ] || return 1
			;;
		file=* | volume=* | *=*:*) return 1 ;;
		?*=*) ;;
		*) return 1 ;;
		esac
	done
}

# _harness_net_ok: a NIC names exactly one bridge, one of HARNESS_BRIDGES.
_harness_net_ok() { # value
	local rest=$1 opt bridges=0
	while [ -n "$rest" ]; do
		opt=${rest%%,*}
		rest=${rest#"$opt"}
		rest=${rest#,}
		case "$opt" in
		bridge=*)
			bridges=$((bridges + 1))
			[[ " $HARNESS_BRIDGES " == *" ${opt#bridge=} "* ]] || return 1
			;;
		esac
	done
	[ "$bridges" = 1 ]
}

# _harness_screen_fields refuses anything not on the endpoint's allow-list: a
# field holding a control character (a newline would start a second line of
# options), a field the set does not name, and a disk that is not on a VM
# this run created or not on the required storage.
_harness_screen_fields() { # set vmid field=value ...
	local set=$1 vmid=$2 kv key value item rc items
	shift 2
	for kv in "$@"; do
		[[ $kv != *[[:cntrl:]]* ]] || _harness_die 2 "a field holds a control character"
		[[ $kv =~ ^([a-z][A-Za-z0-9_-]*)=(.*)$ ]] || _harness_die 2 "'$kv' is not a field=value pair"
		key=${BASH_REMATCH[1]} value=${BASH_REMATCH[2]}
		if [ "$set" != config ] && [ "$set" != create ]; then
			_harness_field_allowed "$set" "$key" || _harness_die 2 "field $key is not allowed here"
			continue
		fi
		rc=0
		_harness_config_field "$key" || rc=$?
		case "$rc" in
		0) ;;
		1)
			[ "$set" = create ] || _harness_created "$vmid" || _harness_die 2 "disk $key may be set only on a VM this run created"
			_harness_disk_ok "$value" || _harness_die 2 "disk $key=$value is not a new allocation on the required storage '${HARNESS_STORAGE}', the installer ISO, or an import from local:import"
			;;
		3) _harness_net_ok "$value" || _harness_die 2 "NIC $key=$value must name exactly one bridge, one of: $HARNESS_BRIDGES" ;;
		*) _harness_die 2 "field $key is not allowed here" ;;
		esac
		if [ "$key" = delete ]; then
			# Split by read, never by an unquoted expansion, which would also
			# expand a glob against the current directory.
			IFS=' ,;' read -r -a items <<<"$value" || _harness_die 2 "cannot split delete=$value"
			for item in "${items[@]}"; do
				rc=0
				_harness_config_field "$item" || rc=$?
				case "$rc" in
				0 | 3) [ "$item" != delete ] || _harness_die 2 "delete=$value is not allowed" ;;
				1) _harness_created "$vmid" || _harness_die 2 "disk $item may be deleted only on a VM this run created" ;;
				*) _harness_die 2 "delete of field $item is not allowed" ;;
				esac
			done
		fi
	done
}

# _harness_api runs one pveforge api call and returns pveforge's status.
_harness_api() { # verb path [field=value ...]
	local verb=$1 path=$2
	shift 2
	local args=() kv
	for kv in "$@"; do
		args+=(--data "$kv")
	done
	"$PVEFORGE_BIN" api "$verb" "$path" "$HARNESS_TARGET" --roster "$HARNESS_ROSTER" -o json "${args[@]}"
}

# harness_get reads any path; it prints PVE's data as JSON.
harness_get() { # path [field=value ...]
	_harness_require_init
	_harness_require_args harness_get 1 "$#"
	[[ $1 =~ ^/[^[:space:][:cntrl:]]*$ ]] || _harness_die 2 "'$1' is not an API path"
	local kv
	for kv in "${@:2}"; do
		[[ $kv != *[[:cntrl:]]* ]] || _harness_die 2 "a read parameter holds a control character"
	done
	_harness_api get "$@" || _harness_die $? "read ${1} failed"
}

_harness_mutate() { # verb path [field=value ...]
	echo "harness: $*" >&2
	_harness_api "$@" || _harness_die $? "$1 $2 failed"
}

_harness_vm_path() { # vmid subpath
	local p=/nodes/$HARNESS_NODE/qemu/$1
	[ -z "$2" ] || p=$p/$2
	printf '%s' "$p"
}

# _harness_created reports whether this run created vmid.
_harness_created() { # vmid
	local rc=0
	"$HARNESS_TOOL_GREP" -qxF -- "$1" "$HARNESS_CREATED_FILE" || rc=$?
	[ "$rc" -le 1 ] || _harness_die 2 "cannot read $HARNESS_CREATED_FILE"
	return "$rc"
}

# _harness_tags_have: PVE's own list split, PVE::Tools::split_list
# (pve-common; since commit 38395cd, 2026-06-28, its body lives in
# PVE::ParseUtils and PVE::Tools delegates): on NUL when the value holds one,
# else on commas, semicolons and whitespace, here ASCII whitespace only
# (space, \t \n \v \f \r, given by code point: jq's regex reads \v in a
# class as a plain v, and its \s matches NBSP). The tag must be one of the
# parts exactly, case included.
_harness_tags_have() { # config-json
	"$HARNESS_TOOL_JQ" -e --arg t "$HARNESS_TAG" '
		(.tags // "") | type == "string" and (
			(if (explode | any(. == 0)) then split("\u0000") else gsub("[,;]"; " ") | [splits("[" + ([32, 9, 10, 11, 12, 13] | implode) + "]+")] end)
			| any(.[]; . == $t))' <<<"$1" >/dev/null
}

# _harness_guard_existing checks an existing VM before it is changed: declared,
# a qemu member of the pool on this node, and tagged. Mode "tag" skips the tag
# check; only harness_vm_create uses it, to tag the VM it has just created.
# Destroy is allowed only for a VM this run created.
_harness_guard_existing() { # vmid mode(change|tag|destroy)
	local vmid=$1 mode=$2 out node
	_harness_require_declared "$vmid"
	out=$(harness_get /pools "poolid=$HARNESS_POOL") || _harness_die $? "reading pool $HARNESS_POOL failed"
	"$HARNESS_TOOL_JQ" -e --arg p "$HARNESS_POOL" 'type == "array" and length == 1 and .[0].poolid == $p and (.[0].members | type == "array")' <<<"$out" >/dev/null ||
		_harness_die 1 "pool $HARNESS_POOL: the answer has an unexpected shape"
	node=$("$HARNESS_TOOL_JQ" -r --argjson v "$vmid" '[.[0].members[]? | select(.type == "qemu" and .vmid == $v)] | if length == 1 then .[0].node else "" end' <<<"$out") ||
		_harness_die 1 "pool $HARNESS_POOL: the answer has an unexpected shape"
	[ -n "$node" ] || _harness_die 2 "VM $vmid is not a qemu member of pool $HARNESS_POOL"
	[ "$node" = "$HARNESS_NODE" ] || _harness_die 2 "VM $vmid is on node $node, not $HARNESS_NODE"
	if [ "$mode" = destroy ] && ! _harness_created "$vmid"; then
		_harness_die 2 "VM $vmid was not created by this run; destroying it needs a fresh operator ask"
	fi
	if [ "$mode" = tag ]; then
		return 0
	fi
	out=$(harness_get "$(_harness_vm_path "$vmid" config)") || _harness_die $? "reading VM $vmid's config failed"
	_harness_tags_have "$out" || _harness_die 2 "VM $vmid does not carry tag $HARNESS_TAG"
}

# harness_vm_get reads a declared VM's subpath.
harness_vm_get() { # vmid subpath [field=value ...]
	_harness_require_init
	_harness_require_args harness_vm_get 2 "$#"
	_harness_require_declared "${1:-}"
	_harness_require_subpath "${2:-}"
	local vmid=$1 sub=$2
	shift 2
	harness_get "$(_harness_vm_path "$vmid" "$sub")" "$@"
}

_harness_vm_change() { # verb vmid subpath [field=value ...]
	_harness_require_init
	_harness_require_args "harness_vm_$1" 2 "$(($# - 1))"
	local verb=$1 vmid=${2:-} sub=${3:-} set
	set=$(_harness_allow_endpoint "$verb" "$sub") || _harness_die 2 "$verb $sub is not an allowed harness change"
	shift 3
	_harness_require_declared "$vmid"
	_harness_screen_fields "$set" "$vmid" "$@"
	_harness_guard_existing "$vmid" change
	_harness_mutate "$verb" "$(_harness_vm_path "$vmid" "$sub")" "$@"
}

harness_vm_put() { # vmid subpath [field=value ...]
	_harness_vm_change put "$@"
}

harness_vm_post() { # vmid subpath [field=value ...]
	_harness_vm_change post "$@"
}

# harness_vm_delete deletes something under a VM, a snapshot. Destroying the
# VM itself is harness_vm_destroy's alone.
harness_vm_delete() { # vmid subpath [field=value ...]
	_harness_vm_change delete "$@"
}

# harness_vm_destroy destroys a VM this run created, always with purge=1 and
# destroy-unreferenced-disks=1 (it takes no fields: lib sends both), so PVE's
# own worker frees every disk the VM owns and reports any it could not in its
# task's exit status (harness_destroy_task_ok). It prints PVE's answer, the
# task's UPID as JSON, which the caller hands to harness_vm_gone.
harness_vm_destroy() { # vmid
	_harness_require_init
	[ "$#" = 1 ] || _harness_die 2 "harness_vm_destroy takes only a VMID: lib itself sends purge=1 destroy-unreferenced-disks=1"
	local vmid=$1
	_harness_require_declared "$vmid"
	_harness_screen_fields destroy "$vmid" purge=1 destroy-unreferenced-disks=1
	_harness_guard_existing "$vmid" destroy
	_harness_mutate delete "$(_harness_vm_path "$vmid" "")" purge=1 destroy-unreferenced-disks=1
}

# ---- Proof that a VMID is free, or a VM gone. ----
# A pool-only token is refused (403) on a VMID outside the pool, and a
# destroyed VM leaves the pool, so PVE never tells this token "does not
# exist": no error text can say "gone". Nor can it see a destroyed VM's
# volumes (harness_storage_leftover). The proof is positive instead, three
# answers the token can read, each decided on its JSON, never on text:
#   - the destroy's own task stopped with exitstatus exactly "OK"
#     (harness_destroy_task_ok): PVE frees the VM's disks inside that task
#     and turns any it could not free into "WARNINGS: <n>";
#   - /cluster/nextid asked for the VMID answers 200 with exactly that VMID,
#     which it does only when no VM anywhere in the cluster holds it (400 for
#     one that does);
#   - the pool no longer lists it.
# Any other answer, or a failed read, is "not proven". None of these
# functions exits: each returns 1 and says why in HARNESS_NOT_FREE; a read's
# own error goes to the caller's stderr, and each answer read is appended to
# the log given (evidence).
HARNESS_NOT_FREE=""

# _harness_log appends a line to log, best-effort (no log: nothing).
_harness_log() { # log line
	[ -n "$1" ] || return 0
	{ printf '%s\n' "$2" >>"$1"; } 2>/dev/null || :
}

# harness_vmid_free: no VM anywhere in the cluster holds vmid.
harness_vmid_free() { # vmid [log]
	_harness_require_init
	[ "$#" -ge 1 ] && [ "$#" -le 2 ] || _harness_die 2 "harness_vmid_free: vmid [log]"
	_harness_require_declared "$1"
	local out
	HARNESS_NOT_FREE=""
	if ! out=$( (harness_get /cluster/nextid "vmid=$1")); then
		_harness_log "${2-}" "nextid vmid=$1: no 200 answer"
		HARNESS_NOT_FREE="/cluster/nextid did not answer 200 for VMID $1: it is in use, or the read failed"
		return 1
	fi
	_harness_log "${2-}" "nextid vmid=$1: $out"
	# One JSON value, exactly the VMID (PVE's string, or a number).
	if ! "$HARNESS_TOOL_JQ" -e -s --arg v "$1" 'length == 1 and (.[0] | (type == "string" and . == $v) or (type == "number" and tostring == $v))' <<<"$out" >/dev/null 2>&1; then
		HARNESS_NOT_FREE="/cluster/nextid answered 200 for VMID $1, but not with $1"
		return 1
	fi
}

# harness_destroy_task_ok: the destroy of vmid, whose answer (the UPID it
# printed, as JSON) is given, ran as a task that PVE reports stopped with
# exitstatus exactly "OK". PVE's destroy_vm (QemuServer.pm:1840-1914, 9.2.11)
# frees every disk inside eval { vdisk_free } with a log_warn on failure, and
# with destroy-unreferenced-disks=1 its worker also lists and frees every
# images volume the VMID owns: a disk left makes the task "WARNINGS: <n>".
# pveforge's api delete exits 0 on WARNINGS too (internal/pve/task.go), so
# its status proves nothing. Only a status for exactly this task counts: its
# upid is the UPID printed, and its type, id and node are qmdestroy, vmid and
# this node.
harness_destroy_task_ok() { # vmid destroy-answer [log]
	local vmid=$1 ans=$2 log=${3-} upid st
	HARNESS_NOT_FREE=""
	upid=$("$HARNESS_TOOL_JQ" -r -s 'if length == 1 and (.[0] | type) == "string" then .[0] else empty end' <<<"$ans" 2>/dev/null) || upid=""
	# UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>:, the numbers
	# in hex, as PVE::Tools::upid_encode writes it.
	if ! [[ $upid =~ ^UPID:([A-Za-z0-9.-]+):[0-9A-F]{8}:[0-9A-F]{8,}:[0-9A-F]{8}:([a-z]+):([0-9]+):[^:[:space:][:cntrl:]]+:$ ]]; then
		_harness_log "$log" "destroy $vmid: printed no UPID"
		HARNESS_NOT_FREE="the destroy of VM $vmid printed no task UPID"
		return 1
	fi
	if [ "${BASH_REMATCH[1]}" != "$HARNESS_NODE" ] || [ "${BASH_REMATCH[2]}" != qmdestroy ] || [ "${BASH_REMATCH[3]}" != "$vmid" ]; then
		_harness_log "$log" "destroy $vmid: $upid is not its qmdestroy task on $HARNESS_NODE"
		HARNESS_NOT_FREE="the destroy of VM $vmid printed $upid, which is not a qmdestroy task for VM $vmid on $HARNESS_NODE"
		return 1
	fi
	if ! st=$( (harness_get "/nodes/$HARNESS_NODE/tasks/$upid/status")); then
		_harness_log "$log" "task $upid: status unreadable"
		HARNESS_NOT_FREE="the status of the destroy task $upid could not be read"
		return 1
	fi
	_harness_log "$log" "task $upid: $st"
	if ! "$HARNESS_TOOL_JQ" -e --arg u "$upid" --arg n "$HARNESS_NODE" --arg id "$vmid" \
		'type == "object" and .upid == $u and .type == "qmdestroy" and .id == $id and .node == $n and .status == "stopped" and .exitstatus == "OK"' <<<"$st" >/dev/null 2>&1; then
		HARNESS_NOT_FREE="the destroy task $upid is not a stopped qmdestroy of VM $vmid on $HARNESS_NODE with exitstatus OK (WARNINGS means a disk was not freed): see its status in the log"
		return 1
	fi
}

# harness_vm_gone: after a destroy, VM vmid is proven gone: its destroy task
# ended OK, its VMID is free in the whole cluster, and the pool no longer
# lists it.
harness_vm_gone() { # vmid destroy-answer [log]
	_harness_require_init
	[ "$#" -ge 2 ] && [ "$#" -le 3 ] || _harness_die 2 "harness_vm_gone: vmid destroy-answer [log]"
	_harness_require_declared "$1"
	harness_destroy_task_ok "$@" || return 1
	harness_vmid_free "$1" "${3-}" || return 1
	local out
	if ! out=$( (harness_get /pools "poolid=$HARNESS_POOL")); then
		_harness_log "${3-}" "pool $HARNESS_POOL: unreadable"
		HARNESS_NOT_FREE="reading pool $HARNESS_POOL failed"
		return 1
	fi
	_harness_log "${3-}" "pool $HARNESS_POOL: $out"
	# Every member's vmid a number (a string "690" must not read as another
	# VM), and the answer this pool's.
	if ! "$HARNESS_TOOL_JQ" -e --argjson v "$1" --arg p "$HARNESS_POOL" 'type == "array" and length == 1 and .[0].poolid == $p and (.[0].members | type == "array") and all(.[0].members[]; (.vmid | type) == "number" and .vmid != $v)' <<<"$out" >/dev/null 2>&1; then
		HARNESS_NOT_FREE="pool $HARNESS_POOL still lists VM $1, or its answer has an unexpected shape"
		return 1
	fi
}

# ---- The harness storage's usage: evidence, and a leftover detector. ----
# A pool token cannot see a destroyed VM's volumes. PVE lists storage content
# only where check_volume_access passes (PVE 9.2.11,
# API2/Storage/Content.pm:172-176: "next if $@"), and for an images volume
# that needs VM.Config.Disk on /vms/<owner> unless the caller holds
# Datastore.Allocate, which the pool token does not (PVE/Storage.pm:644-646).
# Once a VM has left the pool, its leftover disks are silently left out.
# Nor is the storage's usage a proof: pveforge-harness is thin ('sparse 1'),
# so an unwritten disk barely moves `used` (the second probe measured 96544
# bytes for a 1 GiB zvol). What proves a destroyed VM's disks gone is its
# destroy task (harness_destroy_task_ok). The usage and the listing stay as a
# DETECTOR only (harness_storage_leftover): a listed volume, or `used` still
# above its baseline once the wait is over, is a leftover; `used` back at the
# baseline proves nothing. That reading of `used` rests on pveforge-harness
# being dedicated to the harness (D5 G0's P-checks, and the empty pool before
# a run, support that).
#
# HARNESS_USED_SLACK: how far above its baseline `used` may be and not count
# as a leftover. ZFS's usage moves by metadata (a few KiB to a few hundred KiB
# on this dataset; its empty `used` read 165504 bytes at the first probe);
# 1 MiB is the probe's own free-space tolerance.
readonly HARNESS_USED_SLACK=1048576
HARNESS_USED_BASE=""
HARNESS_STORAGE_STATUS=""

# _harness_used prints status-json's `used`, a whole number of bytes.
_harness_used() { # status-json
	local u
	u=$("$HARNESS_TOOL_JQ" -r 'if type == "object" and (.used | type) == "number" and .used >= 0 and (.used | floor) == .used then .used else empty end' <<<"$1" 2>/dev/null) || return 1
	[[ $u =~ ^[0-9]+$ ]] || return 1
	printf '%s' "$u"
}

# harness_storage_baseline records the storage's `used` before this run
# creates anything, from status-json when the caller has just read it, else
# read now. The storage must be EMPTY: at most HARNESS_USED_SLACK, the empty
# dataset's own metadata. A higher figure is an orphan the pool token cannot
# list, or an earlier run's ZFS free still in progress, and a baseline that
# absorbed it would hide a leftover from the detector. So it returns 1,
# naming the figure in HARNESS_NOT_FREE, and the caller refuses to start.
# (The caller also requires the pool empty.)
harness_storage_baseline() { # [status-json]
	_harness_require_init
	[ -n "${HARNESS_STORAGE:-}" ] || _harness_die 2 "harness_storage_baseline before harness_require_storage"
	[ -z "$HARNESS_USED_BASE" ] || _harness_die 2 "harness_storage_baseline called twice"
	local st=${1-} u
	HARNESS_NOT_FREE=""
	if [ "$#" = 0 ] && ! st=$( (harness_get "/nodes/$HARNESS_NODE/storage/$HARNESS_STORAGE/status")); then
		HARNESS_NOT_FREE="storage $HARNESS_STORAGE's status could not be read"
		return 1
	fi
	if ! u=$(_harness_used "$st"); then
		HARNESS_NOT_FREE="storage $HARNESS_STORAGE's status has no usable 'used'"
		return 1
	fi
	if [ "$u" -gt "$HARNESS_USED_SLACK" ]; then
		HARNESS_NOT_FREE="storage $HARNESS_STORAGE is not empty: its used is $u bytes, above the empty dataset's 1 MiB (an orphan the pool token cannot list, or an earlier run's ZFS free still in progress): see what it holds as root, 'zfs list -r' under it"
		return 1
	fi
	HARNESS_USED_BASE=$u
	readonly HARNESS_USED_BASE
}

# harness_storage_used prints the storage's `used` now, or returns 1.
harness_storage_used() {
	_harness_require_init
	[ -n "${HARNESS_STORAGE:-}" ] || _harness_die 2 "harness_storage_used before harness_require_storage"
	local st
	st=$( (harness_get "/nodes/$HARNESS_NODE/storage/$HARNESS_STORAGE/status")) || return 1
	_harness_used "$st"
}

# harness_storage_leftover waits, for at most seconds by lib's clock (0: one
# read), for the storage's `used` to be back within HARNESS_USED_SLACK of its
# baseline with no volume of any vmid given listed; ZFS frees a destroyed
# VM's volumes asynchronously. It returns 0 when it DETECTS a leftover (a
# volume still listed, or `used` still above the baseline when the wait ends,
# however it ends), saying which in HARNESS_NOT_FREE; else 1. A status it
# cannot read detects nothing: this is no proof either way. Each read is a
# line in log; the last status read is left in HARNESS_STORAGE_STATUS.
harness_storage_leftover() { # seconds log vmid...
	_harness_require_init
	[ -n "$HARNESS_USED_BASE" ] || _harness_die 2 "harness_storage_leftover before harness_storage_baseline"
	[[ ${1:-} =~ ^[0-9]+$ ]] || _harness_die 2 "harness_storage_leftover: seconds must be a count, got '${1:-}'"
	local secs=$1 log=$2 start now st u v c listed n=0 ended=""
	shift 2
	for v in "$@"; do
		_harness_require_declared "$v"
	done
	HARNESS_NOT_FREE=""
	start=$("$HARNESS_TOOL_DATE" +%s) && [[ $start =~ ^[0-9]+$ ]] || start=""
	while :; do
		n=$((n + 1))
		st=$( (harness_get "/nodes/$HARNESS_NODE/storage/$HARNESS_STORAGE/status")) || st=""
		HARNESS_STORAGE_STATUS=$st
		u=$(_harness_used "$st") || u=""
		listed=""
		for v in "$@"; do
			c=$( (harness_get "/nodes/$HARNESS_NODE/storage/$HARNESS_STORAGE/content" "vmid=$v")) || c=""
			if [ -n "$c" ] && "$HARNESS_TOOL_JQ" -e 'type == "array" and length > 0' <<<"$c" >/dev/null 2>&1; then
				listed+=" $v"
			fi
		done
		_harness_log "$log" "read $n: used ${u:-unreadable} baseline $HARNESS_USED_BASE listed${listed:- none}"
		if [ -n "$u" ] && [ "$u" -le $((HARNESS_USED_BASE + HARNESS_USED_SLACK)) ] && [ -z "$listed" ]; then
			return 1
		fi
		# The wait ends at its bound, or when the clock or sleep fails.
		if [ -z "$start" ]; then
			ended="the clock could not be read"
		elif ! now=$("$HARNESS_TOOL_DATE" +%s) || ! [[ $now =~ ^[0-9]+$ ]]; then
			ended="the clock could not be read"
		elif [ $((now - start)) -ge "$secs" ]; then
			ended="after ${secs}s"
		elif ! "$HARNESS_TOOL_SLEEP" 5; then
			ended="sleep failed"
		fi
		[ -z "$ended" ] || break
	done
	if [ -n "$listed" ]; then
		HARNESS_NOT_FREE="storage $HARNESS_STORAGE still lists volumes of VM(s)$listed ($ended)"
		return 0
	fi
	if [ -n "$u" ]; then
		HARNESS_NOT_FREE="storage $HARNESS_STORAGE's used is $u, not back within 1 MiB of its baseline $HARNESS_USED_BASE ($ended)"
		return 0
	fi
	_harness_log "$log" "the status could not be read ($ended): nothing detected, nothing proven"
	return 1
}

# harness_vm_create creates a declared VM in the pool with `pveforge vm create`
# (REST as the token, under pveforge's per-VM lock), records it, then tags it.
# params is a JSON object of single-line string values: a line break would
# let one value read as two fields to the screen below while PVE got one. The
# screen then refuses any other control character, and holds each key to the
# field-name pattern and the same config allow-list as put config. lib sets
# vmid, pool and tags. Tags go on
# after the create: a pool-only token cannot set them in the create call
# itself (the D5 review).
harness_vm_create() { # vmid params-json
	_harness_require_init
	_harness_require_args harness_vm_create 2 "$#"
	_harness_require_declared "${1:-}"
	local vmid=$1 params=${2:-} body fields
	"$HARNESS_TOOL_JQ" -e 'type == "object" and all(.[]; type == "string" and (explode | all(. >= 32)))' <<<"$params" >/dev/null ||
		_harness_die 2 "VM $vmid: create params must be a JSON object of single-line strings"
	fields=$("$HARNESS_TOOL_JQ" -r 'to_entries[] | "\(.key)=\(.value)"' <<<"$params") || _harness_die 2 "VM $vmid: cannot read the create params"
	local kvs=()
	[ -z "$fields" ] || mapfile -t kvs <<<"$fields"
	_harness_screen_fields create "$vmid" "${kvs[@]}"
	body=$("$HARNESS_TOOL_JQ" -c --arg p "$HARNESS_POOL" '. + {pool: $p}' <<<"$params") || _harness_die 2 "VM $vmid: cannot build the create body"
	echo "harness: vm create $vmid $body" >&2
	"$PVEFORGE_BIN" vm create "$HARNESS_TARGET" "$vmid" --roster "$HARNESS_ROSTER" --json "$body" ||
		_harness_die $? "VM $vmid: vm create failed"
	printf '%s\n' "$vmid" >>"$HARNESS_CREATED_FILE" || _harness_die 2 "cannot record VM $vmid as created"
	_harness_guard_existing "$vmid" tag
	_harness_mutate put "$(_harness_vm_path "$vmid" config)" "tags=$HARNESS_TAG"
}

# A script's own function cannot replace a lib function by mistake.
while read -r _ _ harness_fn; do
	readonly -f "$harness_fn"
done < <(declare -F)
unset harness_fn
