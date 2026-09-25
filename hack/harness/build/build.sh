#!/usr/bin/env bash
# hack/harness/build/build.sh: T2 of the harness build (pveforge-harness-build).
# Creates the three outer VMs of the nested cluster on qa-pve-02, as the pool
# token, through lib.sh only:
#
#   690 pvh-n1   nested PVE node, installed unattended from pvh-n1-auto.iso
#   691 pvh-n2   nested PVE node, installed unattended from pvh-n2-auto.iso
#   692 pvh-nfs  Debian 13 from the genericcloud image, by cloud-init, its
#                login the site file's NFS_USER (never root) with the nested key
#
#   build.sh --storage <outer storage> [--keep-on-failure] [--repin]
#
# Before anything is created it checks, read-only: none of 690-692 exists in
# the pool, the storage holds no volume of theirs, local:iso/ holds both
# prepared ISOs (prepare-iso.sh) and local:import/ the cloud image, the nested
# SSH key exists, and no host key is already pinned for the three addresses.
# Then it creates the VMs, starts them, and polls TCP 22 (and 8006 on the
# nodes) on each static address, for at most 30 minutes: the installer runs
# no sshd, so an open port means the installed system is up. It ejects each
# node's ISO and boots it from scsi0, and pins the three host keys,
# trust-on-first-use, into ~/.config/pveforge/harness-nested.known_hosts (the
# Chair's O5 ruling). A later build makes new VMs with new host keys, so it
# must be told --repin.
#
# On any failure, cleanup destroys only the VMs this run created (lib refuses
# any other), and says exactly what is left; --keep-on-failure leaves them for
# inspection instead (the Chair's O4 ruling). Removing a VM an earlier run
# built needs a fresh operator ask.
#
# Site values come from ~/.config/pveforge/harness-build.env (O1). Evidence
# goes to a new ~/.config/pveforge/harness-evidence/build/<stamp>/ (mode
# 0700): the raw answers read, result.txt (one line per step, then RESULT),
# and MANIFEST.sha256.
#
# Exit status: 2 is a refusal before anything was sent; 3 a precondition that
# does not hold (nothing created); 4 a step that failed; 129/130/143 a
# signal; any other is pveforge's own, through lib.
source "${0%/*}/../lib.sh"
source "${0%/*}/env.sh"

storage=${HARNESS_STORAGE:-}
keep=0
repin=0
while [ "$#" -gt 0 ]; do
	case "$1" in
	--storage)
		[ "$#" -ge 2 ] || _harness_die 2 "--storage needs a value"
		storage=$2
		shift 2
		;;
	--keep-on-failure)
		keep=1
		shift
		;;
	--repin)
		repin=1
		shift
		;;
	*) _harness_die 2 "usage: build.sh --storage <outer storage> [--keep-on-failure] [--repin]" ;;
	esac
done
readonly keep repin

hb_resolve stat mv chmod date sleep timeout ssh-keyscan getent
harness_init
harness_declare_vmids 690 691 692
harness_require_storage "$storage"
hb_read_env

readonly S=$HARNESS_STORAGE
readonly VMIDS=(690 691 692)
declare -Ar NAME=([690]=pvh-n1 [691]=pvh-n2 [692]=pvh-nfs)
declare -Ar IP=([690]=${HB[N1_IP]} [691]=${HB[N2_IP]} [692]=${HB[NFS_IP]})
declare -Ar MAC=([690]=${HB[N1_MAC]} [691]=${HB[N2_MAC]} [692]=${HB[NFS_MAC]})
# The ports that say each VM's installed system is up.
declare -Ar PORTS=([690]="22 8006" [691]="22 8006" [692]=22)
readonly CFG=$HOME/.config/pveforge
readonly KEY=$CFG/harness-nested_ed25519
readonly KNOWN=$CFG/harness-nested.known_hosts
readonly POLL_EVERY=10
readonly POLL_FOR=1800

# say writes a line to stderr, best-effort: stderr is for the operator.
say() { # line
	printf '%s\n' "$1" >&2 2>/dev/null || :
}

stamp=$("$HB_TOOL_DATE" -u +%Y%m%dT%H%M%SZ) || _harness_die 2 "cannot read the clock"
evid_root=$CFG/harness-evidence/build
"$HARNESS_TOOL_MKDIR" -p -m 700 -- "$evid_root" || _harness_die 2 "cannot create $evid_root"
# mkdir -m does not tighten a directory that already exists.
"$HB_TOOL_CHMOD" 700 -- "$evid_root" || _harness_die 2 "cannot make $evid_root private"
readonly EVID=$evid_root/$stamp
"$HARNESS_TOOL_MKDIR" -m 700 -- "$EVID" || _harness_die 2 "cannot create the evidence directory $EVID (never reused)"
say "build: evidence in $EVID"

evidence() { # name content
	printf '%s\n' "$2" >"$EVID/$1" || _harness_die 2 "cannot write evidence $1"
}
step() { # line: one step's result, in result.txt
	printf '%s\n' "$1" >>"$EVID/result.txt" || _harness_die 2 "cannot write result.txt"
}
# note writes evidence best-effort: on a failure path, an unwritable evidence
# directory must never change the exit status or stop the report.
note() { # name content
	printf '%s\n' "$2" >>"$EVID/$1" 2>/dev/null || :
}
refuse() { # reason: a precondition; nothing has been created
	note result.txt "REFUSED $1"
	say "build: refusing: $1"
	exit 3
}
fail() { # reason
	note result.txt "FAILED $1"
	say "build: $1"
	exit 4
}
jqe() { # json jq-args... : jq -e over json, output discarded
	local j=$1
	shift
	"$HARNESS_TOOL_JQ" -e "$@" <<<"$j" >/dev/null
}
# tcp_open: one connection attempt, bounded; bash opens it, nothing else is
# needed on the workstation.
tcp_open() { # ip port
	"$HB_TOOL_TIMEOUT" 5 "$BASH" -c 'exec 3<>"/dev/tcp/$1/$2"' tcp "$1" "$2" 2>/dev/null
}
# now is the clock, in seconds.
now() {
	local t
	t=$("$HB_TOOL_DATE" +%s) || fail "cannot read the clock"
	[[ $t =~ ^[0-9]+$ ]] || fail "the clock read '$t'"
	printf '%s' "$t"
}
# outer_host prints the host the harness roster names for $HARNESS_TARGET.
outer_host() {
	local l id="" host="" in=0 found=""
	while IFS= read -r l || [ -n "$l" ]; do
		if [[ $l =~ ^[[:space:]]*\[ ]]; then
			[ "$in" = 0 ] || [ "$id" != "$HARNESS_TARGET" ] || found=$host
			in=0
			[[ $l =~ ^[[:space:]]*\[\[targets\]\][[:space:]]*$ ]] && in=1 id="" host=""
			continue
		fi
		[ "$in" = 1 ] || continue
		if [[ $l =~ ^[[:space:]]*id[[:space:]]*=[[:space:]]*\"([^\"]*)\" ]]; then
			id=${BASH_REMATCH[1]}
		elif [[ $l =~ ^[[:space:]]*host[[:space:]]*=[[:space:]]*\"([^\"]*)\" ]]; then
			host=${BASH_REMATCH[1]}
		fi
	done <"$HARNESS_ROSTER"
	[ "$in" = 0 ] || [ "$id" != "$HARNESS_TARGET" ] || found=$host
	printf '%s' "$found"
}
# ip_pinned says whether the known_hosts text pins a key for ip.
ip_pinned() { # text ip
	local l
	while IFS= read -r l; do
		[ "${l%% *}" != "$2" ] || return 0
	done <<<"$1"
	return 1
}

# ---- Preflight: read-only; nothing is created unless all of it holds. ----
pub=
[ -f "$KEY.pub" ] && [ ! -L "$KEY.pub" ] || refuse "the nested SSH key $KEY.pub does not exist: run prepare-iso.sh first"
read -r pub <"$KEY.pub" || refuse "cannot read $KEY.pub"
[[ $pub =~ ^ssh-ed25519\ [A-Za-z0-9+/]+=*(\ [A-Za-z0-9@._-]+)?$ ]] || refuse "$KEY.pub is not one ssh-ed25519 public key"

known=
if [ -e "$KNOWN" ] || [ -L "$KNOWN" ]; then
	[ -f "$KNOWN" ] && [ ! -L "$KNOWN" ] || refuse "$KNOWN is not a regular file"
	mode=$("$HB_TOOL_STAT" -c %a -- "$KNOWN") || refuse "cannot read the mode of $KNOWN"
	[ "$mode" = 600 ] || refuse "$KNOWN has mode $mode, want 600"
	known=$(<"$KNOWN") || refuse "cannot read $KNOWN"
fi
if [ "$repin" = 0 ]; then
	for v in "${VMIDS[@]}"; do
		! ip_pinned "$known" "${IP[$v]}" ||
			refuse "$KNOWN already pins a host key for ${IP[$v]} (${NAME[$v]}); a new build makes new host keys: run with --repin to replace the pins"
	done
fi

# None of the three addresses may be the outer host itself.
outer=$(outer_host) || refuse "cannot read $HARNESS_ROSTER"
[ -n "$outer" ] || refuse "$HARNESS_ROSTER names no host for target $HARNESS_TARGET"
if [[ $outer =~ $HB_IP_RE ]]; then
	outer_ips=$outer
else
	outer_ips=$("$HB_TOOL_GETENT" ahostsv4 "$outer") || refuse "cannot resolve the outer host $outer"
	outer_ips=$(while read -r a _; do printf '%s\n' "$a"; done <<<"$outer_ips")
fi
evidence outer-host "$outer: $outer_ips"
for v in "${VMIDS[@]}"; do
	while IFS= read -r a; do
		[ "$a" != "${IP[$v]}" ] || refuse "${NAME[$v]}'s address ${IP[$v]} is the outer host $outer"
	done <<<"$outer_ips"
done
# Nothing may answer yet at any of the three: a host already there would be
# polled as up, have its ISO "ejected" and its host key pinned.
for v in "${VMIDS[@]}"; do
	for port in ${PORTS[$v]}; do
		! tcp_open "${IP[$v]}" "$port" ||
			refuse "${IP[$v]}:$port already answers, before ${NAME[$v]} exists: the address is in use"
	done
done

pool=$(harness_get /pools "poolid=$HARNESS_POOL")
evidence pool-before.json "$pool"
jqe "$pool" 'type == "array" and length == 1 and (.[0].members | type == "array")' ||
	_harness_die 1 "pool $HARNESS_POOL: the answer has an unexpected shape"
for v in "${VMIDS[@]}"; do
	if jqe "$pool" --argjson v "$v" 'any(.[0].members[]; .vmid == $v)'; then
		refuse "VM $v already exists in pool $HARNESS_POOL: the build runs on a clean slate, and removing an earlier build's VM needs an operator ask"
	fi
	content=$(harness_get "/nodes/$HARNESS_NODE/storage/$S/content" "vmid=$v")
	evidence "content-$v-before.json" "$content"
	jqe "$content" 'type == "array"' || _harness_die 1 "storage $S: the content answer has an unexpected shape"
	jqe "$content" 'length == 0' || refuse "storage $S already holds volumes of VM $v (a leftover): see content-$v-before.json"
done
isos=$(harness_get "/nodes/$HARNESS_NODE/storage/local/content" content=iso)
evidence local-iso.json "$isos"
for v in 690 691; do
	jqe "$isos" --arg id "local:iso/${NAME[$v]}-auto.iso" 'type == "array" and any(.[]; .volid == $id)' ||
		refuse "local:iso/${NAME[$v]}-auto.iso is not on qa-pve-02: upload prepare-iso.sh's output first"
done
imports=$(harness_get "/nodes/$HARNESS_NODE/storage/local/content" content=import)
evidence local-import.json "$imports"
jqe "$imports" --arg id "local:import/${HB[NFS_IMAGE]}" 'type == "array" and any(.[]; .volid == $id)' ||
	refuse "local:import/${HB[NFS_IMAGE]} is not on qa-pve-02: upload the Debian 13 genericcloud image first"
step "PASS preflight"

# ---- Cleanup: on any exit that is not a complete build. ----
done_ok=0
creating=0
# cleanup always runs to its report: errexit off, a closed stderr never
# fatal, and a second Ctrl-C, a TERM or a HUP ignored until it is done.
cleanup() {
	local rc=$?
	set +e
	trap '' PIPE INT TERM HUP
	trap - EXIT
	if [ "$done_ok" = 1 ] || [ "$creating" = 0 ]; then
		exit "$rc"
	fi
	local log=$EVID/cleanup.log v err mine=() left=() members=""
	# A redirect that fails skips its command: an unwritable evidence
	# directory must cost the log, never a cleanup step.
	{ : >>"$log"; } 2>/dev/null || log=/dev/null
	for v in "${VMIDS[@]}"; do
		if "$HARNESS_TOOL_GREP" -qxF -- "$v" "$HARNESS_CREATED_FILE" 2>/dev/null; then
			mine+=("$v")
		fi
	done
	if [ "$keep" = 1 ]; then
		say "build: failed (status $rc); --keep-on-failure: leaving VM(s) ${mine[*]:-none} for inspection"
		note result.txt "KEPT ${mine[*]:-none}"
		report_leftover "kept for inspection (--keep-on-failure)" "${mine[@]}"
		exit "$rc"
	fi
	say "build: failed (status $rc); destroying this run's VM(s) ${mine[*]:-none}; see $log"
	for ((i = ${#mine[@]} - 1; i >= 0; i--)); do
		v=${mine[$i]}
		if (harness_vm_get "$v" status/current 2>>"$log") | "$HARNESS_TOOL_JQ" -e '.status == "running"' >/dev/null 2>&1; then
			(harness_vm_post "$v" status/stop) >>"$log" 2>&1 || echo "cleanup: stop $v failed" >>"$log"
		fi
		(harness_vm_destroy "$v" purge=1 destroy-unreferenced-disks=1) >>"$log" 2>&1 || echo "cleanup: destroy $v failed" >>"$log"
		err=""
		if err=$( { harness_vm_get "$v" status/current >/dev/null; } 2>&1); then
			left+=("$v")
		elif [[ $err != *"does not exist"* ]]; then
			left+=("$v")
		else
			note result.txt "DESTROYED $v"
		fi
	done
	# A VM this run did not record (its create failed after it appeared).
	members=$( (harness_get /pools "poolid=$HARNESS_POOL") 2>>"$log") || members=""
	for v in "${VMIDS[@]}"; do
		[[ " ${mine[*]} " != *" $v "* ]] || continue
		if [ -n "$members" ] && jqe "$members" --argjson v "$v" 'any(.[0].members[]?; .vmid == $v)'; then
			left+=("$v")
		fi
	done
	if [ "${#left[@]}" -gt 0 ]; then
		report_leftover "cleanup could not remove all of them, or this run did not record creating them" "${left[@]}"
	else
		say "build: cleanup: this run's VM(s) ${mine[*]:-none} destroyed"
		note result.txt "CLEANUP ${mine[*]:-none} destroyed"
	fi
	exit "$rc"
}
# report_leftover says which VMs are left and the operator's commands. It
# reads what it can; a read that fails is said to have failed.
report_leftover() { # headline vmid...
	local head=$1 v out conf st
	shift
	[ "$#" -gt 0 ] || return 0
	out="LEFTOVER: $head"
	for v in "$@"; do
		conf=$( (harness_vm_get "$v" config) 2>/dev/null) || conf=""
		st=$( (harness_vm_get "$v" status/current) 2>/dev/null) || st=""
		out+="
  VM $v (${NAME[$v]}): status $([ -n "$st" ] && "$HARNESS_TOOL_JQ" -r '.status // "unknown"' <<<"$st" 2>/dev/null || echo unreadable), lock $([ -n "$conf" ] && "$HARNESS_TOOL_JQ" -r '.lock // "none"' <<<"$conf" 2>/dev/null || echo unreadable)"
	done
	out+="
Removing them needs an operator ask (lib destroys only a VM the same run created).
As root on $HARNESS_NODE, for each VM above:
  qm stop <vmid>
  qm destroy <vmid> --purge
  pvesm list $S --vmid <vmid>     # must list nothing"
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

# ---- Create. ----
sshkeys=$("$HARNESS_TOOL_JQ" -rn --arg k "$pub" '$k | @uri') || _harness_die 2 "cannot encode the SSH key"
node_params() { # vmid
	"$HARNESS_TOOL_JQ" -cn --arg name "${NAME[$1]}" --arg cores "${HB[NODE_CORES]}" --arg mem "${HB[NODE_MEMORY_MIB]}" \
		--arg disk "$S:${HB[NODE_DISK_GIB]}" --arg iso "local:iso/${NAME[$1]}-auto.iso,media=cdrom" \
		--arg net "virtio=${MAC[$1]},bridge=vmbr0,firewall=0" '{
		name: $name, ostype: "l26", cpu: "host", cores: $cores, memory: $mem,
		bios: "seabios", scsihw: "virtio-scsi-single", scsi0: $disk, ide2: $iso,
		net0: $net, boot: "order=scsi0;ide2"}'
}
nfs_params() {
	"$HARNESS_TOOL_JQ" -cn --arg name "${NAME[692]}" --arg cores "${HB[NFS_CORES]}" --arg mem "${HB[NFS_MEMORY_MIB]}" \
		--arg os "$S:0,import-from=local:import/${HB[NFS_IMAGE]}" --arg data "$S:${HB[NFS_DATA_GIB]}" \
		--arg ci "$S:cloudinit" --arg net "virtio=${MAC[692]},bridge=vmbr0,firewall=0" \
		--arg ip "ip=${IP[692]}/${HB[PREFIX]},gw=${HB[GATEWAY]}" --arg dns "${HB[DNS]}" --arg dom "${HB[DOMAIN]}" \
		--arg keys "$sshkeys" --arg user "${HB[NFS_USER]}" '{
		name: $name, ostype: "l26", cpu: "host", cores: $cores, memory: $mem,
		bios: "seabios", scsihw: "virtio-scsi-single", scsi0: $os, scsi1: $data, ide2: $ci,
		net0: $net, boot: "order=scsi0", agent: "1",
		ipconfig0: $ip, nameserver: $dns, searchdomain: $dom, ciuser: $user, sshkeys: $keys}'
}
creating=1
for v in "${VMIDS[@]}"; do
	if [ "$v" = 692 ]; then
		params=$(nfs_params) || _harness_die 2 "cannot build VM $v's parameters"
	else
		params=$(node_params "$v") || _harness_die 2 "cannot build VM $v's parameters"
	fi
	evidence "create-$v.json" "$params"
	harness_vm_create "$v" "$params" >"$EVID/create-$v.out"
	step "PASS create $v ${NAME[$v]}"
done
for v in "${VMIDS[@]}"; do
	harness_vm_post "$v" status/start >"$EVID/start-$v.out"
	step "PASS start $v"
done

# ---- Wait for the installed systems. ----
# The deadline is the clock's, not a count of polls: each poll's connection
# attempts take up to 5 s apiece on top of the sleep.
t=$(now)
deadline=$((t + POLL_FOR))
declare -A open=()
i=0
while :; do
	waiting=0
	for v in "${VMIDS[@]}"; do
		for port in ${PORTS[$v]}; do
			[ -z "${open[$v:$port]:-}" ] || continue
			if tcp_open "${IP[$v]}" "$port"; then
				open[$v:$port]=1
				note poll.log "poll $i: ${IP[$v]}:$port open"
			else
				waiting=1
			fi
		done
	done
	[ "$waiting" = 1 ] || break
	t=$(now)
	if [ "$t" -ge "$deadline" ]; then
		missing=
		for v in "${VMIDS[@]}"; do
			for port in ${PORTS[$v]}; do
				[ -n "${open[$v:$port]:-}" ] || missing+=" ${NAME[$v]}=${IP[$v]}:$port"
			done
		done
		fail "after ${POLL_FOR}s, still closed:$missing"
	fi
	i=$((i + 1))
	"$HB_TOOL_SLEEP" "$POLL_EVERY"
done
step "PASS up after $i polls"

# ---- Eject each node's ISO; boot from its disk. ----
for v in 690 691; do
	harness_vm_put "$v" config ide2=none,media=cdrom boot=order=scsi0 >"$EVID/eject-$v.out"
	step "PASS eject $v"
done

# ---- Pin the host keys (O5). ----
pins=
for v in "${VMIDS[@]}"; do
	scan=$("$HB_TOOL_SSH_KEYSCAN" -T 10 -t ed25519 "${IP[$v]}" 2>>"$EVID/keyscan.stderr") || fail "ssh-keyscan ${IP[$v]} failed: see keyscan.stderr"
	evidence "keyscan-$v.txt" "$scan"
	line=
	n=0
	while IFS= read -r l; do
		case "$l" in '' | '#'*) continue ;; esac
		n=$((n + 1))
		line=$l
	done <<<"$scan"
	[ "$n" = 1 ] && [[ $line =~ ^${IP[$v]//./\\.}\ ssh-ed25519\ [A-Za-z0-9+/]+=*$ ]] ||
		fail "ssh-keyscan ${IP[$v]} did not give exactly one ed25519 host key: see keyscan-$v.txt"
	pins+=$line$'\n'
done
# Every line pinning another address is kept; the three are (re)written.
kept=
if [ -n "$known" ]; then
	while IFS= read -r l; do
		case "${l%% *}" in "${IP[690]}" | "${IP[691]}" | "${IP[692]}") continue ;; esac
		kept+=$l$'\n'
	done <<<"$known"
fi
want=$kept$pins
tmp=$("$HARNESS_TOOL_MKTEMP" -p "$CFG" .harness-nested.known_hosts.XXXXXX) || fail "cannot write $KNOWN"
printf '%s' "$want" >"$tmp" || fail "cannot write $KNOWN"
"$HB_TOOL_CHMOD" 600 -- "$tmp" || fail "cannot write $KNOWN"
# -T: never move INTO a directory that happens to sit at the path.
"$HB_TOOL_MV" -f -T -- "$tmp" "$KNOWN" || fail "cannot write $KNOWN"
got=
if [ -f "$KNOWN" ] && [ ! -L "$KNOWN" ]; then
	got=$(<"$KNOWN") || got=
fi
[ "$got" = "${want%$'\n'}" ] || fail "$KNOWN is not a regular file holding the pins after the write"
evidence known_hosts "$want"
step "PASS pinned ${IP[690]} ${IP[691]} ${IP[692]}$([ "$repin" = 1 ] && echo " (repinned)")"

done_ok=1
step "RESULT built ${VMIDS[*]} evidence=$EVID"
(cd -- "$EVID" && "$HARNESS_TOOL_SHA256SUM" -- * >MANIFEST.sha256) || say "build: cannot write MANIFEST.sha256"
say "build: 690 pvh-n1 ${IP[690]}, 691 pvh-n2 ${IP[691]}, 692 pvh-nfs ${IP[692]} are up; host keys pinned in $KNOWN"
printf 'built=690,691,692 storage=%s known_hosts=%s\n' "$S" "$KNOWN"
