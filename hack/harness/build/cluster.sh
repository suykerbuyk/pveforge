#!/usr/bin/env bash
# hack/harness/build/cluster.sh: T1 of the harness build. Forms the nested
# cluster "pvh" on the VMs build.sh made, over SSH, and never touches the
# outer cluster. Run it through the secrets helper, which supplies the nested
# root password n2's join needs (E1):
#
#   hack/harness/unlock.sh run -- hack/harness/build/cluster.sh
#
# It talks to exactly the three configured addresses: root@N1_IP and
# root@N2_IP (the answer files' root-ssh-keys), and NFS_USER@NFS_IP with
# passwordless sudo (Debian's cloud image refuses root's SSH login; the
# Chair's ruling). Every call uses the nested key
# ~/.config/pveforge/harness-nested_ed25519, BatchMode, StrictHostKeyChecking
# and only the host keys build.sh pinned (O5); no ssh config file is read.
#
#   1. pvh-nfs: nfs-kernel-server and corosync-qnetd; the data disk (scsi1)
#      gets an ext4 filesystem only if it is blank, is mounted at /srv/pvh,
#      and exported to n1 and n2 only.
#   2. n1, n2: pve-no-subscription in place of the enterprise repositories
#      (the nodes have no subscription), then corosync-qdevice.
#   3. n1: pvecm create pvh. n2 joins through the API, unattended (E1):
#      pvesh create /cluster/config/join with n1's certificate fingerprint;
#      the password reaches n2 on ssh's stdin, never the workstation's argv.
#      Then the join is awaited, bounded.
#   4. qdevice (E2): n1's and n2's root keys are authorized for root on
#      pvh-nfs, and pvh-nfs's pinned host key is known to the nodes, before
#      pvecm qdevice setup, so its ssh-copy-id needs no answer.
#   5. n1: pvesm add nfs pvh-shared.
#   6. Verify: pvh, quorate, two nodes online plus the qdevice (3 votes),
#      pvh-shared active on both nodes, the export limited to n1 and n2.
# Each step is safe to run again: what exists already is checked, not
# remade. Nothing is removed on failure; the evidence says where it stopped.
#
# Evidence goes to a new ~/.config/pveforge/harness-evidence/cluster/<stamp>/
# (mode 0700), in the shared form (../evidence.sh): each step's raw output,
# result.txt and MANIFEST.sha256. Exit status: 0 when every step and check
# passed, 1 when one went red, 2 for a refusal before anything was sent.

# lib.sh's own first checks (these scripts do not source lib): a disabled
# builtin would make every refusal below a no-op, and a function inherited
# from the environment (BASH_FUNC_printf%%=...) would run in place of the
# builtin that handles the password. Both are refused before the password is
# read; exit is re-enabled before refusing.
if ! hb_disabled=$(enable -n 2>&1) || [ -n "$hb_disabled" ]; then
	echo "harness-build: refusing: shell builtins are disabled: $hb_disabled" >&2
	enable exit 2>/dev/null
	exit 2
fi
unset hb_disabled
if [ -n "$(declare -F)" ]; then
	echo "harness-build: refusing: shell functions already defined (inherited from the environment)" >&2
	exit 2
fi
# Tracing would print the password the moment it is read: refused before it
# is. So are the other ways the environment can run code in this shell.
case "$-" in *x* | *v*)
	echo "harness-build: refusing: xtrace or verbose is on, and would print the password" >&2
	exit 2
	;;
esac
if [ -n "${BASH_XTRACEFD:-}${BASH_ENV:-}${ENV:-}" ]; then
	echo "harness-build: refusing: BASH_XTRACEFD, BASH_ENV or ENV is set" >&2
	exit 2
fi
LC_ALL=C
export LC_ALL
unalias -a
set -euo pipefail
shopt -s inherit_errexit
IFS=$' \t\n'

# The password, taken before any other program runs and removed from the
# environment every program after this one inherits.
pw=${PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD-}
unset PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD

source "${BASH_SOURCE[0]%/*}/env.sh"
source "${BASH_SOURCE[0]%/*}/../evidence.sh"
[ "$#" = 0 ] || hb_die 2 "usage: cluster.sh (no arguments; site values come from $HB_ENV_FILE)"
[ -n "$pw" ] || hb_die 2 "PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD is not set: run this through 'hack/harness/unlock.sh run --'"
[[ $pw != *[[:cntrl:]]* ]] || hb_die 2 "the nested root password holds a control character"

hb_resolve stat mkdir chmod date sleep flock jq ssh rm grep awk sort tr
hb_read_env

readonly CFG=$HOME/.config/pveforge
readonly KEY=$CFG/harness-nested_ed25519
readonly KNOWN=$CFG/harness-nested.known_hosts
readonly N1=${HB[N1_IP]} N2=${HB[N2_IP]} NFS=${HB[NFS_IP]}
readonly JOIN_EVERY=5
readonly JOIN_FOR=300

# ---- Preflight: local only. ----
exec {lock_fd}>>"$CFG/harness.lock" || hb_die 2 "cannot open $CFG/harness.lock"
"$HB_TOOL_FLOCK" -w 0 "$lock_fd" || hb_die 2 "another harness script holds $CFG/harness.lock"
for f in "$KEY" "$KNOWN"; do
	[ -f "$f" ] && [ ! -L "$f" ] || hb_die 2 "$f does not exist or is not a regular file: run prepare-iso.sh and build.sh first"
	mode=$("$HB_TOOL_STAT" -c %a -- "$f") || hb_die 2 "cannot read the mode of $f"
	[ "$mode" = 600 ] || hb_die 2 "$f has mode $mode, want 600"
done
known=$(<"$KNOWN") || hb_die 2 "cannot read $KNOWN"
# nfs_pin is pvh-nfs's pinned host key line, which the nodes are given.
nfs_pin=
for ip in "$N1" "$N2" "$NFS"; do
	line=
	while IFS= read -r l; do
		[ "${l%% *}" != "$ip" ] || line=$l
	done <<<"$known"
	[[ $line =~ ^${ip//./\\.}\ ssh-ed25519\ [A-Za-z0-9+/]+=*$ ]] || hb_die 2 "$KNOWN pins no ed25519 host key for $ip: run build.sh first"
	[ "$ip" != "$NFS" ] || nfs_pin=$line
done

stamp=$("$HB_TOOL_DATE" -u +%Y%m%dT%H%M%SZ) || hb_die 2 "cannot read the clock"
"$HB_TOOL_MKDIR" -p -m 700 -- "$CFG/harness-evidence/cluster" || hb_die 2 "cannot create $CFG/harness-evidence/cluster"
# mkdir -m does not tighten a directory that already exists.
"$HB_TOOL_CHMOD" 700 -- "$CFG/harness-evidence/cluster" || hb_die 2 "cannot make $CFG/harness-evidence/cluster private"
harness_evidence_open "$CFG/harness-evidence/cluster/$stamp" cluster
readonly EVID=$HARNESS_EVIDENCE_DIR

# ---- SSH: the three addresses, by name, and nothing else. ----
readonly SSH_OPTS=(-F /dev/null -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes
	-o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN" -o GlobalKnownHostsFile=/dev/null
	-o ConnectTimeout=15)
dest() { # n1|n2|nfs
	case "$1" in
	n1) printf 'root@%s' "$N1" ;;
	n2) printf 'root@%s' "$N2" ;;
	nfs) printf '%s@%s' "${HB[NFS_USER]}" "$NFS" ;;
	*) hb_die 2 "no such nested host: $1" ;;
	esac
}
# remote is the command sent for one step: its name, then the script, run by
# bash with errexit, as root (sudo -n on pvh-nfs, never prompting).
remote() { # host name script
	local pre=
	[ "$1" != nfs ] || pre="sudo -n "
	printf '# key: %s\n%sbash -euo pipefail -c %s' "$2" "$pre" "${3@Q}"
}
# rx runs one step's script on a host; stdin is closed unless given.
rx() { # host name script
	local d
	d=$(dest "$1")
	"$HB_TOOL_SSH" "${SSH_OPTS[@]}" "$d" "$(remote "$@")" </dev/null
}
rx_stdin() { # host name script: stdin passed through
	local d
	d=$(dest "$1")
	"$HB_TOOL_SSH" "${SSH_OPTS[@]}" "$d" "$(remote "$@")"
}
# step runs one step, its output into the evidence; a red step ends the run.
step() { # host name script
	if rx "$@" >"$EVID/$2.out" 2>&1; then
		harness_evidence_note "PASS step $2 ($1)"
	else
		harness_evidence_note "RED step $2 ($1): see $2.out"
		HARNESS_EVIDENCE_FAIL=1
		harness_evidence_finish
	fi
}
red() { # message: a step that failed on the workstation's side
	harness_evidence_note "RED $1"
	HARNESS_EVIDENCE_FAIL=1
	harness_evidence_finish
}

step n1 reach 'true'
step n2 reach 'true'
step nfs reach 'true'

# ---- 1. pvh-nfs. ----
step nfs nfs-server "
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends nfs-kernel-server corosync-qnetd
dev=/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi1
[ -b \"\$dev\" ] || { echo \"no data disk at \$dev\" >&2; exit 1; }
rc=0
blkid -p \"\$dev\" >/dev/null 2>&1 || rc=\$?
if [ \"\$rc\" = 2 ]; then
	mkfs.ext4 -q -L pvh-export \"\$dev\"
elif [ \"\$rc\" != 0 ]; then
	echo \"blkid \$dev failed (\$rc)\" >&2
	exit 1
fi
[ \"\$(blkid -o value -s TYPE \"\$dev\")\" = ext4 ] && [ \"\$(blkid -o value -s LABEL \"\$dev\")\" = pvh-export ] ||
	{ echo \"\$dev holds something other than the pvh-export filesystem: left alone\" >&2; exit 1; }
mkdir -p /srv/pvh
grep -q '^LABEL=pvh-export ' /etc/fstab || echo 'LABEL=pvh-export /srv/pvh ext4 defaults 0 2' >>/etc/fstab
mountpoint -q /srv/pvh || mount /srv/pvh
mkdir -p /etc/exports.d
echo '/srv/pvh $N1(rw,sync,no_subtree_check,no_root_squash) $N2(rw,sync,no_subtree_check,no_root_squash)' >/etc/exports.d/pvh.exports
exportfs -ra
systemctl enable --now nfs-server corosync-qnetd
"

# ---- 2. The nodes' packages. ----
node_packages="
export DEBIAN_FRONTEND=noninteractive
for f in /etc/apt/sources.list.d/pve-enterprise.sources /etc/apt/sources.list.d/ceph.sources; do
	[ ! -f \"\$f\" ] || mv -f \"\$f\" \"\$f.disabled\"
done
printf '%s\n' 'Types: deb' 'URIs: http://download.proxmox.com/debian/pve' 'Suites: trixie' 'Components: pve-no-subscription' 'Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg' >/etc/apt/sources.list.d/pve-no-subscription.sources
apt-get update
apt-get install -y corosync-qdevice
"
step n1 node-packages "$node_packages"
step n2 node-packages "$node_packages"

# ---- 3. The cluster: n1 creates it, n2 joins through the API. ----
# in_pvh: the node is in cluster pvh already (true), in no cluster (false),
# or in another cluster (a refusal).
in_pvh="
if [ -e /etc/pve/corosync.conf ]; then
	name=\$(awk '\$1 == \"cluster_name:\" { print \$2 }' /etc/pve/corosync.conf)
	[ \"\$name\" = pvh ] || { echo \"already in cluster '\$name', not pvh: left alone\" >&2; exit 1; }
	echo 'already in cluster pvh'
	exit 0
fi
"
step n1 cluster-create "$in_pvh
pvecm create pvh --link0 $N1
"
certs=$(rx n1 cert-info 'pvenode cert info --output-format json' 2>"$EVID/cert-info.stderr") || red "step cert-info (n1): see cert-info.stderr"
printf '%s\n' "$certs" >"$EVID/cert-info.json"
fp=$("$HB_TOOL_JQ" -r '[.[] | select(.filename == "pve-ssl.pem") | .fingerprint] | if length == 1 then .[0] else "" end' <<<"$certs" 2>/dev/null) || fp=
[[ $fp =~ ^([0-9A-F]{2}:){31}[0-9A-F]{2}$ ]] || red "n1's pve-ssl.pem fingerprint is not one SHA-256 fingerprint: see cert-info.json"
harness_evidence_note "PASS step cert-info (n1): $fp"
# printf is a builtin: the password is on no workstation argv; the remote
# script reads it from its stdin. On n2 it is pvesh's argument (E1's
# accepted risk, operator ruling 2).
if printf '%s\n' "$pw" | rx_stdin n2 cluster-join "$in_pvh
IFS= read -r pw
pvesh create /cluster/config/join --hostname $N1 --fingerprint $fp --password \"\$pw\" --link0 $N2
" >"$EVID/cluster-join.out" 2>&1; then
	harness_evidence_note "PASS step cluster-join (n2)"
else
	red "step cluster-join (n2): see cluster-join.out"
fi
pw=
unset pw
# The join runs as a task on n2: wait, bounded by the clock (each look is an
# ssh round trip on top of the sleep), until n1 sees both nodes.
now() {
	local t
	t=$("$HB_TOOL_DATE" +%s) || red "cannot read the clock"
	[[ $t =~ ^[0-9]+$ ]] || red "the clock read '$t'"
	printf '%s' "$t"
}
t=$(now)
deadline=$((t + JOIN_FOR))
i=0
while :; do
	st=$(rx n1 cluster-status 'pvesh get /cluster/status --output-format json' 2>>"$EVID/join-wait.stderr") || st=
	printf '%s\n' "$st" >>"$EVID/join-wait.json"
	if [ -n "$st" ] && "$HB_TOOL_JQ" -e '[.[] | select(.type == "node" and .online == 1)] | length == 2' <<<"$st" >/dev/null 2>&1; then
		break
	fi
	t=$(now)
	[ "$t" -lt "$deadline" ] || red "after ${JOIN_FOR}s, n1 does not see two nodes online: see join-wait.json"
	i=$((i + 1))
	"$HB_TOOL_SLEEP" "$JOIN_EVERY"
done
harness_evidence_note "PASS step join-wait: two nodes online after $i polls"

# ---- 4. The qdevice (E2). ----
keys=
for h in n1 n2; do
	k=$(rx "$h" root-key 'cat /root/.ssh/id_rsa.pub' 2>"$EVID/root-key-$h.stderr") || red "step root-key ($h): see root-key-$h.stderr"
	[[ $k =~ ^ssh-rsa\ [A-Za-z0-9+/]+=*\ [A-Za-z0-9@._-]+$ ]] || red "$h's root key is not one ssh-rsa public key: $k"
	printf '%s\n' "$k" >"$EVID/root-key-$h.pub"
	keys+="$k"$'\n'
done
harness_evidence_note "PASS step root-keys (n1, n2)"
step nfs qdevice-keys "
install -d -m 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
while IFS= read -r k; do
	[ -z \"\$k\" ] || grep -qxF -- \"\$k\" /root/.ssh/authorized_keys || printf '%s\n' \"\$k\" >>/root/.ssh/authorized_keys
done <<'KEYS'
${keys}KEYS
"
node_known="
touch /root/.ssh/known_hosts
grep -qxF -- '$nfs_pin' /root/.ssh/known_hosts || printf '%s\n' '$nfs_pin' >>/root/.ssh/known_hosts
"
step n1 qdevice-known "$node_known"
step n2 qdevice-known "$node_known"
step n1 qdevice-setup "
if pvecm status | grep -q '^Flags:.*Qdevice'; then
	echo 'the qdevice is set up already'
	exit 0
fi
pvecm qdevice setup $NFS
"

# ---- 5. Shared storage. ----
step n1 storage "
if pvesm status --storage pvh-shared >/dev/null 2>&1; then
	echo 'pvh-shared exists already'
	exit 0
fi
pvesm add nfs pvh-shared --server $NFS --export /srv/pvh --content images,iso --options vers=4.2
"

# ---- 6. Verify: every check runs. ----
# A failed read leaves no answer to check, so every check of it goes red.
fetch() { # host name command: the raw answer goes to <name>.out
	rx "$1" "$2" "$3" >"$EVID/$2.out" 2>>"$EVID/checks.out" || {
		"$HB_TOOL_RM" -f -- "$EVID/$2.out"
		return 1
	}
}
ev() { # name
	printf '%s' "$EVID/$1.out"
}
harness_evidence_check "fetch cluster-status" fetch n1 verify-cluster-status 'pvesh get /cluster/status --output-format json'
harness_evidence_check "fetch pvecm-status" fetch n1 verify-pvecm-status 'pvecm status'
harness_evidence_check "fetch storage-n1" fetch n1 verify-storage-n1 'pvesh get /nodes/pvh-n1/storage/pvh-shared/status --output-format json'
harness_evidence_check "fetch storage-n2" fetch n1 verify-storage-n2 'pvesh get /nodes/pvh-n2/storage/pvh-shared/status --output-format json'
harness_evidence_check "fetch exports" fetch nfs verify-exports 'exportfs -s'
cluster_is_pvh() { "$HB_TOOL_JQ" -e '[.[] | select(.type == "cluster")] | length == 1 and .[0].name == "pvh" and .[0].quorate == 1 and .[0].nodes == 2' "$(ev verify-cluster-status)"; }
nodes_online() { "$HB_TOOL_JQ" -e '[.[] | select(.type == "node" and .online == 1) | .name] | sort == ["pvh-n1", "pvh-n2"]' "$(ev verify-cluster-status)"; }
qdevice_votes() {
	"$HB_TOOL_GREP" -qE '^Quorate:[[:space:]]+Yes$' "$(ev verify-pvecm-status)" &&
		"$HB_TOOL_GREP" -qE '^Total votes:[[:space:]]+3$' "$(ev verify-pvecm-status)" &&
		"$HB_TOOL_GREP" -qE '^Flags:.*[[:space:]]Qdevice([[:space:]]|$)' "$(ev verify-pvecm-status)"
}
storage_active() { "$HB_TOOL_JQ" -e '.active == 1' "$(ev "verify-storage-$1")"; }
# The export is /srv/pvh to n1 and n2, each once, and to nothing else.
export_limited() {
	local clients
	clients=$("$HB_TOOL_AWK" '$1 == "/srv/pvh" { sub(/\(.*/, "", $2); print $2 }' "$(ev verify-exports)" | "$HB_TOOL_SORT" | "$HB_TOOL_TR" '\n' ' ') || return 1
	[ "$clients" = "$(printf '%s\n' "$N1" "$N2" | "$HB_TOOL_SORT" | "$HB_TOOL_TR" '\n' ' ')" ]
}
harness_evidence_check "cluster pvh, quorate, 2 nodes" cluster_is_pvh
harness_evidence_check "pvh-n1 and pvh-n2 online" nodes_online
harness_evidence_check "qdevice: quorate, 3 votes, Qdevice flag" qdevice_votes
harness_evidence_check "pvh-shared active on pvh-n1" storage_active n1
harness_evidence_check "pvh-shared active on pvh-n2" storage_active n2
harness_evidence_check "/srv/pvh exported to n1 and n2 only" export_limited
harness_evidence_finish
