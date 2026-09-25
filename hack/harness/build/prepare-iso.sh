#!/usr/bin/env bash
# hack/harness/build/prepare-iso.sh: T0 of the harness build, on the
# workstation only; it never reaches PVE. Run it through the secrets helper,
# which supplies the nested root password in the environment:
#
#   hack/harness/unlock.sh run -- hack/harness/build/prepare-iso.sh
#
# 1. Takes PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD from the environment and
#    unsets it before any other program runs; the password reaches openssl
#    on stdin only (`openssl passwd -6 -stdin`), never argv, and is never
#    written anywhere: the answer files carry its SHA-512 crypt hash.
# 2. Makes the nested SSH key ~/.config/pveforge/harness-nested_ed25519 if
#    it does not exist (the Chair's O5 ruling); its public half becomes
#    root's authorized key on each node.
# 3. Renders answers/pvh-node.toml.tmpl for pvh-n1 and pvh-n2 into a new
#    ~/.config/pveforge/harness-build/<stamp>/ (mode 0700, files 0600).
# 4. In a throwaway container (podman, CONTAINER_IMAGE), installs
#    proxmox-auto-install-assistant and xorriso from pve-no-subscription,
#    trusting the Proxmox keyring only if its SHA-512 is PVE_KEYRING_SHA512;
#    then validate-answer, prepare-iso --fetch-from iso, and inspect-iso for
#    each node.
# 5. Prints each prepared ISO's sha256. The operator uploads the two ISOs by
#    hand, as root, to qa-pve-02's local:iso/ under these exact names:
#    pvh-n1-auto.iso and pvh-n2-auto.iso.
#
# Site values come from ~/.config/pveforge/harness-build.env (see
# harness-build.env.example). Evidence goes to a new
# ~/.config/pveforge/harness-evidence/prepare-iso/<stamp>/ (mode 0700).
# Exit status: 2 for a refusal before any work, 4 for a failed step, or the
# container's own status.

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
# A replacement's "&" would otherwise stand for the matched text.
shopt -u patsub_replacement 2>/dev/null || :
IFS=$' \t\n'

# The password, taken before any other program runs and removed from the
# environment every program after this one inherits.
pw=${PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD-}
unset PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD

source "${BASH_SOURCE[0]%/*}/env.sh"
[ -n "$pw" ] || hb_die 2 "PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD is not set: run this through 'hack/harness/unlock.sh run --'"
[[ $pw != *[[:cntrl:]]* ]] || hb_die 2 "the nested root password holds a control character"
# The installer's own minimum; it also keeps the plaintext check below from
# matching by chance.
[ "${#pw}" -ge 8 ] || hb_die 2 "the nested root password is shorter than 8 characters"
[ "$#" = 0 ] || hb_die 2 "usage: prepare-iso.sh (no arguments; site values come from $HB_ENV_FILE)"

hb_resolve stat mkdir chmod mv mktemp date sha256sum openssl ssh-keygen podman
hb_read_env

readonly TEMPLATE=${BASH_SOURCE[0]%/*}/answers/pvh-node.toml.tmpl
readonly CFG=$HOME/.config/pveforge
readonly KEY=$CFG/harness-nested_ed25519
readonly NODES=(pvh-n1 pvh-n2)
declare -A NODE_IP=([pvh-n1]=${HB[N1_IP]} [pvh-n2]=${HB[N2_IP]})
declare -A NODE_MAC=([pvh-n1]=${HB[N1_MAC]} [pvh-n2]=${HB[N2_MAC]})

stamp=$("$HB_TOOL_DATE" -u +%Y%m%dT%H%M%SZ) || hb_die 2 "cannot read the clock"
# private_dir makes dir (and its parents) and tightens it to 0700: mkdir -m
# does not tighten a directory that already exists.
private_dir() { # dir
	"$HB_TOOL_MKDIR" -p -m 700 -- "$1" || hb_die 2 "cannot create $1"
	"$HB_TOOL_CHMOD" 700 -- "$1" || hb_die 2 "cannot make $1 private"
}
private_dir "$CFG/harness-evidence/prepare-iso"
private_dir "$CFG/harness-build"
readonly EVID=$CFG/harness-evidence/prepare-iso/$stamp
readonly OUT=$CFG/harness-build/$stamp
"$HB_TOOL_MKDIR" -m 700 -- "$EVID" || hb_die 2 "cannot create the evidence directory $EVID (never reused)"
"$HB_TOOL_MKDIR" -m 700 -- "$OUT" || hb_die 2 "cannot create the output directory $OUT (never reused)"
printf 'prepare-iso: evidence in %s, output in %s\n' "$EVID" "$OUT" >&2

evidence() { # name content
	printf '%s\n' "$2" >"$EVID/$1" || hb_die 4 "cannot write evidence $1"
}
fail() { # message
	printf '%s\n' "$1" >"$EVID/FAILED" 2>/dev/null || :
	hb_die 4 "$1"
}

# ---- The nested SSH key (O5). ----
if [ -e "$KEY" ] || [ -e "$KEY.pub" ]; then
	[ -f "$KEY" ] && [ ! -L "$KEY" ] && [ -f "$KEY.pub" ] && [ ! -L "$KEY.pub" ] || fail "$KEY and $KEY.pub must both be regular files"
	mode=$("$HB_TOOL_STAT" -c %a -- "$KEY") || fail "cannot read the mode of $KEY"
	[ "$mode" = 600 ] || fail "$KEY has mode $mode, want 600"
	evidence ssh-key "reused $KEY"
else
	"$HB_TOOL_SSH_KEYGEN" -q -t ed25519 -N '' -C pveforge-harness-nested -f "$KEY" >"$EVID/ssh-keygen.out" 2>&1 ||
		fail "ssh-keygen failed: see ssh-keygen.out"
	evidence ssh-key "made $KEY"
fi
pub=
read -r pub <"$KEY.pub" || fail "cannot read $KEY.pub"
[[ $pub =~ ^ssh-ed25519\ [A-Za-z0-9+/]+=*(\ [A-Za-z0-9@._-]+)?$ ]] || fail "$KEY.pub is not one ssh-ed25519 public key"
evidence ssh-key.pub "$pub"

# ---- The password hash (E7). ----
# printf is a builtin: the password is on no program's argv, only on
# openssl's stdin.
hash=$(printf '%s\n' "$pw" | "$HB_TOOL_OPENSSL" passwd -6 -stdin) || fail "openssl passwd failed"
[[ $hash =~ ^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$ ]] || fail "openssl passwd did not print one SHA-512 crypt hash"

# ---- Render the answers. ----
template=$(<"$TEMPLATE") || fail "cannot read $TEMPLATE"
for node in "${NODES[@]}"; do
	mac=${NODE_MAC[$node]}
	t=$template
	t=${t//@KEYBOARD@/${HB[KEYBOARD]}}
	t=${t//@COUNTRY@/${HB[COUNTRY]}}
	t=${t//@FQDN@/$node.${HB[DOMAIN]}}
	t=${t//@MAILTO@/${HB[MAILTO]}}
	t=${t//@TIMEZONE@/${HB[TIMEZONE]}}
	t=${t//@ROOT_PASSWORD_HASHED@/$hash}
	t=${t//@ROOT_SSH_KEY@/$pub}
	t=${t//@CIDR@/${NODE_IP[$node]}/${HB[PREFIX]}}
	t=${t//@DNS@/${HB[DNS]}}
	t=${t//@GATEWAY@/${HB[GATEWAY]}}
	t=${t//@MAC_HEX@/${mac//:/}}
	t=${t//@MAC@/$mac}
	! [[ $t =~ @[A-Z_]+@ ]] || fail "$node: a placeholder is left in the rendered answer file"
	[[ $t != *"$pw"* ]] || fail "$node: the rendered answer file holds the plaintext password"
	f=$OUT/$node.toml
	tmp=$("$HB_TOOL_MKTEMP" -p "$OUT" ".$node.XXXXXX") || fail "cannot write $f"
	printf '%s\n' "$t" >"$tmp" || fail "cannot write $f"
	"$HB_TOOL_CHMOD" 600 -- "$tmp" || fail "cannot write $f"
	"$HB_TOOL_MV" -f -T -- "$tmp" "$f" || fail "cannot write $f"
done
# The plaintext is not needed past this point.
pw=
unset pw

# ---- The container: validate, prepare, inspect. ----
# Values reach it as environment variables it is given by name, never
# interpolated into the script.
container_script='
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl
keyring=/usr/share/keyrings/proxmox-archive-keyring.gpg
curl -fsSL -o "$keyring" https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg
echo "$PVE_KEYRING_SHA512  $keyring" | sha512sum -c -
printf "%s\n" "Types: deb" "URIs: http://download.proxmox.com/debian/pve" "Suites: trixie" "Components: pve-no-subscription" "Signed-By: $keyring" >/etc/apt/sources.list.d/pve.sources
apt-get update
apt-get install -y --no-install-recommends proxmox-auto-install-assistant xorriso
for n in pvh-n1 pvh-n2; do
	proxmox-auto-install-assistant validate-answer "/work/$n.toml"
	proxmox-auto-install-assistant prepare-iso "/src/$SOURCE_ISO_NAME" --fetch-from iso --answer-file "/work/$n.toml" --output "/work/$n-auto.iso"
	proxmox-auto-install-assistant inspect-iso "/work/$n-auto.iso"
done
'
iso_dir=${HB[SOURCE_ISO]%/*}
iso_name=${HB[SOURCE_ISO]##*/}
[ -f "${HB[SOURCE_ISO]}" ] || fail "the installer ISO ${HB[SOURCE_ISO]} does not exist"
evidence container-script "$container_script"
rc=0
"$HB_TOOL_PODMAN" run --rm --security-opt label=disable \
	-v "$OUT:/work" -v "$iso_dir:/src:ro" \
	-e "PVE_KEYRING_SHA512=${HB[PVE_KEYRING_SHA512]}" -e "SOURCE_ISO_NAME=$iso_name" \
	"${HB[CONTAINER_IMAGE]}" bash -c "$container_script" >"$EVID/container.log" 2>&1 || rc=$?
if [ "$rc" != 0 ]; then
	printf 'container exited %s: see container.log\n' "$rc" >"$EVID/FAILED" 2>/dev/null || :
	hb_die "$rc" "the container exited $rc: see $EVID/container.log"
fi

# ---- The result. ----
sums=
for node in "${NODES[@]}"; do
	f=$OUT/$node-auto.iso
	[ -f "$f" ] && [ ! -L "$f" ] || fail "the container did not write $f"
	"$HB_TOOL_CHMOD" 600 -- "$f" || fail "cannot make $f private"
	line=$("$HB_TOOL_SHA256SUM" -- "$f") || fail "cannot hash $f"
	sums+="${line%% *}  $node-auto.iso"$'\n'
done
evidence iso.sha256 "${sums%$'\n'}"
evidence SUMMARY "prepared pvh-n1-auto.iso and pvh-n2-auto.iso in $OUT"
(cd -- "$EVID" && "$HB_TOOL_SHA256SUM" -- * >MANIFEST.sha256) || fail "cannot write MANIFEST.sha256"
printf '%s' "$sums"
printf 'prepare-iso: upload both, as root, to qa-pve-02 local:iso/ under these names (from %s), then run build.sh\n' "$OUT" >&2
