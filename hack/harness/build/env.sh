# shellcheck shell=bash
# hack/harness/build/env.sh: the site values the build reads (the Chair's O1
# ruling), shared by prepare-iso.sh and build.sh. Sourced, never run.
#
# The values live outside the repo, in the operator-local
# ~/.config/pveforge/harness-build.env (mode 0600); the repo carries only
# harness-build.env.example, with documentation values. The file is READ,
# never sourced: each line is blank, a # comment, or KEY=value with no quotes
# and no expansion. Every key below is required, an unknown or repeated key
# is refused, and each value must match its key's pattern, so a value can be
# placed in TOML, JSON or a PVE parameter without escaping.
#
# hb_read_env fills the associative array HB; hb_resolve sets HB_TOOL_<NAME>
# to a tool's absolute path.

readonly HB_ENV_FILE=$HOME/.config/pveforge/harness-build.env

# key -> the pattern its value must match.
declare -A HB_PATTERN=(
	[DOMAIN]='^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
	[N1_IP]=ip [N2_IP]=ip [NFS_IP]=ip [GATEWAY]=ip [DNS]=ip
	[PREFIX]='^([1-9]|[12][0-9]|3[0-2])$'
	[N1_MAC]=mac [N2_MAC]=mac [NFS_MAC]=mac
	[KEYBOARD]='^[a-z]{2}(-[a-z]+)?$'
	[COUNTRY]='^[a-z]{2}$'
	[TIMEZONE]='^[A-Za-z]+(/[A-Za-z0-9_+-]+)*$'
	[MAILTO]='^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+$'
	[SOURCE_ISO]='^(/[A-Za-z0-9._+-]+)+\.iso$'
	[NFS_IMAGE]='^[A-Za-z0-9_-][A-Za-z0-9._-]*\.(qcow2|raw)$'
	# pvh-nfs's cloud-init user: never root, whose SSH login Debian's cloud
	# image refuses (disable_root).
	[NFS_USER]=user
	[CONTAINER_IMAGE]='^[a-z0-9][a-z0-9./-]*(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?$'
	[PVE_KEYRING_SHA512]='^[0-9a-f]{128}$'
	[NODE_CORES]=count [NODE_MEMORY_MIB]=count [NODE_DISK_GIB]=count
	[NFS_CORES]=count [NFS_MEMORY_MIB]=count [NFS_DATA_GIB]=count
)
readonly -A HB_PATTERN
readonly HB_IP_RE='^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
# A unicast, locally administered MAC (the second hex digit is 2, 6, a or e),
# lowercase: it never collides with a vendor's.
readonly HB_MAC_RE='^[0-9a-f][26ae](:[0-9a-f]{2}){5}$'
readonly HB_COUNT_RE='^[1-9][0-9]{0,5}$'
readonly HB_USER_RE='^[a-z_][a-z0-9_-]{0,31}$'

declare -A HB=()

hb_die() { # status message
	printf 'harness-build: %s\n' "$2" >&2
	exit "$1"
}

# hb_resolve resolves each tool once, to an absolute path, as lib does its own.
hb_resolve() { # tool...
	local t p
	for t in "$@"; do
		p=$(type -P "$t") || hb_die 2 "$t is not on PATH"
		[[ $p == /* ]] || hb_die 2 "$t resolves to $p, which is not an absolute path"
		t=${t^^}
		declare -gr "HB_TOOL_${t//-/_}=$p"
	done
}

hb_read_env() {
	local f=$HB_ENV_FILE line key value pat mode n=0
	[ -f "$f" ] && [ ! -L "$f" ] || hb_die 2 "the site file $f does not exist (copy hack/harness/build/harness-build.env.example there, mode 0600, and fill it in)"
	mode=$("$HB_TOOL_STAT" -c %a -- "$f") || hb_die 2 "cannot read the mode of $f"
	[ "$mode" = 600 ] || hb_die 2 "the site file $f has mode $mode, want 600"
	while IFS= read -r line || [ -n "$line" ]; do
		n=$((n + 1))
		case "$line" in '' | '#'*) continue ;; esac
		[[ $line =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] || hb_die 2 "$f:$n: not KEY=value"
		key=${BASH_REMATCH[1]} value=${BASH_REMATCH[2]}
		[ -n "${HB_PATTERN[$key]+set}" ] || hb_die 2 "$f:$n: unknown key $key"
		[ -z "${HB[$key]+set}" ] || hb_die 2 "$f:$n: $key is set twice"
		pat=${HB_PATTERN[$key]}
		case "$pat" in
		ip) pat=$HB_IP_RE ;;
		mac) pat=$HB_MAC_RE ;;
		count) pat=$HB_COUNT_RE ;;
		user) pat=$HB_USER_RE ;;
		esac
		[[ $value =~ $pat ]] || hb_die 2 "$f:$n: $key='$value' is not a valid value"
		[ "${HB_PATTERN[$key]}" != user ] || [ "$value" != root ] || hb_die 2 "$f:$n: $key='$value' is not a valid value: never root"
		HB[$key]=$value
	done <"$f"
	for key in "${!HB_PATTERN[@]}"; do
		[ -n "${HB[$key]+set}" ] || hb_die 2 "$f: $key is missing"
	done
	hb_distinct "$f" N1_IP N2_IP NFS_IP GATEWAY DNS
	hb_distinct "$f" N1_MAC N2_MAC NFS_MAC
	readonly -A HB
}

# hb_distinct refuses two of the named keys holding one value: each VM needs
# its own address and MAC, and none may be the gateway's or the resolver's
# (build.sh would poll, eject and pin whatever answered there).
hb_distinct() { # file key...
	local f=$1 a b i j keys
	shift
	keys=("$@")
	for ((i = 0; i < ${#keys[@]}; i++)); do
		for ((j = i + 1; j < ${#keys[@]}; j++)); do
			a=${keys[$i]} b=${keys[$j]}
			[ "${HB[$a]}" != "${HB[$b]}" ] || hb_die 2 "$f: $a and $b are both ${HB[$a]}: each must be distinct"
		done
	done
}
