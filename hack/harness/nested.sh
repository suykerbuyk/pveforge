#!/usr/bin/env bash
# hack/harness/nested.sh: H3's nested bootstrap and bridge
# (pveforge-harness-golden-reset, P2), run on the nested cluster build.sh and
# cluster.sh made, never on the outer cluster. Through the secrets helper:
#
#   hack/harness/unlock.sh run -- hack/harness/nested.sh bootstrap
#   hack/harness/unlock.sh run -- hack/harness/nested.sh bridge
#
# bootstrap: pveforge's own nested harness roster,
# ~/.config/pveforge/harness-nested.toml (created by `pveforge roster init`
# if it does not exist), with targets pvh-n1 and pvh-n2, each bootstrapped
# keyful (RoutedClient dials SSH, so the key is kept) with the grant
# /:Administrator::1. First, a target the roster already holds must name its
# configured address. Then, for each node, in order:
#   1. A pinned SSH login with U4's nested key, trusting ONLY that node's one
#      validated ed25519 line of harness-nested.known_hosts (written alone to
#      the evidence, so no other line, a "*" pattern say, is ever trusted). A
#      host that fails it is sent nothing.
#   2. Through that authenticated session, the node's own sshd is asked for
#      the ECDSA host key it serves (ssh-keyscan -t ecdsa 127.0.0.1 on the
#      node). pveforge's SSH client negotiates ECDSA when a host serves one
#      (golang.org/x/crypto/ssh's default order: ECDSA, then RSA, ED25519
#      last), and every stock PVE node does, so U4's ed25519 pin cannot be
#      the pin pveforge compares; this ECDSA key, vouched for by the
#      ed25519-pinned session, is. Exactly one ECDSA key, or the node is
#      refused. A roster that already records another pin for the node (one
#      from before `build.sh --repin`) is refused here, before any password.
#   3. pveforge bootstrap --host-key-fingerprint <that ECDSA pin>: bootstrap's
#      own password dial refuses any other host key BEFORE the password is
#      sent. The nested root password (PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD,
#      from the U7 blob) reaches it as PVEFORGE_PVE_PASSWORD in that child's
#      environment ONLY: this shell never exports it, and no other program it
#      runs ever sees it.
#   4. Afterwards, belt and braces: bootstrap's reported host_key_fingerprint
#      and the roster's record (read with cmd/pveforge-harness-pins) must be
#      that pin at the configured address. On a mismatch, or on any failed
#      bootstrap once an SSH login is recorded, the roster is moved aside
#      (harness-nested.toml.refused-<stamp>), so nothing can use it.
#   5. The token is held and proven: token_outcome minted, reused or
#      replaced, and validation verified (D5 G4's bar for the outer token).
# The roster passphrase (PVEFORGE_ROSTER_PASSPHRASE, the same one the outer
# harness roster uses: R8) is taken as unlock.sh gave it and handed only to
# pveforge and the accept tool, each in its own environment.
#
# bridge: acceptance FIRST (cmd/pveforge-harness-accept, through the guard:
# the nested cluster must be whole before its network is touched), then, on
# each node, `pveforge network bridge create pvh-nN pvhbr1
# --management-bridge vmbr0` with the nested roster: the nested guests'
# port-less bridge, made before golden.sh so the golden point includes it.
# It needs no password.
#
# Evidence goes to a new ~/.config/pveforge/harness-evidence/nested-<mode>/
# <stamp>/ (mode 0700), in the shared form (evidence.sh). Exit status: 0 when
# every step passed, 1 when one went red, 2 for a refusal before anything was
# sent.

# The checks U4's password scripts make first (build/cluster.sh): a disabled
# builtin would make every refusal below a no-op, and a function inherited
# from the environment would run in place of the builtin that handles the
# password. Both are refused before the password is read; exit is re-enabled
# before refusing.
if ! hb_disabled=$(enable -n 2>&1) || [ -n "$hb_disabled" ]; then
	echo "harness-nested: refusing: shell builtins are disabled: $hb_disabled" >&2
	enable exit 2>/dev/null
	exit 2
fi
unset hb_disabled
if [ -n "$(declare -F)" ]; then
	echo "harness-nested: refusing: shell functions already defined (inherited from the environment)" >&2
	exit 2
fi
# The shell options lib.sh refuses, for the same reasons, before the password
# is read: tracing (x, v) would print it; allexport (a, which SHELLOPTS in
# the environment can turn on) would export it into every program this
# script runs; functrace and errtrace (T, E) would run an inherited DEBUG or
# ERR trap inside functions. So are the other ways the environment can run
# code in this shell.
case "$-" in *x* | *v* | *a* | *T* | *E*)
	echo "harness-nested: refusing: shell options \$-=$- include xtrace, verbose, allexport, functrace or errtrace" >&2
	exit 2
	;;
esac
if [ -n "${BASH_XTRACEFD:-}${BASH_ENV:-}${ENV:-}" ]; then
	echo "harness-nested: refusing: BASH_XTRACEFD, BASH_ENV or ENV is set" >&2
	exit 2
fi
LC_ALL=C
export LC_ALL
unalias -a
set -euo pipefail
shopt -s inherit_errexit
IFS=$' \t\n'

# The password, taken before any other program runs and removed from the
# environment every program after this one inherits. It stays a shell
# variable, never exported.
pw=${PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD-}
unset PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD
# The roster passphrase likewise: a shell variable, never exported, given
# only to the programs that open the nested roster's secrets (pveforge and
# the accept tool), each in its own environment. ssh, ssh-keygen, jq, the
# pins tool (which reads only plain fields) and every other program run
# without it.
pass=${PVEFORGE_ROSTER_PASSPHRASE-}
unset PVEFORGE_ROSTER_PASSPHRASE

source "${BASH_SOURCE[0]%/*}/build/env.sh"
source "${BASH_SOURCE[0]%/*}/evidence.sh"

mode=${1-}
case "$mode" in
bootstrap | bridge) ;;
*) hb_die 2 "usage: nested.sh bootstrap|bridge (site values come from $HB_ENV_FILE)" ;;
esac
[ "$#" = 1 ] || hb_die 2 "usage: nested.sh bootstrap|bridge (one argument)"
if [ "$mode" = bootstrap ]; then
	[ -n "$pw" ] || hb_die 2 "PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD is not set: run this through 'hack/harness/unlock.sh run --'"
	[[ $pw != *[[:cntrl:]]* ]] || hb_die 2 "the nested root password holds a control character"
else
	pw=
	unset pw
fi
# Root's password reaches pveforge only as the bootstrap child's own
# PVEFORGE_PVE_PASSWORD; one already in the environment would reach every
# program this script runs.
[ -z "${PVEFORGE_PVE_PASSWORD+set}" ] || hb_die 2 "PVEFORGE_PVE_PASSWORD is set: the nested password comes only from PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD"
[ -n "$pass" ] || hb_die 2 "PVEFORGE_ROSTER_PASSPHRASE is not set: run this through 'hack/harness/unlock.sh run --'"
# The roster is always named: a default roster never reaches pveforge.
unset PVEFORGE_ROSTER

hb_resolve stat mkdir chmod mv date flock jq ssh ssh-keygen
hb_read_env

case "${PVEFORGE_BIN:-}" in
/*) ;;
*) hb_die 2 "PVEFORGE_BIN must be the absolute path of the pveforge binary, got '${PVEFORGE_BIN:-}'" ;;
esac
[ -f "$PVEFORGE_BIN" ] && [ -x "$PVEFORGE_BIN" ] || hb_die 2 "PVEFORGE_BIN $PVEFORGE_BIN is not an executable file"

readonly CFG=$HOME/.config/pveforge
readonly KEY=$CFG/harness-nested_ed25519
readonly KNOWN=$CFG/harness-nested.known_hosts
readonly NESTED=$CFG/harness-nested.toml
readonly GRANT=/:Administrator::1
readonly BRIDGE=pvhbr1 MGMT_BRIDGE=vmbr0
readonly -A NODE_IP=([pvh-n1]=${HB[N1_IP]} [pvh-n2]=${HB[N2_IP]})
readonly NODES=(pvh-n1 pvh-n2)

# The accept tool reads the nested roster from PVEFORGE_HARNESS_ROSTER; it can
# only ever be this one.
if [ -n "${PVEFORGE_HARNESS_ROSTER:-}" ]; then
	[ "$PVEFORGE_HARNESS_ROSTER" = "$NESTED" ] || hb_die 2 "PVEFORGE_HARNESS_ROSTER is '$PVEFORGE_HARNESS_ROSTER': the nested harness roster is $NESTED"
fi

# ---- Preflight: local only. ----
exec {lock_fd}>>"$CFG/harness.lock" || hb_die 2 "cannot open $CFG/harness.lock"
"$HB_TOOL_FLOCK" -w 0 "$lock_fd" || hb_die 2 "another harness script holds $CFG/harness.lock"
for f in "$KEY" "$KNOWN"; do
	[ -f "$f" ] && [ ! -L "$f" ] || hb_die 2 "$f does not exist or is not a regular file: run prepare-iso.sh and build.sh first"
	m=$("$HB_TOOL_STAT" -c %a -- "$f") || hb_die 2 "cannot read the mode of $f"
	[ "$m" = 600 ] || hb_die 2 "$f has mode $m, want 600"
done
if [ -e "$NESTED" ] || [ -L "$NESTED" ]; then
	[ -f "$NESTED" ] && [ ! -L "$NESTED" ] || hb_die 2 "$NESTED is not a regular file"
	m=$("$HB_TOOL_STAT" -c %a -- "$NESTED") || hb_die 2 "cannot read the mode of $NESTED"
	[ "$m" = 600 ] || hb_die 2 "$NESTED has mode $m, want 600"
elif [ "$mode" = bridge ]; then
	hb_die 2 "$NESTED does not exist: run 'nested.sh bootstrap' first"
fi
# The pins tool: HARNESS_PINS_BIN, or built as unlock.sh builds its helper.
if [ -n "${HARNESS_PINS_BIN:-}" ]; then
	[[ $HARNESS_PINS_BIN == /* ]] && [ -f "$HARNESS_PINS_BIN" ] && [ -x "$HARNESS_PINS_BIN" ] ||
		hb_die 2 "HARNESS_PINS_BIN must be the absolute path of an executable, got '$HARNESS_PINS_BIN'"
	readonly PINS=$HARNESS_PINS_BIN
else
	hb_resolve go
	root=$(cd -- "${BASH_SOURCE[0]%/*}/../.." && pwd) || hb_die 2 "cannot find the repository root"
	PINS=${XDG_CACHE_HOME:-$HOME/.cache}/pveforge-harness/pveforge-harness-pins
	(cd -- "$root" && "$HB_TOOL_GO" build -o "$PINS" ./cmd/pveforge-harness-pins) || hb_die 2 "cannot build cmd/pveforge-harness-pins"
	readonly PINS
fi
if [ "$mode" = bridge ]; then
	[ -n "${PVEFORGE_HARNESS_OUTER_ROSTERS:-}" ] || hb_die 2 "PVEFORGE_HARNESS_OUTER_ROSTERS must list the outer rosters: acceptance refuses any overlap with them"
	if [ -n "${HARNESS_ACCEPT_BIN:-}" ]; then
		[[ $HARNESS_ACCEPT_BIN == /* ]] && [ -f "$HARNESS_ACCEPT_BIN" ] && [ -x "$HARNESS_ACCEPT_BIN" ] ||
			hb_die 2 "HARNESS_ACCEPT_BIN must be the absolute path of an executable, got '$HARNESS_ACCEPT_BIN'"
	elif [ -z "${HB_TOOL_GO:-}" ]; then
		hb_resolve go
	fi
fi

# PIN_LINE is U4's one ed25519 pin line for each node: the only line the
# pinned login trusts.
declare -A PIN_LINE=()
for node in "${NODES[@]}"; do
	ip=${NODE_IP[$node]} line= n=0
	while IFS= read -r l; do
		[ "${l%% *}" != "$ip" ] || { line=$l n=$((n + 1)); }
	done <"$KNOWN"
	[ "$n" = 1 ] && [[ $line =~ ^${ip//./\\.}\ ssh-ed25519\ [A-Za-z0-9+/]+=*$ ]] ||
		hb_die 2 "$KNOWN must pin exactly one ed25519 host key for $ip ($node): run build.sh first"
	PIN_LINE[$node]=$line
done
readonly -A PIN_LINE

# roster_record prints what the nested roster holds for node: "<host> <pin>"
# (pin "-" before an SSH login is recorded), "absent", or "unreadable".
roster_record() { # node
	local out rc=0
	out=$("$PINS" "$NESTED" "$1" 2>/dev/null) || rc=$?
	case "$rc" in
	0) [[ $out =~ ^[^[:space:]]+\ [^[:space:]]+$ ]] && printf '%s' "$out" || printf unreadable ;;
	3) printf absent ;;
	*) printf unreadable ;;
	esac
}
# A target the roster already holds must name its configured address; bridge
# needs both nodes bootstrapped.
if [ -e "$NESTED" ]; then
	for node in "${NODES[@]}"; do
		rec=$(roster_record "$node")
		case "$rec" in
		"${NODE_IP[$node]} -" | absent) [ "$mode" = bootstrap ] || hb_die 2 "$NESTED holds no bootstrapped $node ($rec): run 'nested.sh bootstrap' first" ;;
		# Its pin is compared once the node's own ECDSA key is read (step 2).
		"${NODE_IP[$node]} SHA256:"*) ;;
		*) hb_die 2 "$NESTED holds $node as '$rec', but build.sh's $node is ${NODE_IP[$node]}: a roster from before a rebuild; move it aside and bootstrap again (README.md)" ;;
		esac
	done
fi

stamp=$("$HB_TOOL_DATE" -u +%Y%m%dT%H%M%SZ) || hb_die 2 "cannot read the clock"
"$HB_TOOL_MKDIR" -p -m 700 -- "$CFG/harness-evidence/nested-$mode" || hb_die 2 "cannot create $CFG/harness-evidence/nested-$mode"
"$HB_TOOL_CHMOD" 700 -- "$CFG/harness-evidence/nested-$mode" || hb_die 2 "cannot make $CFG/harness-evidence/nested-$mode private"
harness_evidence_open "$CFG/harness-evidence/nested-$mode/$stamp" "nested-$mode"
readonly EVID=$HARNESS_EVIDENCE_DIR

red() { # message
	harness_evidence_note "RED $1"
	HARNESS_EVIDENCE_FAIL=1
	harness_evidence_finish
}
pass() { # message
	harness_evidence_note "PASS $1"
}

if [ "$mode" = bootstrap ]; then
	if [ -e "$NESTED" ]; then
		pass "roster $NESTED exists already"
	else
		PVEFORGE_ROSTER_PASSPHRASE=$pass "$PVEFORGE_BIN" roster init "$NESTED" >"$EVID/roster-init.out" 2>&1 || red "roster init $NESTED: see roster-init.out"
		pass "roster init $NESTED"
	fi
	# refuse_roster moves the roster aside, so nothing can use it, and stops.
	refuse_roster() { # message
		local aside=$NESTED.refused-$stamp
		"$HB_TOOL_MV" -- "$NESTED" "$aside" 2>>"$EVID/checks.out" || aside="(NOT moved aside: remove $NESTED by hand)"
		red "$1: refused; the roster is now $aside"
	}
	for node in "${NODES[@]}"; do
		ip=${NODE_IP[$node]}
		# 1. The host at ip proves it holds U4's pin, and only that one line is
		# trusted. 2. Through that session, the ECDSA key its sshd serves.
		known=$EVID/known_hosts-$node
		(umask 077 && printf '%s\n' "${PIN_LINE[$node]}" >"$known") || red "cannot write $known"
		"$HB_TOOL_SSH" -F /dev/null -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes \
			-o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$known" -o GlobalKnownHostsFile=/dev/null \
			-o ConnectTimeout=15 "root@$ip" 'ssh-keyscan -t ecdsa 127.0.0.1' </dev/null >"$EVID/served-ecdsa-$node.txt" 2>"$EVID/pinned-login-$node.err" ||
			red "pinned login to root@$ip ($node): its host key is not the one build.sh pinned, or it is unreachable; no password was sent: see pinned-login-$node.err"
		served= n=0
		while IFS= read -r l; do
			case "$l" in '' | '#'*) continue ;; esac
			served=$l n=$((n + 1))
		done <"$EVID/served-ecdsa-$node.txt"
		[ "$n" = 1 ] && [[ $served =~ ^127\.0\.0\.1\ (ecdsa-sha2-nistp(256|384|521)\ [A-Za-z0-9+/]+=*)$ ]] ||
			red "$node serves no single ECDSA host key (see served-ecdsa-$node.txt): pveforge would negotiate another type; no password was sent"
		out=$("$HB_TOOL_SSH_KEYGEN" -l -E sha256 -f /dev/stdin <<<"$ip ${BASH_REMATCH[1]}") || red "ssh-keygen cannot read $node's ECDSA key"
		read -r _ ecdsa _ <<<"$out"
		[[ $ecdsa =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]] || red "ssh-keygen gave no SHA256 fingerprint for $node's ECDSA key: '$out'"
		pass "pinned login to root@$ip ($node); the ECDSA key it serves is $ecdsa"
		rec=$(roster_record "$node")
		case "$rec" in
		absent | "$ip -" | "$ip $ecdsa") ;;
		*) red "$NESTED records $node as '$rec', but $ip serves $ecdsa: a roster from before a rebuild or 'build.sh --repin'; move it aside and bootstrap again (README.md); no password was sent" ;;
		esac
		# 3. The password in this one child's environment only, to a dial that
		# must present that key.
		brc=0
		PVEFORGE_PVE_PASSWORD=$pw PVEFORGE_ROSTER_PASSPHRASE=$pass "$PVEFORGE_BIN" bootstrap "$node" --roster "$NESTED" --host "$ip" --node "$node" \
			--insecure-tls --grant "$GRANT" --host-key-fingerprint "$ecdsa" -o json </dev/null >"$EVID/bootstrap-$node.json" 2>"$EVID/bootstrap-$node.stderr" || brc=$?
		# 4. Afterwards: what the roster recorded, and what bootstrap reported,
		# must be that pin at the configured address.
		rec=$(roster_record "$node")
		printf '%s\n' "$rec" >"$EVID/roster-record-$node.txt"
		if [ "$brc" != 0 ]; then
			case "$rec" in
			absent | "$ip -") red "bootstrap $node (exit $brc): no SSH login recorded, the roster kept: see bootstrap-$node.json and bootstrap-$node.stderr" ;;
			*) refuse_roster "bootstrap $node (exit $brc) failed after its SSH login was recorded ('$rec'): see bootstrap-$node.stderr" ;;
			esac
		fi
		[ "$rec" = "$ip $ecdsa" ] ||
			refuse_roster "the roster records $node as '$rec', but $ip serves $ecdsa"
		got=$("$HB_TOOL_JQ" -r '.host_key_fingerprint // ""' "$EVID/bootstrap-$node.json" 2>/dev/null) || got=
		[ "$got" = "$ecdsa" ] ||
			refuse_roster "bootstrap $node reported host key '$got', but $ip serves $ecdsa"
		# 4. The token is held and proven, as D5's G4 gate asks of the outer
		# one: bootstrap can exit 0 with a token it could not verify.
		outcome=$("$HB_TOOL_JQ" -r '"\(.token_outcome // "")/\(.validation // "")"' "$EVID/bootstrap-$node.json" 2>/dev/null) || outcome=
		case "$outcome" in
		minted/verified | reused/verified | replaced/verified) ;;
		*) red "bootstrap $node: token_outcome/validation is '$outcome', want minted, reused or replaced, and verified: see bootstrap-$node.json" ;;
		esac
		pass "bootstrap $node: grant $GRANT, host key $ecdsa verified before the password, token ${outcome%/*} and verified"
	done
	pw=
	unset pw
	harness_evidence_finish
fi

# ---- bridge: acceptance first, then pvhbr1 on each node. ----
export PVEFORGE_HARNESS_ROSTER=$NESTED
if [ -n "${HARNESS_ACCEPT_BIN:-}" ]; then
	accept=$HARNESS_ACCEPT_BIN
else
	root=$(cd -- "${BASH_SOURCE[0]%/*}/../.." && pwd) || red "cannot find the repository root"
	accept=${XDG_CACHE_HOME:-$HOME/.cache}/pveforge-harness/pveforge-harness-accept
	(cd -- "$root" && "$HB_TOOL_GO" build -o "$accept" ./cmd/pveforge-harness-accept) >"$EVID/accept-build.out" 2>&1 ||
		red "cannot build cmd/pveforge-harness-accept: see accept-build.out"
fi
rc=0
PVEFORGE_ROSTER_PASSPHRASE=$pass "$accept" -deadline 5m </dev/null >"$EVID/accept.out" 2>&1 || rc=$?
[ "$rc" = 0 ] || red "acceptance (exit $rc): the nested cluster is not whole; no bridge was touched: see accept.out"
pass "acceptance: the nested cluster is whole"
for node in "${NODES[@]}"; do
	PVEFORGE_ROSTER_PASSPHRASE=$pass "$PVEFORGE_BIN" network bridge create "$node" "$BRIDGE" --management-bridge "$MGMT_BRIDGE" --roster "$NESTED" \
		</dev/null >"$EVID/bridge-$node.out" 2>&1 || red "bridge $BRIDGE on $node: see bridge-$node.out"
	pass "bridge $BRIDGE on $node (management bridge $MGMT_BRIDGE)"
done
harness_evidence_finish
