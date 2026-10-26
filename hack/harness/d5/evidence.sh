# shellcheck shell=bash
# hack/harness/d5/evidence.sh: the D5 verify scripts' constants, and their
# names for the shared evidence helpers in ../evidence.sh (the Chair's O6
# ruling). Sourced right after lib.sh, never on its own.
#
# Each run writes into a NEW directory, $HARNESS_EVIDENCE (mode 0700, never
# reused or overwritten): the raw answers it read, result.txt (one PASS or RED
# line per check, then a RESULT line) and MANIFEST.sha256. Every check runs,
# even after one goes red, so one run reports them all. The exit status is 0
# when every check passed, 1 when any went red, 2 on a usage error before
# anything was read.
source "$(dirname "${BASH_SOURCE[0]}")/../evidence.sh"

# The outer identity, read and validated BEFORE any D5 read: verify-root.sh runs
# NO harness_init, so a bad site file must refuse here, before the first ssh or
# pveforge call. A pure file parse; idempotent with harness_init's own call.
read_outer_identity

D5_FIXTURES=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../internal/pve/testdata/permissions" && pwd)
readonly D5_FIXTURES
readonly D5_USER=${HARNESS_POOL}@pve
readonly D5_TOKENID=build
readonly D5_TOKEN="$D5_USER!$D5_TOKENID"
readonly D5_POOL=$HARNESS_POOL
readonly D5_STORAGE=$HARNESS_OUTER_STORAGE
readonly D5_NODE=$HARNESS_NODE
readonly D5_TAG=$HARNESS_TAG
readonly D5_ROLE_PREFIX=ForgeHarness
# Host-keyed, matching lib's roster keying, so N hosts coexist without archiving.
readonly D5_P0="$HOME/.config/pveforge/harness-${HARNESS_NODE}-outer.p0"

# d5_ere_escape prints its argument with every ERE metacharacter backslash-
# escaped, so a pool/storage value interpolated into a jq test() regex
# (verify-root.sh's D5_HARNESS_PATHS) is matched literally — belt-and-braces
# behind the per-key patterns that already reject '.' (R7): a '.' in a pool id
# would otherwise read a foreign path as harness-owned.
d5_ere_escape() { # string
	local s=$1 out= c i
	for ((i = 0; i < ${#s}; i++)); do
		c=${s:i:1}
		case "$c" in
		'.' | '\' | '+' | '*' | '?' | '|' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$') out+=\\$c ;;
		*) out+=$c ;;
		esac
	done
	printf '%s' "$out"
}
D5_EVIDENCE=
D5_PHASE=
D5_FAIL=0

# d5_open_evidence creates $HARNESS_EVIDENCE for this run.
d5_open_evidence() { # phase
	D5_PHASE=$1
	D5_EVIDENCE=${HARNESS_EVIDENCE:-}
	harness_evidence_open "$D5_EVIDENCE" "$D5_PHASE"
}

d5_note() {
	harness_evidence_note "$@"
}

d5_check() { # name command...
	harness_evidence_check "$@"
	[ "$HARNESS_EVIDENCE_FAIL" = 0 ] || D5_FAIL=1
}

# d5_finish: a check the verify script failed by hand (D5_FAIL=1) counts too.
d5_finish() {
	[ "$D5_FAIL" = 0 ] || HARNESS_EVIDENCE_FAIL=1
	harness_evidence_finish
}
