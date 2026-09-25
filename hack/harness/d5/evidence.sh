# shellcheck shell=bash
# hack/harness/d5/evidence.sh: the evidence and check helpers the D5 verify
# scripts share. Sourced right after lib.sh, never on its own.
#
# Each run writes into a NEW directory, $HARNESS_EVIDENCE (mode 0700, never
# reused or overwritten): the raw answers it read, result.txt (one PASS or RED
# line per check, then a RESULT line) and MANIFEST.sha256. Every check runs,
# even after one goes red, so one run reports them all. The exit status is 0
# when every check passed, 1 when any went red, 2 on a usage error before
# anything was read.

D5_FIXTURES=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../internal/pve/testdata/permissions" && pwd)
readonly D5_FIXTURES
readonly D5_USER=pveforge-harness@pve
readonly D5_TOKENID=build
readonly D5_TOKEN="$D5_USER!$D5_TOKENID"
readonly D5_POOL=pveforge-harness
readonly D5_STORAGE=pveforge-harness
readonly D5_NODE=qa-pve-02
readonly D5_ROLE_PREFIX=PveforgeHarness
readonly D5_P0="$HOME/.config/pveforge/harness-outer.p0"
D5_EVIDENCE=
D5_PHASE=
D5_FAIL=0

# d5_open_evidence creates $HARNESS_EVIDENCE for this run.
d5_open_evidence() { # phase
	D5_PHASE=$1
	D5_EVIDENCE=${HARNESS_EVIDENCE:-}
	[ -n "$D5_EVIDENCE" ] || _harness_die 2 "HARNESS_EVIDENCE must name a new directory for this run's evidence"
	[ ! -e "$D5_EVIDENCE" ] && [ ! -L "$D5_EVIDENCE" ] || _harness_die 2 "evidence directory $D5_EVIDENCE already exists; evidence is never overwritten"
	mkdir -p -- "$(dirname -- "$D5_EVIDENCE")"
	mkdir -m 700 -- "$D5_EVIDENCE"
}

d5_note() {
	printf '%s\n' "$*" | tee -a "$D5_EVIDENCE/result.txt"
}

# d5_check runs one check; its output goes to the evidence, never decides it.
d5_check() { # name command...
	local name=$1
	shift
	if "$@" >>"$D5_EVIDENCE/checks.out" 2>&1; then
		d5_note "PASS $name"
	else
		d5_note "RED $name"
		D5_FAIL=1
	fi
}

d5_finish() {
	d5_note "RESULT phase=$D5_PHASE fail=$D5_FAIL evidence=$D5_EVIDENCE"
	(cd "$D5_EVIDENCE" && sha256sum -- * >MANIFEST.sha256)
	exit "$D5_FAIL"
}
