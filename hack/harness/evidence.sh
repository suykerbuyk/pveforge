# shellcheck shell=bash
# hack/harness/evidence.sh: the evidence and check helpers the harness scripts
# share (the Chair's O6 ruling: moved here from d5/evidence.sh, whose D5
# names now wrap these). Sourced, never run; it needs nothing from lib.sh.
#
# Each run writes into a NEW directory (mode 0700, never reused or
# overwritten): the raw answers it read, result.txt (one PASS or RED line per
# check, then a RESULT line) and MANIFEST.sha256. Every check runs, even after
# one goes red, so one run reports them all. harness_evidence_finish exits 0
# when every check passed and 1 when any went red; a usage error before
# anything was read exits 2.
HARNESS_EVIDENCE_DIR=
HARNESS_EVIDENCE_PHASE=
HARNESS_EVIDENCE_FAIL=0

harness_evidence_die() { # status message
	echo "harness: $2" >&2
	exit "$1"
}

# harness_evidence_open creates dir, which must not exist yet.
harness_evidence_open() { # dir phase
	local dir=$1
	[ -n "$dir" ] || harness_evidence_die 2 "HARNESS_EVIDENCE must name a new directory for this run's evidence"
	[ ! -e "$dir" ] && [ ! -L "$dir" ] || harness_evidence_die 2 "evidence directory $dir already exists; evidence is never overwritten"
	mkdir -p -- "$(dirname -- "$dir")"
	mkdir -m 700 -- "$dir"
	HARNESS_EVIDENCE_DIR=$dir
	HARNESS_EVIDENCE_PHASE=$2
}

harness_evidence_note() {
	printf '%s\n' "$*" | tee -a "$HARNESS_EVIDENCE_DIR/result.txt"
}

# harness_evidence_check runs one check; its output goes to the evidence,
# never decides it.
harness_evidence_check() { # name command...
	local name=$1
	shift
	if "$@" >>"$HARNESS_EVIDENCE_DIR/checks.out" 2>&1; then
		harness_evidence_note "PASS $name"
	else
		harness_evidence_note "RED $name"
		HARNESS_EVIDENCE_FAIL=1
	fi
}

harness_evidence_finish() {
	harness_evidence_note "RESULT phase=$HARNESS_EVIDENCE_PHASE fail=$HARNESS_EVIDENCE_FAIL evidence=$HARNESS_EVIDENCE_DIR"
	(cd "$HARNESS_EVIDENCE_DIR" && sha256sum -- * >MANIFEST.sha256)
	exit "$HARNESS_EVIDENCE_FAIL"
}
