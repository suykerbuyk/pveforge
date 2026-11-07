#!/usr/bin/env bash
# hack/gate/clean-export.sh: pveforge's landing gate.
#
# WHAT IT CERTIFIES (the contract; read this before changing the refusals):
#
#   This gate certifies the WORKTREE -- every non-ignored path as it stands on
#   disk -- and it refuses only when a staging act has been performed that the
#   worktree does not match, because only then is the tree it certifies not the
#   tree the upcoming `git commit` would produce.
#
# WHY NOT `git archive $(git write-tree)`:
#
#   `git write-tree` writes the INDEX. In a worktree where nothing has been
#   staged the index still equals HEAD, so that recipe exports unmodified main
#   and the gate passes while proving nothing about the change under review.
#   It is correct only AFTER a path-scoped `git add`, which an implementor who
#   is forbidden to stage never performs -- so it is reliably wrong precisely
#   for the agent it was written for. A throwaway GIT_INDEX_FILE exports the
#   worktree while staging nothing in the repository.
#
# MODES:
#
#   clean-export.sh                  build the export, assert it, then run the
#                                    suites inside it (the full gate)
#   clean-export.sh --export-only [DIR]
#                                    build the export and assert it; run no
#                                    `make`. With DIR, extract there and keep
#                                    it, so a caller can inspect the result.
#                                    internal/sourceguard's guard test drives
#                                    THIS FILE through this mode; it never
#                                    re-implements the recipe.
#
# Both modes call build_export(). There is exactly one copy of the recipe in
# this file, between the THROWAWAY-INDEX TREE markers.
set -euo pipefail

die() {
	printf 'clean-export: %s\n' "$*" >&2
	exit 1
}

say() {
	printf 'clean-export: %s\n' "$*"
}

# outside_top refuses a path inside the work tree. The script asserts its
# temporaries are external and, until this check existed, never verified it:
# with TMPDIR set under the repository, `mktemp` put the export directory and
# the throwaway index INSIDE $TOP, `git add -A` swept them in, and the gate
# exited 0 with internal/tmp.* and a .lock in the exported tree. Measured.
outside_top() {
	local path="$1" what="$2" remedy="$3" real
	real=$(cd "$(dirname -- "$path")" && pwd -P)/$(basename -- "$path")
	case "$real/" in
	"$TOP"/*)
		die "$what is inside the work tree ($real): it would be swept into the export. $remedy"
		;;
	esac
}

# TOP_LEVEL is the literal set of entries the repository root may contain,
# copied from `git ls-tree --name-only HEAD` at b305958 (13 entries).
#
# THIS IS THE PREDICATE. It is written out rather than computed from the tree
# under test, because a list derived from that tree would make the check and
# the thing checked the same object. Two failures are intended, not accidents:
# a unit that legitimately adds a top-level entry goes red and gets reviewed
# (update this list in the same commit), and a stray artefact dropped at the
# repository root goes red, which is the point -- `git add -A` once swept a
# 15 MB harness binary into an export from exactly there.
TOP_LEVEL=".github .gitignore .vibe-palace.toml LICENSE Makefile README.md THIRD-PARTY-NOTICES.md cmd docs go.mod go.sum hack internal"

EXPORT=""
IDX=""
TREE=""
KEEP_EXPORT=no
EXPORT_ONLY=no

# cleanup never fails and never kills the run: it runs with errexit off, with
# SIGPIPE ignored so a write to a closed terminal cannot abort it, and with
# INT/TERM/HUP ignored so a second signal cannot strand the temporaries.
cleanup() {
	set +e
	trap '' PIPE
	trap '' INT TERM HUP
	if [ -n "$IDX" ]; then
		rm -f "$IDX"
	fi
	if [ -n "$EXPORT" ] && [ "$KEEP_EXPORT" = no ]; then
		rm -rf "$EXPORT"
	fi
	return 0
}

while [ "$#" -gt 0 ]; do
	case "$1" in
	--export-only)
		EXPORT_ONLY=yes
		shift
		if [ "$#" -gt 0 ]; then
			EXPORT="$1"
			KEEP_EXPORT=yes
			shift
		fi
		;;
	-h | --help)
		sed -n '2,32p' "$0"
		exit 0
		;;
	*)
		die "unknown argument: $1 (see --help)"
		;;
	esac
done

trap cleanup EXIT

# --- step 1: refuse unless we are at the top of a git work tree ---------------
TOP=""
rc=0
TOP=$(git rev-parse --show-toplevel 2>/dev/null) || rc=$?
if [ "$rc" -ne 0 ] || [ -z "$TOP" ]; then
	die "not inside a git work tree (run this from the repository)"
fi
cd "$TOP"

rc=0
git rev-parse --verify HEAD >/dev/null 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then
	die "HEAD is unborn: there is no committed tree to gate against"
fi

# build_export: the one recipe. Writes $TREE, extracts it into $EXPORT, and
# refuses before and after extraction. Both modes call this function.
build_export() {
	# --- step 2: temporaries, ABSOLUTE and OUTSIDE the work tree --------------
	#
	# A RELATIVE GIT_INDEX_FILE is resolved against the repository top level,
	# not the caller's directory: run from a subdirectory it lands at the
	# repository root, untracked and un-ignored, and the next `git add -A`
	# sweeps the index file into its own export. Measured. Always absolute,
	# always outside the work tree.
	if [ -z "$EXPORT" ]; then
		EXPORT=$(mktemp -d)
	else
		if [ ! -d "$EXPORT" ]; then
			die "export directory does not exist: $EXPORT"
		fi
		EXPORT=$(cd "$EXPORT" && pwd -P)
	fi
	if [ "$KEEP_EXPORT" = yes ]; then
		outside_top "$EXPORT" "the export directory" "Pass --export-only a directory outside $TOP."
	else
		outside_top "$EXPORT" "the export directory" "Set TMPDIR to a directory outside $TOP."
	fi

	local rc ht n i entry extracted listed
	local -a ps

	ht=$(git rev-parse 'HEAD^{tree}')

	# >>> THROWAWAY-INDEX TREE: the one recipe. internal/sourceguard's kill
	# >>> mutant replaces exactly this marked range with the bare
	# >>> `TREE=$(git write-tree)` form and asserts the refusals below still
	# >>> fire. Keep the markers; they are the mutant's sed range.
	#
	# Each status is captured in the SAME simple command as the call. With
	# errexit on, "check the status on the next line" never reaches the next
	# line; `rc=0; cmd || rc=$?` does.
	#
	# Creating the throwaway index is PART of the recipe, so it lives inside
	# the markers: the mutant then has no throwaway index at all, $IDX stays
	# empty, and step 3b skips rather than dying on a zero-byte index file.
	IDX=$(mktemp)
	outside_top "$IDX" "the throwaway index" "Set TMPDIR to a directory outside $TOP."

	rc=0
	GIT_INDEX_FILE="$IDX" git read-tree HEAD || rc=$?
	[ "$rc" -eq 0 ] || die "git read-tree HEAD failed: $rc"

	rc=0
	GIT_INDEX_FILE="$IDX" git add -A || rc=$?
	[ "$rc" -eq 0 ] || die "git add -A (throwaway index) failed: $rc"

	rc=0
	TREE=$(GIT_INDEX_FILE="$IDX" git write-tree) || rc=$?
	[ "$rc" -eq 0 ] || die "git write-tree (throwaway index) failed: $rc"
	# <<< THROWAWAY-INDEX TREE <<<

	# --- step 3b: did `git add -A` actually capture the worktree? ------------
	#
	# THE CONTRACT IS "every non-ignored path as it stands on disk", AND
	# `git add -A` CAN SILENTLY FAIL TO HONOUR IT. Under a sparse checkout it
	# omits out-of-cone paths and exits 0. A single out-of-cone edit leaves
	# TREE == HEAD and step 4a catches it; a COMPOUND change -- one in-cone
	# edit captured, one out-of-cone edit omitted -- makes TREE differ from
	# HEAD with nothing staged, so 4a and 4b are both bypassed and the gate
	# certified a tree missing a worktree change. Measured, exit 0.
	#
	# The check is general rather than a sparse-checkout special case: after
	# `add -A`, NOTHING may remain between the worktree and the throwaway
	# index. That holds for any mechanism that makes `add -A` skip a path, not
	# only the one we know about. Both halves are needed -- `diff-files` sees
	# tracked paths the index and the disk disagree on, `ls-files -o` sees a
	# path on disk the index never took. Measured across clean, unstaged-only,
	# untracked-only, staged-only, MM, intent-to-add, unstaged deletion,
	# ignored files, assume-unchanged, skip-worktree and untracked symlinks:
	# both are empty. Under the compound sparse case: 505 paths.
	#
	# Guarded on $IDX so the bare-`write-tree` mutant, which never creates a
	# throwaway index, falls through to step 4a as before.
	if [ -n "$IDX" ]; then
		local missed untracked total
		missed=$(GIT_INDEX_FILE="$IDX" git diff-files --name-only | wc -l)
		untracked=$(GIT_INDEX_FILE="$IDX" git ls-files -o --exclude-standard | wc -l)
		total=$((missed + untracked))
		if [ "$total" -ne 0 ]; then
			# Name which side each path is missing from. The earlier wording
			# said "not represented in the exported tree" for every path,
			# which is the exact inverse for a `D` row: that path IS in the
			# export and is ABSENT from the worktree, which is what a clean
			# sparse checkout looks like.
			local gone
			gone=$(GIT_INDEX_FILE="$IDX" git diff-files --name-status | awk '$1 == "D"' | wc -l)
			printf 'clean-export: in the export but ABSENT from the worktree:\n' >&2
			GIT_INDEX_FILE="$IDX" git diff-files --name-status | awk '$1 == "D" {$1=""; sub(/^\t/, ""); print}' >&2
			printf 'clean-export: in the worktree but MISSING or STALE in the export:\n' >&2
			GIT_INDEX_FILE="$IDX" git diff-files --name-status | awk '$1 != "D" {$1=""; sub(/^\t/, ""); print}' >&2
			GIT_INDEX_FILE="$IDX" git ls-files -o --exclude-standard >&2
			if [ -n "$(git ls-files -v | grep '^S' || true)" ]; then
				printf 'clean-export: this worktree is SPARSE; git add -A omits out-of-cone paths and exits 0.\n' >&2
			fi
			die "the worktree and the export disagree on $total path(s) ($gone present in the export but not on disk, $((total - gone)) on disk but not captured): git add -A did not capture the worktree, so the gate would certify a tree the worktree does not match"
		fi
	fi

	# --- step 4a: a dirty worktree whose export equals HEAD is the bug --------
	#
	# This is the defect this gate exists for, made unreportable-as-green: a
	# dirty worktree whose export is byte-for-byte HEAD.
	#
	# It is NOT the sparse-checkout backstop any more -- step 3b, directly
	# above, catches every omission case first, measured. What 4a still
	# backstops is any OTHER way the recipe could come to produce HEAD's tree
	# from a dirty worktree: a regression to the bare `git archive $(git
	# write-tree)` form (which is exactly what the guard test's mutant does,
	# and 4a is the refusal it asserts), or a future edit that leaves the
	# throwaway index unpopulated. 3b cannot see those, because they are
	# reached with no throwaway index at all.
	if [ -n "$(git status --porcelain)" ] && [ "$TREE" = "$ht" ]; then
		git status --porcelain >&2
		die "the worktree is dirty but the exported tree IS HEAD's tree ($ht): the gate would certify unmodified HEAD"
	fi

	# --- step 4b: the divergence refusal -------------------------------------
	#
	# Refuse when a staging act has been performed AND the worktree does not
	# match it -- then `make gate` and `git commit` would certify different
	# trees.
	#
	# The staging-act test is `git diff-index --cached`, NOT a comparison of
	# the index's tree against HEAD's: `git write-tree` SKIPS an intent-to-add
	# entry, so `git add -N` leaves the index tree equal to HEAD's and a tree
	# comparison is structurally blind to it. `git diff-index --cached` sees it
	# (exit 1). `git diff --cached --quiet` does not (exit 0), and
	# `git diff --quiet` does not look at untracked files at all -- both are
	# kept only as the message that names the paths, never as the predicate.
	#
	# Intent-to-add refuses deliberately: `git commit` with only an `add -N`
	# entry fails outright and moves nothing, while this export carries the
	# file.
	#
	# Unstaged-only and untracked-only PROCEED. They are why this gate exists;
	# no staging act has occurred, and the export carrying the change is
	# correct, not divergence.
	#
	# $ix is computed ONLY when a staging act has occurred. `git write-tree`
	# on the repository index takes .git/index.lock, and concurrent git in the
	# same worktree is this gate's actual running environment: computing a
	# value the predicate will not use would turn a stale lock into a refusal
	# of a worktree the gate should have certified.
	local dix ix
	dix=0
	git diff-index --cached --quiet HEAD || dix=$?

	if [ "$dix" -ne 0 ]; then
		rc=0
		ix=$(git write-tree) || rc=$?
		[ "$rc" -eq 0 ] || die "git write-tree (repository index) failed: $rc"
	else
		ix="$TREE"
	fi

	if [ "$dix" -ne 0 ] && [ "$TREE" != "$ix" ]; then
		git diff --cached --name-status HEAD >&2 || true
		git diff --name-status >&2 || true
		die "something is staged and the worktree does not match it: the export ($TREE) is not the tree git commit would produce ($ix). Stage the rest, or unstage, then re-run."
	fi

	# --- step 5: TREE-SIDE assertions, computed from $TREE BEFORE extract -----
	#
	# These must be here and not after the extract: an assertion about the
	# repository's shape that runs against a still-empty export directory
	# cannot fail.
	# -z and `read -d ""`: a top-level name containing a space would otherwise
	# be word-split and misreported as two entries (it would still refuse,
	# which is the safe direction, but the message would name neither).
	while IFS= read -r -d '' entry; do
		local ok
		ok=no
		for i in $TOP_LEVEL; do
			if [ "$entry" = "$i" ]; then
				ok=yes
			fi
		done
		if [ "$ok" = no ]; then
			# The observer below reports what `git add -A` just wrote. It is
			# the same object as the tree being written, so it is the refusal
			# MESSAGE only. The predicate is TOP_LEVEL above. Do not promote
			# this into the check.
			if [ -n "$IDX" ]; then
				GIT_INDEX_FILE="$IDX" git diff --cached --name-status HEAD >&2 || true
			fi
			die "top-level entry not in the allowlist: $entry (add it to TOP_LEVEL in the same commit, or remove the stray artefact)"
		fi
	done < <(git ls-tree --name-only -z "$TREE")

	# A gitlink (a nested repository or worktree swept in by `git add -A`)
	# carries no files, so the file-count assertion below cannot see it. Match
	# the MODE field: `grep ' commit '` exits 1 on a clean tree -- a false red
	# -- and also matches a path that contains the word.
	n=$(git ls-tree -r "$TREE" | awk '$1 == "160000"' | wc -l)
	if [ "$n" -ne 0 ]; then
		git ls-tree -r "$TREE" | awk '$1 == "160000"' >&2
		die "$n gitlink(s) in the exported tree: a nested repository was swept in"
	fi

	# --- step 6: extract ------------------------------------------------------
	#
	# errexit is suspended across the pipe and nothing else sits inside the
	# window. Three other forms were measured broken: `a=${PIPESTATUS[0]};
	# b=${PIPESTATUS[1]}` loses the second value (`;` is a command boundary and
	# the first assignment replaces PIPESTATUS); a bare `pipe` followed by the
	# array copy never reaches the copy when the pipe fails, because errexit
	# plus pipefail abort at the pipe; and `pipe || ps=(...)` dies on the
	# SUCCESS path under nounset.
	set +e
	git archive "$TREE" | (cd "$EXPORT" && tar xf -)
	ps=("${PIPESTATUS[@]}")
	set -e
	[ "${ps[0]}" -eq 0 ] || die "git archive failed: ${ps[0]}"
	[ "${ps[1]}" -eq 0 ] || die "tar failed: ${ps[1]}"

	# --- step 7: EXPORT-SIDE assertions, AFTER extract ------------------------
	n=$(find "$EXPORT" -type f -size +2M | wc -l)
	if [ "$n" -ne 0 ]; then
		find "$EXPORT" -type f -size +2M >&2
		die "$n file(s) over 2M in the export: a build artefact was swept in"
	fi

	# COUNT ENTRIES, NOT LINES, ON BOTH SIDES. Twice now this assertion has
	# false-redded a COMPLETE export because one side was not counting what it
	# claimed to:
	#   - a committed SYMLINK is a tree entry (mode 120000) that `-type f`
	#     does not match: ls-tree 2, -type f 1. Hence `-o -type l`.
	#   - a committed filename containing a LITERAL NEWLINE is one entry that
	#     newline-counting splits in two: measured, NUL 2, `find | wc -l` 3.
	# NUL-delimited counting closes symlinks, newlines and spaces together
	# instead of one shape per round. `-print0` and `-z` are portable here;
	# `find -printf` is a GNU extension this repo avoids.
	#
	# What this detects: any path `git archive` drops from a tree it was given
	# -- in practice a `.gitattributes export-ignore`. Note it cannot be a
	# ROOT .gitattributes: that name is not in TOP_LEVEL, so step 5 refuses it
	# first (measured). A .gitattributes in a SUBDIRECTORY does reach here,
	# and does drop paths (measured: ls-tree 3, extracted 2).
	extracted=$(find "$EXPORT" \( -type f -o -type l \) -print0 | tr -cd '\0' | wc -c)
	listed=$(git ls-tree -r --name-only -z "$TREE" | tr -cd '\0' | wc -c)
	if [ "$extracted" -ne "$listed" ]; then
		die "the export holds $extracted entries but the tree lists $listed: git archive dropped paths (an export-ignore attribute in a subdirectory .gitattributes does this)"
	fi

	say "TREE=$TREE"
	say "HEAD^{tree}=$ht"
	say "EXPORT=$EXPORT"
	say "entries=$extracted (tree lists $listed)"
}

# require_count refuses a count that is not a single plain integer, so a
# malformed value can never reach `[ -ne ]` and be treated as a pass.
require_count() {
	local target="$1" what="$2" value="$3"
	case "$value" in
	"" | *[!0-9]*)
		die "make $target: the $what count is not a plain integer: [$value]. The skip detector cannot assert on it, so the gate refuses rather than reporting green."
		;;
	esac
	# All-digits is not enough. A value past INTMAX makes `[ -ne ]` ERROR
	# rather than compare, the `if` takes the else branch, and the check
	# passes -- the same fail-open this function exists to close, one layer
	# in. Measured: okn=1 against 40 nines -> "integer expression expected",
	# then PASS. Nine digits is ~1e9 packages; anything longer is a bug in
	# whatever produced it, not a package count.
	if [ "${#value}" -gt 9 ]; then
		die "make $target: the $what count is ${#value} digits long: [$value]. A value that large makes the comparison error instead of compare, which would read as a pass, so the gate refuses."
	fi
}

# run_counted runs one `make` target in the export and proves the package set
# it covered, because an exit code cannot show that a package was SKIPPED.
# $2 is the package count to compare the `ok` lines against, or "-" to read it
# from the target's own `packages=N` line (the derivation then lives in exactly
# one place, the Makefile, and is still compared against a different producer:
# go test's output).
run_counted() {
	local target listed log rc okn nonen
	target="$1"
	listed="$2"
	log="$EXPORT/.gate-$target.log"
	rc=0
	say "running make $target in the export"
	( cd "$EXPORT" && make "$target" ) >"$log" 2>&1 || rc=$?
	cat "$log"
	say "make $target exit=$rc"
	if [ "$rc" -ne 0 ]; then
		return "$rc"
	fi
	# THE SKIP DETECTOR MUST NOT FAIL OPEN. `[ "$okn" -ne "$listed" ]` with a
	# multi-line $listed prints "integer expression expected" on stderr and
	# takes the ELSE branch -- the comparison silently stops asserting and the
	# gate reports green. Measured: okn=26, listed=$'2\n1' -> PASSED, rc 0.
	# And because run_counted is called with `|| rc=$?`, errexit is off inside
	# it, so nothing catches the fall-through. Validate both operands before
	# comparing; a count that cannot be trusted is a refusal, not a pass.
	if [ "$listed" = "-" ]; then
		local hits
		hits=$(grep -c '^.*: packages=[0-9][0-9]*$' "$log" || true)
		if [ "$hits" -ne 1 ]; then
			die "make $target printed $hits packages=N lines, want exactly 1: the package count cannot be checked"
		fi
		listed=$(sed -n 's/^.*: packages=\([0-9][0-9]*\)$/\1/p' "$log")
	fi
	okn=$(grep -c '^ok[[:space:]]' "$log" || true)
	nonen=$(grep -c 'no test files' "$log" || true)
	require_count "$target" listed "$listed"
	require_count "$target" ok "$okn"
	require_count "$target" no-test-files "$nonen"
	say "make $target: ok=$okn listed=$listed no-test-files=$nonen"
	if [ "$nonen" -ne 0 ]; then
		grep 'no test files' "$log" >&2 || true
		die "make $target: $nonen package(s) have no test files, so the ok count cannot be compared against the package count. Give each package named above a test, or exclude it from the target's package list and say why in the Makefile comment."
	fi
	if [ "$okn" -ne "$listed" ]; then
		die "make $target: $okn ok lines for $listed listed packages: a package was skipped"
	fi
	return 0
}

build_export

if [ "$EXPORT_ONLY" = yes ]; then
	say "--export-only: the export is built and asserted; no suite was run"
	exit 0
fi

# --- step 8: the suites, inside the export ------------------------------------
#
# This script never exports GIT_INDEX_FILE: it prefixes it onto individual
# git calls (`GIT_INDEX_FILE=... git add -A`), which puts it in THAT command's
# environment only. The unset defends against a value the CALLER exported into
# our environment -- a chair or wrapper mid-export of its own. Measured, both
# forms: a prefixed assignment is inherited by that command's descendants, and
# an exported one reaches a child `make` recipe verbatim, which would hand an
# index to every git the suite runs.
unset GIT_INDEX_FILE

# Same fail-open class as require_count: this is a pipe, so without pipefail
# a failing `go list` would still produce a count (0) from `wc`, and the ok/
# listed comparison would then be asserting on a number no command vouched
# for. pipefail is on from the top of the file, and the status is captured in
# the same simple command as the call.
rc=0
LISTED=$(cd "$EXPORT" && go list ./... | wc -l) || rc=$?
[ "$rc" -eq 0 ] || die "go list ./... in the export failed: $rc"
require_count check listed "$LISTED"
if [ "$LISTED" -eq 0 ]; then
	die "go list ./... in the export found 0 packages: the export is not a Go module"
fi
say "go list ./... in the export: $LISTED packages"

FAILED=0
rc=0
run_counted check "$LISTED" || rc=$?
if [ "$rc" -ne 0 ]; then
	FAILED=1
fi
rc=0
run_counted test-harness - || rc=$?
if [ "$rc" -ne 0 ]; then
	FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
	die "the gate FAILED on tree $TREE"
fi
say "the gate PASSED on tree $TREE"
