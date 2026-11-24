#!/usr/bin/env bash
# hack/release/release.sh: build a pveforge RELEASE (or release CANDIDATE) locally.
#
#   hack/release/release.sh                      a release: HEAD must be exactly a v<semver> tag
#   hack/release/release.sh --candidate          a candidate: HEAD need not be tagged
#       [--changes-for vX.Y.Z]                   the CHANGES.md section the candidate is for (default: Unreleased)
#       [--previous-schema FILE]                 the previous release's schema.json: a breaking diff needs an honest CHANGES
#       [--out DIR]                              default ./dist; refused if it exists and is not empty
#
# This script NEVER tags, pushes, commits, publishes or contacts a network
# (an unserviceable GOPROXY, no curl, no gh): tagging, pushing and publishing are the
# operator's steps (docs/releasing.md). It builds from a CLONE of the current
# repository at the tag (or at HEAD for a candidate), never from the working
# tree, because only a git checkout carries the VCS stamp `pveforge version`
# reports: a `git archive` export is "(devel)" and no release can be made of it.
#
# Output (all in --out): pveforge-<ver>-linux-amd64.tar.gz, pveforge-<ver>-source.tar.gz,
# schema-<ver>.json, SHA256SUMS. Judge the run ONLY by its last line,
# "release: the ... PASSED"; every step below is an explicit status check, never
# errexit (errexit is off inside functions called from if/&&/||).
#
# The platform matrix is linux/amd64 only (operator decision D4). The build is
# CGO_ENABLED=0 -trimpath so two builds of one tag are byte-identical
# (AC-B3, measured by internal/sourceguard TestRelease_*).

set -o pipefail
export LC_ALL=C

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P) || exit 2
CANDIDATE=no OUT="" PREV_SCHEMA="" CHANGES_FOR="" PLATFORM="linux/amd64"
WORK=""

say() { printf 'release: %s\n' "$*" >&2; }
die() {
	printf 'release: REFUSED: %s\n' "$*" >&2
	exit 1
}
cleanup() {
	set +e
	trap '' PIPE
	[ -n "$WORK" ] && [ -d "$WORK" ] && rm -rf -- "$WORK"
}
trap cleanup EXIT

while [ "$#" -gt 0 ]; do
	case "$1" in
	--candidate) CANDIDATE=yes; shift ;;
	--out) [ "$#" -ge 2 ] || die "--out needs a directory"; OUT=$2; shift 2 ;;
	--previous-schema) [ "$#" -ge 2 ] || die "--previous-schema needs a file"; PREV_SCHEMA=$2; shift 2 ;;
	--changes-for) [ "$#" -ge 2 ] || die "--changes-for needs a version"; CHANGES_FOR=$2; shift 2 ;;
	--platform) [ "$#" -ge 2 ] || die "--platform needs a value"; PLATFORM=$2; shift 2 ;;
	--repo) [ "$#" -ge 2 ] || die "--repo needs a directory"; ROOT=$(cd -- "$2" && pwd -P) || die "no such repository"; shift 2 ;;
	*) die "unknown argument '$1'" ;;
	esac
done

[ "$PLATFORM" = "linux/amd64" ] || die "only linux/amd64 is built (decision D4); got '$PLATFORM'"
GOOS=linux GOARCH=amd64
[ -n "$OUT" ] || OUT=$ROOT/dist

for tool in go git tar gzip sha256sum awk sort mktemp find install; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is not on PATH"
done

# ---- 1. the tree: a clean git repository (untracked files count) -----------
top=$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null) || die "$ROOT is not a git repository"
[ "$(cd -- "$top" && pwd -P)" = "$ROOT" ] || die "$ROOT is not the top of its repository"
if [ -n "$(git -C "$ROOT" status --porcelain 2>&1)" ]; then
	die "the working tree is not clean (a change or an untracked file): a release is built from a commit, never from a modified tree"
fi
HEAD_COMMIT=$(git -C "$ROOT" rev-parse HEAD) || die "cannot read HEAD"
CT=$(git -C "$ROOT" log -1 --format=%ct HEAD) || die "cannot read the commit time"

# ---- 2. the tag --------------------------------------------------------------
TAG=""
tag_re='^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'
n_valid=0
while IFS= read -r t; do
	[ -n "$t" ] || continue
	if [[ $t =~ $tag_re ]]; then
		TAG=$t
		n_valid=$((n_valid + 1))
	elif [[ $t =~ ^v[0-9] ]] && [ "$CANDIDATE" = no ]; then
		die "tag '$t' points at HEAD but is not a valid release tag (^v<major>.<minor>.<patch>(-rc.<n>)?\$): -alpha, -beta, -rc and -rc.1.2 are refused"
	fi
done < <(git -C "$ROOT" tag --points-at HEAD)
[ "$n_valid" -le 1 ] || die "$n_valid release tags point at HEAD"
if [ "$CANDIDATE" = no ]; then
	[ -n "$TAG" ] || die "HEAD is not exactly a release tag (v<major>.<minor>.<patch>); tag it yourself and re-run, or use --candidate"
	VER=$TAG
	CHANGES_VER=$TAG
else
	VER="candidate-${HEAD_COMMIT:0:12}"
	CHANGES_VER=${CHANGES_FOR:-Unreleased}
fi

# ---- 3. the toolchain: the one go.mod names, copied from CI's rule ----------
# setup-go's parseGoVersionFile (actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e),
# column-0 anchored, exactly as hack/gate/clean-export.sh copies it: never an
# "equivalent-looking" parse (instruments-that-lie-green #20).
tc=$(awk '
	t == "" && match($0, /^toolchain go1\.[0-9]+(\.[0-9]+|rc[0-9]+)?/) { t = "go" substr($0, 13, RLENGTH - 12) }
	g == "" && match($0, /^go [0-9]+(\.[0-9]+)*/) { g = "go" substr($0, 4, RLENGTH - 3) }
	END { if (t != "") print t; else print g }
' "$ROOT/go.mod") || die "cannot read go.mod"
case "$tc" in
go[0-9]*.[0-9]*.[0-9]*) ;;
*) die "cannot derive a full toolchain version from go.mod (got [$tc])" ;;
esac
have=$(GOTOOLCHAIN=local go version 2>&1) || die "go version failed: $have"
case "$have" in
"go version $tc "*) ;;
*) die "the local toolchain is [$have], go.mod names $tc: a release is built with exactly the toolchain go.mod names" ;;
esac
GOMODCACHE=$(go env GOMODCACHE) GOCACHE=$(go env GOCACHE) GOROOT_=$(go env GOROOT)
[ -n "$GOMODCACHE" ] && [ -n "$GOCACHE" ] && [ -n "$GOROOT_" ] || die "cannot read the go environment"

# ---- 4. the output directory: never overwritten -----------------------------
if [ -e "$OUT" ]; then
	[ -d "$OUT" ] || die "$OUT exists and is not a directory"
	[ -z "$(find "$OUT" -mindepth 1 -maxdepth 1 -print -quit)" ] || die "$OUT is not empty: a release is never written over another"
fi
WORK=$(mktemp -d) || die "mktemp failed"

# ---- 5. build from a clone of the tag (or of HEAD for a candidate) ----------
SRC=$WORK/src
git clone --quiet --no-hardlinks "$ROOT" "$SRC" || die "git clone failed"
if [ -n "$TAG" ]; then
	git -C "$SRC" checkout --quiet --detach "refs/tags/$TAG" || die "cannot check out tag $TAG in the clone"
else
	git -C "$SRC" checkout --quiet --detach "$HEAD_COMMIT" || die "cannot check out HEAD in the clone"
fi
[ "$(git -C "$SRC" rev-parse HEAD)" = "$HEAD_COMMIT" ] || die "the clone is not at HEAD (the tag does not name HEAD's commit)"

# NOT GOPROXY=off. Measured (Go 1.27.4): with GOPROXY=off the toolchain stamps a
# STALE pseudo-version on a commit that was built before in any directory once
# that commit is tagged (a candidate built, then the same commit tagged: the
# "release" came out v0.0.0-<time>-<rev>, release=false). Any other value
# recomputes the tag. A proxy that cannot serve anything keeps the build offline
# (GOFLAGS=-mod=readonly plus go.sum: nothing is fetched, a missing module fails)
# without that defect; the identity checks below refuse a build that still
# carries the wrong version.
BUILD_ENV=(CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH GOFLAGS=-mod=readonly GOPROXY=file:///nonexistent-pveforge-release GOWORK=off GOTOOLCHAIN=local GOENV=off GOMODCACHE="$GOMODCACHE" GOCACHE="$GOCACHE")
STAGE=$WORK/stage
mkdir -p "$STAGE" || die "mkdir failed"
( cd "$SRC" && env "${BUILD_ENV[@]}" go build -trimpath -buildvcs=true -o "$STAGE/pveforge" ./cmd/pveforge ) || die "go build failed"

# ---- 6. what the binary says it is ------------------------------------------
kv=$("$STAGE/pveforge" version) || die "the built binary does not run"
getkv() { printf '%s\n' "$kv" | awk -F= -v k="$1" '$1 == k { sub(/^[^=]*=/, ""); print; exit }'; }
[ "$(getkv static)" = true ] || die "the binary is not static (version says static=$(getkv static))"
[ "$(getkv trimpath)" = true ] || die "the binary was not built with -trimpath"
[ "$(getkv stamped)" = true ] || die "the binary carries no VCS stamp"
[ "$(getkv dirty)" = false ] || die "the binary says dirty=$(getkv dirty)"
[ "$(getkv commit)" = "$HEAD_COMMIT" ] || die "the binary's commit $(getkv commit) is not HEAD $HEAD_COMMIT"
[ "$(getkv goos)" = "$GOOS" ] && [ "$(getkv goarch)" = "$GOARCH" ] || die "the binary is for $(getkv goos)/$(getkv goarch)"
if [ "$CANDIDATE" = no ]; then
	if [[ $TAG =~ -rc\.[0-9]+$ ]]; then
		# a release-candidate TAG is not a release: release=false, prerelease=true
		[ "$(getkv release)" = false ] && [ "$(getkv prerelease)" = true ] && [ "$(getkv version)" = "$TAG" ] || die "the binary says version=$(getkv version) release=$(getkv release) prerelease=$(getkv prerelease), the tag is $TAG: an rc tag must build release=false prerelease=true"
	else
		[ "$(getkv release)" = true ] && [ "$(getkv version)" = "$TAG" ] || die "the binary says version=$(getkv version) release=$(getkv release), the tag is $TAG: a tagged build must be release=true"
	fi
else
	[ "$(getkv release)" = false ] || die "a candidate must not claim release=true"
fi
# relative path: the first line names the file, and a temp directory in it would make two builds differ
( cd "$STAGE" && go version -m pveforge ) >"$STAGE/BUILDINFO.txt" || die "go version -m failed"

# ---- 7. the schema OF the shipped binary (run, not regenerated) -------------
"$STAGE/pveforge" schema >"$WORK/schema.json" || die "schema failed"
[ -s "$WORK/schema.json" ] || die "schema is empty"
grep -q '"schemaVersion": 2' "$WORK/schema.json" || die "schema.json is not schema version 2"

# ---- 8. CHANGES.md: this version's section, honest about breaks -------------
[ -f "$SRC/CHANGES.md" ] || die "CHANGES.md is missing"
section=$(awk -v want="$CHANGES_VER" '
	/^## / { if (on) exit; h=substr($0,4); sub(/ .*/,"",h); if (h == want) on = 1 }
	on { print }
' "$SRC/CHANGES.md")
[ -n "$section" ] || die "CHANGES.md has no '## $CHANGES_VER' section"
for h in Breaking Added Fixed Contract; do
	grep -q "^### $h\$" <<<"$section" || die "CHANGES.md section $CHANGES_VER lacks '### $h' (write 'none' if empty)"
done
breaking_body=$(printf '%s\n' "$section" | awk '/^### Breaking$/ { on = 1; next } /^### / { on = 0 } on { print }' | sed -e 's/^[[:space:]]*[-*][[:space:]]*//' | tr -d '[:space:].' | tr '[:upper:]' '[:lower:]')
if [ -n "$PREV_SCHEMA" ]; then
	[ -f "$PREV_SCHEMA" ] || die "--previous-schema $PREV_SCHEMA is not a file"
	diffout=$("$STAGE/pveforge" schema diff "$PREV_SCHEMA" "$WORK/schema.json") || die "schema diff failed"
	verdict=$(printf '%s\n' "$diffout" | awk -F= '$1 == "verdict" { print $2; exit }')
	say "schema diff against the previous release: verdict=$verdict"
	if [ "$verdict" = breaking ] && { [ "$breaking_body" = none ] || [ -z "$breaking_body" ]; }; then
		die "the schema diff finds a BREAKING change and CHANGES.md says Breaking: none"
	fi
fi

# ---- 9. the licence bundle: the DERIVED module set, exactly -----------------
derived=$(cd "$SRC" && env "${BUILD_ENV[@]}" go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' ./cmd/pveforge | sort -u) || die "go list failed"
[ -n "$derived" ] || die "no linked module was found: the derivation is broken"
derived_set=$(printf '%s\n' "$derived" | awk '{ print $1 " " $2 }' | sort -u)
# the notices table rows for this GOOS: "| `path` | vX | licence |"; a row marked
# "Windows only" is not linked on linux
table_set=$(awk -v goos="$GOOS" -F'|' '
	/^\| `/ {
		p = $2; v = $3; l = $4
		gsub(/[` ]/, "", p); gsub(/ /, "", v)
		if (goos != "windows" && l ~ /Windows only/) next
		print p " " v
	}' "$SRC/THIRD-PARTY-NOTICES.md" | sort -u)
if [ "$derived_set" != "$table_set" ]; then
	printf 'derived from go list:\n%s\nTHIRD-PARTY-NOTICES.md rows for %s:\n%s\n' "$derived_set" "$GOOS" "$table_set" >&2
	die "the linked module set differs from THIRD-PARTY-NOTICES.md (exact equality is required)"
fi
printf '%s\n' "$derived" >"$WORK/modlist" || die "cannot write the module list"
lic_out=$("$ROOT/hack/release/licenses.sh" "$WORK/modlist" "$STAGE/licenses") || die "the licence bundle was refused: $lic_out"
n_mod=${lic_out##*licenses: }; n_mod=${n_mod%% *}
[ "$n_mod" = "$(printf '%s\n' "$derived_set" | grep -c .)" ] || die "bundled $n_mod modules, derived $(printf '%s\n' "$derived_set" | grep -c .)"
mkdir -p "$STAGE/licenses/go" || die "mkdir failed"
[ -f "$GOROOT_/LICENSE" ] || die "Go's own LICENSE is missing at $GOROOT_/LICENSE"
install -m 0644 "$GOROOT_/LICENSE" "$STAGE/licenses/go/LICENSE" || die "cannot copy Go's LICENSE"

# ---- 10. assemble ------------------------------------------------------------
install -m 0644 "$SRC/LICENSE" "$STAGE/LICENSE" || die "cannot copy LICENSE"
install -m 0644 "$SRC/THIRD-PARTY-NOTICES.md" "$STAGE/THIRD-PARTY-NOTICES.md" || die "cannot copy the notices"
printf '%s\n' "$section" >"$STAGE/CHANGES.md" || die "cannot write CHANGES.md"
install -m 0644 "$WORK/schema.json" "$STAGE/schema.json" || die "cannot copy schema.json"
mkdir -p "$STAGE/docs/man" || die "mkdir failed"
for m in "$SRC"/docs/man/*.1; do
	install -m 0644 "$m" "$STAGE/docs/man/" || die "cannot copy $m"
done
chmod 0755 "$STAGE/pveforge" || die "chmod failed"
find "$STAGE" -type d -exec chmod 0755 {} + || die "chmod failed"
find "$STAGE" -type f ! -name pveforge -exec chmod 0644 {} + || die "chmod failed"

NAME=pveforge-$VER-$GOOS-$GOARCH
mkdir -p "$WORK/pack" || die "mkdir failed"
mv "$STAGE" "$WORK/pack/$NAME" || die "mv failed"
mkdir -p "$OUT" || die "cannot create $OUT"
# deterministic archives: sorted names, owner 0, the COMMIT time as every mtime,
# gzip without a name or timestamp
( cd "$WORK/pack" && tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$CT" --format=gnu -cf - "$NAME" ) |
	gzip -n -9 >"$OUT/$NAME.tar.gz" || die "packing failed"
git -C "$SRC" archive --format=tar --prefix="pveforge-$VER-source/" HEAD | gzip -n -9 >"$OUT/pveforge-$VER-source.tar.gz" || die "git archive failed"
install -m 0644 "$WORK/schema.json" "$OUT/schema-$VER.json" || die "cannot copy the schema"
( cd "$OUT" && for f in $(ls | grep -v '^SHA256SUMS$' | sort); do sha256sum -- "$f"; done >SHA256SUMS ) || die "sha256sum failed"
( cd "$OUT" && sha256sum -c --quiet SHA256SUMS ) || die "SHA256SUMS does not verify"
[ -s "$OUT/$NAME.tar.gz" ] || die "the archive is empty"

say "version        $(getkv version)  (release=$(getkv release) commit=$(getkv commit))"
say "modules        $n_mod licence texts + Go's"
say "artifacts      $(ls "$OUT" | tr '\n' ' ')"
if [ "$CANDIDATE" = no ]; then
	say "the release $VER PASSED: built from tag $TAG at $HEAD_COMMIT into $OUT (nothing was tagged, pushed or published)"
else
	say "the candidate $VER PASSED: built from $HEAD_COMMIT into $OUT, release=false (nothing was tagged, pushed or published)"
fi
exit 0
