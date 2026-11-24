#!/usr/bin/env bash
# hack/release/verify.sh DIR: verify a release (or candidate) built by release.sh.
#
# It trusts nothing the build said about itself: it re-reads DIR, checks
# SHA256SUMS, extracts the archive into a scratch directory, RUNS the shipped
# binary, and compares what it reports with BUILDINFO.txt (the toolchain's own
# record), the standalone schema file, the schema inside the archive and the
# licence directory. Judge it ONLY by its last line, "verify: PASSED".
set -o pipefail
export LC_ALL=C
say() { printf 'verify: %s\n' "$*" >&2; }
die() { printf 'verify: REFUSED: %s\n' "$*" >&2; exit 1; }
[ "$#" -eq 1 ] || die "usage: verify.sh DIR"
DIR=$1
[ -d "$DIR" ] || die "$DIR is not a directory"
for tool in tar gzip sha256sum awk sort mktemp find; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is not on PATH"
done
( cd "$DIR" && sha256sum -c --quiet SHA256SUMS ) || die "SHA256SUMS does not verify"
# every file in DIR (but the sums) is listed, so a file cannot ride along unchecked
listed=$(awk '{ print $2 }' "$DIR/SHA256SUMS" | sort)
present=$(cd "$DIR" && ls | grep -v '^SHA256SUMS$' | sort)
[ "$listed" = "$present" ] || die "SHA256SUMS does not list exactly the files in $DIR"
arch=$(cd "$DIR" && ls | grep -- '-linux-amd64\.tar\.gz$')
[ "$(printf '%s\n' "$arch" | grep -c .)" = 1 ] || die "expected exactly one linux-amd64 archive in $DIR"
W=$(mktemp -d) || die "mktemp failed"
trap 'rm -rf -- "$W"' EXIT
tar -xzf "$DIR/$arch" -C "$W" || die "cannot extract $arch"
B=$(find "$W" -mindepth 1 -maxdepth 1 -type d | head -n 1)
[ -n "$B" ] || die "the archive has no top directory"
for f in pveforge LICENSE THIRD-PARTY-NOTICES.md CHANGES.md schema.json BUILDINFO.txt licenses/go/LICENSE docs/man; do
	[ -e "$B/$f" ] || die "the archive lacks $f"
done
kv=$("$B/pveforge" version) || die "the shipped binary does not run"
getkv() { printf '%s\n' "$kv" | awk -F= -v k="$1" '$1 == k { sub(/^[^=]*=/, ""); print; exit }'; }
[ "$(getkv static)" = true ] && [ "$(getkv trimpath)" = true ] && [ "$(getkv stamped)" = true ] && [ "$(getkv dirty)" = false ] || die "the shipped binary's identity is not a clean, stamped, static, trimpath build: $kv"
# the binary's own report against the toolchain's record
grep -q "CGO_ENABLED=0" "$B/BUILDINFO.txt" || die "BUILDINFO.txt does not record CGO_ENABLED=0"
grep -q "vcs.revision=$(getkv commit)" "$B/BUILDINFO.txt" || die "BUILDINFO.txt's vcs.revision is not the binary's commit"
grep -q "build.-trimpath=true\|-trimpath=true" "$B/BUILDINFO.txt" || die "BUILDINFO.txt does not record -trimpath"
# the schema inside the archive is what the shipped binary prints now, and the standalone file is the same bytes
"$B/pveforge" schema >"$W/schema.now" || die "schema failed"
cmp -s "$W/schema.now" "$B/schema.json" || die "schema.json in the archive is not the shipped binary's schema"
standalone=$(cd "$DIR" && ls | grep '^schema-.*\.json$')
cmp -s "$DIR/$standalone" "$B/schema.json" || die "the standalone schema differs from the archive's"
# the licence directory against the modules the toolchain recorded in the binary
rec=$(awk '$1 == "dep" { print $2 "@" $3 }' "$B/BUILDINFO.txt" | sort -u)
have=$(cd "$B/licenses" && find . -mindepth 2 -type d -name '*@*' | sed 's|^\./||' | sort -u)
[ -n "$rec" ] || die "BUILDINFO.txt records no module"
[ "$rec" = "$have" ] || { printf 'recorded:\n%s\nbundled:\n%s\n' "$rec" "$have" >&2; die "the licence directories are not exactly the modules recorded in the binary"; }
while IFS= read -r d; do
	n=$(find "$B/licenses/$d" -maxdepth 1 -type f | grep -ic 'licen[cs]e\|copying')
	[ "${n:-0}" -ge 1 ] || die "$d has no licence text"
done <<<"$have"
say "version $(getkv version) release=$(getkv release) commit=$(getkv commit); $(printf '%s\n' "$have" | grep -c .) module licence directories; checksums verify"
say "PASSED"
