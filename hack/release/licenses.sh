#!/usr/bin/env bash
# hack/release/licenses.sh MODLIST OUTDIR: copy the licence texts of a module set.
#
# MODLIST is a file of lines "<module path> <version> <directory>" (what
# release.sh derives from `go list -deps`, main module excluded). For each module
# it copies every licence file, matched CASE-INSENSITIVELY against
# ^(licen[cs]e|copying|unlicense)([.-].*)?$ (so LICENSE, LICENSE.md, LICENSE.txt,
# License, COPYING-GPL) and EVERY NOTICE* file, into OUTDIR/<path>@<version>/.
# A module with no licence file REFUSES the run: its text must ship with the
# binary. Prints "licenses: <n> modules" on success. Separate from release.sh so
# a fixture module set can drive it (internal/sourceguard TestRelease_Licenses*).
set -o pipefail
export LC_ALL=C
die() { printf 'licenses: REFUSED: %s\n' "$*" >&2; exit 1; }
[ "$#" -eq 2 ] || die "usage: licenses.sh MODLIST OUTDIR"
MODLIST=$1 OUTDIR=$2
[ -f "$MODLIST" ] || die "$MODLIST is not a file"
lic_re='^(licen[cs]e|copying|unlicense)([.-].*)?$'
notice_re='^notice([.-].*)?$'
n=0
while IFS=' ' read -r mpath mver mdir; do
	[ -n "$mpath" ] || continue
	[ -d "$mdir" ] || die "module $mpath@$mver: $mdir is not a directory"
	dest=$OUTDIR/$mpath@$mver
	mkdir -p "$dest" || die "mkdir $dest failed"
	nl=0
	while IFS= read -r f; do
		base=${f##*/}
		lower=${base,,}
		if [[ $lower =~ $lic_re ]]; then
			install -m 0644 "$f" "$dest/$base" || die "cannot copy $f"
			nl=$((nl + 1))
		elif [[ $lower =~ $notice_re ]]; then
			install -m 0644 "$f" "$dest/$base" || die "cannot copy $f"
		fi
	done < <(find "$mdir" -maxdepth 1 -type f | sort)
	[ "$nl" -ge 1 ] || die "module $mpath@$mver has no licence file (LICENSE*, COPYING*, UNLICENSE*): its text must ship with the binary"
	n=$((n + 1))
done <"$MODLIST"
[ "$n" -ge 1 ] || die "no module was listed: the derivation is broken"
printf 'licenses: %d modules\n' "$n"
