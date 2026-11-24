# Releasing pveforge

pveforge is a **provider**: a consumer pins a release and verifies it on its own
hosts. This page is the process, the policy that decides what a version number
means, and what a consumer needs to pin a release and to detect a break. Tagging,
pushing and publishing are the **operator's** steps: nothing in the repository
tags, pushes or publishes (the release scripts contain no `git tag`, `git push`
or network call; a test pins that).

## What a consumer pins and checks

| What | How |
|---|---|
| Which release is this binary | `pveforge version` (kv) or `pveforge version -o json`. `release=true` only for a clean build of a semver tag with no `replace`. `stamped=false` is an export or a `-buildvcs=false` build; `dirty=true` a modified tree. `commit_time` is the commit's time. |
| That the artifact is the one published | `sha256sum -c SHA256SUMS`, then `hack/release/verify.sh <dir>` (it extracts the archive, runs the binary, and compares it with `BUILDINFO.txt`, the schema files and the licence directories). |
| That it can be rebuilt | The archive carries `BUILDINFO.txt` (`go version -m`): the Go version, `CGO_ENABLED=0`, `-trimpath`, the commit. With the same Go toolchain, `make release` on the tag gives a byte-identical binary and archive. |
| The contract of this release | `schema-<version>.json` (also inside the archive as `schema.json`): the command tree, flags (type, default, required), arguments, mutation tiers, exit statuses per verb, output keys per verb, environment variables and roster keys. |
| What changed since the last release | `pveforge schema diff <previous schema.json> <this schema.json>` (verdict `none`, `additive`, `breaking`, `incomparable`) and `CHANGES.md`. |

## Versions

A release version is `v<major>.<minor>.<patch>`; `-rc.<n>` marks a release
candidate tag. No other suffix is a valid release tag (`make release` refuses
`-alpha`, `-beta`, `-rc` and `-rc.1.2`); `release=true` is only ever a plain
`v<major>.<minor>.<patch>`. The first release is `v0.1.0`.

**What is contract** (a change to any of these is a change to the version):

1. command and subcommand names and aliases;
2. positional arguments and flags: name, shorthand, type, default, requiredness
   (including a flag the command itself refuses to run without);
3. the mutation tier of every command (`safe`, `mutating`, `destructive`);
4. exit statuses, global and per verb, and the named states `child_status` and
   `unobserved_dispatch`;
5. the kv/json **keys** of what a verb renders, and their kinds (a PVE object a
   verb prints is PVE's, not pveforge's: `passthrough`);
6. the roster file's keys;
7. the environment variables pveforge reads, sets or strips, with their
   direction, whether they are secret, and their scope.

Not contract: the text of an error or a notice, `usage`/`short` wording, man-page
prose, the order of kv keys beyond "sorted".

**Breaking** is anything `pveforge schema diff` reports as `breaking`: a removed
or renamed verb, flag, shorthand, alias, environment variable, output key or
roster key; a changed flag type or default (any flag); a changed requiredness;
any mutation-tier change, in either direction; a changed, removed or reordered
argument; a removed exit status, **or a verb gaining one** (a consumer keyed on
`1` sees different behaviour); a removed or renamed named state.
**Additive** is a new verb, alias, optional flag, optional argument, output key,
environment variable or roster key. Wording is informational: a changed `short`, flag usage or exit-status meaning is reported as an informational finding and does not change the verdict.

**Incomparable is never "none".** `pveforge schema diff` reports `incomparable` (and names why) when either file has a `schemaVersion` newer than the binary compares, carries a JSON field the binary does not know, or lacks a surface the other has: an older `schema diff` cannot vouch for a newer schema, so a consumer should upgrade to the newer release's `pveforge` to compare. A real breaking finding still wins over `incomparable`.

**The number**, while the major version is 0 (decision D2): a breaking change
raises the **minor**; an additive change raises the minor; a fix raises the
patch. From 1.0 a breaking change raises the major. `pveforge schema diff`
decides the class; the operator chooses the number. `make release` refuses a
release whose CHANGES section says `Breaking: none` when the diff finds a
breaking change.

## The operator's steps

1. **Land the work and run the gate**: `make gate` (alone, on an idle machine).
2. **Edit `CHANGES.md`**: the section heading is `## <version>`; the four
   headings `Breaking`, `Added`, `Fixed`, `Contract` stay (write `none` when
   empty). Commit it.
3. **Build a candidate first** (optional, nothing is tagged):
   `make release-candidate CHANGES_FOR=v0.1.0`, then `make release-verify`. The
   candidate says `release=false`: it is not a release.
4. **Tag, yourself**: `git tag -a v0.1.0 -m "pveforge v0.1.0"` on the commit you
   built. The scripts never create a tag.
5. **Build the release**: `make release` (add
   `RELEASE_ARGS="--previous-schema /path/to/previous/schema.json"` so a breaking
   diff must be admitted in CHANGES), then `make release-verify`.
   The script refuses a dirty tree, a HEAD that is not exactly the tag, an invalid
   tag shape, a toolchain other than the one `go.mod` names, a module set that
   differs from `THIRD-PARTY-NOTICES.md`, a module without its licence text, and
   an output directory that is not empty.
6. **Check what you are about to publish**: the `SHA256SUMS`, `schema-<version>.json`
   and, for a new release, the `schema diff` against the previous one.
7. **Push the tag and publish the artifacts**, yourself. There is no signing in the
   process (decision D11): `SHA256SUMS` is the integrity statement; add your own
   signature if you want one.

## What is in the artifacts

`pveforge-<version>-linux-amd64.tar.gz` holds `pveforge` (static), `LICENSE`
(pveforge's dual MIT / Apache-2.0), `THIRD-PARTY-NOTICES.md`, `licenses/` (the
full licence text of every module linked into the binary, every module's `NOTICE`,
and Go's own `LICENSE`), `schema.json`, this release's `CHANGES.md` section,
`BUILDINFO.txt` and the man pages. `pveforge-<version>-source.tar.gz` is
`git archive` of the tag. The platform is linux/amd64 only (decision D4).

## The static build and name resolution

The binary is built with `CGO_ENABLED=0`, so it uses Go's own DNS resolver and not
libc's: `nsswitch.conf` modules such as mDNS or NIS are not consulted (`/etc/hosts`
is). A roster host given as an IP address, or a name in DNS or `/etc/hosts`, is
unaffected. This is a documented difference, not a measured one: only the
`/etc/hosts` case is tested.
