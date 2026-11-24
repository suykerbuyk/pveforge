# Changes

Each release has one section, `## <version>`, with the four headings below
(`none` when empty). `make release` refuses a release whose section is missing,
lacks a heading, or says `Breaking: none` while `pveforge schema diff` against
the previous release finds a breaking change. The policy that decides what is
breaking is in [`docs/releasing.md`](docs/releasing.md); what a consumer pins
and diffs is `pveforge version`, `pveforge schema` and the exit-status table in
the README.

## v0.1.0 (not yet tagged; the operator tags it)

The first release. Before it, pveforge was distributed only as source, pinned by
commit. Everything below is relative to that source distribution (up to commit
`1bfab5a`).

### Breaking

- **A verb that dispatches a change can now exit 3 or 4; they were exit 1
  before** (a verb gaining a reserved exit status is a breaking change: a
  consumer keyed on `1` sees different behaviour). 3 = a change was dispatched
  and its outcome was not observed; 4 = refused before anything was changed on a
  PVE host or in the roster file (the definition is in the README). The exit
  sets, from `pveforge schema` (`exits`):
  - 3 and 4: `acl enable-vm-destroy`, `acl grant`, `api delete|post|put`,
    `bootstrap`, `group ensure`, `user ensure`, `harness build|golden|probe|reset`,
    `harness vm destroy|shutdown|stop`, `harness vm snapshot create|delete|rollback`,
    `network bridge create|destroy`, `network set`, `storage create`,
    `storage free-orphans`, `storage set-content`, `vm create`, `vm destroy`,
    `vm snapshot create|delete|rollback`;
  - 4 only: `doctor`, `exec` (before the handover; after it the status is the
    child's: the named state `child_status`), `roster import-token|init|pin-tls|rekey`,
    `storage alloc`, `vm set`.
  Of these only `api` writes, `vm destroy`, `doctor` and `acl enable-vm-destroy`
  used 3 or 4 before.
- **`acl enable-vm-destroy` is one command with a prompt**: it prints a plan, asks
  `Proceed? [y/N]` on a terminal (`--yes` answers for scripts; with no terminal and
  no `--yes` it is refused, exit 4), writes, then reports whether `vm destroy`'s
  reads now succeed (`ready`). Its output is a structured kv/json report (it was
  prose). A write that leaves the check not ready exits 1.
- **The exit statuses are one table**: the README table, `pveforge schema`
  (`exitStatuses`) and the code are held to each other by a test.

### Added

- `pveforge version` and `pveforge --version`: the version, commit, commit time,
  clean or dirty, static, Go version, and `release=true` only for a clean build of
  a semver tag with no `replace`. Read from the build information the toolchain
  stamps; no ldflags.
- A static build (`CGO_ENABLED=0`, `-trimpath`) for linux/amd64, reproducible:
  two builds of one tag are byte-identical. The static binary uses Go's own DNS
  resolver, not libc's (no `nsswitch`, mDNS or NIS); a roster host given as an
  IP address is unaffected.
- `pveforge schema` is schema version 2: `schemaVersion`, `contract.pveforge`
  (the build identity), per-flag `required` / `requiredWhen`, structured `args`,
  per-verb `exits` (with the named states `child_status` and
  `unobserved_dispatch`) and `output` (a golden list of what each verb renders),
  the global `exitStatuses`, `env` (every environment variable read, set or
  stripped) and the roster file's `keys`. Every version-1 field is unchanged.
- `pveforge schema diff <old.json> <new.json>`: classifies the change between two
  releases' schemas as breaking or additive (`--fail-on breaking` for a gate).
- `make release`, `make release-candidate` and `make release-verify`: the
  release process (`docs/releasing.md`): artifacts, `SHA256SUMS`, `schema.json`,
  the full licence text of every linked module, every module `NOTICE`, Go's
  licence, and this file's section.

### Fixed

- none

### Contract

- First release: there is no previous schema to diff. The v1 → v2 diff of the
  development tree (`pveforge schema diff` on the schema of `f731f9e` and this
  release) is `incomparable` (the older file lacks the new surfaces) with no
  breaking finding.

## Unreleased

### Breaking

- none

### Added

- none

### Fixed

- none

### Contract

- none
