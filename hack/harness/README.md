# The nested PVE test harness, end to end

A nested Proxmox cluster, `pvh` (VMs 690 pvh-n1, 691 pvh-n2 and 692 pvh-nfs on
qa-pve-07), for pveforge's real end-to-end and destructive tests (epic
`pveforge-nested-pve-test-harness`). This page gives the order of the steps,
who runs each one, and which secrets each needs. Each script's header has its
details.

## Secrets

The secrets live in one age-encrypted blob in this directory
(`pveforge-harness-secrets-unlock`). `hack/harness/unlock.sh run -- <cmd>`
puts them into `<cmd>`'s environment only, and a blob can hold only these two
names:

- `PVEFORGE_ROSTER_PASSPHRASE`: encrypts both harness rosters, the outer
  `~/.config/pveforge/harness-qa-pve-07-outer.toml` (the pool token; host-keyed
  `harness-<OUTER_NODE>-outer.toml` since `b21c9c2`) and the nested
  `~/.config/pveforge/harness-nested.toml`.
- `PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD`: root's password on the nested
  nodes. It is a test password, never the outer one.

The outer root password is in no blob and never reaches an agent. Only the
operator types it, at D5's G4. No step uses 1Password.

The steps that run pveforge also need `PVEFORGE_BIN`, the absolute path of the
pveforge binary: D5's verify-token.sh, the probe, build, nested, golden and
reset. prepare-iso.sh, cluster.sh and D5's verify-root.sh don't run pveforge. The steps that read
the nested cluster also need
`PVEFORGE_HARNESS_OUTER_ROSTERS`, which lists the outer rosters, since the
guard refuses any overlap with them. golden.sh and reset.sh need
`PVEFORGE_HARNESS_ROSTER` set to the nested roster; nested.sh sets it itself.

## The pveforge binary must be a clean build of a commit

`harness_init` reads the build info the binary carries (`go version -m`) and
refuses a `PVEFORGE_BIN` that corresponds to no commit, so the harness cannot
run a build nobody can reproduce:

- **refused (exit 2):** `vcs.modified=true` (built from a tree with a change
  or an untracked file), no VCS info at all (`-buildvcs=false`, a build from a
  `git archive` export, or a file that is not a Go binary), or no `go` on `PATH`;
- **warned, and it runs:** `vcs.revision` is not `HEAD` of the checkout that
  holds `lib.sh` (a `.wt/` worktree build is such), or that `HEAD` cannot be
  read (no `git`, or not a repository).

Build it with `make build`, from a tree with no changes and no untracked files
(`git status` empty), then point `PVEFORGE_BIN` at `bin/pveforge`.

## Migrating from the pre-`b21c9c2` names

Before `b21c9c2` the outer roster was `harness-outer.toml` and the P0 baseline
`harness-outer.p0`. The harness now reads names keyed from `OUTER_NODE` in
`harness-outer.env` (`harness-<OUTER_NODE>-outer.toml`, `harness-<OUTER_NODE>-outer.p0`),
and it never reads the old names and never falls back to them: a missing
host-keyed roster is refused (exit 2), and the refusal says so.

To migrate, COPY the old files to the host-keyed names in your own terminal,
preserving modes (the roster 0600, the `.p0` directory 0700). **qa-pve-07 was
already migrated on 2026-11-05: its host-keyed copies exist, so on this host the
copy step below must NOT be run.** Each line stands alone, uses absolute paths
(no `cd`), and refuses visibly when its destination exists, so pasting one line
is safe by itself. The refusal is a check followed by a copy, not an atomic
step: run these lines only when no other pveforge process is running on this
host (the same precondition as the cleanup below), or a concurrent writer could
create the destination between the check and the copy:

```
if [ -e ~/.config/pveforge/harness-qa-pve-07-outer.toml ] || [ -L ~/.config/pveforge/harness-qa-pve-07-outer.toml ]; then echo "harness-qa-pve-07-outer.toml exists - stop: already migrated"; else cp -p -- ~/.config/pveforge/harness-outer.toml ~/.config/pveforge/harness-qa-pve-07-outer.toml; fi
if [ -e ~/.config/pveforge/harness-qa-pve-07-outer.p0 ] || [ -L ~/.config/pveforge/harness-qa-pve-07-outer.p0 ]; then echo "harness-qa-pve-07-outer.p0 exists - stop: already migrated"; else cp -a -- ~/.config/pveforge/harness-outer.p0 ~/.config/pveforge/harness-qa-pve-07-outer.p0; fi
```

The roster's encrypted secret travels with the file; nothing is re-credentialled.
Rekey, TLS re-pin and validate then act on the host-keyed file (the docs name it).

Deleting the old set is a separate, later step of yours, and only when NO
pveforge process in ANY session is still using the old roster: its `.lock` file
and `.locks/` directory are live synchronisation paths
(`internal/roster/writeback.go`, `internal/lock/lock.go`), and unlinking one
while a process holds it lets a later process take a second, unrelated lock.
Once that holds, one operation per line, absolute paths:

```
rm -rf -- ~/.config/pveforge/harness-outer.p0
rm -f -- ~/.config/pveforge/harness-outer.toml
rm -f -- ~/.config/pveforge/harness-outer.toml.lock
rm -rf -- ~/.config/pveforge/harness-outer.toml.locks
```

## `PATH`

`lib.sh` resolves `jq`, `grep`, `flock`, `sha256sum`, `stat`, `mktemp`, `mkdir`,
`sleep` and `date` from `PATH` once, when it is sourced, and refuses with
`harness: refusing: <tool> is not on PATH` (exit 2). On this workstation `jq`
lives in `~/.local/bin`, which a scrubbed PATH (`env -i`, cron, a bare agent
pane) leaves out. Run harness steps with your login `PATH`, or add that
directory explicitly.

## The order

The implementor steps run under the Chair's GO. Every run writes new evidence
under `~/.config/pveforge/harness-evidence/`, which is never overwritten.

| # | Step | Command | Who | Secrets | Task |
|---|---|---|---|---|---|
| 1 | D5: the outer pool, its owner and the scoped token | `d5/sequence.md`, printed, never self-executing (revert: `d5/revert.md`) | Implementor for the root writes (key-based root ssh) and gates G0–G3 and G5. **The operator** runs G4 in their own terminal. | G4: the **outer root password** and `PVEFORGE_ROSTER_PASSPHRASE`. G5: `PVEFORGE_ROSTER_PASSPHRASE`. | `pveforge-harness-d5-scripts` |
| 2 | The storage capability probe | `unlock.sh run -- hack/harness/probe.sh --storage <id>` | Implementor | `PVEFORGE_ROSTER_PASSPHRASE` | `pveforge-harness-capability-probe` |
| 3 | The installer ISOs | `unlock.sh run -- hack/harness/build/prepare-iso.sh` (workstation only) | Implementor | `PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD` (it becomes a crypt hash in the answer files) | `pveforge-harness-build` |
| 3a | Uploads | `pvh-n1-auto.iso` and `pvh-n2-auto.iso` to qa-pve-07 `local:iso/`, and the Debian 13 genericcloud image to `local:import/` | **The operator**, as root on qa-pve-07 | root's own access | `pveforge-harness-build` |
| 4 | The three VMs | `unlock.sh run -- hack/harness/build/build.sh --storage <id>` | Implementor | `PVEFORGE_ROSTER_PASSPHRASE` | `pveforge-harness-build` |
| 5 | The nested cluster `pvh` | `unlock.sh run -- hack/harness/build/cluster.sh` | Implementor | `PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD` (sent over ssh, on stdin, for n2's join) | `pveforge-harness-build` |
| 6 | The nested bootstrap (the roster `harness-nested.toml`, targets pvh-n1 and pvh-n2) | `unlock.sh run -- hack/harness/nested.sh bootstrap` | Implementor | `PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD` (put in the bootstrap child's environment only, as `PVEFORGE_PVE_PASSWORD`), `PVEFORGE_ROSTER_PASSPHRASE` | `pveforge-harness-golden-reset` |
| 7 | The nested bridge `pvhbr1` | `unlock.sh run -- hack/harness/nested.sh bridge` | Implementor | `PVEFORGE_ROSTER_PASSPHRASE` | `pveforge-harness-golden-reset` |
| 8 | The golden point | `unlock.sh run -- hack/harness/golden.sh --storage <id>` | Implementor | `PVEFORGE_ROSTER_PASSPHRASE` | `pveforge-harness-golden-reset` |
| 9 | Reset, as often as needed | `unlock.sh run -- hack/harness/reset.sh --storage <id>` | Implementor, under D11's standing authority: 690–692 only, through the pool token only | `PVEFORGE_ROSTER_PASSPHRASE` | `pveforge-harness-golden-reset` |

Each step relies on the ones before it:

- **1 → 2:** the probe runs as the pool token D5 minted. It must pass before
  anything is built.
- **3 → 3a → 4:** build.sh refuses to start until both ISOs and the cloud
  image are on qa-pve-07. It pins the nested host keys into
  `harness-nested.known_hosts`.
- **5:** cluster.sh reaches the three VMs only through build.sh's pins and
  the nested key.
- **6:** no node is sent root's password until its host key is verified:
  1. The node must pass an SSH login that trusts only build.sh's ed25519
     pin for it.
  2. Through that authenticated session, nested.sh reads the ECDSA host key
     the node's sshd serves. It needs ECDSA because pveforge's SSH client
     negotiates ECDSA when a host serves one, and a stock PVE node does, so
     build.sh's ed25519 pin cannot be what pveforge compares.
  3. `pveforge bootstrap --host-key-fingerprint <that ECDSA key>` refuses
     any other key before the password is sent.
  4. Afterwards, what bootstrap reports and what the roster records must
     both be that key, or the nested roster is moved aside.

  A node that doesn't serve exactly one ECDSA key is refused before any
  password.

  Each node is bootstrapped with its own `--token-id` (the node name), so the
  tokens are `root@pam!pvh-n1` and `root@pam!pvh-n2`: PVE's token store is
  cluster-wide, so one shared token-id would collide on the second node.
- **After `build.sh --repin`, or any rebuild:** the new VMs have new host
  keys, so the old nested roster's pins no longer match. nested.sh refuses
  that roster before sending any password, naming what it holds. To recover:
  1. Move the old roster aside, e.g. `mv ~/.config/pveforge/harness-nested.toml{,.old}`.
     Its tokens belong to the old nodes.
  2. Rerun step 6, then step 7.
  3. Retake the golden point (step 8), with `--replace-golden` if a golden
     exists already.
- **7:** acceptance (`cmd/pveforge-harness-accept`, through the guard of
  `pveforge-harness-guard`) must pass before either bridge is made.
- **8:** golden.sh needs a passing acceptance before it shuts anything down,
  and it takes the golden point after the bridge, so the point includes it.
  `--replace-golden` retakes all three goldens as one point.
- **9:** reset.sh refuses unless all three goldens carry golden.sh's one
  run stamp.

Common to every script: `lib.sh` (`pveforge-harness-script-base`) is the only
path to the outer cluster. How a script behaves on failure varies:

- **The step scripts** (cluster.sh's steps, nested.sh, golden.sh, reset.sh)
  stop at the first failure and leave things where they are. Their evidence
  says how far they got. The one exception: nested.sh moves the nested
  roster aside when it cannot vouch for that roster's pins.
- **The check scripts** (D5's verify scripts, cluster.sh's final checks) run
  every check even after one goes red, so one run reports them all.
- **build.sh** destroys the VMs its own run created when a step fails,
  unless `--keep-on-failure` is given. It never destroys a VM an earlier run
  built.
- **probe.sh** cleans up what it created in its EXIT trap, or says exactly
  what is left.
