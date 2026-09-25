# The nested PVE test harness, end to end

A nested Proxmox cluster, `pvh` (VMs 690 pvh-n1, 691 pvh-n2 and 692 pvh-nfs on
qa-pve-02), for pveforge's real end-to-end and destructive tests (epic
`pveforge-nested-pve-test-harness`). This page gives the order of the steps,
who runs each one, and which secrets each needs. Each script's header has its
details.

## Secrets

The secrets live in one age-encrypted blob in this directory
(`pveforge-harness-secrets-unlock`). `hack/harness/unlock.sh run -- <cmd>`
puts them into `<cmd>`'s environment only, and a blob can hold only these two
names:

- `PVEFORGE_ROSTER_PASSPHRASE`: encrypts both harness rosters, the outer
  `~/.config/pveforge/harness-outer.toml` (the pool token) and the nested
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

## The order

The implementor steps run under the Chair's GO. Every run writes new evidence
under `~/.config/pveforge/harness-evidence/`, which is never overwritten.

| # | Step | Command | Who | Secrets | Task |
|---|---|---|---|---|---|
| 1 | D5: the outer pool, its owner and the scoped token | `d5/sequence.md`, printed, never self-executing (revert: `d5/revert.md`) | Implementor for the root writes (key-based root ssh) and gates G0–G3 and G5. **The operator** runs G4 in their own terminal. | G4: the **outer root password** and `PVEFORGE_ROSTER_PASSPHRASE`. G5: `PVEFORGE_ROSTER_PASSPHRASE`. | `pveforge-harness-d5-scripts` |
| 2 | The storage capability probe | `unlock.sh run -- hack/harness/probe.sh --storage <id>` | Implementor | `PVEFORGE_ROSTER_PASSPHRASE` | `pveforge-harness-capability-probe` |
| 3 | The installer ISOs | `unlock.sh run -- hack/harness/build/prepare-iso.sh` (workstation only) | Implementor | `PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD` (it becomes a crypt hash in the answer files) | `pveforge-harness-build` |
| 3a | Uploads | `pvh-n1-auto.iso` and `pvh-n2-auto.iso` to qa-pve-02 `local:iso/`, and the Debian 13 genericcloud image to `local:import/` | **The operator**, as root on qa-pve-02 | root's own access | `pveforge-harness-build` |
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
  image are on qa-pve-02. It pins the nested host keys into
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
