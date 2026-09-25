# D5: the outer pool, its owner and its scoped token (printed sequence)

This is the reviewed D5 sequence (task `pveforge-harness-d5-scripts`, from D5
draft r4). It is **printed, never self-executing**: each command below is run
by hand, one at a time, and the run STOPS at every gate. Nothing is retried
after a failure. A red gate goes to the Chair, who decides to fix forward or
to revert with `revert.md`.

- Steps 1-10 are root writes on qa-pve-02, each a single
  `ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com '<pveum ...>'` line,
  run by the implementor (operator ruling 2026-09-24 (2)) after the Chair has
  reviewed this file.
- Step 11 (gate G4) is **OPERATOR-RUN**, in the operator's own terminal: it
  needs root's PVE password, which never reaches an agent.
- Every gate writes its evidence to a new directory under `$E` (below), never
  overwritten. The vault gets a summary, never the raw user list.
- The checks and fixtures: `verify-root.sh` and `verify-token.sh` here, and
  `internal/pve/testdata/permissions/d5r3-expected-*.json`. A test
  (`internal/sourceguard/harness_d5_test.go`) holds this file's commands to
  those fixtures.

Run everything from the repository root.

```
E=~/.config/pveforge/harness-evidence/d5/$(date -u +%Y%m%dT%H%M%SZ)
echo "E=$E"
```

Record the printed `E=…` line with the G0 evidence. The operator's terminal at
G4 is a different shell, so the operator sets `E` to that exact value there.

## G0: step 0, read-only

```
install -d -m 700 ~/.config/pveforge
HARNESS_EVIDENCE="$E"/g0 D5_PIN_ROSTER=pveforge.toml hack/harness/d5/verify-root.sh p0
```

The FIRST thing it does is `ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com true`:
steps 1-10 need non-interactive, key-based root ssh, and if that fails G0 fails
naming it, having read nothing else. Then it reads the ACL list, roles, users,
groups, pools and the storage status, and checks (P1-P5) that nothing named for
the harness exists yet and that storage `pveforge-harness` is active. It scans
every host key qa-pve-02 serves and checks (K1) that the one `./pveforge.toml`
pins for qa-pve-02 is among them, recording which type it is (pveforge's SSH
client prefers ECDSA, so an ed25519-only scan would compare the wrong key).
When K1 passes it prints `PIN host_key_fingerprint=SHA256:…`: the fingerprint
it verified. G4 passes that exact value to bootstrap, so the outer root
password is never sent to a host K1 did not verify.
When every check passes it writes the P0 baseline to
`~/.config/pveforge/harness-outer.p0/` once.

STOP. Evidence: `$E/g0/`, and the P0 baseline.

## G1: steps 1-4, the four roles

```
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum role add PveforgeHarness --privs "Pool.Audit,VM.Allocate,VM.Audit,VM.Config.CDROM,VM.Config.CPU,VM.Config.Cloudinit,VM.Config.Disk,VM.Config.HWType,VM.Config.Memory,VM.Config.Network,VM.Config.Options,VM.PowerMgmt,VM.Snapshot"'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum role add PveforgeHarnessSpace --privs "Datastore.AllocateSpace,Datastore.Audit"'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum role add PveforgeHarnessIso --privs "Datastore.Audit"'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum role add PveforgeHarnessNet --privs "SDN.Use"'
```

Each must exit 0; record each status. Then:

```
HARNESS_EVIDENCE="$E"/g1 hack/harness/d5/verify-root.sh roles
```

V0 (the four roles are exactly the pinned definitions), V0b (every other custom
role is as P0 recorded it), L1b (pveum's raw shape for a custom role, recorded
in `L1b.txt`).

STOP. Evidence: `$E/g1/`.

## G2: steps 5-6, the pool and the owner

```
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum pool add pveforge-harness --comment "pveforge nested harness (D5)"'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum user add pveforge-harness@pve --enable 1 --expire 0 --comment "pveforge harness token owner; no password"'
HARNESS_EVIDENCE="$E"/g2 hack/harness/d5/verify-root.sh owner
```

The user gets no password: it only owns the token. O1 (the pool exists, no
members), O2 (the user, enabled, never expiring), O3 (no ACL row for it yet).

STOP. Evidence: `$E/g2/`.

## G3: steps 7-10, the owner's four ACL rows

These must exist before step 11: bootstrap refuses a non-root owner lacking
them (`ErrOwnerLacksPrivileges`, a non-verdict that touches nothing).

```
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum acl modify /pool/pveforge-harness --users pveforge-harness@pve --roles PveforgeHarness --propagate 0'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum acl modify /storage/pveforge-harness --users pveforge-harness@pve --roles PveforgeHarnessSpace --propagate 0'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum acl modify /storage/local --users pveforge-harness@pve --roles PveforgeHarnessIso --propagate 0'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum acl modify /sdn/zones/localnetwork/vmbr0 --users pveforge-harness@pve --roles PveforgeHarnessNet --propagate 0'
HARNESS_EVIDENCE="$E"/g3 hack/harness/d5/verify-root.sh granted
```

V1u (the user's four rows are exactly the pinned ones), V1b (every other row is
as P0), V1c (no one else holds a row on a harness path), V5 (the user's tree is
the pre-build tree).

STOP. Evidence: `$E/g3/`.

## G4: step 11, mint, grant, validate and persist the token (OPERATOR-RUN)

OPERATOR-RUN, in the operator's own terminal. Bootstrap logs in to qa-pve-02 as
root with the PVE password (password-only SSH, `internal/sshexec/client.go`),
read from `PVEFORGE_PVE_PASSWORD` or a terminal prompt. It never reaches an
agent. The secret of the new token stays inside pveforge.

`roster init` does not create the directory (G0 did), and refuses an existing
file: check `~/.config/pveforge/harness-outer.toml` is absent first. First set
`E` in this terminal to the value G0 printed (`E=…`), so the result lands with
the other gates' evidence, and `PIN` to the fingerprint G0's K1 printed
(`PIN=SHA256:…`, copied exactly). Bootstrap checks qa-pve-02's host key
against it before the password is sent (`--host-key-fingerprint`), and refuses
any other key.

```
pveforge roster init ~/.config/pveforge/harness-outer.toml
pveforge bootstrap qa-pve-02-harness --roster ~/.config/pveforge/harness-outer.toml --host qa-pve-02.lab.quantum.com --node qa-pve-02 --insecure-tls --pve-user root@pam --no-ssh-key --host-key-fingerprint "$PIN" --token-owner pveforge-harness@pve --token-id build --grant '/pool/pveforge-harness:PveforgeHarness:Pool.Audit,VM.Allocate,VM.Audit,VM.Config.CDROM,VM.Config.CPU,VM.Config.Cloudinit,VM.Config.Disk,VM.Config.HWType,VM.Config.Memory,VM.Config.Network,VM.Config.Options,VM.PowerMgmt,VM.Snapshot:0' --grant '/storage/pveforge-harness:PveforgeHarnessSpace:Datastore.AllocateSpace,Datastore.Audit:0' --grant '/storage/local:PveforgeHarnessIso:Datastore.Audit:0' --grant '/sdn/zones/localnetwork/vmbr0:PveforgeHarnessNet:SDN.Use:0' -o json > "$E/g4-bootstrap.json"
```

Its stdout carries no secret. The gate: `token_outcome` is `minted`,
`validation` is `verified`, `host_key_fingerprint` equals the key K1 matched at
G0, and the roster's mode is 600. Anything else is red:
- `unverified`: the token was persisted but not proven. STOP; the Chair decides.
- `discarded`: nothing survived; the root writes stand.
- A failed run leaves a token-less stub `[[targets]]` entry in the roster. A
  re-run reuses it; delete it by hand first (no pveforge command removes a
  target).

A later bootstrap of this target needs `--no-ssh-key` and `--token-owner` again,
and none may run before G5's post-build V3/V5 (hazard H-1).

STOP. Evidence: `$E/g4-bootstrap.json`.

## G5: steps 12+, verification

Implementor-run. `verify-token.sh` needs the harness roster's passphrase in
`PVEFORGE_ROSTER_PASSPHRASE` (the operator's decision O-a) and
`PVEFORGE_BIN`, the absolute path of the pveforge binary.

```
HARNESS_EVIDENCE="$E"/g5-root hack/harness/d5/verify-root.sh token
HARNESS_EVIDENCE="$E"/g5-token hack/harness/d5/verify-token.sh pre
```

Root side: V0, V0b, V1 (all 8 rows), V1b, V1c, V2 (privsep), V2b (the owner is
in no group), V3 and V5 (the token's and the user's trees are the pre-build
tree), V4 (the token holds nothing at 13 paths it must not reach), V7 (no
members). Token side, through lib.sh only: V3t, V0t for each role, V1t (the
token sees no ACL row), V7t and V7t-node, and Z0: the zero-privilege answer
`{"/storage/local-lvm":{}}`, owed live since L2, recorded raw.

STOP. Evidence: `$E/g5-root/`, `$E/g5-token/`. D5 is done when both are green.

## After the build (not part of D5)

`verify-root.sh post` and `verify-token.sh post` (members 690-692). Hazard H-1:
take this first post-build V3/V5 BEFORE anyone re-runs bootstrap on
qa-pve-02-harness.
