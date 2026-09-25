# D5 revert (printed, never self-executing)

Undoes `sequence.md`, in this order: PVE refuses to delete a pool that still
has members, and deleting the user before its token strands the token's secret
in `/etc/pve/priv/token.cfg`. Each command is run by hand, one at a time; stop
at the first failure. Each remote command is one single-quoted argument: an
interactive bash or zsh expands `!` (history expansion) even inside double
quotes, so `"…!build…"` fails there with "event not found", while inside
single quotes nothing is expanded. On qa-pve-02 the command runs under a
non-interactive `sh -c`, which does no history expansion, so the token id can
sit in double quotes inside it.

## Which steps to run: it depends on how far D5 got

An R-step fails on an object that does not exist (a role, pool or user never
made, a token never minted, an ACL row never granted), so run only the steps
for what the run actually made. Find the last gate that went green; for a gate
that failed partway, also check each object with a read before deleting it
(`pveum role list`, `pvesh get /pools`, `pveum user list`, `pveum acl list`,
`pveum user token list pveforge-harness@pve`) and skip what is absent.

| Last gate reached | What exists | Run |
|---|---|---|
| G0 (reads only) | nothing but the P0 baseline | nothing |
| G1 (steps 1-4) | some or all of the four roles | R6 for each role present |
| G2 (steps 5-6) | the roles; the pool and/or the user | R4 if the user exists, R5 if the pool exists, R6 |
| G3 (steps 7-10) | the above, and some or all of the user's four rows | R2 user rows present, R4, R5, R6 |
| G4 `discarded` | the above; no token (bootstrap removed its fresh one) | R2 user rows, R4, R5, R6; R7 if a token-less stub target was left in the roster |
| G4 `unverified`, G4 `minted`, or G5 | everything, the token and its four rows included | R0-R7 in order |

Then R-V in every case but G0.

## R0: the harness VMs

At D5 time no harness VM exists, so R0 does nothing. Later, lib.sh destroys
only a VM created by the same run (operator ruling 2026-09-24 (3)): tearing
down VMs from an earlier run is a fresh operator ask, or root's hand
(`qm destroy <vmid>` on qa-pve-02, run by the operator).

## R1-R2: the eight ACL rows

```
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum acl delete /pool/pveforge-harness --tokens "pveforge-harness@pve!build" --roles PveforgeHarness'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum acl delete /storage/pveforge-harness --tokens "pveforge-harness@pve!build" --roles PveforgeHarnessSpace'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum acl delete /storage/local --tokens "pveforge-harness@pve!build" --roles PveforgeHarnessIso'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum acl delete /sdn/zones/localnetwork/vmbr0 --tokens "pveforge-harness@pve!build" --roles PveforgeHarnessNet'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum acl delete /pool/pveforge-harness --users pveforge-harness@pve --roles PveforgeHarness'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum acl delete /storage/pveforge-harness --users pveforge-harness@pve --roles PveforgeHarnessSpace'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum acl delete /storage/local --users pveforge-harness@pve --roles PveforgeHarnessIso'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum acl delete /sdn/zones/localnetwork/vmbr0 --users pveforge-harness@pve --roles PveforgeHarnessNet'
```

(Skip the four token rows if G4 never minted the token.)

## R3-R6: token, user, pool, roles

```
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum user token remove pveforge-harness@pve build'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum user delete pveforge-harness@pve'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum pool delete pveforge-harness'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum role delete PveforgeHarness'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum role delete PveforgeHarnessSpace'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum role delete PveforgeHarnessIso'
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com 'pveum role delete PveforgeHarnessNet'
```

## R7: the roster entry, by hand

Delete the `qa-pve-02-harness` `[[targets]]` entry, its `[targets.token]` block
included, from `~/.config/pveforge/harness-outer.toml`. No pveforge command
removes a target.

## R-V: back to P0

The P0 baseline stays: it is what R-V compares against, and what a later D5
would compare against. With a new evidence directory:

```
HARNESS_EVIDENCE=$E/rv hack/harness/d5/verify-root.sh reverted
```

It checks that no harness role, pool, user or ACL row remains, and that the
ACL list, the custom roles, the users, the groups and the pools are each
exactly as P0 recorded them. Any difference is listed in the evidence for the
operator to judge.
