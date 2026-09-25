# D5 revert (printed, never self-executing)

Undoes `sequence.md`, in this order: PVE refuses to delete a pool that still
has members, and deleting the user before its token strands the token's secret
in `/etc/pve/priv/token.cfg`. Each command is run by hand, one at a time; stop
at the first failure. The token id is single-quoted inside the remote command
because `!` is history expansion in an interactive shell.

## R0: the harness VMs

At D5 time no harness VM exists, so R0 does nothing. Later, lib.sh destroys
only a VM created by the same run (operator ruling 2026-09-24 (3)): tearing
down VMs from an earlier run is a fresh operator ask, or root's hand
(`qm destroy <vmid>` on qa-pve-02, run by the operator).

## R1-R2: the eight ACL rows

```
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com "pveum acl delete /pool/pveforge-harness --tokens 'pveforge-harness@pve!build' --roles PveforgeHarness"
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com "pveum acl delete /storage/pveforge-harness --tokens 'pveforge-harness@pve!build' --roles PveforgeHarnessSpace"
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com "pveum acl delete /storage/local --tokens 'pveforge-harness@pve!build' --roles PveforgeHarnessIso"
ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com "pveum acl delete /sdn/zones/localnetwork/vmbr0 --tokens 'pveforge-harness@pve!build' --roles PveforgeHarnessNet"
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
