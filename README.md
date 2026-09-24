# pveforge

A standalone Go CLI for Proxmox VE cluster lifecycle management: idempotent,
self-describing (`pveforge schema` prints its own command tree as JSON), and
token-first. PVE's REST API, with a scoped API token, is the default path. SSH
is kept as a standing second path for the few operations the API cannot do,
such as root-only VM config fields like `args` (`docs/prd.md` §3).

**Status:** under active development. Specific behaviours have been checked
against a two-node PVE 9.2.11 cluster: the API-doc tree `discover` reads, and
`args` being root-only. Much of the PVE behaviour it relies on is still owed a
live check: see [Not yet verified on a live host](#not-yet-verified-on-a-live-host).
The design and the evidence behind it are in [`docs/prd.md`](docs/prd.md).

## Why

Every existing option for Proxmox automation — Terraform's providers,
Ansible's collection, Salt's community extension, Kubernetes Cluster API — was
evaluated against a real, unusually demanding workload (raw QEMU device
configuration, exotic NVMe/BMC/PCIe emulation, non-cloud-init boot paths) and
found wanting in a concrete, evidenced way. `docs/prd.md` §0.1 records exactly
what was tested and what broke.

## Install

Requires Go 1.27.1 or later (`go.mod`) and GNU `install` (Linux).

```sh
make build                 # bin/pveforge
make install               # $(PREFIX)/bin/pveforge, PREFIX defaults to ~/.local,
                           # and the man pages to $(PREFIX)/share/man/man1
```

There is one man page per command (`man pveforge`, `man pveforge-vm-set`),
generated from the command tree into `docs/man`. `make man` regenerates them;
`make test` fails while they are out of date.

## Commands

| Command | What it does |
|---|---|
| `roster init [path]` / `validate [path]` | Create an empty roster file; parse and validate one |
| `roster import-token` | Put an API token minted outside pveforge into the roster, once PVE proves its grants |
| `bootstrap` | Turn a PAM login into a scoped API token held in the roster |
| `exec <target> -- <command>` | Run a command with the target's API token in its environment |
| `user ensure`, `group ensure` | Create a PVE user or group, or bring it to the state asked for (as root over SSH) |
| `acl grant` | Grant a role on a path to a user, group or token (as root over SSH) |
| `vm create` / `get` / `set` | Create a VM at the VMID you name; read one; set or delete config fields |
| `vm snapshot list` / `create` / `delete` / `rollback` | List, create and delete a VM's snapshots; roll back to the newest one and prove the guest came back |
| `node get`, `storage get`, `network get` | Read a node, storage backend, or network interface |
| `network set`, `network bridge create` / `destroy` | Change node-level network interfaces |
| `storage orphans` | Diff claimed against actual storage volumes |
| `discover …` | Describe PVE's own object schemas, or a pveforge device type |
| `api get` / `post` / `put` / `delete` | Raw PVE REST passthrough |
| `schema` | pveforge's own command tree, flags and mutation levels, as JSON |
| `completion` | Shell completion scripts (bash, fish, powershell, zsh) |

`pveforge <command> --help` is the reference for every flag and default.

## The roster and its secrets

The roster is a TOML file listing targets (`id`, `host`, `node`) and the
credentials pveforge holds for them. It is found at `--roster`, else
`PVEFORGE_ROSTER`, else `./pveforge.toml`. `pveforge roster init` writes a
commented template (mode 0600). `id`, `host` and `node` are required, and
`api_port` (default 8006) and `insecure_tls` may be set by hand, and so may
`export = "token"`, which lets `pveforge exec` hand that target's API token to
another program. `export` is set only by hand: no pveforge command writes it,
and any other value is refused when the roster is loaded. The
`[targets.token]` and `[targets.ssh]` blocks are written by `bootstrap` and
`import-token`, and their `*_enc` fields must not be edited.

Keys are case-sensitive. A roster holding a key that is not spelled exactly as
above (`Export`, `Host_Key_Fingerprint`), or a key pveforge does not know, is
refused at load with the key and its line. The TOML library alone would match
keys regardless of case and let the last spelling win.

Secrets are encrypted at rest with age (scrypt passphrase). The passphrase is
taken from `PVEFORGE_ROSTER_PASSPHRASE`, else from a no-echo prompt when stdin
is a terminal, else the command fails. There is deliberately no flag for any
secret. For scripts: sourcing the variable from a 0600 file keeps it out of
shell history. Typing `export PVEFORGE_ROSTER_PASSPHRASE=…` at a prompt does
not.

## Environment

| Variable | Used for |
|---|---|
| `PVEFORGE_ROSTER` | Roster path, when `--roster` is not given |
| `PVEFORGE_ROSTER_PASSPHRASE` | The roster passphrase; without it, a terminal prompt (never for `roster import-token`, whose stdin is the token secret). Removed from `exec`'s command's environment |
| `PVEFORGE_PVE_PASSWORD` | `bootstrap`'s PAM login password, and root's password for `user ensure`, `group ensure` and `acl grant` with `--no-ssh-key`; without it, a terminal prompt. Removed from `exec`'s command's environment |
| `PVEFORGE_PVE_AUTHORIZATION` | Set by `exec` in its command's environment, never read by pveforge: the `Authorization` header value `PVEAPIToken=<token id>=<secret>` |

## Bootstrap

```sh
pveforge bootstrap qa-pve-01 --host qa-pve-01.example.com --node qa-pve-01 \
  --grant /pool/lab:PVEVMUser
```

`bootstrap` logs in over SSH as `--pve-user` (default `root@pam`, which must be
an `@pam` user) and mints an API token (`--token-id`, default `pveforge`) owned
by `--token-owner` (default: `--pve-user`). It records the token in the roster.

- `--grant PATH:ROLE[:PRIVS[:PROPAGATE]]` is repeatable. At least one grant is
  required: there is no default. The token is validated to hold exactly those
  grants before it is kept.
- A non-root `--token-owner` must itself hold the whole role at each granted
  path, or bootstrap refuses before touching anything.
- `--no-ssh-key` uses the PVE password for this run only. No key is installed
  on the target or stored in the roster, and the host key is trusted on first
  use every run. Such a target needs the flag on every later run.
- Re-running `bootstrap` with different grants, or a different owner, can
  replace, revoke or orphan the held token. `--help` describes each case.
  **The command's own output and its stderr warnings are the record of what
  happened to each token.** Read them.

## Importing a token minted elsewhere

```sh
mint-token-somehow | PVEFORGE_ROSTER_PASSPHRASE=… \
  pveforge roster import-token qa-pve-02 --token-id 'ops@pve!ci' \
  --grant /vms/100:PVEVMUser --host qa-pve-02.example.com --node qa-pve-02
```

The secret is read from stdin only, and stdin must not be a terminal, so the
roster passphrase must come from `PVEFORGE_ROSTER_PASSPHRASE`. The token
must prove it holds exactly the `--grant` scopes before anything is written.
Nothing on PVE is created or revoked. A target that already holds a different
token is refused unless `--replace` is given; the replaced token stays live on
PVE. An imported target holds no SSH key, so a later plain `bootstrap` of it is
refused: pass `--no-ssh-key`.

## Handing a token to a script

```sh
PVEFORGE_ROSTER_PASSPHRASE=… pveforge exec qa-pve-01 -- sh -c '
  printf "header = \"Authorization: %s\"\n" "$PVEFORGE_PVE_AUTHORIZATION" |
    curl -sS -K - https://qa-pve-01.example.com:8006/api2/json/version'
```

`exec` decrypts the target's API token and replaces itself with the command
(execve). The command's environment gains `PVEFORGE_PVE_AUTHORIZATION` and
loses `PVEFORGE_ROSTER_PASSPHRASE` and `PVEFORGE_PVE_PASSWORD`; everything
else passes through. Its exit status is the command's own.

- Only a target marked `export = "token"` in the roster is handed out. The
  SSH key never is. The mark is a guardrail against handing out a token by
  accident, not a security boundary: anyone holding the passphrase can copy a
  target's `secret_enc` into a roster where it is marked.
- Nothing is written to disk and no host is contacted. On Linux, pveforge
  makes itself non-dumpable before it decrypts, so no core dump or same-user
  process can read the secret out of it. That protection ends at the execve:
  the command is dumpable again, and any process of the same user can read
  its environment (`/proc/<pid>/environ`), secret included.
- One stderr line names the token id, the target and the command, never the
  secret. It is printed after every check has passed, just before the execve.
  If the execve itself fails, an error follows it saying the token was not
  handed over, and the exit status is 1.
- Keep the secret out of argv, which every user on the host can read: the
  recipe above passes it to curl on stdin (`printf` is a shell builtin). Never
  write `curl -H "Authorization: $PVEFORGE_PVE_AUTHORIZATION"`.
- **Never run a command under `exec` that prints its environment** (`env`,
  `printenv`, `set`, a debug log). It prints the secret, into a terminal, a
  log or an agent's transcript.

## Users, groups and ACL grants

```sh
pveforge group ensure qa-pve-01 ops --comment "Ops team"
pveforge user ensure qa-pve-01 alice@pve --group ops --email alice@example.com
pveforge acl grant qa-pve-01 --group ops --grant /pool/lab:PVEVMUser::1
```

These write as root over SSH with `pveum`, never with the roster's API token,
which never holds `User.Modify` or `Permissions.Modify`. A target that holds no
SSH key needs `--no-ssh-key`, which connects as root with the PVE password for
that run, as `bootstrap --no-ssh-key` does.

- `user ensure` and `group ensure` are idempotent. The read that decides
  whether to write uses the token (root's `pveum` when the token may not read
  users or groups), so a run with nothing to change never connects as root.
  `--enable`/`--disable` set a user's state; with neither, an existing user
  keeps its state. Group membership is only ever added. A `@pve` user is
  created with no password; set one with `pveum passwd`. Disabling the user
  that owns the roster's own token is refused.
- Joining a group grants that group's ACLs, so `--group` is guarded like a
  grant: the user owning the roster's own token may join no group (always),
  and no user may join a group holding, anywhere, a role that confers an
  escalating privilege (listed under `acl grant` below), unless
  `--allow-escalating-role` is given, which prints a warning for every such
  holding of every group joined. Both lists are read as root before the
  write.
- `acl grant` takes `--grant PATH:ROLE[:PRIVS[:PROPAGATE]]` as `bootstrap`
  does: propagate is 0 unless given, and PRIVS must be exactly the role's. It
  refuses a grant to the roster's own token, to its user, or to a group that
  user is in, always; and a role conferring an escalating privilege —
  `Permissions.Modify`, `User.Modify`, `Sys.Modify`, `Realm.Allocate`,
  `Sys.Console`, `VM.Monitor`, `Realm.AllocateUser`, `Datastore.Allocate` or
  `Mapping.Modify` — unless `--allow-escalating-role` is given, which prints a
  warning. After granting,
  it reads the ACL list back as root and requires each exact entry.
- **The checks are of the state as read, not as it stays.** They see the
  groups, ACLs and roles as read just before the write. A group granted an
  escalating role, or a role widened with `pveum role modify`, after a user
  joins it is not caught, and the user holds it unwarned; a grant to a group
  reaches members who join later. Nothing serialises `user ensure` against
  `acl grant`, or either against changes made outside pveforge. Review with
  `pveum acl list` after changing a group's grants.
- Nothing here deletes a user or group or revokes a grant: use `pveum`.
- pveforge never writes PVE's `/access` API with the roster's token. Every
  request it makes passes through one HTTP transport that refuses any method
  but GET or HEAD on `/access` or below it, before the request is sent; that
  includes `pveforge api post|put|delete /access/...`.

## Idempotence and locking

`vm set` and the `network` commands read the object first and write only what
differs, so a repeat run changes nothing. `vm create` instead fails if the
VMID is already taken, and never picks another. Two creates with the same
tags both succeed, unless `--unique-tag X` is given (X one of the create's own
tags): then the create is refused if any VM in the cluster already carries X,
in any letter case (PVE matches tags case-insensitively). That check fails
closed (a list it cannot read refuses), needs `VM.Audit` on `/vms` because
PVE lists only the VMs a token can see, and runs under a pveforge lock on the
tag, held until the new VM is listed. Its limits: the lock is per roster
target, so two targets that are nodes of one cluster, and the web UI, are not
held off; a `NoAccess` ACL on a single `/vms/<id>` hides that VM while the
`VM.Audit` check still passes; LXC containers carrying the tag are not
counted; and a signal during the wait for the new VM to be listed exits
130/143 saying the VM was created but not yet listed. `api` is a raw passthrough and
is not idempotent.

Commands that touch a VM, node, storage or network object, or a user or
group (`user ensure`, `group ensure`), take a per-object lock (files under `<roster>.locks/`): a mutation takes it exclusively, and a
read shares it. So two pveforge processes never mutate the same object at once,
and a read waits for a mutation in progress. `--lock-wait` bounds the wait for another
process's lock: 0 means the 15m default, and the maximum is 1h.

`api` locks by path. A path that names a pveforge-managed object is always
locked; `--unsafe-no-lock` does not change that. On any other path:
- `api get` proceeds with no lock, and `--lock-wait` has no effect;
- `api post`, `put` and `delete` are refused, unless `--unsafe-no-lock` is
  given. With it, they proceed with no lock and print a warning saying so.

## Output

- Commands that print data take `-o kv|json`: the `get` commands,
  `storage orphans`, `discover`, `api`, `bootstrap` and `roster import-token`.
  `-o kv` (the default) prints one `key=value` line per field. A key or value
  that could be misread (a line break or control character, edge whitespace, a
  leading `"`, a key containing `=`, or the string `null`) is written as one
  JSON string. `-o json` prints the data as is, and keeps its types.
- Results go to stdout. Notices, warnings and errors go to stderr.
- A command's error is printed as one line. Error text longer than 4 KiB keeps
  its head and ends in `… [N bytes elided]`.
- `vm set` on a running VM prints one stderr notice per change PVE holds as
  pending until the next cold boot. Its stdout and exit status are unchanged.
- A PVE task that ends with exit status `WARNINGS: <n>` succeeded, as PVE
  itself counts it: the command exits 0 and prints one stderr notice per such
  task, naming it, so the warnings are never silent. Read them in the task's
  log. Anything but `OK` or exactly `WARNINGS: <n>` is a failure.
  How PVE reports pending changes is itself not yet verified live (see below).

## Exit status

| Status | Meaning |
|---|---|
| `0` | Success, including a command that completed with a printed warning, or completed although it was interrupted after its outcome was observed |
| `1` | The command failed |
| `130` | Interrupted by SIGINT before completing |
| `143` | Interrupted by SIGTERM before completing |

`exec` exits with these statuses only when it fails before handing over. Once
it runs the command, the exit status is the command's own.

On the first SIGINT or SIGTERM, pveforge stops and finishes any cleanup it had
started. Unless it was only waiting for a lock or at a prompt, it says on
stderr that any change already sent may or may not have been applied. A second
signal kills the process immediately. The kernel releases any lock it held.

## Not yet verified on a live host

These rest on PVE's documentation or source, not yet on observation. Each is
owed to the nested PVE test harness:

- `vm set`'s pending-change detection: the `/pending` answer's shape, that a
  stopped VM reports nothing pending, and that hot-pluggable changes are not
  left pending.
- Where PVE puts a "does not exist" message (the HTTP reason phrase or the
  body). If it is missed, the result is a loud error, never a silent no-op.
- `vm set --delete` on a running VM: whether a key that cannot be hot-unplugged
  goes pending, and what PVE answers for deleting a key that is already
  absent. pveforge skips an absent key rather than depend on the answer.
- `api`'s task wait: which endpoints answer with a bare task id, whether the
  10-minute wait ceiling is enough for a long task, and which node a
  cross-node task id names. If it names the proxying node, the wait refuses
  the task as outcome-unknown.
- A task's exit status for success with warnings: pveforge accepts `OK` and
  exactly `WARNINGS: <n>`, following PVE's own `PVE::UPID::status_is_error`.
  A differently worded warnings status would be reported as a failure.
- The task id (UPID) grammar pveforge accepts before it waits on a task,
  taken from PVE's own `PVE::UPID::decode`. A UPID outside it is refused as an
  unverifiable read, so a task PVE really started would be reported as
  outcome-unknown.
- `bootstrap`'s parsing of `pveum user token add --output-format json`. It
  accepts two shapes, and fails loudly on anything else.
- The text iproute2's `ip` and `bridge` print for an interface that does not
  exist, which the network checks read.
- `storage orphans`: how linked clones' volumes are identified. **Do not treat
  its output as safe to delete without checking.**
- The exact error answers of network bridge and interface changes.
- `user ensure`, `group ensure` and `acl grant`: the `pveum` flags they use,
  the JSON the `/access` lists answer with (read from PVE's API schema), and
  the ACL list's entry shape the grant's read-back requires. A shape that
  differs is refused as unverifiable, and a read-back that cannot find the
  grant fails the command after the grant was made.
- `vm snapshot`: whether PVE's REST rollback itself refuses a snapshot that
  is not the newest (pveforge refuses it first, under the VM's lock, but a
  change from the web UI is not held off), leaf-only deletion, the snapshot
  list's shape, how long a snapshot, delete or rollback takes against the
  10-minute task wait, whether a VM is left running after a rollback to a
  snapshot with RAM state, and how soon the guest agent answers the
  rollback's witness (`--witness-timeout`, default 2m). The default witness
  runs `/bin/echo` in the guest, which assumes a POSIX guest.
- `vm create --unique-tag`: how far PVE's cluster resource list lags a create
  (about 10 seconds; the create waits up to 30 for its own VM to be listed,
  then only warns), that PVE stores tags `;`-joined whatever separators were
  used, that tags match case-insensitively (PVE's default), and that
  `VM.Audit` on `/vms` is enough to be listed every VM.
- Library code with no command yet: full vs linked clones, VM destroy beyond
  PVE's documentation, and guest-agent command timing and encoding outside
  the rollback witness.
- The text PVE uses for a config digest conflict, and which config fields
  beyond `args` are root-only.

pveforge has been exercised on PVE 9.2.11 only. It has no VM migration support.

## Development

`make help` lists the targets. `make check` runs everything CI runs: offline
module hygiene, gofmt, vet, and the tests under the race detector.
`make vuln` runs govulncheck. Changes are expected to be proven by mutation:
break the behaviour a test claims to guard, and watch that test fail by name.

## License

Dual-licensed under your choice of MIT or Apache-2.0. See [`LICENSE`](LICENSE).

The compiled binary also contains third-party code under its own licenses —
including Apache-2.0 code from `go-proxmox`, which pveforge forks. See
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
