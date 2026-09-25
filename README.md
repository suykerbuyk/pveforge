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
| `access inventory` | List every user, group and ACL entry, and each `@pam` user's account on the node (read as root over SSH) |
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
| `PVEFORGE_PVE_PASSWORD` | `bootstrap`'s PAM login password, and root's password for `user ensure`, `group ensure`, `acl grant` and `access inventory` with `--no-ssh-key`; without it, a terminal prompt. Removed from `exec`'s command's environment |
| `PVEFORGE_HARNESS_AGE_IDENTITY_FILE` | Not read by pveforge. The nested-harness secrets helper (`hack/harness/unlock.sh`): a file holding one consumer's private age identity, mode 0600 or 0400, owned by the user; see "Harness secrets". Removed from `unlock.sh run`'s command's environment |
| `PVEFORGE_HARNESS_AGE_IDENTITY` | Not read by pveforge. The same identity's content, for a CI runner's secret store; exactly one of the two may be set. Removed from `unlock.sh run`'s command's environment |
| `PVEFORGE_HARNESS_ROSTER` | Not read by pveforge. The nested-harness suites (`make harness`): the absolute path of the roster whose targets are the nested `pvh-*` nodes. The suites refuse to run without it, or when it is the same file as an outer roster |
| `PVEFORGE_HARNESS_OUTER_ROSTERS` | Not read by pveforge. The nested-harness suites: every roster that reaches the OUTER cluster, absolute and colon-separated. Required: the suites refuse any nested target that shares a target id, host, node, resolved address, SSH host key or API token id with them. A harness run also refuses a set `PVEFORGE_ROSTER` (unset it: it is never unset for you) and any proxy variable (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, either case) |
| `PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD` | Not read by pveforge. Set by `unlock.sh run` from the sealed secrets: the nested harness nodes' test root password, which the harness passes to `bootstrap` as `PVEFORGE_PVE_PASSWORD` for a nested node only |
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
that run, as `bootstrap --no-ssh-key` does. The password is asked for before
the user's or group's lock is taken; root is dialed only if something must be
read or written as root.

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
- `access inventory` lists every user, group and ACL entry, read as root
  (never with the token, whose view is filtered by its privileges and can be
  a shorter list that looks complete; the token is not even decrypted).
  Each user carries the ACL entries naming it and, marked `via`, those of
  each group it is in. Those groups come from the user list's `groups`
  field, which every user must carry, cross-checked both ways against each
  group's members: if the lists disagree, the inventory fails rather than
  show a user holding less than it does. API tokens appear only in the
  top-level `acls`. Every entry whose role confers an escalating privilege
  lists them under `escalating`.
- Each `@pam` user is looked up on the node with `getent passwd`, run as
  root: `os_account_status` is `found`, `absent`, `not-pam`, or `unchecked`
  for a name getent would read as a UID (digits, optionally after `+`).
  Accounts on the node that no PVE user names are not listed. Effective
  permissions are not computed (`pveum user permissions` does that), and
  the lists are read without a lock, one after another.
- pveforge never writes PVE's `/access` API with the roster's token. Every
  request it makes passes through one HTTP transport that refuses any method
  but GET or HEAD on `/access` or below it, before the request is sent; that
  includes `pveforge api post|put|delete /access/...`.

## Idempotence and locking

`vm set` and the `network` commands read the object first and write only what
differs, so a repeat run changes nothing. `vm create` instead fails if the
VMID is already taken, and never picks another. Two creates with the same
tags both succeed, unless `--unique-tag X` is given (X one of the create's own
tags): then the create is refused if any guest in the cluster, VM or
container, already carries X, in any letter case (PVE matches tags
case-insensitively). The guests are listed as root over SSH (`pvesh get
/cluster/resources`), because PVE leaves out of a token's list every guest
the token lacks `VM.Audit` on at that guest's own path (any narrower role
there for the token, its user or a group, or a `NoAccess` on its pool), and
no read a token can make shows that none was left out; root's list leaves out
nothing. So `--unique-tag` needs root SSH, as `user ensure` does: a stored SSH
key, or `--no-ssh-key` and the PVE password; root is reached before the tag's
lock is taken. That check fails closed (a list it cannot read, one that is not
what PVE returns, or a root read taking over 30 seconds refuses) and runs under
a pveforge lock on the tag, held until the new VM is in root's list. Tags are
folded even when the datacenter's tag style is case-sensitive, so pveforge then
refuses more than PVE distinguishes, never less. Root's list is PVE's
replicated cluster config: a guest on an offline node is still listed, but a
node without quorum may serve a stale list. Its limits: the lock is per roster
target, so two targets that are nodes of one cluster, and the web UI, are not
held off; and a signal during the wait for the new VM to be listed exits
130/143 saying the VM was created but not yet listed. `api`
is a raw passthrough and is not idempotent.

Commands that touch a VM, node, storage or network object, or a user or
group (`user ensure`, `group ensure`), take a per-object lock (files under `<roster>.locks/`): a mutation takes it exclusively, and a
read shares it. So two pveforge processes never mutate the same object at once,
and a read waits for a mutation in progress. `--lock-wait` bounds the wait for another
process's lock: 0 means the 15m default, and the maximum is 1h.

Every command pveforge runs over SSH is bounded, so a dead connection or a hung
host never holds a lock without end:

- 30 seconds by default: every read, and two small writes, bootstrap's append
  of its key to root's `authorized_keys` (which on PVE lives in
  `/etc/pve/priv`) and a live `bridge link set` for bridge isolation;
- 90 for `pveum` user, group, ACL and token writes (PVE itself allows about
  70), except bootstrap's cleanup removal of a token it could not use, which
  its own 30-second cleanup bound ends first;
- 120 for `qm set` on a root-only field (it may apply the VM's other pending
  changes);
- slightly more than 30 for a snippet upload, scaled by its size.

A command that runs past its bound is sent SIGKILL and reported with exit 1 as
timed out, with an unknown outcome: it may or may not have taken effect, and on
the host it may outlive pveforge and its lock. A read made after it cannot
settle that either, so pveforge reports such a token or write as possibly
applied, never as definitely not. If the connection is so dead that even the
SIGKILL cannot be sent within 2 seconds, pveforge closes it. A command whose
session never opened was never sent, and is reported as a plain failure.
Re-running `user ensure`, `group ensure`, `acl grant` or `vm set` is safe; each
reads the current state first. Only a signal (Ctrl-C) exits 130 or 143.

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
  pending until the next cold boot, and per requested field it left untouched
  because it already read as set but which PVE still holds pending. Its stdout
  and exit status are unchanged.
- `vm create`, `user ensure` and `group ensure` read their result back after
  the change. A read that fails, a VM PVE then reports does not exist, or a
  user or group without every requested value is one stderr warning; stdout
  and the exit status are unchanged.
- A PVE task that ends with exit status `WARNINGS: <n>` succeeded, as PVE
  itself counts it: the command exits 0 and prints one stderr notice per such
  task, naming it, so the warnings are never silent. Read them in the task's
  log. Anything but `OK` or exactly `WARNINGS: <n>` is a failure.
  How PVE reports pending changes is itself not yet verified live (see below).

## Exit status

| Status | Meaning |
|---|---|
| `0` | Success, including a command that completed with a printed warning, or completed although it was interrupted after its outcome was observed |
| `1` | The command failed, including a usage error: an unknown subcommand, or a command group such as `vm` run with no subcommand (its help goes to stderr). Asking for help (`--help`, `-h`, `pveforge help vm`) exits 0 |
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
  body). If it is missed, the result is a loud error, never a silent no-op;
  after `vm create`, a warning that the result could not be re-read.
- That a VM whose create task reported OK is readable at once, so `vm create`'s
  "does not exist" warning is never a false alarm.
- `vm set`'s `/pending` answer for a field re-requested while it is still
  pending.
- That `pveum`'s flags produce the values `user ensure` reads back.
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
  then only warns), the JSON `pvesh get /cluster/resources --type vm
  --output-format json` prints as root (read from PVE's source: `type`,
  `vmid` and `tags` per guest, containers included), and that PVE stores tags
  lower-cased and `;`-joined under the default tag style.
- Library code with no command yet: full vs linked clones, VM destroy beyond
  PVE's documentation, and guest-agent command timing and encoding outside
  the rollback witness.
- The text PVE uses for a config digest conflict, and which config fields
  beyond `args` are root-only.

pveforge has been exercised on PVE 9.2.11 only. It has no VM migration support.

## Harness secrets

The nested test harness (`hack/harness/`) keeps its two secrets — the harness
roster passphrase (`PVEFORGE_ROSTER_PASSPHRASE`) and the nested nodes' test
root password (`PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD`) — in
`hack/harness/secrets.age`, age ciphertext committed to the repository, sealed
to the public recipients in `hack/harness/recipients.txt`. Each consumer (the
operator, each CI runner) has its own private age identity, which is never
committed. No password manager is required; keep a backup of your identity
wherever you keep such things (any offline medium, or a password manager if you
use one). The outer cluster's root password is never in the blob.

- `hack/harness/unlock.sh run [--] <cmd> [args…]` decrypts the secrets in
  memory and replaces itself with `<cmd>`, the values in its environment only:
  never on disk, never in argv. The identity variables are removed from that
  environment, and a secret whose name is already set refuses to run rather
  than override it. So is every variable through which an environment runs
  code in a bash child before its first line: exported functions
  (`BASH_FUNC_*`, which bash imports under any name, `declare` and `unset`
  included, so no check inside a script can survive one), `SHELLOPTS`,
  `BASHOPTS`, `BASH_ENV`, `ENV` and `PS4`. Everything else passes unchanged.
  `unlock.sh` itself runs under `bash -p` (its interpreter line), which
  imports no function and reads none of those from the environment either;
  run it as a command, not as `bash unlock.sh`, which it refuses.
- `unlock.sh seal` encrypts a new env file — read from stdin, or prompted for
  with no echo on a terminal — to every recipient. `unlock.sh reseal`
  re-encrypts the current secrets to the current recipients. `unlock.sh status`
  shows the recipients and, with an identity set, the variable names; never a
  value.
- The identity comes from exactly one of `PVEFORGE_HARNESS_AGE_IDENTITY_FILE`
  (a file of mode 0600 or 0400, owned by you) and
  `PVEFORGE_HARNESS_AGE_IDENTITY` (its content). Both, neither, or an empty one
  is refused.
- The env file is `NAME=value` lines (plus `#` comments and blank lines),
  parsed without a shell: the value is the rest of the line, verbatim. Only
  `PVEFORGE_ROSTER_PASSPHRASE` and `PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD` are
  accepted — age does not authenticate who sealed a blob, so this list is what
  stops a committed blob from setting anything else in a CI command's
  environment. Adding a name is a code change.

**Enabling a CI runner** (a one-time human act): `age-keygen -o runner.key`;
store the key's content in the runner's secret store as
`PVEFORGE_HARNESS_AGE_IDENTITY`, then delete the local file; add its `age1…`
line to `recipients.txt` as `<recipient> # ci-runner-<name>`; run
`unlock.sh reseal` with your own identity; commit both files. Before any
`reseal`, a human must review the `recipients.txt` diff line by line: a
recipient someone else committed would otherwise be sealed to, and its holder
could decrypt the secrets from then on. Harness runs
happen only on a self-hosted runner in the lab, on protected branches or a
manual trigger, never for pull requests from forks.

**Revoking a consumer.** Removing a recipient does **not** revoke that key's
access to older copies of `secrets.age` in git history: whoever holds it can
still decrypt every blob it was ever sealed to. Revocation is therefore:
remove the recipient, **rotate the values**, then `reseal` and commit. Rotating
the harness roster passphrase means a new harness roster and a re-run of
`pveforge bootstrap` for the harness token, because pveforge has no command to
change a roster's passphrase today; rotating the nested password means
re-provisioning the nested nodes with a new one.

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
