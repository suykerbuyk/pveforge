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

## Releases

A release is a `v<major>.<minor>.<patch>` tag the operator creates; `make release`
builds it into `dist/` as a static (`CGO_ENABLED=0`), byte-reproducible linux/amd64
archive with `SHA256SUMS`, `schema.json`, the licence text of every linked module
and `CHANGES.md`. Nothing in the repository tags, pushes or publishes. To pin and
check a release: `pveforge version` (`release=true` only for a clean build of a
semver tag with no `replace`), `sha256sum -c SHA256SUMS`, and
`pveforge schema diff <previous schema.json> <this schema.json>` to see whether the
contract (commands, flags, exit statuses, output keys, environment variables,
roster keys) changed in a breaking way. The process, the version policy and the
meaning of breaking are in [`docs/releasing.md`](docs/releasing.md); what changed
is in [`CHANGES.md`](CHANGES.md). The static binary uses Go's own DNS resolver, not
libc's (no `nsswitch` mDNS/NIS modules).

## Commands

| Command | What it does |
|---|---|
| `roster init [path]` / `validate [path]` | Create an empty roster file; parse and validate one |
| `roster rekey` | Change the roster's passphrase: re-encrypt every secret under a new one, contacting nothing |
| `roster import-token` | Put an API token minted outside pveforge into the roster, once PVE proves its grants |
| `bootstrap` | Turn a PAM login into a scoped API token held in the roster |
| `exec <target> -- <command>` | Run a command with the target's API token in its environment |
| `user ensure`, `group ensure` | Create a PVE user or group, or bring it to the state asked for (as root over SSH) |
| `acl grant` | Grant a role on a path to a user, group or token (as root over SSH) |
| `acl enable-vm-destroy [--yes] [--dry-run] [--role-only] [--vmid N]` | Give the roster's token the privileges `vm destroy` needs (`Sys.Audit`) without rotating it (as root over SSH): prints the plan, asks `Proceed? [y/N]` (`--yes` skips it; with no terminal and no `--yes` a run that would write is refused, exit 4), writes, then reports, in `ready` and `verdict`, whether `vm destroy`'s own privilege reads now succeed (or the rows still missing; exit 1 when not ready or the check could not run) |
| `access inventory` | List every user, group and ACL entry, and each `@pam` user's account on the node (read as root over SSH) |
| `access keys` | List pveforge's SSH keys in root's `authorized_keys`, which roster holds each, and each stray's manual removal command (read-only) |
| `vm create` / `get` / `set` | Create a VM at the VMID you name; read one; set or delete config fields |
| `vm destroy` | Destroy the VM you name and prove it is gone; re-running resolves an outcome left unknown |
| `vm snapshot list` / `create` / `delete` / `rollback` | List, create and delete a VM's snapshots; roll back to the newest one and prove the guest came back |
| `node get`, `storage get`, `network get` | Read a node, storage backend, or network interface |
| `doctor <target> [--vmid N]` | Report which privileges `vm destroy` needs and which the token holds (token over REST, GET only; exit 4 unless every row is held) |
| `network set`, `network bridge create` / `destroy` | Change node-level network interfaces |
| `storage orphans` | Diff claimed against actual storage volumes |
| `storage create` | Create a cluster-wide storage definition, idempotently; refuses a differing one |
| `discover …` | Describe PVE's own object schemas, or a pveforge device type |
| `api get` / `post` / `put` / `delete` | Raw PVE REST passthrough |
| `version` (and `--version`) | This binary's identity: version, commit, clean or dirty, static, Go; `release=true` only for a clean build of a semver tag |
| `schema` | pveforge's own contract as JSON (schema version 2): commands, flags, requiredness, arguments, exit statuses and output keys per verb, environment variables, roster keys |
| `schema diff <old> <new>` | Classify the change between two releases' schemas as breaking or additive (`--fail-on breaking` for a gate) |
| `completion` | Shell completion scripts (bash, fish, powershell, zsh) |

`pveforge <command> --help` is the reference for every flag and default.

## The roster and its secrets

**The procedures for every secret and key** (first bootstrap, pinning,
reprovisioning, token rotation, age recipients, backup and recovery, and what
each refusal means) are in
[`docs/operations/secrets-and-keys.md`](docs/operations/secrets-and-keys.md).
This section is the summary.

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

A target may also hold a `[targets.tls]` block, `spki_sha256 =
"sha256//<base64>"`: the SHA-256 of the API certificate's public key, in
curl's `--pinnedpubkey` form. When it is present, every REST connection to
the target must present that key, checked in the TLS handshake before any
request (the token included) is sent. With `insecure_tls` the pin replaces
certificate-chain verification; without it, the chain and the pin must both
hold. An `http://` proxy (`HTTPS_PROXY`) still works with a pin, since the
pin is checked through its CONNECT tunnel; an `https://` proxy does not, and
every request to a pinned target through one fails with a pin mismatch.
A malformed value is refused at load, never read as "no pin". Beside the
pin, `source` records how it was first obtained: `ssh-verified` (over an SSH
session pinned to the host key you gave), `ssh-stored` (pinned to the host key
the roster held), `ssh-tofu` (an SSH host key trusted on first use, by
`--ssh-tofu`) or `expect` (given with `pin-tls --expect`). An `insecure_tls`
target that holds NO pin is refused: pveforge makes no REST request to it at
all (every request, GETs included, would carry the token to whatever
answers), and the error names `pveforge roster pin-tls <target> --roster
<path>`. `pveforge roster validate --require-tls-pins` lists the `insecure_tls`
targets that have none. A CA-verified target (no `insecure_tls`) needs no pin.
`roster import-token` into an `insecure_tls` target the roster holds no pin for
needs `--expect sha256//…`, the pin you verified; the validation's connection
must present it, and it is written, with source `expect`, only once the token
validated. `--expect` is not only for `insecure_tls` targets: given for a
CA-verified target the roster holds no pin for, it pins that target the same
way, and the chain and the pin must then both hold. Root commands that include a REST view (such as `access inventory`)
fail entirely on an unpinned `insecure_tls` target.

The pin is captured, never trusted on first REST contact. `bootstrap` of an
`insecure_tls` target reads the certificate pveproxy serves on the node itself
(`openssl s_client` to `127.0.0.1:8006` over the run's SSH session;
`--capture-port` names another node-local port), requires the target's address
to serve the same key, and writes the pin, all before any token is minted or
sent; a mismatch stops the run there. A CA-verified target (no `insecure_tls`)
is never pinned implicitly. `pveforge roster pin-tls <target>` pins a target
bootstrapped before pins existed, without touching its token: over the stored
SSH pin for a target with SSH auth, or, for one without, from `--expect
sha256//…`, which the address must serve exactly. It refuses a different stored
pin unless `--repin` (SSH auth only), and `--print` writes nothing.

Keys are case-sensitive. A roster holding a key that is not spelled exactly as
above (`Export`, `Host_Key_Fingerprint`), or a key pveforge does not know, is
refused at load with the key and its line. The TOML library alone would match
keys regardless of case and let the last spelling win.

Secrets are encrypted at rest with age (scrypt passphrase). The passphrase is
taken from `PVEFORGE_ROSTER_PASSPHRASE`, else from a no-echo prompt when stdin
is a terminal, else the command fails. There is deliberately no flag for any
secret. A roster that holds no secret yet takes its passphrase from the first
`bootstrap` or `roster import-token` that writes one; `bootstrap` then asks for
it twice when it prompts (`import-token` never prompts).
`pveforge roster rekey` changes the passphrase later: every secret is
re-encrypted under a new one, read from a terminal only and asked for twice,
and nothing but the roster file is touched. For scripts: sourcing the variable from a 0600 file keeps it out of
shell history. Typing `export PVEFORGE_ROSTER_PASSPHRASE=…` at a prompt does
not.

## Environment

| Variable | Used for |
|---|---|
| `PVEFORGE_ROSTER` | Roster path, when `--roster` is not given |
| `PVEFORGE_ROSTER_PASSPHRASE` | The roster passphrase; without it, a terminal prompt (never for `roster import-token`, whose stdin is the token secret). Removed from `exec`'s command's environment |
| `PVEFORGE_PVE_PASSWORD` | `bootstrap`'s PAM login password, and root's password for `user ensure`, `group ensure`, `acl grant`, `access inventory` and `access keys` with `--no-ssh-key`; without it, a terminal prompt. Removed from `exec`'s command's environment |
| `PVEFORGE_HARNESS_AGE_IDENTITY_FILE` | Not read by pveforge. The nested-harness secrets helper (`hack/harness/unlock.sh`): a file holding one consumer's private age identity, mode 0600 or 0400, owned by the user; see "Harness secrets". Removed from `unlock.sh run`'s command's environment |
| `PVEFORGE_HARNESS_AGE_IDENTITY` | Not read by pveforge. The same identity's content, for a CI runner's secret store; exactly one of the two may be set. Removed from `unlock.sh run`'s command's environment |
| `PVEFORGE_HARNESS_ROSTER` | Not read by pveforge. The nested-harness suites (`make harness`): the absolute path of the roster whose targets are the nested `pvh-*` nodes. The suites refuse to run without it, or when it is the same file as an outer roster |
| `PVEFORGE_HARNESS_OUTER_ROSTERS` | Not read by pveforge. The nested-harness suites: every roster that reaches the OUTER cluster, absolute and colon-separated. Required: the suites refuse any nested target that shares a target id, host, node, resolved address, SSH host key or API token id with them. A harness run also refuses a set `PVEFORGE_ROSTER` (unset it: it is never unset for you) and any proxy variable (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, either case) |
| `PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD` | Not read by pveforge. Set by `unlock.sh run` from the sealed secrets: the nested harness nodes' test root password, which the harness passes to `bootstrap` as `PVEFORGE_PVE_PASSWORD` for a nested node only |
| `PVEFORGE_PVE_AUTHORIZATION` | Set by `exec` in its command's environment, never read by pveforge: the `Authorization` header value `PVEAPIToken=<token id>=<secret>` |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and the lower-case spellings) | Honoured by the REST transport (Go's `net/http`); the nested-harness guard refuses a run with any of them set |
| `ALL_PROXY`, `all_proxy` | Not read by pveforge; the nested-harness guard refuses a run with either set |
| `HARNESS_STORAGE`, `HARNESS_CREATED_FILE`, `HARNESS_RESET_MIN_FREE_GIB`, `HARNESS_PROBE_MIN_FREE_GIB` | The `harness` verbs' defaults when `--storage`, the created-VMs ledger path or the free-space minimum is not given |

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
  on the target or stored in the roster, and no host key pin is stored, so
  every such run is a fresh password connection: give it
  `--host-key-fingerprint` (required for an `insecure_tls` target, next
  bullet), or its host key is trusted on first use. Such a target needs the
  flag on every later run.
- For an `insecure_tls` target, a run whose password session captures the TLS
  pin (a first run, or `--no-ssh-key`) needs `--host-key-fingerprint`, or
  `--ssh-tofu` to accept trust on first use of the SSH host key, recorded as
  `tls_pin_source` `ssh-tofu`. A run that dials a stored SSH pin needs
  neither. The result reports `tls_spki_sha256` and `tls_pin_source`.
- `--reprovisioned` is the one command after a node is REBUILT: it replaces
  the stored SSH host key pin, the keypair installed on the node, and the TLS
  pin, together, and mints a fresh token (the old one died with the node).
  Read the new host key on the node's CONSOLE (`ssh-keygen -lf
  /etc/ssh/ssh_host_ecdsa_key.pub`) and pass it with `--host-key-fingerprint`.
  Never pin the key a failing connection presented: that is what an impostor
  would show, and pveforge's mismatch errors label it so. Every run still needs
  `--grant` (the roster stores none), `--no-ssh-key` for a keyless target,
  `--capture-port` if one was used, and the PVE password. Where the stored pins
  already match the node, the run is a plain bootstrap, so repeating the
  command after a partial failure converges. Recovery is one command per
  roster; for a node that two rosters address (qa-pve-07 and its harness
  target), for example:

      pveforge bootstrap qa-pve-07 --roster ./pveforge.toml --reprovisioned \
        --host-key-fingerprint SHA256:<console> --grant /:PVEVMAdmin::1
      pveforge bootstrap qa-pve-07-harness --roster ~/.config/pveforge/harness-qa-pve-07-outer.toml \
        --no-ssh-key --reprovisioned --host-key-fingerprint SHA256:<console> \
        --token-owner pveforge-harness@pve --token-id build --grant …

  The `--grant /:PVEVMAdmin::1` above gives a token that cannot run `vm destroy`.
  For one that can, run `pveforge acl enable-vm-destroy qa-pve-07 --role-only`
  first, then bootstrap with `--grant /:ForgeVMAdminAudit::1`. `--role-only`
  creates the role and nothing else: a rebuilt node's roster still holds the old
  token record, which PVE no longer knows, so without the flag the command would
  take it for a token to upgrade and refuse.
  The second needs its owner, pool and roles recreated first (for the nested
  harness: D5's G1–G3); a rebuild does not keep them. A disposable roster (a
  harness nested target) can instead be moved aside and bootstrapped afresh.
  The result reports `reprovisioned` and the `previous_host_key_fingerprint`
  and `previous_tls_spki_sha256` it replaced. `[targets.ssh]` records
  `host_key_source` (`ssh-verified` or `ssh-tofu`) beside its pin.
- `--host-key-fingerprint SHA256:…` pins the SSH connection that carries the
  password (the key install's, or `--no-ssh-key`'s) to the host key you
  verified, exactly as `ssh-keygen -l -E sha256` prints it and the roster
  stores it. SSH checks the host key before authentication, so a host
  presenting any other key is refused before the password is sent. Without it
  the host key is trusted on first use, and the accepted fingerprint is
  reported as `host_key_fingerprint`. For a target already pinned by an earlier
  run, a different value is refused before anything is dialed. The keyless
  root commands (`user ensure`, `group ensure`, `acl grant`, `access
  inventory` and `vm create --unique-tag`, each with `--no-ssh-key`) take the
  same flag; a target that holds a pin is checked against it on every
  connection, `--no-ssh-key` included, and the flag may only repeat it. The
  pin is compared with the key type pveforge's SSH client negotiates: ECDSA
  when the host serves one, as PVE does by default. Pinning the host's
  ED25519 key there is refused (fail-closed), and the error names the type it
  got; `ssh-keyscan <host> | ssh-keygen -lf -` lists every type served.
- Re-running `bootstrap` with different grants, or a different owner, can
  replace, revoke or orphan the held token. `--help` describes each case.
  After `acl enable-vm-destroy`, the token holds `ForgeVMAdminAudit` as well as
  `PVEVMAdmin`: re-run bootstrap only with `--grant /:ForgeVMAdminAudit::1`,
  which is `reused`. `--grant /:PVEVMAdmin::1` would revoke it for every holder.
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

## `vm destroy`

```
pveforge vm destroy qa-pve-01 691 --yes
```

`vm destroy <target-id> <vmid> --yes` destroys the VM you name on the target's
node, purging it and its disks, and proves it is gone. It is irreversible, and
it destroys exactly the VM you name: **nothing in it protects against naming
the wrong VM correctly.** There is no VMID band, ledger, pool or tag guard.
`--yes` is required, and is checked after the reads, so a refusal tells you
the real reason first. A re-run that only resolves an earlier destroy needs
`--yes` too. There is no `--force`, `--no-wait` or `--wait-timeout`.

Every run ends in exactly one of four outcomes. The `outcome` field is on
stdout, identical in `-o kv` and `-o json`, and the exit status says the same:

| `outcome` | Exit | Meaning | What to do |
|---|---|---|---|
| `ok` | `0` | The VM is proven gone: a destroy task ended exactly `OK` and PVE says the vmid is free | Treat it as destroyed |
| `failed` | `1` | A known failure | Do not retry blindly |
| `unknown` | `3` | A destroy or stop request may have been sent and how it ended was not observed. A stop that is unknown never dispatches the destroy | Re-run: it asks PVE, never a local file. Or follow up the `upid` |
| `refused` | `4` | Nothing was dispatched | Wait for what the refusal names, and re-run |

Exit 1 with an EMPTY stdout is different: the command never ran (a malformed
vmid, an unknown target, an unreadable roster). A signal after the dispatch
exits 130 or 143 and still prints `outcome=unknown`. A signal that coincides
with an outcome the command had already OBSERVED (a destroy task seen to fail)
prints that outcome, and only the exit status is 130 or 143. A signal during a
retry's gone-proof, when nothing was dispatched, reports `outcome=refused` with
exit 130 or 143 and no "may have been applied" note.

The `situation` field names the row. The report carries the `vmid`, and the
facts of that row; a fact that does not apply is absent:

| `situation` | `outcome` | Exit | Meaning |
|---|---|---|---|
| `B1` | `ok` | `0` | This run destroyed it. `upid` and `exitstatus=OK` |
| `B1-unclean` | `failed` | `1` | The task ended `WARNINGS: n`, or the per-task status read after the wait returned showed a non-`OK` error string: not proven cleanly destroyed, volumes may remain. PVE counts that as success and its stderr notice still appears, beside an exit-1 verdict |
| `task-failed` | `failed` | `1` | The destroy task ended with an error |
| `B2` | `unknown` | `3` | The wait hit the 10-minute ceiling; the task may still run |
| `B3` | `unknown` | `3` | The task status could not be read |
| `B9` | `unknown` | `130` or `143` | Interrupted after the dispatch |
| `B1-unproven` | `unknown` | `3` | Dispatched, but PVE did not confirm the vmid free |
| `dispatch-unconfirmed` | `unknown` | `3` | The destroy request got no definite answer (or a 2xx without a task id): a worker may exist. There is no `upid` |
| `stop-unknown` | `unknown` | `3` | The stop before the destroy got no definite answer, or its wait could not be completed. The destroy was NOT dispatched |
| `stop-failed` | `failed` | `1` | PVE answered the stop with an error, or the stop task failed. The destroy was NOT dispatched |
| `dispatch-refused` | `failed` | `1` | PVE answered the destroy request with an error (a 403 names the privilege). Nothing was destroyed |
| `B4` | `refused` | `4` | A destroy of this vmid is unfinished (`inflight_upid`) |
| `B4b` | `refused` | `4` | A migrate, clone or restore of this vmid is unfinished |
| `B4c` | `refused` | `4` | A stop or shutdown of this vmid is unfinished. The cost: a destroy issued seconds after a shutdown of the same VM refuses until that task has ended |
| `B4d` | `refused` | `4` | `--yes` was not given |
| `B5-gone` | `ok` | `0` | A re-run: the earlier destroy ended `OK` on some member and the vmid is free. `already_destroyed` |
| `B5-unclean` | `failed` | `1` | A re-run: the earlier destroy ended other than `OK`, and the VM is gone |
| `B5-elsewhere` | `refused` | `4` | The VM is not on this node but PVE still claims the vmid |
| `B5-absent-without-task` | `refused` | `4` | The VM is absent and no destroy of it is visible: absence alone is not proof (a destroy older than PVE's task retention reads this way) |
| `B10` | `refused` | `4` | A read could not be completed: the object lock, the visibility probe, the task list, the node-local config, the status gate, or the free-proof. `read` and `error` name it |

A re-run after a failed destroy that left the VM in place is a new attempt, not
a refusal: stderr says a prior destroy failed, and the report carries
`prior_upid` and `prior_exitstatus`. The `reason` field is carried only by
`failed` and `unknown` rows: `deadline`, `read-failure`, `interrupted`,
`proof-unestablished`, `dispatch-unconfirmed`, `stop-unknown`, `unclean`,
`task-failed`, `dispatch-refused`, `stop-failed`. A refusal never carries a
`reason` or a `upid`.

The token needs `Sys.Audit` on `/nodes/<node>` (PVE filters the task list to a
token's own tasks without it, and the command refuses rather than trust that
list), `VM.PowerMgmt` (the stop) and `VM.Allocate` (the destroy). Resolving a
retry also reads the cluster member list, which needs `Sys.Audit` on `/`.
`PVEVMAdmin` holds the last two and neither audit privilege.
`pveforge acl enable-vm-destroy <target>` adds `Sys.Audit` to the roster's token
without revoking or re-minting it. It is one command and one question: it shows
the plan, asks `Proceed? [y/N]`, writes, and runs the same check `pveforge
doctor` makes: its report carries `ready` and `verdict` (read together), naming
the exact rows still missing, and the bootstrap form that is safe afterwards.
Ready means the privilege reads on the roster node and `/` (node-level unless
`--vmid`), not that every VM can be destroyed; an exit 1 whose verdict says the
check did not run means nothing was verified. `--yes` writes the plan the locked
re-read decides; nothing is confirmed, so there is no confirmed-plan comparison. A refused `vm destroy` whose
`Sys.Audit` read PVE answered 403 names this command as its `fix`. The operator guide
([`docs/operations/secrets-and-keys.md`](docs/operations/secrets-and-keys.md),
procedure 11) describes it and what to run afterwards.

Residuals the command states rather than hides:
- PVE decides, from a read followed later by a write. Another actor can start a
  hazardous task between the two, including during the stop and its wait: the
  command refuses only what it observed.
- A stop PVE answered with a 500 is a known failure; a stop with no answer is
  unknown. They are different rows.
- On newer PVE a destroy runs `register_used_id` before it forks, so a destroy
  that fails with a 500 there may already have registered the vmid.
- A disk reassign (`qmmove`) in flight is not detected.
- On a non-clustered host a re-run whose VM is already absent is refused,
  because the member list cannot be read as proof.

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
  log. Anything but `OK` or exactly `WARNINGS: <n>` is a failure. `vm destroy`
  is the exception: a destroy that ends `WARNINGS: <n>` may have left a disk
  behind, so it is `failed` (exit 1) and the notice still appears beside it.
  How PVE reports pending changes is itself not yet verified live (see below).

## Exit status

| Status | Meaning |
|---|---|
| `0` | Success, including a command that completed with a printed warning, or completed although it was interrupted after its outcome was observed |
| `1` | The command failed, including a usage error: an unknown subcommand, or a command group such as `vm` run with no subcommand (its help goes to stderr). Asking for help (`--help`, `-h`, `pveforge help vm`) exits 0. `acl enable-vm-destroy` also exits 1 when it wrote the grant, or found it already in place, and `vm destroy`'s reads still do not all succeed (the report's `wrote` and `ready` say which) |
| `3` | The outcome is unknown: the command dispatched a change and did not observe how it ended, so it may have been applied, may still be running, or may have failed. Every command that dispatches a change can exit 3 (the list is below): a PVE task wait that started and did not observe its task (`vm destroy`, `vm create`, `vm snapshot …`, `network …`, `storage …`, `api post|put|delete`, the `harness` verbs), and a root-SSH write that was sent and then ran out of time (`acl grant`, `user ensure`, `group ensure`, `acl enable-vm-destroy`, `bootstrap`). A signal during the wait is 130 or 143 instead. Look the task up by the UPID printed at dispatch, or re-run the command where re-running resolves it. A task seen to FAIL is exit 1, as is a root-SSH read that timed out, a response that cannot be decoded as the UPID a verb requires (`api post|put|delete` is the exception: a response that carries no UPID, such as a `null` answer to a PUT or DELETE, is an ordinary success, exit 0), and a lost response on a synchronous write (`vm set`, `storage alloc`, the network stage): exit 1 there is NOT proof that nothing changed. `api post|put|delete --no-wait` with a UPID exits 0: the named state `unobserved_dispatch` (dispatched, outcome not observed, the UPID is on stderr) |
| `4` | The command was refused before it changed anything: nothing was changed on a PVE host or in the roster file, so fix the cause and re-run. Every command that can refuse before it dispatches can exit 4 (the list is below), `vm destroy`, `doctor` and `acl enable-vm-destroy` among them; `doctor` exits 4 when any privilege is missing, unknown or not checked, so pass `--vmid` to check the VM privileges, or grant what is missing; `acl enable-vm-destroy` exits 4 when its plan was declined at the prompt, or there was no terminal to ask on and no `--yes`. A refusal that comes AFTER a write is exit 1, whatever it says: exit 4 is decided by whether the run had already sent a change, never by the name of the error. What counts as a change is state on a PVE host (any REST request other than GET and HEAD that leaves the process, a root-SSH write, an SSH key install or removal) or the roster file (any write to it, including `roster init`). Local bookkeeping is explicitly NOT a change and may have been written before a 4: the lock files `<roster>.lock` and `<roster>.locks/`, the harness evidence directories and files, the harness ledger, the probe's `harness-state/` file, and the harness's own known-hosts file (`harness-nested.known_hosts`, written after the PVE writes) |
| `130` | Interrupted by SIGINT before completing |
| `143` | Interrupted by SIGTERM before completing |

### Which commands exit 3 and 4

The two lists are held to the code (`TestExitRegistry_*`): every command that
changes state has a row in the code's exit registry, and these lists are that
registry. A command in neither list can only exit 0, 1, 130 or 143.

Commands that can exit 3:

- `api post`
- `api put`
- `api delete`
- `vm destroy`
- `vm create`
- `vm snapshot create`
- `vm snapshot delete`
- `vm snapshot rollback`
- `network bridge create`
- `network bridge destroy`
- `network set`
- `storage create`
- `storage set-content`
- `storage free-orphans`
- `acl enable-vm-destroy`
- `acl grant`
- `user ensure`
- `group ensure`
- `bootstrap`
- `harness build`
- `harness probe`
- `harness golden`
- `harness reset`
- `harness vm destroy`
- `harness vm shutdown`
- `harness vm stop`
- `harness vm snapshot create`
- `harness vm snapshot delete`
- `harness vm snapshot rollback`

`vm set` is exit 4 only for its Validate refusals (a field both set and
deleted, a duplicate delete) and a lock-wait timeout, which are raised before
anything is sent; an allow-list or digest refusal raised inside the write is
exit 1, because by then the run has already opened its write.

Commands that can exit 4:

- `doctor`
- `api post`
- `api put`
- `api delete`
- `vm destroy`
- `vm create`
- `vm set`
- `vm snapshot create`
- `vm snapshot delete`
- `vm snapshot rollback`
- `network bridge create`
- `network bridge destroy`
- `network set`
- `storage create`
- `storage set-content`
- `storage alloc`
- `storage free-orphans`
- `acl enable-vm-destroy`
- `acl grant`
- `user ensure`
- `group ensure`
- `bootstrap`
- `roster init`
- `roster rekey`
- `roster import-token`
- `roster pin-tls`
- `exec`
- `harness build`
- `harness probe`
- `harness golden`
- `harness reset`
- `harness vm destroy`
- `harness vm shutdown`
- `harness vm stop`
- `harness vm snapshot create`
- `harness vm snapshot delete`
- `harness vm snapshot rollback`

`exec` exits with these statuses only when it fails before handing over. Once
it runs the command, the exit status is the command's own, so a `3` or a `4`
from `exec` is its command's, not pveforge's (the named state `child_status`).

On the first SIGINT or SIGTERM, pveforge stops and finishes any cleanup it had
started. Unless it was only waiting for a lock or at a prompt, it says on
stderr that any change already sent may or may not have been applied. A second
signal kills the process immediately. The kernel releases any lock it held.

## Not yet verified on a live host

These rest on PVE's documentation or source, not yet on observation. Each is
owed to the nested PVE test harness:

- A failed first bootstrap's removal of its own key from root's
  `authorized_keys`: that pmxcfs allows creating `authorized_keys.tmp.*`
  beside `/etc/pve/priv/authorized_keys` and renaming it onto it; that the
  other nodes see the result; that `~/.ssh/authorized_keys` stays a symlink;
  that root logins during the rename survive it; that with quorum lost the
  removal fails at that create and leaves the file intact; and that a hangup
  mid-run leaves no `.tmp.` file in `/etc/pve/priv`.

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
to the public recipients in `hack/harness/recipients.txt`. Recipient changes,
backup and recovery are step by step in
[`docs/operations/secrets-and-keys.md`](docs/operations/secrets-and-keys.md). Each consumer (the
operator, each CI runner) has its own private age identity, which is never
committed. No password manager is required; keep a backup of your identity
wherever you keep such things (any offline medium, or a password manager if you
use one). The outer cluster's root password is never in the blob.

- `hack/harness/unlock.sh run [--] <cmd> [args…]` decrypts the secrets in
  memory and replaces itself with `<cmd>`, the values in its environment only:
  never on disk, never in argv. The identity variables are removed from that
  environment, and a secret whose name is already set refuses to run rather
  than override it. Every variable through which an environment runs code in
  a bash child before its first line is removed too, silently, not refused:
  exported functions (`BASH_FUNC_*`, which bash imports under any name,
  `declare` and `unset` included, so no check inside a script can survive
  one), `SHELLOPTS`, `BASHOPTS`, `BASH_ENV`, `ENV` and `PS4`. Everything
  else passes unchanged.
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
the harness roster passphrase means `pveforge roster rekey` on both harness
rosters and then `unlock.sh seal`, in that order (see the guide); rotating the
nested password means re-provisioning the nested nodes with a new one.

## Development

`make help` lists the targets. `make deps` fetches, online, every module the
checks need; run it once in a fresh clone (or on a fresh module cache), since
the checks themselves never fetch. `make check` runs everything CI runs: offline
module hygiene, gofmt, vet, and the tests under the race detector.
`make vuln` runs govulncheck; `make gate` runs it too, on the Go toolchain go.mod names, so it needs the network. Changes are expected to be proven by mutation:
break the behaviour a test claims to guard, and watch that test fail by name.

## License

Dual-licensed under your choice of MIT or Apache-2.0. See [`LICENSE`](LICENSE).

The compiled binary also contains third-party code under its own licenses —
including Apache-2.0 code from `go-proxmox`, which pveforge forks. See
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
A release archive carries the full licence text of every linked module, every module `NOTICE`, and Go's licence (`licenses/`).
