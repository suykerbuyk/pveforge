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
| `vm create` / `get` / `set` | Create a VM at the VMID you name; read one; set or delete config fields |
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
`api_port` (default 8006) and `insecure_tls` may be set by hand. The
`[targets.token]` and `[targets.ssh]` blocks are written by `bootstrap` and
`import-token`, and their `*_enc` fields must not be edited.

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
| `PVEFORGE_ROSTER_PASSPHRASE` | The roster passphrase; without it, a terminal prompt (never for `roster import-token`, whose stdin is the token secret) |
| `PVEFORGE_PVE_PASSWORD` | `bootstrap`'s PAM login password; without it, a terminal prompt |

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

## Idempotence and locking

`vm set` and the `network` commands read the object first and write only what
differs, so a repeat run changes nothing. `vm create` instead fails if the
VMID is already taken, and never picks another. `api` is a raw passthrough and
is not idempotent.

Commands that touch a VM, node, storage or network object take a per-object
lock (files under `<roster>.locks/`): a mutation takes it exclusively, and a
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
  How PVE reports pending changes is itself not yet verified live (see below).

## Exit status

| Status | Meaning |
|---|---|
| `0` | Success, including a command that completed with a printed warning, or completed although it was interrupted after its outcome was observed |
| `1` | The command failed |
| `130` | Interrupted by SIGINT before completing |
| `143` | Interrupted by SIGTERM before completing |

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
- `bootstrap`'s parsing of `pveum user token add --output-format json`. It
  accepts two shapes, and fails loudly on anything else.
- The text iproute2's `ip` and `bridge` print for an interface that does not
  exist, which the network checks read.
- `storage orphans`: how linked clones' volumes are identified. **Do not treat
  its output as safe to delete without checking.**
- The exact error answers of network bridge and interface changes.
- Library code with no command yet: snapshot rules (the reserved names
  `current` and `pending`, leaf-only deletion, refusing to roll back on ZFS),
  full vs linked clones, VM destroy beyond PVE's documentation, and
  guest-agent command timing and encoding.
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
