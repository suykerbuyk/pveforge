# PRD — `pveforge`

**Status:** Living spec, reconciled against main on 2026-10-02.
The v1 foundational CLI ships: §3 states the design intent and the decisions
behind it, §4.2 the command surface, §7 the implementation as built, and §8
what is in flight. First drafted 2026-09-13, before any code existed.
**Author:** John Suykerbuyk, drafted with Claude Code during a same-day investigation
in the `quantum-ng` workspace.
**License:** Dual MIT / Apache-2.0 (matches the author's other software products).
**Repo:** standalone, module `github.com/suykerbuyk/pveforge` — not owned by or
embedded in any consumer's repository.

**What holds this document to the code.** `cmd/pveforge/readme_test.go` checks
every command line and every command it names in prose against the real
command tree; every `PVEFORGE_*` variable it names against the documented
ones; every file path, `Err*` name, package-qualified symbol and bare Go name
it cites against the source; the tier table in §4.2 against each command's
own annotation; the timeouts, waits and limits it states against the
constants that define them; and every section, §3.5 layer and §6 item it or
the source cites against its own headings. `internal/roster/prd_example_test.go`
holds the roster example in §4 to the roster's key set and the stated work
factor to the code's, and `internal/sourceguard/prd_packagemap_test.go` holds
the package map in §7.3 to `go list`. Nothing else here is checked: in
particular no line number is cited, because nothing could hold one.

---

## 0. Provenance — why this document exists and what it's built on

This PRD is the direct output of a single-day, evidence-driven investigation
conducted inside `quantum-ng` (a separate, private workspace) into how that
project should replace ~21,600 lines of ad-hoc bash (`mk/proxmox/*.sh`) that
manage Proxmox VE clusters via root SSH + hand-parsed `pvesh` text output. That
investigation ruled out several alternatives with live, reproducible evidence
(not just reading docs) and converged on: **build a standalone Go CLI**. That
CLI now exists (§7); this document is its foundational spec, kept current so
`pveforge` is developed as its own product rather than as an implicit extension
of one consumer's internal facade.

**`quantum-ng` is a consumer of the `pveforge` binary, not an owner of the
project** — the same relationship any other consumer has. This is a deliberate
correction of the pattern Quantum's own `kvm.py`/`myriad_vsphere.py` follow today,
where the provisioning tool is welded into one product's source tree. A
portable, per-architecture Go binary with no runtime dependencies is expected to
be more repeatable and reliable than that pattern, not just differently
licensed.

### 0.1 Findings this design is built on (verified, not assumed)

These were established empirically, against a live Proxmox VE 9.2.11 host
(`qa-pve-01`/`qa-pve-02`, a 2-node cluster), not inferred from documentation:

1. **Proxmox's own API hard-blocks the `args` VM config field from token
   auth, unconditionally.** An API token belonging to `root@pam`, granted
   full `PVEVMAdmin` on the target VM, can create a VM and set `description`
   (`HTTP 200`), but setting `args` fails every time with `HTTP 500` /
   `"only root can set 'args' config"`, regardless of the token's
   privileges. It is a deliberate, hardcoded server-side restriction, not an
   ACL problem. Community reports (not independently verified by us) say
   `rng`, `affinity` and `hugepages` are likely the same; they stay
   unregistered until each is verified the same way (§3.1, §6 item 2).
2. **This restriction is universal across client implementations.** It was
   reproduced through a completely separate client (`saltext-proxmox`, a
   Python/Salt cloud driver) with the identical error and HTTP code. No
   client-side way around it exists.
3. **`suykerbuyk/go-proxmox`, our own fork of `luthermonson/go-proxmox`**, is a
   fully-typed Go client covering PVE's `/api2/json` surface for 8.x and 9.x.
   Its `proxmox.VirtualMachineConfig` exposes PVE's `args`, `hookscript`,
   `efidisk0` and `bios` config fields as first-class struct fields, its
   write path (`proxmox.VirtualMachineOption`, a name and a value) is a raw,
   schema-free passthrough of "the same names `qm create` takes", and it
   supports native API-token auth (`proxmox.WithAPIToken`).

   **Why a fork.** We carry the client because we control it: transport
   changes pveforge needs are made on our own schedule, not an external
   maintainer's. That ability has been used. Forked 2026-09-18 as a
   module-path rename only (`v0.8.2-pveforge.0`), the fork has since diverged
   by behaviour:
   - `.1` (2026-09-19): every non-2xx response is a typed
     `proxmox.StatusError` (before, 404, 409, 502–504 and 595–599 decoded as
     success); 500 and 501 keep the response body (before, the client's
     response handler discarded it); a failed cloud-init ISO lookup no longer
     lets `proxmox.VirtualMachine.Delete` delete the VM.
   - `.2` (2026-09-24): seven latent library defects (ipset delete
     parameters, `proxmox.VirtualMachine.AgentExec` errors, null-reply getters, the cloud-init ISO
     task status, short UPIDs, the TFA delete password, `WARNINGS` tasks
     counted as success).
   - `.3` (2026-09-24): a typed shape error in place of panics on unchecked
     type assertions; WebSocket TLS through one helper.

   The fork's `CHANGES` file records the fork, the rename and the `.1`
   fixes; its `migration/v0.8.2.md` records every change through `.3`,
   including `.2` and `.3`, with what a caller newly sees. Each fix is kept
   as its own commit so it can be offered upstream; whether to offer them is
   an open operator item (§8). Upstream remains the canonical project and
   the better choice for anyone who does not need these changes. The pin is
   held in code (§5).

   **Why pveforge still sends some requests itself** (`pve.Client.RawRequest`
   and the VM write paths built on it): a `proxmox.StatusError`'s text is only the
   HTTP status line, whose reason phrase HTTP/2 erases, while pveforge's own
   error puts PVE's body text in the message — and PVE uses 500 for most of
   its own rejections (root-only fields, digest conflicts, bad parameters),
   where that text is the diagnosis. go-proxmox's `Post`/`Put` also
   JSON-encode the body, where PVE expects form encoding.
4. **A live trial of the leading alternative (`saltext-proxmox`) surfaced two
   concrete problems within the first hour:** installing it failed twice on
   native C-extension builds before succeeding (real Python dependency
   baggage, demonstrated), and its `create()` crashed with `KeyError: 'name'`
   inside its own helper on the first successful create — a live bug in its
   primary code path, corroborating a maintenance-risk read with evidence.
5. **Cluster API for Proxmox (`cluster-api-provider-proxmox`)** solves a
   narrower problem: clone-plus-cloud-init only, no field for raw device
   args, and it needs a permanently running Kubernetes management cluster —
   a chicken-and-egg problem for provisioning the infrastructure a cluster
   doesn't exist on yet. Ruled out.
6. **A Kubernetes in-cluster app-lifecycle control plane
   (`quantum-orchestrator`)** was ruled out as a category error: it runs Helm
   installs inside an already-formed cluster and contains no
   infrastructure-provisioning code. Recorded because it is the kind of
   "wrong layer" mistake to guard against: **`pveforge`'s job ends at "the VM
   shell exists, correctly configured." It does not configure guest
   operating systems, install Kubernetes, or manage application lifecycle.**

The full session record lives in `quantum-ng`'s own vault and is reachable
cross-project, but is **not** part of this project's history — this section
exists so `pveforge` doesn't depend on that external memory.

---

## 1. Problem

There is no widely-adopted, well-maintained "libvirt-equivalent" abstraction
layer for Proxmox VE the way there is for KVM. Every option surveyed —
Terraform's two competing providers, Ansible's collection, Salt's community
extension, Kubernetes Cluster API — is either missing support for raw/exotic
QEMU device configuration, carries real native-dependency or maintenance risk,
or solves a structurally different problem. Consumers who need Proxmox VM
lifecycle management with unusual device requirements (custom NVMe/BMC/PCIe
device trees, non-cloud-init boot paths, precise thin-provisioning control)
are left hand-rolling it — today, usually as SSH + `pvesh` shell scripts with
brittle hand-parsed text output and a permanent root-credential dependency.

`pveforge` is a from-scratch, standalone, MIT/Apache-2.0 dual-licensed Go CLI
that fills that gap as its own product, not as a bolt-on to any one consumer.

## 2. Non-goals

- Guest OS configuration, Kubernetes installation, or application-lifecycle
  management. `pveforge`'s scope ends at the VM/container/network/storage
  object model Proxmox itself exposes.
- A general multi-hypervisor abstraction (no vSphere/libvirt/Hyper-V target).
  Proxmox only, at least through v1.
- **For v1:** an MCP server, an AI-agent-only interface, or anything that
  cannot be invoked deterministically and non-interactively from a shell
  script or `make` target. Machine- and AI-readable discoverability (§3.5) is
  a *format* requirement, not an *interaction-model* requirement — `pveforge`
  must work identically whether invoked by a human, a cron job, CI, or an
  agent, with zero non-determinism introduced by any of them.
- VMID allocation policy. The CLI never picks a VMID: the caller names it
  (§3.4.3). Operator-specific VMID bands, ceilings and auto-allocation are out
  of scope (operator, 2026-09-16). The library's `pve.Client.NextVMID` can
  also auto-allocate (given no pin, it walks forward from PVE's suggestion);
  `vm create` calls it only with the caller's VMID, never that path.

**Future direction (operator, 2026-10-02).** Library first: the deterministic
CLI and the packages behind it are the product, and an MCP server or an
OpenTofu/Pulumi provider would be thin wrappers over them, not a second
implementation. Today every library package is under `internal/`, so no other
module can import one; when, and what, becomes a public Go API is open (§6
item 7).

## 3. Architecture: design intent and decisions

§3 says what the design is and why. §7 maps it onto the packages that
implement it.

### 3.1 Transport

- **Primary: Proxmox's REST API over HTTPS, authenticated by API token.**
  This covers the large majority of VM/node/storage/network operations
  (§0.1, finding 1). Every REST connection is either CA-verified or pinned
  to the target's TLS key; an `insecure_tls` target with no pin is refused
  before any request is built (§4.1, transport enforcement).
- **SSH is a permanently retained Tier-2 execution vector, not a
  bootstrap-only concession** (operator, 2026-09-13). It is used as root, on
  demand, for exactly the operations the token must not or cannot perform.
  Every SSH dial checks the host key against the roster's stored pin, else
  the operator's `--host-key-fingerprint`. A password dial with neither — a
  first bootstrap, or any command's `--no-ssh-key` run (`bootstrap`, `user
  ensure`, `group ensure`, `acl grant`, `access inventory`, `vm create
  --unique-tag`) — trusts the key on first use. `--ssh-tofu` is required for
  that only where bootstrap captures a TLS pin over the session (§4.1, ruling
  B′). What runs over it, and why:

  | Operation | Why not the token |
  |---|---|
  | Root-only VM config fields (`args` today), via `qm set` | PVE refuses them from any token (§0.1, finding 1) |
  | Users, groups, ACLs and API tokens, via `pveum` | The token must never hold `User.Modify` or `Permissions.Modify`; REST writes to `/access` are refused at the transport (`pve.ErrAccessWriteRefused`) |
  | Uploading a hookscript snippet to a node | No REST endpoint exists: an API gap, not a permissions gap |
  | Reading and setting bridge port isolation and link state (`bridge`, `ip`) | Host state below PVE's object model |
  | Installing pveforge's public key in `authorized_keys` (bootstrap) | Precedes any token |
  | The root guest listing behind `vm create --unique-tag` | A token's list silently omits guests it lacks `VM.Audit` on |

- **One routing point.** `pve.RoutedClient` decides REST or SSH per call:
  a field in `sshexec.RootOnlyFields` goes over SSH, everything else over
  REST, and a REST write that PVE refuses with "only root can set" is retried
  once over SSH (`sshexec.IsRootOnlyWriteError`), so an unregistered
  root-only field still lands. Nothing records or reports that it happened:
  such a field is found only by the live test below. The registry
  holds only `args`: each further field is added only after the same live
  test `args` received (§6 item 2). A root-only field written over SSH has no
  digest compare-and-set (§3.4.2).
- **Root-channel deadlines** (Chair, 2026-09-24). The SSH dial is lazy and
  bounded at 15s; a command at 30s, a `pveum` write at 90s (bootstrap's
  cleanup of a fresh token runs under a shorter bound), a `qm set` at 120s;
  no keepalives. A command that overruns is killed and its outcome is
  reported as unknown, never as failed. The root password is resolved before
  any pveforge lock is taken. The dial is made on first use, except that
  `vm create --unique-tag` dials root before it takes its tag lock, so the
  lock is never held across a password prompt or a dial.
- **Hookscript and standing SSH solve different problems; both are needed.**
  A hookscript re-applies state automatically at VM lifecycle transitions
  with no live pveforge invocation (§3.4's bridge-isolation example); the
  standing SSH vector serves an arbitrary, operator-initiated mutation at any
  time, which an event-triggered hookscript cannot.
- **Raw REST escape hatch** (`pveforge-raw-api-escape-hatch`, built
  2026-09-14): `api get`, `api post`, `api put` and `api delete` reach any PVE
  REST path with no dedicated command yet — complementing §3.5's `discover`
  (learn the shape, then poke it directly). A mutating verb on a path that
  resolves to an object pveforge models takes that object's §3.4 lock with no
  opt-out; any other path refuses to mutate without `--unsafe-no-lock`. A
  returned task id is waited on, under the lock (§6 item 6). `get` is `safe`;
  the mutating verbs are `destructive`, tiered by verb, not path. Paths at or
  below `/access` are refused for every verb. For example, a node's status:

  ```
  pveforge api get /nodes/qa-pve-01/status qa-pve-01 -o json
  ```

  (Idea surfaced by reviewing
  `davegallant/pvectl`, GPL-3.0 — read for the idea only, its code was never
  used.)
- **Known limitation:** the routed SSH vector dials port 22. The roster
  stores no SSH port, so a `bootstrap --ssh-port` is not remembered for later
  root operations.

### 3.2 Bootstrap

`pveforge` must be able to go from "nothing exists yet" to "fully
token-authenticated" using only credentials an operator already has, plus the
node's host-key fingerprint read on its console:

1. Accept a PAM username/password: the SSH login (`--pve-user`, default
   `root@pam`; the password from `PVEFORGE_PVE_PASSWORD` or a prompt, never
   argv).
2. Over that password session, whose host key must match the operator's
   `--host-key-fingerprint`, generate an ed25519 keypair and install its
   public key, so later root operations need no password. **Or keyless:**
   `--no-ssh-key` installs and stores no key, and every later root operation
   on that target authenticates with the password again. Without a
   fingerprint, the host key is trusted on first use: allowed only with an
   explicit `--ssh-tofu` where the run captures a TLS pin, and implicitly
   where it captures none (§4.1, ruling B′).
3. As root over SSH, mint the API token and its ACLs with `pveum`, then
   validate the token over REST with the token itself, and persist it into the
   target's roster entry (§4), encrypted.
   - **The scope is explicit; there is no default** (operator, 2026-09-22;
     this superseded the 2026-09-13 default of `PVEVMAdmin` on `/`).
     `bootstrap` refuses to run without at least one
     `--grant PATH:ROLE[:PRIVS[:PROPAGATE]]` (repeatable), and checks that
     before it prompts for any secret or touches the target. Each grant is
     ROLE on PATH with its own propagate flag, **defaulting to 0**. The
     optional PRIVS pins exactly the role's privileges; a pin that differs
     from the role's definition on PVE is refused before any existing token
     is touched.
   - **The roster stores no grants.** Every run states its grants again; that
     is what lets a re-run detect a change of scope.
   - The token's owner is `--token-owner` (default: the login), a PVE
     principal that needs no SSH account. A non-root owner must itself hold
     the whole role at each granted path, or bootstrap refuses before
     touching anything. Changing the owner deliberately leaves the previous
     token live on PVE, held by nobody (`orphaned_token`), never revoked.
   - The token is validated by its effective permissions: it must hold every
     requested grant and reach no further, within the validator's stated
     known limits (`internal/pve/validate.go`: e.g. pool membership is read
     only for a non-propagating pool grant whose `Pool.Audit` the token
     holds, and delegations on pool members are not seen). On success the
     granted scope is printed with the result (`grants`), only when a token
     survives the run.
   - Re-running with grants whose paths or privileges differ from the held
     token's effective grants revokes that token (for every holder) and then
     tries to mint a replacement (if that fails, the run ends
     `revoked_not_replaced`). Since propagate defaults to 0, a token granted
     `PVEVMAdmin` on `/` with propagate 1 must be re-requested as
     `--grant /:PVEVMAdmin::1` to be kept.
4. From that point forward, default to token auth for everything token auth
   can do.

For an `insecure_tls` target, a TLS pin is captured over the SSH session of
step 2 and written before step 3 mints or sends any token. The whole run holds
the target's per-target §3.4 lock (also taken by `roster import-token` and
`roster pin-tls`). A node that was rebuilt is re-bootstrapped with
`--reprovisioned`, which replaces its SSH pin, keypair and TLS pin together.
The trust model behind all of this, and the rest of secret management, is
§4.1. The operator procedures are `docs/operations/secrets-and-keys.md`.

**The other ways into a roster.** `roster import-token` adopts a token minted
outside pveforge once PVE proves its grants; `roster pin-tls` pins a target's
TLS key without touching its token; `roster rekey` changes the passphrase
(§4.1).

A typical first bootstrap:

```
pveforge bootstrap qa-pve-01 --host 192.0.2.10 --node qa-pve-01 \
  --grant /pool/lab:PVEVMAdmin --host-key-fingerprint SHA256:<console-value>
```

### 3.3 Object/property model

Mirrors the split verified in `go-proxmox` (§0.1, finding 3):

- **Read side:** typed structs per object class, so callers get real types
  instead of hand-parsed strings, with tolerant types where Proxmox's own JSON
  is inconsistently typed across versions. The classes modelled today: VMs,
  nodes, storage (status, and volumes as far as the orphan scan needs them),
  node network interfaces, and PVE's access objects (users, groups, ACLs,
  tokens).
- **Write side:** raw name/value option pairs matching Proxmox's own
  parameter names 1:1, so nothing about our exotic device configuration
  (§3.1) is fought by an opinionated schema ("Don't let the typed read-side
  model tempt a typed write-side model", `pveforge-object-model-get-set`). A
  key is deleted through PVE's own `delete` parameter, never by writing it
  empty, which leaves the key present.
- **What PVE reads back is not always what is live.** On a running VM, a
  change PVE cannot apply hot is stored as pending and taken at the next cold
  boot, yet the config read shows it as applied; a cloud-init setting is
  saved at once but reaches the guest only when the cloud-init drive is
  regenerated. pveforge asks PVE which of its changes are pending and says so
  on stderr, rather than report a pending change as done.
- **The semantic layer** (`internal/device`, `pveforge-device-semantic-resolvers`):
  `pveforge` owns device intents on top of the raw primitive — "add an
  emulated NVMe drive with this serial" resolves to the right `args:`
  fragment — while the write primitive stays schema-free. One resolver ships,
  `device.NVMeDrive`, with its backing path validated (no denylist; the trust
  boundary is stated, `pveforge-nvme-backing-qemu-protocol`). It is
  discoverable (`discover device`, §3.5 Layer 2) but no command applies it
  yet; it always appends, so applying it is not idempotent.

### 3.4 Idempotent mutation

Every mutating command on an object pveforge models follows check-then-act:
read current state, compare to requested state, no-op (report nothing to do)
if they match, else mutate and report what changed. Acknowledged limitation:
some state genuinely cannot be inspected before the mutating action
(accepted, not a design flaw): `acl grant` relies on PVE merging a repeated
grant instead, and the raw `api` writes (§3.1) pass through as given.

#### 3.4.1 The engine contract

- An operation is an `idempotent.Op`: `Read` the current state, decide whether
  it is already `Satisfied`, else `Apply`. `idempotent.Run` holds the object's
  lock (§3.4.2) for the **whole** read-compare-apply cycle, so no concurrent
  pveforge reader sees a half-made change and no two mutations interleave.
  Most mutating commands run through it. The snapshot writes and the `api`
  writes take the object's lock directly instead, because their check is the
  command's own (a snapshot's existence, or none for a raw path); `acl grant`
  takes no lock (§3.4.2).
- A write rejected by a PVE `digest` compare-and-set returns
  `idempotent.ErrConflict`, and `Run` re-runs the whole cycle from a fresh
  read, up to 3 attempts in all.
- After a successful apply, `Run` re-reads, and an Op may check its own
  effect (`idempotent.PostApplier`) or demand a stricter re-read
  (`idempotent.ReReader`). These checks are advisory: the mutation already
  happened, so a failed re-read is a warning on stderr with exit 0, never a
  failure.
- A batch (`vm set` with several fields) is one cycle, applied in order, and
  stops at the first failure: earlier fields stay applied, never rolled back.
- **`--force`:** the engine can bypass the no-op check (`idempotent.Run`'s
  `force` argument), but **no command exposes it**; every command passes
  false. It was deliberately deferred: "not speculatively added; file
  separately if wanted" (`pveforge-vm-set-unlocked`). Some guards have no
  bypass at all by design (the network stage guard). `roster init --force`,
  which overwrites a roster file, is unrelated to the engine.

#### 3.4.2 Serialization

**Operator mandate (2026-09-13):** pveforge implements its own serialization
rather than relying only on documentation or Proxmox's optimistic concurrency.
The originating environment (this project's own multi-agent workflow) runs
several orchestration agents at once against shared hosts, each potentially
pursuing different objectives against overlapping properties — a materially
different threat model from one sequential script.

- **Mutations on an object are always serialized** (one exception, below):
  never two pveforge mutations of the same object in flight at once. The scope is **per
  object**, not global, not per target (Decision 1 of
  `pveforge-idempotent-mutation-engine`, confirmed with the operator: the
  original "full stop" was emphasis, not a global scope). Two mutations of
  different VMs run concurrently.
- **One exception: `acl grant` takes no lock.** PVE merges a repeated grant,
  so repeating one changes nothing, and the command reads its result back as
  root; nothing serialises it against `user ensure` (whose group join grants
  ACLs too) or against changes made outside pveforge, which its help states.
- **A pending mutation takes priority over a pending read.** A read that
  arrives after a mutation starts waiting never overtakes it, so reads cannot
  starve a writer; a mutation also waits for every read in progress.
- **Mechanism.** `internal/lock`: a writer-priority readers-writers lock built
  from two OS advisory file locks per object (a turnstile and the resource
  lock), keyed by roster file, target, object kind and id, in a
  `<roster>.locks/` directory beside the roster. The kernel releases them
  when a process dies, so no lock can go stale. Kinds in use: `vm`, `vm-tag`,
  `node`, `storage`, `network` (one lock per **node**: PVE stages network
  changes node-wide), `user`, `group`, and one per-target lock taken by
  `bootstrap`, `roster import-token` and `roster pin-tls`.
- **Reach.** Across every pveforge process that shares a roster file. **Not**
  across machines, and not across two roster files that describe the same
  target. PVE's own config `digest` covers that residual gap as
  defense-in-depth for REST writes — it detects a lost race after the fact
  rather than preventing one, and does not exist for a root-only field written
  over SSH.
- **Waiting is bounded.** `--lock-wait` defaults to 15 minutes (more than the
  10-minute task ceiling, which a legitimate holder may spend waiting on a PVE
  task under the lock) and is capped at 1 hour. A lock not acquired in
  time fails with `lock.ErrLockWaitTimeout` and names the lock file; a signal
  while waiting is `lock.ErrLockWaitInterrupted` (exit 130 or 143, §3.6).
- **Held to account statically.** `internal/lock/lockguard` (§7.6) requires
  every lock call and every PVE task wait to receive its caller's own
  context, and every command that reaches a lock to carry `--lock-wait`.

#### 3.4.3 Deliberate departures

- **VM create bends idempotence** (operator, 2026-09-16): "The VMID is an
  artifact of the operation as much or more than it is an artifact of the
  deliverable." `vm create` takes an explicit VMID and **fails** if it is
  taken, with no comparison of the existing VM's configuration; it never
  substitutes another id. Two creates with the same parameters at two VMIDs
  are two VMs.
- **Identity by tag is opt-in.** `vm create --unique-tag X` refuses the create
  if any guest in the cluster, VM or container, already carries tag `X`. The
  guests are listed as root over SSH, the check runs under a lock on the tag
  itself (scoped to the roster target, `vm-tag`), and it fails closed on any listing it cannot fully trust.

#### 3.4.4 Built, not yet on the CLI

The engine also has Ops no command reaches yet: `idempotent.VMTagEnsure`,
`idempotent.VMClone`, `idempotent.VMShutdown` (ACPI only; a source guard
proves no hard-stop path is reachable from it), `idempotent.VMDestroy` and
`idempotent.BridgeIsolationEnsure`. Destroy's behaviour after a failed stop is
undecided (§6 item 8) and must be settled before it reaches the CLI.

**The standing example that motivated this mechanism:** Linux bridge port
isolation (`bridge link set dev <tap> isolated on`) does not survive a VM
stop/start — the flag lives on the ephemeral tap device, recreated fresh on
every boot. "Ensure isolation is set" must be safely re-runnable every boot,
forever. `idempotent.BridgeIsolationEnsure` does this with a hookscript
(uploaded over SSH, set by digest compare-and-set, falling back to SSH when
root-only) plus setting the flag on the running taps; it is library-only
today (§6 item 9).

### 3.5 Discoverability

Every noun and verb the CLI exposes must be walkable from the top down
without static documentation — by a human, a script, or an AI, with no
distinction in interface between them (this is a schema-introspection
requirement, not an agent-interaction-model concern; see §2).

This splits into three layers, all shipped.

**Layer 1 — PVE's own generic object model (nodes, VMs, storage, network).**
`pveforge` proxies PVE's own schema rather than hand-authoring a parallel one
that could drift from PVE's real, version-dependent shape. The mechanism is
**not** HTTP `OPTIONS`: verified live on 2026-09-14 against PVE 9.2.11, PVE's
API daemon rejects `OPTIONS` on every path, before auth or routing
(`HTTP 501 method 'OPTIONS' not available`).

- **The actual mechanism, also verified live:** PVE's own `pvesh usage` and
  its web API viewer are built from a static, **unauthenticated** JavaScript
  asset pveproxy serves at `/pve-docs/api-viewer/apidoc.js` (about 4.3MB on
  9.2.11, same scheme/host/port as the REST API). Its body is
  `const apiSchema = [ ... ];` followed by UI code that is not JSON;
  `pveforge` fetches it with no `Authorization` header and extracts the
  embedded array. Each element describes one API path as a **templated**
  string (e.g. `/nodes/{node}/qemu/{vmid}/config` — never a real object id,
  so no object needs to exist), with an `info` object keyed by HTTP method,
  split into `parameters` (request side) and `returns` (response side). A
  caller needs both: which half carries the fuller field list varies by
  endpoint.
- **Because this is an unversioned doc-generation artifact, not a REST
  contract,** its format could change between PVE releases without notice.
  `pveforge` MUST fail loudly, with a named error saying what broke, rather
  than return an empty or partial schema, if the expected marker, bracket
  structure, JSON shape, or a duplicate templated path is encountered.
- **Noun → PVE path grammar** (`discover <noun> <target-id>`, a schema read
  only). `vm` and `storage` take `--verb config` (the default) or
  `--verb status`:

  | Noun | `--verb config` (default) path | `--verb status` path |
  |---|---|---|
  | `vm` | `/nodes/{node}/qemu/{vmid}/config` | `/nodes/{node}/qemu/{vmid}/status/current` |
  | `node` | `/nodes/{node}/status` (bare `/nodes/{node}` is only the index endpoint and carries no real fields) | — |
  | `storage` | `/storage/{storage}` (cluster-wide config) | `/nodes/{node}/storage/{storage}/status` (per-node runtime status) |
  | `network` | `/nodes/{node}/network/{iface}` | — |
  | `device` | *(no PVE call at all — Layer 2, below)* | — |

**Layer 2 — `pveforge`'s own device-semantic layer** (§3.3) is invisible to
Proxmox's schema — to Proxmox, `args:` is an opaque string. Its schema is
hand-authored (`discover.DeviceSchemas`; today only `NVMeDrive`; revisit the
convention once a second resolver exists, not before) and reachable purely
locally — no roster, network call or live host. `discover device` with no
type lists the type names, its help names them, and an unknown type is
refused with the known names, so the layer is walkable without reading
source. Names match exactly.

**Layer 3 — `pveforge`'s own command surface** (`pveforge-cli-self-schema`,
built 2026-09-14). `pveforge schema` prints the full command tree — names,
flags, short descriptions — as JSON, needing no roster and contacting no host.
Every runnable command carries a mutation tier, so a calling agent can tell
which commands are safe to run freely and which need §3.4's guarantees or
human confirmation, without hardcoded per-command knowledge:

- **safe:** never changes state, on PVE or locally;
- **mutating:** changes state reversibly and routinely — a normal part of
  operating pveforge;
- **destructive:** a point of no return, or an unbounded blast radius (a
  command that hands off to arbitrary execution).

The worst case a command can reach sets its tier; `api` verbs are tiered by
verb, not path. A command with no tier is unknown, never safe — and a test
fails any runnable command that lacks one. The tiers as shipped are §4.2.

**Derived artifacts.** The man pages in `docs/man` are generated from the
command tree (`make man`) and held to it byte for byte
(`cmd/pveforge/man_test.go`); shell completion is cobra's built-in
`completion` command. Neither is hand-maintained.

### 3.6 I/O and process contract

- Getters/setters accept and emit plain `key=value` pairs for simple,
  scriptable one-liners.
- kv output is one field per line, and a line-oriented consumer reads it by
  two rules (`internal/kvjson` package doc):
  1. **Key:** if the line starts with `"`, the key is exactly one JSON string
     token and the next character is `=`; otherwise the key is everything
     before the first `=`.
  2. **Value:** everything after that `=`; if it starts with `"` it is
     exactly one JSON string, otherwise literal text.

  A key or string value is JSON-quoted only when it could otherwise be
  misread — it contains a control character (C0 or C1, e.g. U+0085) or
  U+2028/U+2029, starts or ends with whitespace, or starts with `"`; a key
  also when it contains `=`, a value also when it is the string `"null"` (JSON
  null prints as a bare `null`). No line splitter, Python's `splitlines()`
  included, can find a second line in one field. kv does not preserve JSON
  types; `-o json` is the exact form.
- kv flattens a top-level object only, in sorted key order; a nested value
  prints as compact one-line JSON. A payload that is not an object (a task
  id, a string, a number, null, a list — what `api` can return) prints as one
  `data=<value>` line, keyed by PVE's own envelope name.
- **JSON** is the primary structured format for reading (`-o json`) and for
  writing several fields at once: `vm set` and `vm create` take a JSON object
  (`--json`, `--json-file`) as well as `field=value` arguments; a JSON `null`
  deletes the key in `vm set` and is refused by `vm create`. The other
  writers take `field=value` arguments only (`api` takes repeatable
  `--data key=value`).
- **Streams.** Results go to stdout. Notices (pending changes, a PVE task
  that ended `WARNINGS: <n>`, which counts as success), warnings (a result
  that could not be re-read) and errors go to stderr. An error prints as one
  line, elided past 4 KiB.
- **Exit status.** 0 success, including a printed warning; 1 failure,
  including a usage error (an unknown subcommand, or a bare command group);
  130 interrupted by SIGINT, 143 by SIGTERM. Asking for help exits 0. `exec`
  exits with its command's own status once it hands over. A second signal
  kills the process at once; the kernel releases any lock it held. The README
  holds the table, and `cmd/pveforge/readme_test.go` holds it to the code.
- **Task waits.** A command that gets a PVE task id (a UPID) back waits for the
  task, holding its lock, up to the 10-minute task ceiling. Only the `api`
  writes can lower it (`--wait-timeout`) or skip the wait (`--no-wait`, which
  returns at dispatch); `vm create`, the snapshot commands and the network
  commands always wait up to the ceiling. A wait that runs out or is
  interrupted is reported as outcome-unknown — the task may still be running
  — never as failed.

## 4. Roster / target configuration

A list of targets and how to reach them — filling the role a Salt roster or
Ansible inventory plays.

- **Format: TOML**, not YAML or JSON. It matches an established local
  convention (`.vibe-palace.toml`, `nextgen-builder/manifest.toml` in the
  originating workspace), has mature native Go support, and avoids YAML's
  footguns (implicit type coercion, indentation-as-syntax) for a hand-edited
  file. JSON remains the CLI's *wire* format (§3.6); the roster is a config
  file optimized for human editing and diffing.
- **Location.** `--roster`, else `PVEFORGE_ROSTER`, else `./pveforge.toml`
  (`roster.DefaultPath`). `roster init` creates an empty one with mode 0600,
  which later writes keep.
- **Shape.** One `[[targets]]` table per target; the `token` and `ssh` tables
  appear once bootstrap (or `roster import-token`) has written them, `tls`
  once a pin has:

  ```toml
  [[targets]]
  id = "qa-pve-01"          # the name every command takes
  host = "192.0.2.10"
  node = "qa-pve-01"
  api_port = 8006
  insecure_tls = true       # self-signed: needs [targets.tls]
  # export = "token"        # hand-set only: lets `exec` hand out the token

  [targets.token]
  id = "root@pam!pveforge"
  secret_enc = "-----BEGIN AGE ENCRYPTED FILE-----..."

  [targets.ssh]
  user = "root"
  public_key = "ssh-ed25519 AAAA..."
  host_key_fingerprint = "SHA256:..."
  host_key_source = "ssh-verified"
  private_key_enc = "-----BEGIN AGE ENCRYPTED FILE-----..."

  [targets.tls]
  spki_sha256 = "sha256//..."
  source = "ssh-verified"
  ```

- **The key set is closed and case-sensitive.** An unknown or misspelled key is
  refused at load (`internal/roster/keys.go`), so a pin cannot be replaced by
  a differently spelled one or read as absent.
- **Secrets: `age` (`filippo.io/age`), embedded as a Go library, not shelled
  out to an external binary** — consistent with `pveforge` staying a single
  Go binary that needs no other tool installed. Only the secret *values* are encrypted (each an armored `age`
  blob string) inside an otherwise-plaintext file, so the roster stays
  reviewable and diffable — which hosts exist, how each is reached — while
  only credential material is opaque. A master passphrase derives a
  scrypt-based `age` identity at runtime (environment variable or interactive
  prompt, **never a CLI argument**). §4.1 is the full design. Per-person
  `age` recipients for rosters are deferred (§6 item 5); the harness already
  uses them for its own secrets.
- **`export = "token"`** is the operator's hand-edited opt-in that lets
  `pveforge exec` hand a target's API token — never its SSH key — to a child
  process. No pveforge writer sets it, and every writer refuses to change it
  (§4.1, egress).
- **Writes are surgical.** Every write takes the roster's own file lock
  (`<roster>.lock`), splices only the bytes it changes rather than
  re-serializing the file, checks that nothing else changed, compare-and-sets
  against the bytes it read, and replaces the file atomically
  (`internal/roster/writeback.go`). The per-object §3.4 locks are separate,
  in `<roster>.locks/`.

### 4.1 Secret management: design and architecture

This section states the design. The step-by-step procedures, and what each
refusal means to an operator, are in `docs/operations/secrets-and-keys.md`;
they are not repeated here.

**Scope: what is secret and what is not.**
- Secret: the roster passphrase, each target's API token secret, and each
  keyful target's SSH private key.
- Harness only: the nested test root password, the harness rosters'
  passphrase, and each consumer's age identity.
- Never stored anywhere: the outer cluster's root password
  (`PVEFORGE_PVE_PASSWORD`, read from the environment or a prompt for the run
  that needs it, never from argv).
- Not secret but integrity-critical: the SSH host-key pin, the TLS SPKI pin,
  their recorded provenance, and the harness's public age recipients.

The roster keeps secrets and pins side by side. Only the secrets are
ciphertext, so the file stays reviewable.

**Trust model.**
- **The SSH host key is the anchor.** The operator vouches for it with
  `--host-key-fingerprint`, a value read on the node's console. The client
  checks it during key exchange, before any password is sent. Once stored in
  `[targets.ssh]`, a pin binds every later SSH dial to the target, keyless
  (`--no-ssh-key`) dials included. The pin is compared against the key type
  the client negotiates: ECDSA, where the host serves it.
- **The TLS pin is captured over the verified SSH session, never on first
  REST contact** (operator ruling 2, 2026-09-25). Over the session, bootstrap
  runs `openssl s_client` against `127.0.0.1:<capture port>` on the node and
  parses the leaf certificate in Go. That covers a custom, ACME or
  cluster-signed certificate alike, since it reads what pveproxy actually
  serves. The capture port (`--capture-port`, default 8006) is not stored.
  The capture is bounded in time, like every SSH command, and in size: its
  answer may not exceed 64 KiB on each of stdout and stderr
  (`tlspin.MaxCaptureOutput`, one certificate being a few KiB). A node that
  prints more is stopped and the capture refused, so a hostile or broken
  node cannot stream an unbounded answer into memory. The limit is a
  per-call option of the SSH runner (`sshexec.WithMaxOutput`), set by the
  capture alone; every other command keeps unlimited output.
- **A network cross-check** (`pve.ServedPin`) then requires the target's REST
  address to serve the same key. It is a TLS handshake with no HTTP request,
  so no token or header can leave. It dials through REST's own transport
  clone, and it refuses when that transport would use a proxy: it could not
  then compare what REST will reach.
- **Read-only, then write, in this order.**
  1. The capture and the cross-check.
  2. The TLS pin, by compare-and-set.
  3. On a first run, the SSH auth.
  4. Only then preflight and the token phase.

  A mismatch therefore stops the run before any token is minted, validated
  or sent, and before any pin is stored. The order governs the roster and the
  token; one node-side write precedes it: a keyful first run installs its
  public key in the node's `authorized_keys` during the password session,
  before step 1, which is where a failed first run's stray key line comes
  from (a known gap, below). Whatever step a run fails at, every pin it
  stored came from the one session pinned to the operator's fingerprint (or
  trusted on first use under `--ssh-tofu`, and recorded as such), so a retry
  is sound; the guide walks through what a retry finds. No state exists in
  which a live token sits on a target whose peer identity was never
  established.
- **Ruling B′ (operator ruling RQ3).** A TLS pin captured over a password
  session (a first run, or a keyless run) needs `--host-key-fingerprint`. The
  one exception is an explicit `--ssh-tofu`, which records the lesser
  provenance. A run over a stored SSH pin is exempt. **B′ governs TLS pin
  capture only:** a CA-verified target captures no pin, so its first run, or
  a `--no-ssh-key` run, without `--host-key-fingerprint` trusts the SSH host
  key on first use with no `--ssh-tofu`, and `--ssh-tofu` there is refused as
  meaningless. A keyful first run records that pin as `host_key_source =
  ssh-tofu`; a `--no-ssh-key` run stores no SSH pin at all. Every other
  command's `--no-ssh-key` dial follows the same general rule (§3.1): the
  stored pin, else the fingerprint, else trust on first use.
- **Provenance is recorded, not inferred.**
  - `[targets.tls] source` records how the TLS pin was first obtained:
    `ssh-verified`, `ssh-stored`, `ssh-tofu` or `expect`.
  - `[targets.ssh] host_key_source` records the same for the SSH pin:
    `ssh-verified` or `ssh-tofu`.
  - A target reachable only without SSH is pinned from an operator-verified
    `--expect` value. No trust-on-first-use path exists for it.
- **A pin is never replaced silently.**
  - A pin that replaces or follows a stored value is written by
    compare-and-set against the value the writer read (`roster.WriteTLSPin`,
    `roster.ReplaceSSHAuth`). A first run's SSH auth (`roster.WriteSSHAuth`)
    has no prior value to compare; bootstrap's per-target lock serializes it.
  - A differing pin is replaced only by an explicit act, and only where a
    verified session vouches for the new key:
    - `roster pin-tls --repin`, for an `insecure_tls` target with SSH auth;
    - `bootstrap --reprovisioned --host-key-fingerprint <console value>`
      (operator ruling 3), which replaces the SSH pin, the installed keypair
      and the TLS pin together. It writes the TLS pin before the SSH auth.
      Where the stored pins already match the node it degrades to a plain
      bootstrap, so repeating the command always converges.
  - `roster pin-tls --print` shows what would be pinned and writes nothing;
    `roster validate --require-tls-pins` fails a roster with an unpinned
    `insecure_tls` target.
  - Every mismatch message labels the presented key "Do NOT pin", points to
    the console, and never fills a presented key into a suggested command. A
    test holds that wording.

**Encryption at rest.**
- **Each secret value is its own armored age ciphertext.** It uses a scrypt
  passphrase recipient at work factor logN 18 (age's default, about 0.8s per
  derivation). `filippo.io/age` is embedded, never shelled out to.
- **The passphrase is never a CLI argument.** It comes from
  `PVEFORGE_ROSTER_PASSPHRASE`, else a no-echo prompt on a terminal, else the
  command fails rather than hang. `roster import-token` reads the token secret
  from stdin, so its passphrase must come from the environment. In memory the
  passphrase is a type that prints as `[redacted]` under every format verb.
- **Every encrypting write proves the passphrase first.** It must open a
  secret the roster already holds (`roster.ErrWrongPassphrase`,
  `roster.ErrNoReadableSecret`), so a roster can never split into secrets
  sealed under two passphrases.
- **The work factor has a test-only seam** (`roster.SetScryptWorkFactorForTests`).
  It exists because the full factor made the suite take minutes. Five layers
  keep it out of production:
  1. a `testing.Testing()` gate, inert in any production binary, proved by
     building and executing a probe main;
  2. a static guard over `sourceguard.NonTestReferences`, refusing any
     production reference;
  3. `internal/roster/kdf_guard_test.go`, asserting logN 18 exactly, the
     override zero at rest, and its restore after a cycle;
  4. a blast radius confined to ciphertext a test writes into its own temp
     directory;
  5. `sourceguard.DirectiveEvasions`, refusing `//go:linkname`, `unsafe`,
     cgo and non-Go sources (assembly included) in production code, and the
     module guard's `TestModule_NoVendorTree`, refusing a `vendor/` tree.
     Those are the routes the AST walkers cannot see; two of them, a
     linkname and a vendor tree, were proven to ship a weakened binary with
     every older guard green.

  The one route left open is a dependency module linking in. The module
  guard holds which modules are in the dependency set (§5); it does not
  inspect their source.
- **The passphrase is confirmed when set, and can be changed.** When a roster
  holds no secret yet, the run that will seal its first one (bootstrap)
  prompts twice and refuses a mismatch; an environment-supplied passphrase is
  taken as given. `roster rekey` changes it, all or nothing: it is the third
  writer allowed to encrypt, beside the two proving writers, and its proof
  is every secret opening under the old passphrase (rekeying only some would
  split the roster); each is then sealed afresh under the new one, and the
  result is verified and compare-and-set against the bytes read before one
  atomic replace, under the roster lock. The new passphrase is terminal-only and
  asked twice, never taken from the environment. Rekey contacts nothing and
  touches no token, and it cannot reach copies made before it (backups, git
  history), so after a leak the tokens are rotated too. The checks and
  refusals are in `internal/roster/rekey.go`; the procedure is in the guide.

**Egress: the one way a secret leaves the roster.**
`pveforge exec <target> -- <command>` decrypts the target's API token and replaces itself (execve) with
the command, whose environment gains exactly one variable,
`PVEFORGE_PVE_AUTHORIZATION=PVEAPIToken=<token id>=<secret>`, and loses
`PVEFORGE_ROSTER_PASSPHRASE` and `PVEFORGE_PVE_PASSWORD`. Only a target the
roster marks `export = "token"` by hand can be exported, and the SSH key never
leaves. On Linux pveforge makes itself non-dumpable before it decrypts
(`nodump.Set`); after the execve the command is an ordinary process of the
same user. The mark is a guardrail, not a security boundary: anyone holding
the passphrase can copy a `secret_enc` into a roster where it is marked.
`exec` is `destructive`: it hands off to arbitrary execution.

**Transport enforcement (T3, operator ruling 1).**
- **The one HTTP client constructor refuses an `insecure_tls` configuration
  with no pin** (`pve.ErrTLSPinRequired`). No transport is built and no
  request of any method is made. The chain-skipping TLS configuration exists
  only together with a `VerifyConnection` callback.
- **The callback checks the leaf's SPKI hash on every handshake**, resumed
  ones included. The connection uses TLS 1.2 at minimum. It runs before any
  request byte, so a wrong key never receives the token.
- **A CA-verified target** (`insecure_tls = false`) needs no pin. With one,
  the chain AND the pin must both hold.
- **Proxies.** An `http://` proxy works, since the pin is checked end to end
  through its CONNECT tunnel. An `https://` proxy fails closed with a pin
  mismatch: net/http applies the same TLS configuration to the proxy leg, and
  no second configuration is built.
- **A source guard holds the transport shape**
  (`cmd/pveforge/httpconstructor_test.go`), with exact per-file counts:
  - the transport clone site;
  - `RoundTrip` calls;
  - `crypto/tls` dials;
  - `tls.Config.InsecureSkipVerify`: exactly two sites, the pinned transport and
    `servedPin`, which never carries a request.

  Every request also passes one transport that refuses any method but GET or
  HEAD on `/access`.
- **`roster import-token`** into an unpinned `insecure_tls` target needs
  `--expect`. It is refused before the secret is read from stdin. The pin is
  written only after the token validated through it.

**The older-binary lockout rule (R-b′).** Since `7d99123` a roster refuses
unknown keys, so a binary from `7d99123` up to a pin key's commit fails
closed on a roster that holds that key. **Binaries built before `7d99123` are the dangerous
case:** they ignore unknown keys, so they read a pinned roster without error,
ignore the pin and send an `insecure_tls` target's token unchecked. No design
inside the roster can stop an old binary that never looks; the defence is
operational, and the guide's "Older binaries: the lockout rule" gives the
rollout order (upgrade every reader of a roster before pinning it).

**Harness secrets.**
- **The harness keeps its secrets in one age blob,
  `hack/harness/secrets.age`:** the nested nodes' test root password and the
  harness rosters' passphrase. It is committed, and sealed to per-consumer
  public recipients (`hack/harness/recipients.txt`), not to a shared
  passphrase. This is the multi-consumer model §4 defers for rosters, applied
  to the harness only.
- **Age does not authenticate the sealer**, so the blob may carry only an
  allow-listed pair of names. Adding a name is a code change.
- **`hack/harness/unlock.sh run` puts the values into one exec'd command's
  environment only.** It never writes them to disk or argv and refuses to
  override a name already set; it strips, rather than refuses, the private
  identity and the variables through which an environment runs code in a
  bash child. The guide's "Harness specifics" has the variables and
  commands.
- **A recipient's removal is not revocation**, because git history keeps
  every blob it could open. Revocation is removal plus rotation of the
  values.
- **The outer root password is in no blob and never reaches an agent.** The
  harness guard refuses to run while `PVEFORGE_PVE_PASSWORD`, a set
  `PVEFORGE_ROSTER` or any proxy variable is present. It also requires a TLS
  pin on every nested target, distinct from every outer target's and from
  every other nested target's.

**Deliberately out of scope.**
- **ACME.** It is not in use, and Let's Encrypt cannot validate hosts that
  are not publicly reachable (operator ruling 5).
- **An internal CA.** If one is ever offered, the CA-verified mode
  (`insecure_tls = false`) is the path, and pins become optional there. No CA
  is built or managed by pveforge.
- **Multi-operator access to one roster.** Rosters keep a single passphrase
  (see §6 item 5).
- **These are known gaps, recorded rather than built** (§8 names the work in
  flight on the second; none is in flight on the first):
  - a command to rotate the SSH keypair of a node that was not rebuilt;
  - removal of stray `authorized_keys` lines left by failed first runs.

### 4.2 Command surface

This section says what each command family is for and why it writes the way
it does. It is not the command reference: `docs/man` and `pveforge schema`
are, and both are generated from the command tree and held to it by tests.

| Family | Purpose | Writes through | Design rationale |
|---|---|---|---|
| `bootstrap` | Password to token-authenticated roster entry | Root over SSH (`pveum`), then the roster | §3.2. Fails closed with no `--grant`; a changed scope revokes and re-mints |
| `roster` (`init`, `validate`, `import-token`, `pin-tls`, `rekey`) | The roster's own lifecycle | The roster file only | §4, §4.1. `import-token` creates nothing on PVE and never revokes |
| `exec` | Hand a target's API token to another tool | Nothing (execve) | §4.1 egress. Opt-in per target; the SSH key never leaves |
| `vm` (`get`, `set`, `create`, `snapshot …`) | VM config and lifecycle | Token over REST; root-only fields over SSH | §3.3, §3.4. Create takes an explicit VMID and fails on a taken one. Snapshot rollback goes to the newest snapshot only, never deletes one, and proves the guest is running with an in-guest witness through the guest agent unless `--no-witness` (operator, 2026-09-23) |
| `network` (`get`, `set`, `bridge create`, `bridge destroy`) | Node network interfaces | Token over REST, PVE's stage-then-commit | One lock per node. `bridge create` and `bridge destroy` require a `--management-bridge` canary read before and after staging; `set` instead proves every other interface on the node unchanged. A staged change pveforge did not make reverts the stage rather than be swept in; no bypass |
| `node`, `storage` (`get`, `orphans`) | Read node and storage state | Nothing | `storage orphans` keeps no state, fails closed on any read it cannot trust, and refuses shared storage. Its output is not a list of volumes safe to delete |
| `access inventory`, `user ensure`, `group ensure`, `acl grant` | PVE principals and ACLs | Root over SSH (`pveum`), never the token | The token must never hold `User.Modify` or `Permissions.Modify`. A grant to the roster's own token, its owner or a group it is in is refused; escalating roles need `--allow-escalating-role`; membership is only ever added; every write is read back as root |
| `api` (`get`, `post`, `put`, `delete`) | Any PVE REST path with no command yet | Token over REST | §3.1. Locks a modelled object, else needs `--unsafe-no-lock`; waits on a returned task; `/access` refused |
| `discover`, `schema` | Describe PVE's schema and pveforge's own | Nothing | §3.5 |

The mutation tiers as shipped (§3.5 Layer 3; `cmd/pveforge/readme_test.go`
holds this table to every runnable command's annotation, both ways):

| Tier | Commands |
|---|---|
| destructive | `bootstrap`, `exec`, `roster init`, `roster import-token`, `roster rekey`, `acl grant`, `api post`, `api put`, `api delete`, `network bridge destroy`, `vm snapshot delete`, `vm snapshot rollback` |
| mutating | `roster pin-tls`, `vm create`, `vm set`, `vm snapshot create`, `network set`, `network bridge create`, `user ensure`, `group ensure` |
| safe | `roster validate`, `vm get`, `vm snapshot list`, `node get`, `storage get`, `storage orphans`, `network get`, `access inventory`, `api get`, `discover vm`, `discover node`, `discover storage`, `discover network`, `discover device`, `schema` |

Cobra's own `help` and `completion` commands carry no tier.

Not on the CLI yet, though the library has them: VM destroy, clone,
shutdown, VM tagging and bridge port isolation (the §3.4.4 Ops), and running
a command in the guest (`pve.RoutedClient.AgentExec`, which the rollback
witness uses). There
is no VM migration support. The only PVE version exercised is 9.2.11.

## 5. Licensing, distribution and repository

- **License:** dual MIT / Apache-2.0 (`LICENSE`), matching the author's other
  software products. Source files carry no per-file SPDX header.
- **Repository:** standalone, its own git history and its own vibe-palace
  project space; module `github.com/suykerbuyk/pveforge`.
- **Distribution today is source only** (operator, 2026-10-02). There are no
  tags, no `--version` flag and no release tooling; a consumer (including
  `quantum-ng`) builds the binary from a pinned commit and never vendors or
  owns the source. Every library package is `internal/`, so only the binary
  is consumable. Release and versioning policy is open (§6 item 10).
- **Toolchain and build:** Go 1.27.1; a single Go binary, needing no other
  tool installed beside it. The Makefile is the interface: `make build`, `make
  test` (race detector and coverage), `make check` (lint, then test: what CI
  runs), `make lint` (module hygiene, gofmt, go vet), `make modcheck`
  (offline, read-only), `make vuln` (govulncheck), `make man`, `make
  install`, `make harness` (§7.7).
- **CI:** `.github/workflows/ci.yml` runs `make check` and `make vuln`
  (operator, 2026-09-23).
- **Dependencies are pinned and attributed, and a test holds both**
  (`internal/sourceguard/module_guard_test.go`, offline):
  - go-proxmox is required only from the fork, at a `vX.Y.Z-pveforge.N` tag
    (never a pseudo-version, never indirect), with no `replace` or `exclude`
    directive, and upstream `luthermonson/go-proxmox` appears nowhere in the
    module graph (operator, 2026-09-17: rename the module, tag after the
    push, guard it);
  - `THIRD-PARTY-NOTICES.md` lists exactly the modules linked into the
    module's binaries, across every supported platform, at the versions
    `go.mod` requires;
  - there is no `vendor/` tree.

  Binary distribution will also need the notices bundled with the binary, a
  mechanism that does not exist yet (§6 item 10).
- **Layout:** `cmd/` (the product binary and three harness helpers),
  `internal/` (every package; §7.3), `hack/harness/` (the nested test
  harness), `docs/` (this PRD, `docs/operations/` guides, generated
  `docs/man/`).

## 6. Open questions (tracked here until resolved, not assumed)

1. ~~Does the args-class-field workaround retain a standing SSH/password
   credential, or move entirely to hookscript injection?~~ **Resolved
   (operator, 2026-09-13, §3.1): both.** Standing SSH retained for on-demand
   root-only operations; hookscript still separately required for the
   boot-persistence case (§3.4.4).
2. Which other config fields, beyond `args`, are actually root-only on our
   target PVE version? (`rng`, `affinity`, `hugepages` are reported
   elsewhere, not independently verified.) Owed to the nested harness. A
   field that passes the live test joins `sshexec.RootOnlyFields` and is then
   written over SSH with no digest (§3.1).
3. ~~Concurrency/locking discipline for idempotent mutations against a
   concurrently-used host (§3.4).~~ **Resolved (operator, 2026-09-13; scope
   by `pveforge-idempotent-mutation-engine` Decision 1, confirmed with the
   operator):** per-object, writer-priority, cross-process advisory locks
   scoped to one roster file; network per node; PVE's digest as
   defense-in-depth for what they cannot reach (§3.4.2).
4. ~~Scope and shape of the hand-authored discoverability schema for the
   bespoke device-model layer (§3.5).~~ **Resolved:** split out as
   `pveforge-device-semantic-resolvers` (one resolver, NVMe, library-level)
   and `pveforge-discoverability-schema` (Layer 2, §3.5).
5. Multi-operator secret access (`age` recipients vs. a single passphrase) —
   deferred past v1. **Partly answered (2026-09-26, §4.1):** the nested test
   harness's secrets use per-consumer age recipients (`hack/harness/secrets.age`),
   so the operator and each CI runner hold their own identity. Rosters still
   use a single scrypt passphrase; that part stays open.
6. ~~Whether `api post/put` gets §3.4's locking for object types the engine
   already models, or an explicit unsafe posture for paths it doesn't
   cover.~~ **Resolved in two steps.** `pveforge-raw-api-escape-hatch`
   (2026-09-14): a path matching a modeled object type (vm/storage/network/
   node) takes that object's §3.4 lock with no opt-out, and any other path
   refuses to mutate without an explicit `--unsafe-no-lock`. What that left
   open was the lock's REACH: it was released when the HTTP call returned,
   while PVE was still running the task the call started.
   `pveforge-mutation-success-second-signal` (2026-09-21) closed it: `api
   post/put/delete` now waits on a returned task id (UPID), up to the
   10-minute task ceiling, before reporting success or failure, and holds the
   lock for the whole wait. `--no-wait` opts out, and states that the lock is
   then released before the task ends. (The kv rendering of a non-object
   payload this introduced is §3.6.)
7. **When, and what, becomes a public Go API** (operator, 2026-10-02, §2
   future direction): which packages leave `internal/`, under what stability
   promise, and whether an MCP server or OpenTofu/Pulumi provider lives in
   this repository.
8. **VM destroy after a failed stop** (`pveforge-vm-destroy-stop-failure-gate`):
   keep the best-effort stop, or gate destroy on the VM's status and fail
   closed. Must be settled before a destroy command reaches the CLI.
9. **Bridge port isolation on the CLI:** §3.4's canonical example exists only
   as library code. Ship a command for it, or keep it library-only and say
   why.
10. **Release and versioning policy** (operator, 2026-10-02): tags, a
    `--version` flag, and bundling `THIRD-PARTY-NOTICES.md` with a binary.
11. **A stale roster backup** (`pveforge-stale-roster-backup-revokes-live-token`):
    restoring an old roster and re-running bootstrap revokes the live token,
    because a persistent 401 counts as a verdict. Whether that rule should be
    amended needs an operator ruling; the guide documents the hazard.

## 7. Implementation architecture (as built)

What §3 describes, as it is built on `main`. Each package's own doc comment
is the detailed account; this section is the map.

### 7.1 Module and dependencies

Module `github.com/suykerbuyk/pveforge`, Go 1.27.1. Direct dependencies:
`github.com/suykerbuyk/go-proxmox` (the fork, §0.1 finding 3), `filippo.io/age`
(secrets), `github.com/gofrs/flock` (locks and roster writes),
`github.com/pelletier/go-toml/v2` (the roster), `github.com/spf13/cobra` and
`pflag` (the CLI), `golang.org/x/crypto` (SSH) and `golang.org/x/term`
(prompts). §5 says how they are pinned.

### 7.2 Binaries

- `cmd/pveforge` — the product (§4.2).
- `cmd/pveforge-harness-accept` — waits until the nested `pvh` cluster is
  whole (quorate, QDevice connected, shared storage active), through
  `harness.Open`. The only main allowed to link a test-support package.
- `cmd/pveforge-harness-pins` — prints a roster target's host and SSH pin,
  needing no passphrase, for the harness scripts.
- `cmd/pveforge-harness-secrets` — opens and seals `hack/harness/secrets.age`;
  run through `hack/harness/unlock.sh`.

None of the harness binaries is shipped, documented in `docs/man`, or present
in `pveforge schema`.

### 7.3 Package map

Every package `go list ./...` reports, under the default build or
`-tags harness`, and its plane:
- **binary:** the product's main;
- **production:** linked into `cmd/pveforge`;
- **harness tool:** a harness helper's main;
- **harness library:** linked only into a harness helper;
- **test-support:** shared test machinery, never linked into the product;
- **harness suite:** test files only, run with `-tags harness`.

`internal/sourceguard/prd_packagemap_test.go` holds this table to `go list`
both ways, plane included.

| Package | Plane | Role |
|---|---|---|
| `cmd/pveforge` | binary | The CLI: one cobra command per §4.2 row; flags, output and exit status (§3.6) |
| `cmd/pveforge-harness-accept` | harness tool | §7.2 |
| `cmd/pveforge-harness-pins` | harness tool | §7.2 |
| `cmd/pveforge-harness-secrets` | harness tool | §7.2 |
| `internal/bootstrap` | production | §3.2's flow; `pveum` as root (`bootstrap.RootAccess`) for every access write; TLS pin capture; token rotation. Talks to the network only through its own `SSHTransport`/`APIValidator` interfaces |
| `internal/idempotent` | production | §3.4's engine (`idempotent.Op`, `idempotent.Run`) and every Op |
| `internal/discover` | production | §3.5 Layers 1 and 2: parses PVE's apidoc tree, holds pveforge's device schemas |
| `internal/device` | production | §3.3's semantic resolvers (`device.NVMeDrive`) over a small client interface |
| `internal/pve` | production | The PVE client: go-proxmox plus `pve.Client.RawRequest`; TLS policy and the `/access` write guard; `pve.RoutedClient`, the REST/SSH routing point; digest compare-and-set writes; task waits |
| `internal/roster` | production | §4: load, strict keys, per-value age encryption, surgical write-back, rekey |
| `internal/lock` | production | §3.4.2's per-object lock |
| `internal/sshexec` | production | The SSH transport: pinned host keys, deadlines, a per-call output limit, `qm set`, file writes, bridge and link state, key install |
| `internal/tlspin` | production | The SPKI pin form, the per-handshake check, the capture command and its output cap |
| `internal/kvjson` | production | §3.6's kv and JSON contract |
| `internal/nodump` | production | Makes the process non-dumpable before it holds a decrypted secret (`exec`) |
| `internal/harnesssecrets` | harness library | The age-sealed harness environment (§4.1) |
| `internal/harness` | test-support | The nested-harness guard (`harness.Open`) and acceptance checks (§7.7) |
| `internal/harness/suites` | harness suite | The `-tags harness` suites, which get clients only from `harness.Open` |
| `internal/lock/lockguard` | test-support | §3.4.2's static lock and task-wait context rules |
| `internal/netguard` | test-support | Loopback-only dial trip-wire for unit tests |
| `internal/pvefake` | test-support | In-process fake PVE sshd and scripted fake REST servers |
| `internal/sourceguard` | test-support | The AST guard library and the module-wide guards (§7.6) |

Layering, production packages only (an arrow is "imports"). These are the
principal edges, not an exhaustive import graph: `go list -f '{{.Imports}}'`
is the authority.

```
cmd/pveforge ─► bootstrap ─► idempotent ─► pve ─► roster ─► tlspin, kvjson
    │               │            │          └──► sshexec, tlspin
    │               │            └──► lock, sshexec, kvjson
    │               └──► pve, lock, roster, sshexec, tlspin, kvjson
    ├──► idempotent, pve, roster, lock, sshexec, tlspin, kvjson  (directly, too)
    ├──► discover ─► device            (device imports only go-proxmox)
    └──► nodump
```

`lock` imports `sshexec` only to shell-quote a path in its timeout message.

### 7.4 Transport boundaries

- **REST** is built in exactly one place, `internal/pve`'s HTTP client
  constructor: TLS policy (§4.1), the `/access` write refusal, and the raw
  request path. A source guard holds that no other package builds an HTTP
  client or transport, outside three files it allow-lists by exact path:
  bootstrap's first-contact SSH adapter (`internal/bootstrap/deps.go`, which
  runs before any PVE client can exist) and the two files of the test-support
  `internal/netguard` (`cmd/pveforge/transportboundary_test.go`,
  `cmd/pveforge/httpconstructor_test.go`).
- **SSH** is built only in `internal/sshexec`: key-only dials for routine
  root work, password dials for bootstrap and keyless runs, host keys checked
  against a pin (`sshexec.PinnedHostKeyCallback`) or the operator's
  fingerprint (`sshexec.ExpectedHostKeyCallback`), and trust on first use
  (`sshexec.CaptureHostKeyCallback`) for a password dial with neither, as
  §3.1 states. The caller's stdin is never forwarded.
- **`pve.RoutedClient`** is the one place that chooses between them (§3.1).
  A guard holds that each of its exported methods is accounted for and
  exercised, and that its over-SSH fallbacks occur only at the root-only
  refusal sites.

### 7.5 The mutation path

Most mutating commands resolve the roster and target, build a
`pve.RoutedClient`, and call `idempotent.Run` with an object key and an Op:
`vm create`, `vm set`, `network set`, `network bridge create` and `destroy`,
`user ensure` and `group ensure`. `Run` takes `lock.Mutation` for that key,
then reads, compares, applies (retrying on a digest conflict), re-reads and
post-checks, all under the lock; a PVE task the apply started is waited on
before the lock is released. The exceptions:
- the snapshot writes (`vm snapshot create`, `delete`, `rollback`) and the
  `api` writes take `lock.Mutation` directly and run their own check under it;
- `bootstrap`, `roster import-token` and `roster pin-tls` take the target's
  per-target lock for their whole run;
- `acl grant` takes no lock (§3.4.2).

Reads that must not see a half-made change take `lock.Read`.

### 7.6 Invariants enforced by source guards

The guards are tests that read the source, so a refactor that breaks an
invariant fails the build's tests rather than a review. Most walk the syntax
tree (`internal/sourceguard`, `internal/lock/lockguard`);
`sourceguard.DirectiveEvasions` is deliberately a text scan, since a
directive is a comment the syntax tree drops; the harness-script guards run
the scripts. Not exhaustive:

| Invariant | Held by |
|---|---|
| No `//go:linkname`, `unsafe`, cgo, assembly or non-Go source in production code | `sourceguard.DirectiveEvasions`, module-wide |
| The fork pin, no `replace`/`exclude`, no upstream, notices equal to the linked modules, no `vendor/` (`TestModule_NoVendorTree`) | `internal/sourceguard/module_guard_test.go` |
| Test-support packages and the man-page generator never reach a production binary | `internal/sourceguard/testsupport_guard_test.go` |
| No `t.Parallel` in packages whose tests share process globals | `internal/sourceguard/noparallel_guard_test.go` |
| HTTP and SSH transports built only in `internal/pve` and `internal/sshexec` | `cmd/pveforge/transportboundary_test.go` |
| Test seams (scrypt work factor, task timings, the SSH dial guard and port) referenced only from tests, and inert outside a test binary | `sourceguard.NonTestReferences` plus a probe main per seam |
| Every lock call and task wait gets its caller's context; every command reaching a lock has `--lock-wait` | `internal/lock/lockguard` |
| `pveum` root writers, and the root session itself, used only at their reviewed sites | `internal/bootstrap/access_guard_test.go` (`TestRootSession_OnlyAtItsSites` among them) |
| Every exported `pve.RoutedClient` method accounted for and exercised; its over-SSH fallbacks only at the root-only refusal sites | `internal/pve/routedforwarding_test.go`, `internal/pve/overssh_guard_test.go` (`TestOverSSHFallbacks_OnlyAtTheRootOnlyRefusalSites`) |
| VM shutdown can reach no hard-stop path | `sourceguard.ReachableTokens` |
| No unit test dials a non-loopback address | `internal/netguard`, installed in each networked package's `TestMain` |
| The harness shell scripts parse and behave against fakes | `internal/sourceguard/harness_scripts_test.go` and the harness behaviour tests |

### 7.7 Verification architecture

- **Unit tests** run against fakes, never a live host: `internal/pvefake`
  drives a real `pve.RoutedClient` over both transports, and `internal/netguard`
  fails any test that dials a non-loopback address. `make test` runs them
  with the race detector and coverage.
- **Documents held to the code:** the README's environment and exit-status
  tables and its command lines and the secrets guide's command lines by
  `cmd/pveforge/readme_test.go`; this PRD by the tests its header names;
  `docs/man` by `cmd/pveforge/man_test.go`.
- **CI** runs `make check` and `make vuln` (§5).
- **The nested PVE test harness** (`hack/harness/`, `pveforge-nested-pve-test-harness`)
  is for real end-to-end and destructive tests: a two-node PVE cluster
  (`pvh-n1`, `pvh-n2`, with a shared NFS node `pvh-nfs`) nested as VMs on the
  outer cluster. `hack/harness/lib.sh` is the scripts' only path to the
  outer hypervisor, through pveforge as a pool-scoped token with fail-closed
  allow-lists. `harness.Open` refuses to hand out a client unless the nested
  roster is the only one in play: no `PVEFORGE_ROSTER`, no
  `PVEFORGE_PVE_PASSWORD`, no proxy variable, `pvh-*` targets only, pins
  present and distinct, no overlap with any outer roster, and the live
  cluster is exactly `pvh` with its two nodes. `make harness` runs the
  `-tags harness` suites through `hack/harness/unlock.sh`. Shell is thin
  glue; pin logic is Go only, and the outer scripts are to be ported to Go
  after the first live run.
- **Owed to the harness:** the README's "Not yet verified on a live host"
  list is the backlog of behaviour that rests on PVE's documentation or
  source rather than observation, together with §6 item 2.

## 8. Status and in flight

As of the status line at the top. Work listed here is not merged; this
document describes `main` only. Where work exists, it is staged in a
worktree with no commits yet: its branch still points at an older `main`.

- **Refusals after a prompt** (`pveforge-refuse-before-prompting`; staged in
  the `refuse-early` worktree): bootstrap's B′, `--ssh-tofu` and reprovision
  refusals currently fire after the operator has typed the password or
  passphrase, and `roster pin-tls` and `roster import-token` have the same
  order. §3.2's "before it prompts" holds for `--grant` today, not yet for
  these.
- **TLS pinning, remainder** (`pveforge-rest-tls-certificate-pinning`): T1a
  to T3 are merged. T2k (staged in the `t2k` worktree; sent back in review)
  removes pveforge's own `authorized_keys` line after a failed first run and
  adds a read-only access-keys report of stray lines; removing strays left by
  earlier runs stays manual (operator ruling). It addresses §4.1's second
  known gap; nothing is in flight on SSH keypair rotation. (The byte cap on
  the TLS capture's output, once a third gap, has landed: §4.1.)
- **Keyless targets cannot store a host-key pin**
  (`pveforge-keyless-target-host-key-pin`): every `--no-ssh-key` run needs
  the fingerprint again, or trusts the host key on first use (only with
  `--ssh-tofu` where the run captures a TLS pin).
- **Stale roster backups** (§6 item 11) and **destroy after a failed stop**
  (§6 item 8): awaiting rulings.
- **The nested harness** (`pveforge-nested-pve-test-harness`): the build and
  golden-snapshot/reset code is merged; the first live build, cluster
  formation and golden run are owed, then the Go port of the outer scripts.
- **Storage volume lifecycle** (`pveforge-storage-volume-lifecycle`): only the
  orphan scan ships; volume tracking, the content-type toggle and a
  cluster-wide claimed-volume set (shared storage) are planned.
- **The go-proxmox fixes upstream:** whether to offer them, and under which
  author identity, is an open operator item.
