# PRD — `pveforge`

**Status:** Foundational draft, 2026-09-13. Not yet implemented — no code exists yet.
**Author:** John Suykerbuyk, drafted with Claude Code during a same-day investigation
in the `quantum-ng` workspace.
**License:** Dual MIT / Apache-2.0 (matches the author's other software products).
**Repo:** standalone, `/home/johns/code/pveforge` — not owned by or embedded in any
consumer's repository.

---

## 0. Provenance — why this document exists and what it's built on

This PRD is the direct output of a single-day, evidence-driven investigation
conducted inside `quantum-ng` (a separate, private workspace) into how that
project should replace ~21,600 lines of ad-hoc bash (`mk/proxmox/*.sh`) that
manage Proxmox VE clusters via root SSH + hand-parsed `pvesh` text output. That
investigation ruled out several alternatives with live, reproducible evidence
(not just reading docs) and converged on: **build a standalone Go CLI**. This
document is that decision's foundational spec, written so `pveforge` can be
developed as its own product rather than as an implicit extension of one
consumer's internal facade.

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
   auth, unconditionally.** Tested directly: an API token belonging to
   `root@pam`, granted full `PVEVMAdmin` role on the specific target VM, can
   create a VM and set `description` via token (`HTTP 200`), but a request to
   set `args` fails every time with `HTTP 500` /
   `"only root can set 'args' config"` — regardless of the token's granted
   privileges. This is not a permissions bug fixable by better ACLs; it is a
   deliberate, hardcoded server-side restriction. It applies to `args` and, per
   community reports (not independently verified by us), likely `rng`,
   `affinity`, and `hugepages` as well.
2. **This restriction is universal across client implementations**, not a
   quirk of one library. It was independently reproduced through a completely
   separate client (`saltext-proxmox`, a Python/Salt cloud driver) with the
   identical error message and HTTP code. Any tool built on Proxmox's REST API
   will hit the same wall for these fields; there is no client-side way around
   it.
3. **`suykerbuyk/go-proxmox`, our own fork of `luthermonson/go-proxmox`**, is a
   fully-typed Go client covering the entire PVE `/api2/json` surface for both
   8.x and 9.x. Verified directly from source: its `VirtualMachineConfig`
   struct exposes `Args`, `Hookscript`, `EFIDisk0`, and `Bios` as first-class
   fields (not omitted or hidden), and its write path
   (`VirtualMachineOption{Name, Value}`) is explicitly documented as raw,
   schema-free passthrough of "the same names `qm create` takes" — so it never
   fights custom/exotic device configuration the way a rigid ORM-style client
   would. It supports native API-token auth (`WithAPIToken`).

   **Why a fork (2026-09-18).** This entry previously justified the dependency
   as "mature (287★), actively maintained". That described the upstream
   project's popularity, and it is no longer the reason pveforge carries this
   client: we carry it because we control it. The fork exists so that
   transport-layer changes pveforge needs can be made on our own schedule,
   rather than depending on an external maintainer accepting them — the
   concrete limitation already driving that need is upstream's
   `handleResponse` (`proxmox.go:446-449`), which returns
   `errors.New(res.Status)` on HTTP 500/501 without ever reading the
   response body, discarding exactly the PVE diagnostic text this project
   treats as load-bearing. That single defect is why the whole `RawRequest`
   subsystem exists; it is cited throughout `internal/pve` (`rawrequest.go:26`,
   `vmshutdown.go:66-68`, `vmconfig.go:55`, `vmdestroy.go:49`, `vmcreate.go:29`,
   `vmclone.go:25-26`, `snapshot.go:177`, `vmguest.go:285`, and in the tests
   that pin the behaviour). Upstream
   remains the canonical project and the better choice for anyone who does not
   need those changes. As of this writing the fork is a module-path rename
   only, with no behavioural divergence from upstream (see the fork's
   `CHANGES`) — what has been acquired is the ability to diverge, not any
   divergence itself.
4. **A live trial of the leading alternative (`saltext-proxmox`, a
   community-maintained Salt Proxmox cloud driver) surfaced two independent,
   concrete problems within the first hour of real use**, not hypothetical
   ones:
   - Installing it (masterless, no daemon) failed twice on native C-extension
     builds (`timelib`) before succeeding, requiring a full compiler toolchain
     and Python dev headers on the target host — real "Python dependency
     baggage," demonstrated rather than asserted.
   - Its `create()` function unconditionally calls `start()` immediately after
     creating a VM, which crashed with a `KeyError: 'name'` inside the
     extension's own `_get_vm_by_name` helper on the very first successful
     create — a live bug in its primary code path. This corroborates a
     maintenance-risk read on the extension (third-party maintainer, thin
     commit velocity dominated by dependency bumps) with direct evidence,
     not just a GitHub-activity inference.
5. **Cluster API for Proxmox (`cluster-api-provider-proxmox`)** is a real,
   moderately active project, but solves a different, narrower problem: its
   `ProxmoxMachineSpec` is clone-plus-cloud-init only, has no field for raw
   device args, and requires a permanently-running Kubernetes "management
   cluster" to host its controllers — a chicken-and-egg problem for
   provisioning the infrastructure a Kubernetes cluster doesn't exist on yet.
   Ruled out.
6. **A Kubernetes in-cluster app-lifecycle control plane
   (`quantum-orchestrator`, specific to the `quantum-ng` investigation)** was
   ruled out as a category error — it runs Helm installs *inside* an
   already-formed cluster and contains zero infrastructure-provisioning code.
   Not relevant to `pveforge` directly, but recorded here because it's the
   kind of "wrong layer" mistake worth guarding against when people propose
   future integrations: **`pveforge`'s job ends at "the VM shell exists,
   correctly configured." It does not configure guest operating systems,
   install Kubernetes, or manage application lifecycle.**

Full session record (methodology, exact commands, cleanup discipline) lives in
`quantum-ng`'s own vault under its `Projects/quantum-ng/sessions/` tree and is
reachable cross-project via `vp_search_cross_project`, but is **not**
automatically part of this project's own history — this section exists so
`pveforge` doesn't depend on that external memory.

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
- An MCP server, an AI-agent-only interface, or anything that cannot be
  invoked deterministically and non-interactively from a shell script or
  `make` target. Machine- and AI-readable discoverability (§3.5) is a *format*
  requirement, not an *interaction-model* requirement — `pveforge` must work
  identically whether invoked by a human, a cron job, CI, or an agent, with
  zero non-determinism introduced by any of them.

## 3. Architecture

### 3.1 Transport

- **Primary: Proxmox's REST API over HTTPS, authenticated by API token.**
  This covers the large majority of VM/node/storage/network operations,
  verified directly (§0.1, finding 1 — everything except a small set of
  root-only fields worked cleanly via token once ACLs were granted).
- **A permanently-retained, narrowly-scoped local/password-authenticated path
  for the fields Proxmox's API refuses to accept from any token** (`args`,
  and likely `rng`/`affinity`/`hugepages` — to be independently verified per
  field, not assumed from community reports). This is not a bootstrap-only
  concession — operator confirmed (2026-09-13) this is expected to be a
  standing capability, since more such fields may surface over time as device
  requirements grow.
  - **Resolved (operator, 2026-09-13):** this path is retained as a standing,
    narrowly-scoped SSH/password-authenticated command-execution vector,
    invoked directly by the binary at the moment such a field needs setting —
    not moved entirely to hookscript injection. Reason: some required
    operations (specific networking setups, and `qm set`-class operations not
    yet exposed by the REST API) are only reachable via `pvesh` or equivalent
    root-level tooling on the hypervisor itself, invoked on demand — a
    hookscript's event-triggered model (pre-start/post-start/pre-stop/
    post-stop) cannot serve an arbitrary, operator-initiated mutation issued
    at any time. **This is in addition to, not instead of, the hookscript
    mechanism** — §3.4's bridge port-isolation case still needs a hookscript,
    since that state must be reapplied automatically on every boot without a
    live `pveforge` invocation driving it. The two mechanisms solve different
    problems and both are needed: hookscript for automatic re-application at
    VM lifecycle transitions, standing SSH for on-demand root-only operations.
- **SSH is a permanently-retained Tier-2 execution vector, not a bootstrap-only
  concession.** REST API (token-authenticated) remains the default and
  preferred path for everything it covers (§0.1, finding 1). SSH/`pvesh` is
  reserved for the specific, narrow class of operations confirmed to have no
  REST equivalent — but for that class, it is a standing capability the
  binary may invoke at any time, not a one-time bootstrap or hookscript-
  deployment mechanism only.
- **Planned, not yet built (`pveforge-raw-api-escape-hatch`):** a raw
  `pveforge api get/post/put/delete <path> [--data key=value ...]`
  passthrough for any PVE REST path with no dedicated command yet —
  complementing §3.5's `discover` (learn the shape, then poke it directly).
  Idea surfaced by reviewing `davegallant/pvectl` (GPL-3.0 — read for the
  idea only, its code was never used). Open design question before this is
  built: see §6, item 6.

### 3.2 Bootstrap

`pveforge` must be able to go from "nothing exists yet" to "fully
token-authenticated" using only credentials an operator already has:

1. Accept a PAM (or PVE-realm) username/password.
2. Generate an SSH keypair, install the public key on the target host(s) via
   that password (so future non-API-token operations, if any remain, don't
   need the password again).
3. Generate a scoped API token via the PVE API (or `pveum` locally over the
   freshly-installed SSH key) and persist it into the target's roster entry
   (§4), encrypted.
4. From that point forward, default to token auth for everything token auth
   can do.

### 3.3 Object/property model

Mirrors the split verified in `go-proxmox` (§0.1, finding 2):

- **Read side:** typed structs per object class (VM, node, storage volume,
  network interface, ...), so callers get real types instead of hand-parsed
  strings, with tolerant types where Proxmox's own JSON is inconsistently
  typed across versions.
- **Write side:** raw name/value option pairs matching Proxmox's own
  parameter names 1:1, so nothing about our exotic device configuration
  (§3.1) is fought by an opinionated schema. `pveforge` owns the *semantic*
  layer on top (e.g., "add an emulated NVMe drive with this serial" resolves
  internally to the correct `args:` fragment), but the underlying write
  primitive stays schema-free.

### 3.4 Idempotent mutation

Every mutating command follows check-then-act: read current state, compare
to requested state, no-op (report "already satisfied") if they match, else
mutate and report what changed. A `--force` flag bypasses the no-op and
re-applies unconditionally. Acknowledged limitation: some state genuinely
cannot be inspected before the mutating action (accepted, not a design flaw).

**Concurrency, resolved (operator, 2026-09-13):** `pveforge` implements its own
serialization discipline rather than relying only on documentation or on
Proxmox's own optimistic-concurrency primitives. Motivation, confirmed real
rather than hypothetical: the originating environment (this project's own
vibe-palace multi-agent workflow) already runs multiple concurrent
orchestration agents against shared hosts, each potentially pursuing
different objectives against overlapping or identical properties — a
materially different threat model from single-script sequential execution.
Mandate:

- **All mutating operations are always blocked and serialized** — never two
  concurrent mutations in flight against the framework at once, full stop.
- **A pending mutation takes priority over a pending read.** A read that
  would otherwise run next yields to a mutation waiting behind it.
- Exact scope/granularity (per-object, per-target/host, per-process, or
  needing to reach across separate `pveforge` invocations/machines
  entirely) is this area's own design task —
  `pveforge-idempotent-mutation-engine` — to size properly, not assumed
  here. Proxmox's own config `digest` field (see that task's recorded
  research findings) remains valuable as defense-in-depth against a write
  from outside `pveforge` entirely (e.g. a concurrent GUI edit), but does not
  by itself satisfy the always-serialize-and-prioritize-writers mandate above
  — it only detects a lost race after the fact, it doesn't prevent or order
  one.

**Standing example already known to need this exact mechanism:** Linux bridge
port isolation (`bridge link set dev <tap> isolated on`) does not survive a
VM stop/start — the flag lives on the ephemeral tap device, recreated fresh
on every boot. This is the canonical case that motivates both the hookscript
requirement (§3.1) and the idempotency model: "ensure isolation is set" must
be safely re-runnable every single boot, forever, not just at VM creation.

### 3.5 Discoverability

Every noun and verb the CLI exposes must be walkable from the top down
without static documentation — by a human, a script, or an AI, with no
distinction in interface between them (this is a schema-introspection
requirement, not an agent-interaction-model concern; see §2).

This splits into three layers: two shipped, one planned.

**Layer 1 — PVE's own generic object model (nodes, VMs, storage, network).**
`pveforge` proxies PVE's own schema rather than hand-authoring a parallel
one that could drift from PVE's real (version-dependent) shape — but the
mechanism is **not** Proxmox's HTTP `OPTIONS` method. That was the original
plan, and it does not work:

- **Verified false, 2026-09-14, against a live 2-node PVE 9.2.11 cluster:**
  PVE's API daemon rejects the HTTP `OPTIONS` method unconditionally, for
  every path, before auth or routing ever runs — a hardcoded server-side
  restriction (its method allowlist has no `OPTIONS` entry at all), not a
  permissions or path issue. Confirmed live across five distinct paths (a
  real object's config, a nonexistent object's config, a status endpoint, a
  node-level path, a cluster-level path): all five returned an identical
  `HTTP 501 method 'OPTIONS' not available`, independent of whether the
  path's object id was real.
- **The actual mechanism, also verified live:** PVE's own `pvesh usage` and
  its web API-viewer are both ultimately built from a static, **unauthenticated**
  JavaScript asset pveproxy itself serves at `/pve-docs/api-viewer/apidoc.js`
  (part of the `pve-docs` package; ~4.3MB on a 9.2.11 host, same
  scheme/host/port as the REST API). Its body is
  `const apiSchema = [ ... ];` followed by unrelated UI code that is not
  itself valid JSON — `pveforge` fetches this file and extracts just the
  embedded JSON array. Each array element describes one PVE API path as a
  literal **templated** string (e.g. `/nodes/{node}/qemu/{vmid}/config` — a
  placeholder segment name, never a real object id, so no runtime path
  substitution is ever needed to look up a schema), with an `info` object
  keyed by HTTP method, itself split into `parameters` (request-side
  fields) and `returns` (response-side fields) — a caller needing "what
  fields can I set or read here" needs both, since which half carries the
  more complete field list varies by endpoint.
- **Because this is an unversioned doc-generation artifact, not a REST
  contract,** its exact format could change between PVE releases without
  notice. `pveforge` MUST fail loudly (a clear, named error identifying
  what broke) rather than silently returning an empty or partial schema if
  the expected marker, bracket structure, JSON shape, or a duplicate
  templated path is encountered — masking a future format drift as "no
  schema for this path" is explicitly the wrong failure mode here.
- **CLI noun → PVE path grammar** (`pveforge discover <noun> <target-id>`,
  purely a schema read — no object needs to exist, since paths are
  templated):

  | Noun | Default path | `--verb status` path |
  |---|---|---|
  | `vm` | `/nodes/{node}/qemu/{vmid}/config` | `/nodes/{node}/qemu/{vmid}/status/current` |
  | `node` | `/nodes/{node}/status` (bare `/nodes/{node}` is only the index/listing endpoint and carries no real fields) | — |
  | `storage` | `/storage/{storage}` (cluster-wide config) | `/nodes/{node}/storage/{storage}/status` (per-node runtime status) |
  | `network` | `/nodes/{node}/network/{iface}` | — |
  | `device` | *(no PVE call at all — Layer 2, below)* | — |

**Layer 2 — `pveforge`'s own bespoke device-semantic layer** (the NVMe/BMC/
PCIe device-model abstractions) is invisible to Proxmox's schema — to
Proxmox, `args:` is just an opaque string. Making this layer self-describing
is hand-authored (currently just `device.NVMeDrive`; revisit the convention
once a second resolver exists, not before) and reachable via
`pveforge discover device <type>`, purely locally — no roster, network
call, or live host needed. Owned by `pveforge-object-model-get-set` /
`pveforge-discoverability-schema` (operator, 2026-09-13; both landed).

**Layer 3 — `pveforge`'s own command surface, planned, not yet built
(`pveforge-cli-self-schema`).** Layers 1–2 describe *PVE's* object model;
nothing today describes *pveforge's own* CLI surface for a calling agent
without parsing `--help` text. Planned: a `pveforge schema` command
printing the full command tree (names, flags, short descriptions) as JSON,
with every runnable command annotated `safe`/`mutating`/`destructive` —
letting a calling agent decide which subcommands are safe to run freely
versus which need §3.4's idempotent-mutation-engine guarantees or human
confirmation, without hardcoded per-command knowledge. (Idea surfaced by
reviewing `davegallant/pvectl`, GPL-3.0 — read for the idea only, its code
was never used.)

### 3.6 I/O

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
- Full JSON is supported as the primary structured format for both reading
  (`-o json`) and writing (a JSON body/file for multi-field set operations) —
  the efficient, well-structured path for anything beyond a single field.

## 4. Roster / target configuration

A default list of targets and how to reach them — filling the role a Salt
roster or Ansible inventory plays.

- **Format: TOML**, not YAML or JSON. This isn't arbitrary — it matches an
  existing, established local convention (`.vibe-palace.toml`,
  `nextgen-builder/manifest.toml` in the originating investigation's
  workspace), has mature native Go support, and avoids YAML's well-known
  footguns (implicit type coercion, indentation-as-syntax) for a
  human-hand-edited file. JSON remains the CLI's *wire* format (§3.6); the
  roster is a config file optimized for human editing and diffing.
- **Secrets: `age` (`filippo.io/age`), embedded as a Go library, not shelled
  out to an external binary** — consistent with `pveforge` staying a single
  static binary with no new runtime dependency. Encrypt only the secret
  *values* (each an armored `age` blob string) inside an otherwise-plaintext
  TOML file, so the roster stays reviewable and diffable in source control —
  which hosts exist, which auth mode each uses — while only the actual
  credential material is opaque. A master passphrase derives a scrypt-based
  `age` identity at runtime (environment variable or interactive prompt,
  **never a CLI argument** — matches this project's standing rule against
  secrets on the command line).
  - **Future option, not v1:** `age` also supports recipient/identity
    keypairs instead of a shared passphrase, which matters if multiple people
    need to decrypt the same roster without sharing one secret. Worth
    revisiting once this has more than one operator.

## 5. Licensing and repository structure

- Dual MIT / Apache-2.0, matching the author's other software products.
- Standalone repository at `/home/johns/code/pveforge`, its own git history,
  its own vibe-palace project space. Any consumer (including `quantum-ng`)
  depends on a released binary/module version — it does not vendor or own
  the source.

## 6. Open questions (tracked here until resolved, not assumed)

1. ~~Does the args-class-field workaround retain a standing SSH/password
   credential, or move entirely to hookscript injection?~~ **Resolved
   (operator, 2026-09-13, §3.1): both.** Standing SSH/password credential
   retained for on-demand root-only/`pvesh`-only operations; hookscript still
   separately required for the boot-persistence case (§3.4).
2. Which other config fields, beyond `args`, are actually root-only on our
   target PVE version? (`rng`, `affinity`, `hugepages` are reported
   elsewhere, not independently verified.)
3. ~~Concurrency/locking discipline for idempotent mutations against a
   concurrently-used host (§3.4).~~ **Resolved in principle (operator,
   2026-09-13, §3.4): `pveforge` always serializes mutations, with mutation
   priority over reads.** Exact locking granularity remains
   `pveforge-idempotent-mutation-engine`'s own design work.
4. ~~Scope and shape of the hand-authored discoverability schema for the
   bespoke device-model layer (§3.5) — a real design task, not yet sized.~~
   **Resolved (operator, 2026-09-13): folded into
   `pveforge-object-model-get-set` / `pveforge-discoverability-schema`**
   rather than sized as a standalone task — those tasks already own this
   layer of the architecture.
5. Multi-operator secret access (`age` recipients vs. a single passphrase) —
   deferred past v1.
6. ~~Whether `pveforge api post/put` (planned, `pveforge-raw-api-escape-hatch`,
   §3.1) gets §3.4's idempotent-mutation-engine locking for object types the
   engine already models, or an explicit unsafe/no-locking posture for paths
   it doesn't cover. Not cosmetic: a raw passthrough that silently bypasses
   locking would undercut this project's whole multi-agent-safety premise
   (§3.4) for exactly the paths it's meant to reach. Must be resolved before
   that task is implemented, not while.~~
   **Resolved in two steps.** `pveforge-raw-api-escape-hatch` (2026-09-14):
   a path matching a modeled object type (vm/storage/network/node) takes
   that object's §3.4 lock with no opt-out, and any other path refuses to
   mutate without an explicit `--unsafe-no-lock`. What that left open was
   the lock's REACH: it was released when the HTTP call returned, while PVE
   was still running the task the call started.
   `pveforge-mutation-success-second-signal` (2026-09-21) closed it:
   `api post/put/delete` now waits on a returned task id (UPID), up to the
   10-minute task ceiling, before reporting success or failure, and holds
   the lock for the whole wait. `--no-wait` opts out, and states that the
   lock is then released before the task ends. The same change altered kv
   output for every `api` verb: a payload that is not a JSON object (a task
   id, any other string, a number, null, a list) now renders as one
   `data=<value>` line. Before, it was a render error, or no output at all
   for null.
