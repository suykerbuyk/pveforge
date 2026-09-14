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
3. **`luthermonson/go-proxmox`** is a mature (287★), actively maintained,
   fully-typed Go client covering the entire PVE `/api2/json` surface for both
   8.x and 9.x. Verified directly from source: its `VirtualMachineConfig`
   struct exposes `Args`, `Hookscript`, `EFIDisk0`, and `Bios` as first-class
   fields (not omitted or hidden), and its write path
   (`VirtualMachineOption{Name, Value}`) is explicitly documented as raw,
   schema-free passthrough of "the same names `qm create` takes" — so it never
   fights custom/exotic device configuration the way a rigid ORM-style client
   would. It supports native API-token auth (`WithAPIToken`).
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
  `make` target. Machine- and AI-readable discoverability (§5) is a *format*
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
  - **Design question, not yet resolved:** does this path stay as a retained,
    narrowly-scoped SSH/password credential invoked directly by the binary at
    the moment such a field needs setting, or does it move entirely to a
    **Proxmox `hookscript`** — a script that runs locally on the hypervisor as
    root, invoked by `qm`'s own lifecycle mechanism (pre-start/post-start/
    pre-stop/post-stop), entirely outside the API's auth layer? A hookscript
    is *already* required regardless (see §3.4 — bridge port-isolation state
    does not survive VM stop/start and must be reapplied every boot), so
    piggybacking the args-class-field logic onto that same mechanism avoids
    introducing a second root-auth code path. Whether a hookscript can be
    *deployed* itself via the API (Proxmox's storage `snippets` content type
    is API-uploadable) or needs SFTP/SCP is an open, cheap-to-answer question
    that determines whether SSH is needed only once, ever (at bootstrap), or
    as a standing capability.
- **SSH is never a Tier-1 operational dependency.** It is scoped to bootstrap
  (§3.2) and, pending the question above, possibly to hookscript deployment.

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

**Concurrency note, not yet resolved:** check-then-act has a real TOCTOU race
if two invocations target the same object concurrently (a realistic scenario
— the originating investigation's environment already runs multiple
concurrent orchestration agents against shared Proxmox hosts). Whether
`pveforge` needs its own locking discipline, or leans on Proxmox's own
per-VM config lock (`qm set --lock`), or simply documents "single invocation
at a time per object" as a stated constraint, is open.

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

This splits into two layers with very different cost:

- **The generic Proxmox object model (nodes, VMs, storage, network, users,
  ...) can largely inherit Proxmox's own introspection for free.** Proxmox's
  REST API already supports `OPTIONS` requests on every path, returning full
  parameter schema, types, defaults, and enums — this is the exact mechanism
  `pvesh` itself is built on (a generic walker, not per-object hardcoding).
  `pveforge` should expose/proxy this schema rather than hand-author a
  parallel one.
- **`pveforge`'s own bespoke semantic layer (the NVMe/BMC/PCIe device-model
  abstractions, the hookscript-backed isolation state, etc.) is invisible to
  Proxmox's schema** — to Proxmox, `args:` is just an opaque string. Making
  *this* layer self-describing is a real, hand-authored engineering task
  (tractable via Go struct tags/reflection, akin to how `kubectl explain` or
  a Cobra command tree can be introspected), not something inherited for
  free. Size it as its own deliverable.

### 3.6 I/O

- Getters/setters accept and emit plain `key=value` pairs for simple,
  scriptable one-liners.
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

1. Does the args-class-field workaround retain a standing SSH/password
   credential, or move entirely to hookscript injection? Depends on whether
   hookscripts are API-uploadable (Proxmox storage `snippets` content type)
   or need SFTP.
2. Which other config fields, beyond `args`, are actually root-only on our
   target PVE version? (`rng`, `affinity`, `hugepages` are reported
   elsewhere, not independently verified.)
3. Concurrency/locking discipline for idempotent mutations against a
   concurrently-used host (§3.4).
4. Scope and shape of the hand-authored discoverability schema for the
   bespoke device-model layer (§3.5) — a real design task, not yet sized.
5. Multi-operator secret access (`age` recipients vs. a single passphrase) —
   deferred past v1.
