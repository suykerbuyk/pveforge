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
   - **The scope is explicit; there is no default.** `bootstrap` refuses to
     run without at least one `--grant PATH:ROLE[:PRIVS[:PROPAGATE]]`
     (repeatable), and checks that before it prompts for any secret or
     touches the target. Each grant is ROLE on PATH with its own propagate
     flag, **defaulting to 0**. The optional PRIVS pins exactly the role's
     privileges; a pin that differs from the role's definition on PVE is
     refused before any existing token is touched.
   - The token is then validated by its effective permissions: it must hold
     every requested grant and reach no further, within the validator's
     stated known limits (`internal/pve/validate.go`: e.g. pool membership
     is read only for a non-propagating pool grant whose Pool.Audit the
     token holds, and delegations on pool members are not seen). On success the granted
     scope is printed with the result (`grants`), only when a token
     survives the run.
   - Re-running with grants whose paths or privileges differ from the held
     token's effective grants revokes that token (for every holder) and
     then tries to mint a replacement (if that fails, the run ends
     `revoked_not_replaced`). Note that propagate now defaults to 0: a token
     granted `PVEVMAdmin` on `/` with propagate 1 must be re-requested as
     `--grant /:PVEVMAdmin::1` to be kept.
4. From that point forward, default to token auth for everything token auth
   can do.

For an `insecure_tls` target, a TLS pin is captured over the SSH session of
step 2 and written before step 3 mints or sends any token. The trust model
behind that order, and the rest of secret management, is §4.1. The operator
procedures are `docs/operations/secrets-and-keys.md`.

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

### 4.1 Secret management: design and architecture

This section states the design. The step-by-step procedures, and what each
refusal means to an operator, are in `docs/operations/secrets-and-keys.md`;
they are not repeated here.

**Scope: what is secret and what is not.**
- Secret: the roster passphrase, each target's API token secret, and each
  keyful target's SSH private key.
- Harness only: the nested test root password and each consumer's age
  identity.
- Never stored anywhere: the outer cluster's root password.
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
  serves.
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
  or sent, and before any pin is stored. A first run that fails in steps 1–2
  leaves no stored SSH pin, so its retry is again a first run under the same
  rules. One that fails later (in preflight, or in the token phase) has
  already stored the TLS pin, and for a keyful run the SSH auth; a keyful
  retry dials that stored pin, while a keyless one stores no SSH pin and
  still needs the fingerprint. That is sound: both pins came from one session
  pinned to the operator's fingerprint. Under `--ssh-tofu` that session was
  trusted on first use, and the stored pins are only as good as that
  connection, which their recorded `ssh-tofu` provenance says. No state exists in which a live token sits on a target
  whose peer identity was never established.
- **Ruling B′ (operator ruling RQ3).** A pin captured over a password session
  (a first run, or a keyless run) needs `--host-key-fingerprint`. The one
  exception is an explicit `--ssh-tofu`, which records the lesser provenance.
  A run over a stored SSH pin is exempt.
- **Provenance is recorded, not inferred.**
  - `[targets.tls] source` records how the TLS pin was first obtained:
    `ssh-verified`, `ssh-stored`, `ssh-tofu` or `expect`.
  - `[targets.ssh] host_key_source` records the same for the SSH pin:
    `ssh-verified` or `ssh-tofu`.
  - A target reachable only without SSH is pinned from an operator-verified
    `--expect` value. No trust-on-first-use path exists for it.
- **A pin is never replaced silently.**
  - Every pin write is a compare-and-set against the value the writer read.
  - A differing pin is replaced only by an explicit act, and only where a
    verified session vouches for the new key:
    - `roster pin-tls --repin`, for an `insecure_tls` target with SSH auth;
    - `bootstrap --reprovisioned --host-key-fingerprint <console value>`
      (operator ruling 3), which replaces the SSH pin, the installed keypair
      and the TLS pin together. It writes the TLS pin before the SSH auth.
      Where the stored pins already match the node it degrades to a plain
      bootstrap, so repeating the command always converges.
  - Every mismatch message labels the presented key "Do NOT pin", points to
    the console, and never fills a presented key into a suggested command. A
    test holds that wording.

**Encryption at rest.**
- **Each secret value is its own armored age ciphertext.** It uses a scrypt
  passphrase recipient at work factor logN 18 (age's default, about 0.8s per
  derivation). `filippo.io/age` is embedded, never shelled out to.
- **The passphrase is never a CLI argument.** It comes from
  `PVEFORGE_ROSTER_PASSPHRASE`, else a no-echo prompt on a terminal, else the
  command fails rather than hang.
- **Every encrypting write proves the passphrase first.** It must open a
  secret the roster already holds (`ErrWrongPassphrase`,
  `ErrNoReadableSecret`), so a roster can never split into secrets sealed
  under two passphrases.
- **The work factor has a test-only seam** (`SetScryptWorkFactorForTests`).
  It exists because the full factor made the suite take minutes. Five layers
  keep it out of production:
  1. a `testing.Testing()` gate, inert in any production binary, proved by
     building and executing a probe main;
  2. a static guard over `sourceguard.NonTestReferences`, refusing any
     production reference;
  3. `kdf_guard_test.go`, asserting logN 18 exactly, the override zero at
     rest, and its restore after a cycle;
  4. a blast radius confined to ciphertext a test writes into its own temp
     directory;
  5. `sourceguard.DirectiveEvasions`, refusing `//go:linkname`, `unsafe`,
     assembly, cgo and `vendor/` in production code. Those are the routes the
     AST walkers cannot see, and two of them were proven to ship a weakened
     binary with every older guard green.

  The one route left open is a dependency module linking in. The module
  guard's pinned dependency set holds that.
- **The passphrase is confirmed when set, and can be changed.** When a roster
  holds no secret yet, the run that will seal its first one (bootstrap)
  prompts twice and refuses a mismatch; an environment-supplied passphrase is
  taken as given. `roster rekey` changes it: under the roster lock, every
  secret must open with the current passphrase (one that opens only some is
  refused, since rekeying part would split the roster), each is sealed afresh
  under the new one at the production work factor and spliced over its old
  ciphertext, and the result is decoded and checked (every other field
  unchanged; every new ciphertext is the one composed for it, differs from
  the old one, and opens with the new passphrase to its old plaintext; it is
  not separately tried against the old passphrase) and compare-and-set
  against the bytes read before an atomic replace. The early check a
  command makes before asking for the new passphrase (`CheckRekey`) stops at
  the first secret that opens; the every-secret rule is enforced under the
  lock. The new
  passphrase is terminal-only and asked twice, never from the environment.
  Rekey contacts nothing and touches no token. It cannot reach copies made
  before it (backups, git history), so after a leak the tokens are rotated
  too. A writer still holding the old passphrase fails `prove` and writes
  nothing. `rekeySecrets` is the third function allowed to call
  `EncryptString`, beside the two proving writers; its proof is every secret
  opening.
- **Roster keys are case-sensitive, and an unknown key is refused at load.**
  Otherwise the TOML library's case-insensitive, last-wins matching could
  replace a pin with a differently spelled one, or read a misspelled pin as
  absent.

**Transport enforcement (T3, operator ruling 1).**
- **The one HTTP client constructor refuses an `insecure_tls` configuration
  with no pin** (`ErrTLSPinRequired`). No transport is built and no request of
  any method is made. The chain-skipping TLS configuration exists only
  together with a `VerifyConnection` callback.
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
  - `InsecureSkipVerify`: exactly two sites, the pinned transport and
    `servedPin`, which never carries a request.

  Every request also passes one transport that refuses any method but GET or
  HEAD on `/access`.
- **`roster import-token`** into an unpinned `insecure_tls` target needs
  `--expect`. It is refused before the secret is read from stdin. The pin is
  written only after the token validated through it.

**The older-binary lockout rule (R-b′).** Pins added three roster keys: `tls`
(T1a), `source` (T1b) and `host_key_source` (T2). Since `7d99123` a roster
refuses unknown keys, so any command that writes one makes the whole roster
unreadable to every binary from `7d99123` up to that key's commit: those fail
closed. **Binaries built before `7d99123` are the dangerous case.** They decode
with plain `toml.Unmarshal`, which ignores unknown keys, so they read a pinned
roster without error, ignore the pin, skip verification for an `insecure_tls`
target and send its token unchecked. No design inside the roster can stop an
old binary that never looks. The only defence is operational: no such build
may remain where it could be run against a roster. The commands that write
the keys are `bootstrap`, `roster pin-tls` and `roster import-token --expect`.
The rule: use a pinning binary against a roster only once every reader of that roster
is at least that new. The readers are the operator's binary, the harness's
`PVEFORGE_BIN`, and the checkout's go-built harness helpers. Rollouts
therefore upgrade readers first, then pin, then merge enforcement.

**Harness secrets.**
- **The harness keeps its two secrets in one age blob,
  `hack/harness/secrets.age`.** It is committed, and sealed to per-consumer
  public recipients (`recipients.txt`), not to a shared passphrase. This is
  the multi-consumer model §4's future option describes, applied to the
  harness only.
- **Age does not authenticate the sealer**, so the blob may carry only an
  allow-listed pair of names. Adding a name is a code change.
- **`unlock.sh run` puts the values into one exec'd command's environment
  only.** It never writes them to disk or argv, strips the identity
  variables, refuses to override a set name, and refuses the variables that
  run code in a bash child.
- **A recipient's removal is not revocation**, because git history keeps
  every blob it could open. Revocation is removal plus rotation of the
  values.
- **The outer root password is in no blob and never reaches an agent.** The
  harness guard refuses to run while `PVEFORGE_PVE_PASSWORD`, a set
  `PVEFORGE_ROSTER` or any proxy variable is present. It also requires a TLS
  pin on every nested target, distinct from every outer target's.

**Deliberately out of scope.**
- **ACME.** It is not in use, and Let's Encrypt cannot validate hosts that
  are not publicly reachable (operator ruling 5).
- **An internal CA.** If one is ever offered, the CA-verified mode
  (`insecure_tls = false`) is the path, and pins become optional there. No CA
  is built or managed by pveforge.
- **Multi-operator access to one roster.** Rosters keep a single passphrase
  (see §6 item 5).
- **These are known gaps, recorded rather than built:**
  - a command to rotate the SSH keypair of a node that was not rebuilt;
  - removal of stray `authorized_keys` lines left by failed first runs;
  - a byte cap on the capture's output, which is bounded in time only.

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
   deferred past v1. **Partly answered (2026-09-26, §4.1):** the nested test
   harness's secrets use per-consumer age recipients (`hack/harness/secrets.age`),
   so the operator and each CI runner hold their own identity. Rosters still
   use a single scrypt passphrase; that part stays open.
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
