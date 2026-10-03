# Secrets and keys: the operator guide

This guide covers every secret and key pveforge and its nested test harness
use: where each lives, who holds it, and how to create, pin, rotate, back up
and recover each one. The design behind it is in
[`docs/prd.md`](../prd.md) §4.1. `pveforge <command> --help` stays the
reference for every flag. A test (`cmd/pveforge/readme_test.go`) holds every
`pveforge` command line in this file to the real command tree: its flags, its
required flags, its argument count, and the values of `--grant` and
`--expect`. A renamed or removed flag fails `make test`; run just those checks
with `go test ./cmd/pveforge -run README`.

## Three rules before anything else

1. **Run every command that asks for a secret in your OWN terminal.** That
   means the roster passphrase, a PVE root password (`bootstrap`, and the root
   commands with `--no-ssh-key`), and `unlock.sh seal`. Never run one through
   an AI agent's session, and never through Claude Code's `!` prefix. Neither
   has a terminal on stdin, so pveforge's prompt fails (`no roster passphrase
   available: set PVEFORGE_ROSTER_PASSPHRASE or run interactively`, or the
   same for `PVEFORGE_PVE_PASSWORD`). `unlock.sh seal` reads stdin instead,
   finds it empty, and refuses (`no NAME=value line`). Even when a command does
   run there, the secret has passed through a transcript. The outer cluster's
   root password in particular never reaches an agent.
2. **`--print` never writes.** `pveforge roster pin-tls --print` captures and
   checks the pin and prints it. It does not write the roster, take a lock or
   create lock files. Only the same command without `--print` writes.
3. **Never pin the key a failing connection presented.** Every SSH and TLS
   mismatch error prints the key it was shown ("the host presented …", "the
   peer's public key is …") and labels it "Do NOT pin the presented key": that
   is exactly what an impostor would show. The value you pin comes from the
   node's CONSOLE (`ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub`), or from
   another channel you already trust. Never copy it out of an error.

## Inventory

| Secret or key | Where it lives | What protects it | Who holds it | In git? |
|---|---|---|---|---|
| Roster passphrase | Nowhere on disk by pveforge. It comes from `PVEFORGE_ROSTER_PASSPHRASE`, else a no-echo prompt on a terminal. There is no flag. | Your memory or password manager. For the harness rosters: `hack/harness/secrets.age` (below). | You. For the harness rosters also every age recipient, and any command run under `unlock.sh run`, the implementor's included. | Never in plaintext. |
| API token secret, per target | The roster's `[targets.token]` `secret_enc`: an age ciphertext, scrypt passphrase recipient, work factor logN 18. `id` beside it is not secret. | The roster passphrase. Decrypted in memory only. `exec` hands it to a command only for a target marked `export = "token"` by hand. | Whoever holds the roster file and its passphrase. | The ciphertext may be, by design (the roster is meant to stay reviewable). This repository ignores `/pveforge.toml`. Committed ciphertext is protected by the passphrase alone, forever, since history cannot be un-published. |
| SSH keypair, per keyful target | The roster's `[targets.ssh]`: `private_key_enc` (age, as above), `public_key` and `user` in clear. The public key is a line in root's `~/.ssh/authorized_keys` on the node (on PVE, `/etc/pve/priv/authorized_keys`, shared by the cluster), with the comment `pveforge@<target-id>`. | The roster passphrase for the private half. | The roster holder. A keyless target (`--no-ssh-key`, or an imported token) has none. | As the token. |
| SSH host-key pin, and `host_key_source` | The roster's `[targets.ssh]` `host_key_fingerprint` (`SHA256:…`) and `host_key_source` (`ssh-verified`: the value you gave with `--host-key-fingerprint`; `ssh-tofu`: trusted on first use). An older roster may lack the source; that reads as unknown. | Not secret: its integrity is what matters. A stored pin binds every SSH dial to the target, `--no-ssh-key` ones included. | The roster. | Yes, harmlessly. |
| TLS SPKI pin, and its `source` | The roster's `[targets.tls]` `spki_sha256` (`sha256//<base64>`, curl's `--pinnedpubkey` form) and `source`: `ssh-verified`, `ssh-stored`, `ssh-tofu` or `expect`. `source` records how the pin was FIRST obtained. | Not secret. Written only by a compare-and-set, so no writer replaces a pin it did not first read. | The roster. | Yes, harmlessly. |
| Age identity (harness) | A private `AGE-SECRET-KEY-1…` line per consumer, never committed. You point to it with `PVEFORGE_HARNESS_AGE_IDENTITY_FILE` (a file you own, mode 0600 or 0400). A CI runner has its content in its secret store as `PVEFORGE_HARNESS_AGE_IDENTITY`. Exactly one of the two may be set. | Your own storage and backups. | You. Each CI runner holds its own. | Never. |
| `hack/harness/secrets.age` and `recipients.txt` | `secrets.age`: the two harness secrets as `NAME=value` lines, age-encrypted to every public recipient in `recipients.txt` (`<age1…> # <consumer>`). | Each recipient's private identity. Age does not authenticate who sealed a blob, so only two names are ever accepted from it (`PVEFORGE_ROSTER_PASSPHRASE`, `PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD`). | Every recipient. | Both committed. That is safe only while every line in `recipients.txt` is one you reviewed. |
| Nested test root password | In `secrets.age` as `PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD`. It becomes a crypt hash in the nested installer ISOs, and is sent on stdin over SSH for n2's cluster join. For a nested node only, it reaches the bootstrap child's environment as `PVEFORGE_PVE_PASSWORD`. | The age identities. A test password, never the outer one. | The recipients, and harness steps run under `unlock.sh run`. | Only inside `secrets.age`. |
| Outer root password (qa-pve-02) | Nowhere. Never stored, in no blob. | Not being written down anywhere pveforge or the harness can reach. | The operator only, typed at the prompt in their own terminal (D5 G4, or any bootstrap of an outer target). | Never. |

**The roster file itself.** `pveforge roster init` creates it with mode 0600.
Later writes keep an existing file's mode. The harness rosters live in
`~/.config/pveforge/` (created 0700 at D5 G0). The roster lists your hosts,
nodes, token ids and pins in clear. Only the `*_enc` values are ciphertext.

## How the trust fits together

The SSH host key is the anchor. Either you vouch for it (`--host-key-fingerprint`,
read on the console) or you accept it on first use (`--ssh-tofu`, recorded as
such). Over that SSH session, bootstrap reads the certificate pveproxy serves
on the node itself (`127.0.0.1:8006`). The target's network address must then
serve the same key. Only then is the TLS pin written, and only after that is
any token minted or sent. From then on, every REST connection must present the
pinned key in the TLS handshake, before the token is sent. An `insecure_tls`
target without a pin gets no REST request at all. The reasoning is in
`docs/prd.md` §4.1.

## Procedures

Each procedure ends with a verification step. A procedure is not done until
that step has been run and has passed.

### 1. First bootstrap of a new node

1. **At the node's console** (IPMI, iKVM, or the physical screen, never an SSH
   session to the node), read the ECDSA host key:

   ```
   ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub
   ```

   It must be the ECDSA key, because pveforge's SSH client negotiates ECDSA
   whenever the host serves it, as PVE does by default. An ED25519 fingerprint
   is refused (fail-closed), and the error names the type it got.
2. **Create the roster if it does not exist yet.** Bootstrap never creates
   one: it refuses a missing roster ("create it first with `pveforge roster
   init`"), before any prompt.

   ```
   pveforge roster init ./pveforge.toml
   ```

3. **In your own terminal**, run bootstrap with the console value (`SHA256:…`
   exactly as printed):

   ```
   pveforge bootstrap qa-pve-01 --roster ./pveforge.toml --host qa-pve-01.example.com --node qa-pve-01 --insecure-tls --host-key-fingerprint SHA256:<console-value> --grant /pool/lab:PVEVMUser -o json
   ```

   It asks for the roster passphrase and the PVE password. The host key is
   checked during the key exchange, before the password is sent.
   - **The passphrase of a new roster is set by this first run.** When the
     roster holds no secret yet, the prompt says so and asks twice, and two
     entries that differ are refused before anything happens. A passphrase
     from `PVEFORGE_ROSTER_PASSPHRASE` is taken as given, with no second
     entry to compare, so a typo in it becomes the roster's passphrase. Step
     4's decrypt check catches either while it is cheap to undo, and
     procedure 10 changes a passphrase later.
   - For an `insecure_tls` target, a run that captures the TLS pin over a
     password session needs `--host-key-fingerprint`, or else `--ssh-tofu`.
     That covers every first run and every `--no-ssh-key` run. This rule is
     ruling B′. Only `--ssh-tofu` accepts the host key on first use, and it
     records the TLS pin as `ssh-tofu`, only as good as that one connection.
     Prefer the console read.
   - A keyless target (`--no-ssh-key`) never stores an SSH pin. **Every**
     later bootstrap of it needs `--host-key-fingerprint` again (or
     `--ssh-tofu`).
   - The B′ refusal ("a TLS pin captured over a password SSH session needs
     --host-key-fingerprint …") comes before any prompt, as do the other
     refusals that need no secret (the `--ssh-tofu` conflicts, the
     `--reprovisioned` rules, a missing `--host`, `--node` or `--token-id`, a
     login that is not `@pam`, a held token another principal owns, a
     `--no-ssh-key` that does not match the roster's SSH state, a
     `--host-key-fingerprint` that is not the stored pin, a roster that is
     missing or cannot take the write). They read only the roster's
     unencrypted fields, so a run they refuse asks for neither the
     passphrase nor the password.
   - A CA-verified target (no `--insecure-tls`) is never pinned implicitly. Its
     chain is its identity.
4. **Verify.**
   - **The decrypt check, first.** In a fresh command, type the passphrase
     again:

     ```
     pveforge node get qa-pve-01 --roster ./pveforge.toml
     ```

     It decrypts the new token under the passphrase you type now, and reads
     the node through the pin. An error ending `incorrect passphrase` (`decrypt
     target "qa-pve-01" token: decrypt: … incorrect passphrase`) means the
     first prompt took something else. Start over
     while it is cheap: move the roster aside, remove the new token on PVE
     (`pveum user token remove <owner> <token-name>`), delete the new key
     line (procedure 6), and repeat from step 2.
   - The JSON result has `token_outcome` `minted` and `validation` `verified`.
   - `host_key_fingerprint` is your console value.
   - `tls_pin_source` is `ssh-verified`, and `tls_spki_sha256` holds the pin.
   - Then:

     ```
     pveforge roster validate ./pveforge.toml --require-tls-pins
     ```

     It exits 0 and lists the target as `token + ssh configured, ssh host key
     ssh-verified, tls pinned`.

   **What a failed first run leaves.** The capture, the network cross-check
   and the TLS pin write all come before the SSH auth is stored. So a run that
   fails in any of those (a capture failure, a pin mismatch) stores no SSH pin,
   and its rerun is again a first run under B′. A run that fails LATER, in
   preflight (an unknown role or node, an owner lacking privileges) or in the
   token phase, has already stored the TLS pin, and for a KEYFUL run the SSH
   auth too (host key pin and keypair). A keyful rerun dials that stored pin,
   and no longer needs `--host-key-fingerprint`. A keyless (`--no-ssh-key`)
   run never stores an SSH pin, so its rerun still needs the fingerprint. Either way the roster may hold a token-less
   `[[targets]]` entry, which a rerun reuses. No pveforge command removes a
   target, so delete it by hand if you abandon it.

### 2. Pinning a target bootstrapped before TLS pins existed

Since T3, an unpinned `insecure_tls` target is refused outright ("an
insecure_tls target needs a TLS pin: no REST request is made to one that holds
none"). `roster pin-tls` pins it without touching its token.

- **A keyful target** (the roster holds its SSH key). Print first, then write:

  ```
  pveforge roster pin-tls qa-pve-02 --roster ./pveforge.toml --print
  pveforge roster pin-tls qa-pve-02 --roster ./pveforge.toml
  ```

  It captures over an SSH session pinned to the roster's stored host key. The
  address must serve the same key. It writes with source `ssh-stored` and
  takes the target's bootstrap lock. The passphrase is needed even for
  `--print`, which decrypts the SSH key. `--expect` is refused here ("drop
  --expect"), before the passphrase prompt, as is every flag that does not
  fit the target's mode. Name `--roster` explicitly, so you never pin the
  default `./pveforge.toml` by accident.
- **A keyless target** (no SSH key in the roster) needs `--expect` with a pin
  you verified by other means:

  ```
  pveforge roster pin-tls qa-pve-02-harness --roster ~/.config/pveforge/harness-outer.toml --expect sha256//<verified-pin>
  ```

  The address must serve exactly that key, and the pin is written with source
  `expect`. There is no trust-on-first-use path. Two ways to get a pin you can
  trust:
  - From a keyful roster that addresses the same node: its `pin-tls --print`
    captured the pin over a pinned SSH session.
  - On the node's console, compute it from what pveproxy serves:

    ```
    openssl s_client -connect 127.0.0.1:8006 </dev/null 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64
    ```

    Prefix the output with `sha256//`. This pipeline gives the same value as
    pveforge's own computation, checked for both EC and RSA keys.

  Running the same pipeline from your workstation against
  `<host>:8006` only shows what the network serves you. That is the half
  pveforge already checks, not an anchor.
- **A CA-verified target** is pinned only if you choose to, with `--expect`.
  Its chain must still verify as well.
- A different stored pin is refused. `--repin` replaces it, for an
  `insecure_tls` target with SSH auth only, whose pinned session vouches for
  the new key. Use it when only the TLS key changed deliberately and the SSH
  key did not. After a rebuild, use procedure 3 instead.
- **Verify:** `pveforge roster validate <roster> --require-tls-pins` exits 0,
  and the target shows `tls pinned`.

### 3. Reprovisioning a rebuilt node

A rebuilt node has a new SSH host key and a new TLS key, and its API token
died with the old install. One command per ROSTER replaces the SSH pin, the
installed keypair and the TLS pin together, then mints a fresh token.

1. At the rebuilt node's CONSOLE: `ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub`.
2. **Recreate what a rebuild loses before the run:** a non-root token owner,
   its pool, its roles and its ACLs. For the harness's outer target, that means
   replaying D5 G1–G3 (`hack/harness/d5/sequence.md`). Without them, bootstrap
   fails at preflight after the pins were replaced, and says so. The fix is to
   recreate them and run the same command again.
3. Run your usual bootstrap line, adding `--reprovisioned` and the console
   value. Every run still needs `--grant` (the roster stores none),
   `--no-ssh-key` for a keyless target, `--capture-port` if you used one, and
   the PVE password. For qa-pve-02, which two rosters address:

   ```
   pveforge bootstrap qa-pve-02 --roster ./pveforge.toml --reprovisioned --host-key-fingerprint SHA256:<console-value> --grant /:PVEVMAdmin::1
   pveforge bootstrap qa-pve-02-harness --roster ~/.config/pveforge/harness-outer.toml --no-ssh-key --reprovisioned --host-key-fingerprint SHA256:<console-value> --token-owner pveforge-harness@pve --token-id build --grant '/pool/pveforge-harness:ForgeHarness:Pool.Audit,VM.Allocate,VM.Audit,VM.Config.CDROM,VM.Config.CPU,VM.Config.Cloudinit,VM.Config.Disk,VM.Config.HWType,VM.Config.Memory,VM.Config.Network,VM.Config.Options,VM.PowerMgmt,VM.Snapshot:0' --grant '/storage/pveforge-harness:ForgeHarnessSpace:Datastore.AllocateSpace,Datastore.Audit:0' --grant '/storage/local:ForgeHarnessIso:Datastore.Audit:0' --grant '/sdn/zones/localnetwork/vmbr0:ForgeHarnessNet:SDN.Use:0'
   ```

   The grants must be exactly the held token's, since grants that differ are
   a verdict that revokes it. The harness line's four are D5 G4's
   (`hack/harness/d5/sequence.md`), and the first line keeps the live token's
   propagate flag with `::1` (see procedure 5). If D5 changes its grants,
   copy them from there.
4. **Verify.** On the run that did the replacing:
   - The result reports `reprovisioned` true, `previous_host_key_fingerprint`
     (keyful only; a keyless target has no SSH pin to replace) and
     `previous_tls_spki_sha256`.
   - It also reports `tls_pin_source` `ssh-verified`, and a `token_outcome` of
     `replaced` or `minted`.
   - `pveforge roster validate <roster> --require-tls-pins` exits 0.

   A converging rerun (after a partial failure, or a repeat) reports
   `reprovisioned` false and no `previous_*` values, because this run replaced
   nothing. The previous values were printed by the run that replaced them,
   including in the error of a run that stopped afterwards.

Repeating the command is safe. Where the stored pins already match the node,
it runs as a plain bootstrap, reports `reprovisioned` false, and says "the
stored pins already match this node" on stderr. So after a partial failure,
rerun the same line. `--reprovisioned` refuses `--ssh-tofu`, requires
`--host-key-fingerprint`, and refuses a target with no stored pin ("nothing to
replace"). These refusals come before any prompt.

A disposable roster (a harness nested target) can instead be moved aside and
bootstrapped afresh. `hack/harness/README.md` ("After `build.sh --repin`, or
any rebuild") gives that recovery.

### 4. Importing a token minted elsewhere

The secret comes from stdin, which must not be a terminal, so the passphrase
must come from `PVEFORGE_ROSTER_PASSPHRASE`. Scope it to the one command with
a subshell that reads it without echo (in bash: `read -s` is not POSIX). It
is then in no file, no shell history and no other command's environment:

```
(
  read -rsp 'Roster passphrase: ' PVEFORGE_ROSTER_PASSPHRASE; echo >&2
  export PVEFORGE_ROSTER_PASSPHRASE
  mint-token-somehow | pveforge roster import-token qa-pve-03 --roster ./pveforge.toml --host qa-pve-03.example.com --node qa-pve-03 --insecure-tls --token-id 'ops@pve!ci' --grant /vms/100:PVEVMUser --expect sha256//<verified-pin>
)
```

The example is a NEW target, so it needs `--host`, `--node` and
`--insecure-tls` (an existing target takes them from the roster). A target
that already holds a different token refuses the import unless you add
`--replace`, and the replaced token stays live on PVE.

- An `insecure_tls` target (by the flag, or by the roster's own setting)
  needs a pin: the roster's, or `--expect`. `--expect` also pins a new
  CA-verified target (source `expect`), whose chain must verify as well. Without one, the import is refused
  before the passphrase is resolved or the secret read ("nothing was read,
  validated or written"). So is an `--expect` that differs from the roster's
  pin.
- A new target with no `--host` or `--node`, a missing roster, and a roster
  whose directory cannot take the write are refused at the same point,
  before the passphrase or the secret.
- The validation connects through the pin, so a wrong key fails in the
  handshake before the token is sent. The pin is written (source `expect`)
  only after the token validated, and before the token itself.
- An `--expect` that differs from the roster's pin is refused. The message
  names the keyless reprovision.
- **Verify:** `token_outcome` is `imported` (or `already_held`), and `roster
  validate --require-tls-pins` exits 0. An imported target holds no SSH key,
  so any later bootstrap of it needs `--no-ssh-key`.

### 5. Rotating and revoking a token

pveforge has no dedicated rotate command. It revokes a token only on a
definite verdict about it, and never on a read failure. Before any mint, a
401 or 403 against a token this roster holds and PVE still lists is a
refusal, not a verdict: nothing is touched (see section 8). After a mint, a
fresh token's persistent 401 is still a verdict: that token is removed and
nothing is persisted.

- **Rotate a token you suspect has leaked.** Revoke it on PVE as root (in your
  terminal, over your own root access):

  ```
  pveum user token remove <owner> <token-name>
  ```

  Then rerun your usual bootstrap line. The held token fails validation with
  a 401, which is a verdict, and preflight finds it gone. So nothing more is
  revoked: the roster's copy is cleared and a new token is minted.
  **Verify:** `token_outcome` is `replaced`.
- **Rotate without a gap.** Rerun bootstrap with a new `--token-id`. The new
  token is minted and stored. The old one stays live on PVE and is never
  removed or cleared by pveforge: it is reported as `orphaned_token`. Revoke it
  with `pveum user token remove` once nothing uses it.
- **Revoke without replacing.** `pveum user token remove` on PVE. The roster
  then points at a dead token until the next bootstrap replaces it.
- **Re-running bootstrap is itself a rotation trigger.** If the `--grant`
  paths or privileges differ from what the held token effectively has, the
  run REVOKES that token on PVE, for every holder, then mints a replacement. If
  the mint fails, the run ends `revoked_not_replaced`. Propagate defaults to
  0. So the live `root@pam!pveforge` token on qa-pve-02 (PVEVMAdmin on `/`,
  propagate 1) must be re-requested with the trailing `::1`:

  ```
  pveforge bootstrap qa-pve-02 --roster ./pveforge.toml --grant /:PVEVMAdmin::1
  ```

  The same grant without the trailing `::1` reads as too wide, which is a
  verdict, and revokes the token. A test holds every grant on `/` in this
  guide to `::1`.
- Changing `--token-owner` leaves the previous token live and held by nobody
  (`orphaned_token`), never revoked.
- **Read the command's own output and stderr warnings.** They are the record of
  what happened to each token.

### 6. SSH keys: revoking one, and stray keys

- **Revoke pveforge's SSH access to a node.** Remove the line equal to the
  target's `public_key` (comment `pveforge@<target-id>`) from root's
  `authorized_keys` on the node. On PVE that file is
  `/etc/pve/priv/authorized_keys`, shared by the whole cluster. The roster
  still holds the dead keypair, and every keyful command then fails to
  connect.
- **Stray keys.** A first run that fails after installing its key (a failed
  cross-check, say) leaves that key in `authorized_keys`, and each retry adds
  another, all with the same comment. Remove the lines whose key is not the
  roster's `public_key`. No command does this yet.
- **No command rotates the keypair of a node that was not rebuilt.**
  `--reprovisioned` with the unchanged fingerprint runs as a plain bootstrap
  and keeps the keypair. What remains is the first-run path, in a new roster:
  bootstrap afresh with `--host-key-fingerprint`, removing the old token first
  or giving a new `--token-id`, then delete the old key line.

### 7. Adding and revoking an age recipient (a CI runner)

- **Add one**, as a one-time human act:
  1. Run `age-keygen -o runner.key`.
  2. Put the key's content in the runner's secret store as
     `PVEFORGE_HARNESS_AGE_IDENTITY`, then delete the local file.
  3. Add its `age1…` line to `hack/harness/recipients.txt` as
     `<recipient> # ci-runner-<name>`.
  4. **Review the whole `recipients.txt` diff line by line:**

     ```
     git diff -- hack/harness/recipients.txt
     ```

     Every recipient you reseal to can decrypt the secrets from then on,
     including one someone else committed without your noticing.
  5. With your own identity set, run `hack/harness/unlock.sh reseal`, then
     commit both files.
- **Verify:** with your identity set, `hack/harness/unlock.sh status` prints
  every consumer and both names, never a value:

  ```
  recipients: 2 (operator, ci-runner-<name>)
  names: PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD, PVEFORGE_ROSTER_PASSPHRASE
  ```

  Without an identity the second line reads `names: not shown (no identity
  set)`.
- **Revoke one.** Removing a recipient does NOT revoke that key's access to
  older copies of `secrets.age` in git history. Revocation is therefore:
  1. Remove the line.
  2. **Rotate both values:**
     - A new harness roster passphrase: procedure 10's harness pair (rekey
       both harness rosters, then seal). If the revoked consumer could also
       have copied a harness roster, its tokens open with the old
       passphrase in that copy: rotate them too (procedure 5).
     - A new nested root password. This means reprovisioning the nested nodes
       with it.
  3. `unlock.sh seal` the new values, in your own terminal (procedure 10's
     pair ends with this same seal: one seal can carry both new values).
  4. Commit.
- **`seal` replaces the whole blob.** At the prompt, a name left empty is left
  out. Give both names, or the other secret is gone from the blob.

### 8. Backups, and recovering from a loss

**Back up:** your age identity file; each roster file (`./pveforge.toml`,
`~/.config/pveforge/harness-*.toml`); and your roster passphrase, apart from
the rosters. A roster backup is ciphertext plus pins, useless without the
passphrase and dangerous only with it. Keep backups offline or in a password
manager.

- **Lost roster passphrase.** Nothing in that roster can be decrypted, and no
  command recovers it. `roster rekey` needs the current passphrase, so it
  cannot help here. Recovery:
  1. Create a new roster with `pveforge roster init <path>`.
  2. First-bootstrap each target (procedure 1).
  3. On PVE, the old token of the same name still exists. Bootstrap refuses it
     ("an API token of this name already exists on PVE and this roster does
     not hold it") and prints the `pveum user token remove` line to run first.
     Or give a new `--token-id`, and remove the old token afterwards.
  4. Delete the old SSH key lines (procedure 6).
- **Lost roster file, passphrase known.** Restore the backup, or rebuild as
  for a lost passphrase.
  - A restored copy whose token was rotated since holds a stale secret, and
    so does any other copy of a roster once one copy rotates its token. Its
    next bootstrap gets a 401 for a token PVE still lists, and refuses:
    nothing is touched on PVE or in the roster, so the copies still using
    the token keep working. This refusal comes after the prompts, since only
    PVE's answer shows the secret is stale.
  - Put the current secret into the stale copy with `roster import-token
    <target> --token-id <id> --grant … --replace`, piping it in. The refusal
    names the exact line. No pveforge command prints a stored secret, so the
    current one must come from wherever it was recorded when it was minted
    or imported: a password manager, or its holder's own copy.
  - The refusal also names `pveum user token remove`: a last resort, once you
    know no copy holds the live secret, since it revokes it for every holder.
  - Restore only the copy you actually use.
  - **Verify:** `pveforge roster validate <path> --require-tls-pins`.
- **Lost age identity.** You can no longer decrypt `secrets.age`.
  1. Generate a new identity (`age-keygen -o <file>`, mode 0600).
  2. Replace your line in `recipients.txt`, reviewing the diff.
  3. If you still know both values, `unlock.sh seal` them in your own terminal
     and commit. If not, rotate them as for revocation (procedure 7).
  4. If the old identity was lost rather than destroyed, treat it as
     compromised: revoke it as in procedure 7, rotating both values.
  5. **Verify:** with the new identity set, `unlock.sh status` prints
     `names: PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD, PVEFORGE_ROSTER_PASSPHRASE`.

### 9. Validating everything

For every roster in use:

```
pveforge roster validate ./pveforge.toml --require-tls-pins
pveforge roster validate ~/.config/pveforge/harness-outer.toml --require-tls-pins
pveforge roster validate ~/.config/pveforge/harness-nested.toml --require-tls-pins
```

Each must exit 0. It contacts nothing and writes nothing. It fails (exit 1)
naming every `insecure_tls` target that holds no pin, and never names a
CA-verified target. The listing shows `ssh host key <source>` for a target
whose roster records `host_key_source` (an older roster may not), and `tls
pinned` for a pinned one. The TLS pin's own `source` is in the roster file's
`[targets.tls]` block.

### 10. Changing a roster's passphrase

Change it after a typo, a leak, or when handing the roster on. In your own
terminal:

```
pveforge roster rekey --roster ./pveforge.toml
```

- It asks for the current passphrase (or reads `PVEFORGE_ROSTER_PASSPHRASE`).
  Before asking for the new one, it checks that the current one opens the
  roster: a wrong passphrase, or a roster with no secret, is refused there.
  That early check stops at the first secret that opens. The rule that the
  current passphrase must open EVERY secret is enforced later, under the
  roster lock, after the new passphrase has been asked for: a partly
  readable roster is refused then, with nothing written. Then it asks for
  the new passphrase twice. The new one
  is read from a terminal only, never from an environment variable or a
  pipe, so this command cannot run from an agent's session or a script.
- It contacts nothing. No node, and no token on PVE, is touched. Only the
  roster file changes: each secret is re-encrypted under the new passphrase,
  every other byte is kept, and the file is replaced atomically once the
  result checks out. Any failure leaves the file as it was.
- **Old copies still open with the old passphrase.** Rekey keeps no copy of
  its own, but a backup, a copy on another machine, or a committed roster in
  git history still opens with the old passphrase. After a LEAK, rekeying is
  not enough: rotate the tokens those copies hold (procedure 5), and replace
  your backups with copies of the rekeyed file.
- A pveforge command already running against the roster with the old
  passphrase fails its next roster write (`wrong roster passphrase`) and
  writes nothing. It never splits the roster between two passphrases. Rerun
  it with the new passphrase.
- **Verify:** it prints `<roster>: rekeyed N secret(s) of M target(s)`. Then,
  in a fresh command with the NEW passphrase, `pveforge node get <target>
  --roster <roster>` must work, as in procedure 1's decrypt check.

**The harness rosters are one ordered pair of steps.** Their passphrase is
also sealed in `hack/harness/secrets.age`, where the harness steps that run
pveforge take it from. The steps built on `hack/harness/lib.sh` (probe, build, golden, reset)
open `harness-outer.toml`; `nested.sh` opens `harness-nested.toml`, and
golden and reset read it too, through acceptance. Rekeying without resealing
breaks every step that opens a rekeyed roster,
so do both, in this order, in your own terminal, with no harness step running
in between:

1. Rekey both harness rosters to the same new passphrase:

   ```
   pveforge roster rekey --roster ~/.config/pveforge/harness-outer.toml
   pveforge roster rekey --roster ~/.config/pveforge/harness-nested.toml
   ```

   Each prints a reminder to seal (the harness roster names are recognised).
2. Seal the new passphrase, giving the nested root password again as well:
   `seal` replaces the whole blob (procedure 7).

   ```
   hack/harness/unlock.sh seal
   ```

   Then commit `secrets.age`.
- **Verify:** `hack/harness/unlock.sh status` still lists both names. The
  passphrase itself is proved by the next harness step run under `unlock.sh
  run`: a passphrase that does not open the rosters fails there at once, on
  the decrypt, before any request is sent. (`roster validate` decrypts
  nothing, so it proves nothing here.)

## Reading the refusals

Every refusal below writes nothing unless it says otherwise. The central rule:
**never pin the "presented", "got" or "serves" key. Read the console.**

| Message (start) | What it means | What to do | NEVER |
|---|---|---|---|
| `host key mismatch for <host>: the host presented …, the roster pins …` | A stored-pin SSH dial met another key. Either the node was rebuilt, or something else answers at that address. | Read the key at the node's console. If it is new, reprovision (procedure 3). If the console matches the roster, find out what is answering at that address. | Pin the presented key, or hand-edit the roster to it. |
| `host key mismatch …, expected … (the value you gave, e.g. --host-key-fingerprint)` | The password dial met a key other than the one you gave. The password was not sent. | Compare your value with the console read. If they differ, correct your value. If they match, something else answers. | Retry with the presented value. |
| `--host-key-fingerprint … is not the host key this target is pinned to (…); nothing was dialed` | Your value differs from the stored pin. | If your value is a console read after a rebuild, add `--reprovisioned`. | Edit the stored pin by hand. |
| `a TLS pin captured over a password SSH session needs --host-key-fingerprint (or --ssh-tofu …)` | Ruling B′: a first run or a keyless run of an `insecure_tls` target, with nothing vouching for the host key. | Read the console and pass `--host-key-fingerprint`. Use `--ssh-tofu` only knowingly. | Treat `--ssh-tofu` as routine. |
| `--ssh-tofu and --host-key-fingerprint contradict each other`, or `--ssh-tofu applies only to an insecure_tls target`, or `--ssh-tofu does not apply …` | `--ssh-tofu` given where it means nothing, or alongside a fingerprint. | Drop it. | |
| `the target's address does not serve the TLS key the node serves: <host>:<port> serves X, the node Y` | The capture over SSH and the network disagree. Nothing was written and no token was sent. | Connect to the node directly. A TLS-terminating proxy in front of it makes this permanent: pin it by `--expect` only after verifying the front end's key. | Pin X. |
| `TLS pin mismatch: the peer's public key is X, the roster pins Y` | A REST connection met another key, in the handshake, before any request or token was sent. The causes: something else answers; a TLS-terminating proxy; `HTTPS_PROXY` naming an `https://` proxy (unsupported with a pin, while `http://` works); or a rebuilt node. | Rebuilt: procedure 3. Proxy: use an `http://` proxy or `NO_PROXY`. Otherwise investigate. | Pin X. pveforge never re-pins silently. |
| `the roster pins another TLS key for this target: … pins X, the node now serves Y` | A capture found a new key, and the roster holds another. Nothing was written. | TLS key changed deliberately and the SSH key did not (keyful): `roster pin-tls <id> --repin`. Node rebuilt: `bootstrap <id> --reprovisioned …` (the message gives the keyless form). | Delete `[targets.tls]` by hand to make the error go away. |
| `target "<id>": an insecure_tls target needs a TLS pin: no REST request is made to one that holds none … (roster <path> …)` | T3: an unpinned `insecure_tls` target. Every command using its REST API fails, including root commands with a REST view (such as `access inventory`), entirely. No request was sent. | Procedure 2, against the roster the message names. | Set `insecure_tls = false` to get past it, unless the node really has a CA-trusted certificate. |
| `import token <id>: … pass the pin you verified with --expect sha256//…` | Import into an unpinned `insecure_tls` target. Nothing was read. | Procedure 4 with `--expect`. | |
| `could not capture the node's TLS certificate over SSH …` | openssl is missing on the node, or pveproxy is not on `127.0.0.1:8006`. | Pass `--capture-port` if pveproxy listens elsewhere on the node, and repeat it on every later capture (it is not stored). | |
| `a proxy is configured for this address (HTTPS_PROXY/NO_PROXY); the served-pin probe dials directly …` | The network cross-check cannot see what REST will reach through a proxy. | Set `NO_PROXY` for the host. | |
| `the roster's TLS pin is not the one this write expected (another pveforge wrote it since it was read)` (and its SSH twin) | A compare-and-set lost a race. Nothing was written. | Rerun. | |
| `--reprovisioned needs --host-key-fingerprint …`, `--reprovisioned: the roster holds no SSH or TLS pin …`, `--ssh-tofu does not apply with --reprovisioned …` | The reprovision rules. Refused before any prompt. | Give the console value. For a target never pinned, drop `--reprovisioned`. | |
| `the roster's secrets do not all open with this passphrase: …` (rekey) | Some secrets open with the passphrase given and some do not: the roster is already split, or damaged. Nothing was written. | Find which passphrase opens the named secrets. Re-bootstrap or re-import the targets named, then rekey. | Rekey only part of the roster by hand-editing. |
| `the two passphrase entries differ; nothing was changed` | The two entries of a passphrase being set (a new roster's first, or rekey's new one) differ. | Run the command again. | |
| `the new roster passphrase is read from a terminal only …` | `roster rekey` was run without a terminal: in a script, a pipe, an agent's session or Claude Code's `!` prefix. | Run it in your own terminal. | |
| `roster line N: key "tls" is not a roster key in [targets]` (or `source`, `host_key_source`) | The binary is older than the roster it reads (next section). A binary older still, before `7d99123`, gives NO error and ignores the pin. | Use a current binary. | Delete the key to make an old binary happy. |

## Older binaries: the lockout rule

Pins added three roster keys: `tls` (T1a, merged `4e4f0c9`), `source` (T1b,
`d1aa251`) and `host_key_source` (T2, `10cd982`). `bootstrap`, `roster
pin-tls` and `roster import-token --expect` write them. What an older binary
does with such a roster depends on its age:

- **Built before `7d99123`: DANGEROUS.** These decode the roster with plain
  `toml.Unmarshal`, which silently IGNORES unknown keys. Such a binary reads
  a pinned roster without complaint, ignores the pin, skips certificate
  verification for an `insecure_tls` target, and sends the token to whatever
  answers. No error warns you. Never run one against any roster that holds a
  secret you care about, and delete such builds.
- **Built from `7d99123` up to the key's own commit: locked out.** From
  `7d99123` a roster refuses any key the binary does not know, so these fail
  closed (`roster line N: key "tls" is not a roster key in [targets]`).
- **Built from T1b on:** reads pins and honours them. **From T3 (`cebe383`)
  on,** it also refuses an unpinned `insecure_tls` target.

So before a pinning write, make sure every reader of that roster is current,
and that no pre-`7d99123` build is left anywhere it could be run:
- your PATH binary or `bin/pveforge`;
- `PVEFORGE_BIN` for the harness;
- the harness's roster-reading helpers, which `build/env.sh`, `nested.sh` and
  `golden-reset.sh` build from the checkout (`unlock.sh` builds the secrets
  helper).

## Harness specifics

`hack/harness/README.md` has the run order. Who holds which secret at which
step:

| Step | Who runs it | Secrets it needs |
|---|---|---|
| D5 G0–G3, G5 | Implementor, with key-based root SSH for the root writes | G5: the harness roster passphrase, via `unlock.sh run` |
| **D5 G4**, and any later bootstrap of an outer target | **The operator, in their own terminal** | The **outer root password**, typed at the prompt. Also the harness roster passphrase, prompted or from the environment |
| probe, build, nested bridge, golden, reset | Implementor, under `unlock.sh run` | The harness roster passphrase |
| prepare-iso, cluster.sh, nested bootstrap | Implementor, under `unlock.sh run` | The nested test root password. The nested bootstrap also needs the passphrase |
| `unlock.sh seal`, recipient changes, age identity backups | The operator | Their age identity, and the values being sealed |

- `hack/harness/unlock.sh run [--] <cmd> [args…]` decrypts the secrets in
  memory and replaces itself with `<cmd>`. The values go into that command's
  environment only: never on disk, never in argv. The identity variables are
  removed from that environment, and so, silently, is every variable that runs
  code in a bash child before its first line (`BASH_FUNC_*`, `SHELLOPTS`,
  `BASHOPTS`, `BASH_ENV`, `ENV`, `PS4`). A secret whose name is already set
  refuses to run rather than override it.
- `unlock.sh seal` encrypts a new env file to every recipient. On a terminal
  it prompts twice per name, without echo. Prefer that: it can also read the
  file from stdin, but a file of secrets on disk is exactly what the blob
  exists to avoid. Run it in your own terminal only, and give both names
  (procedure 7).
- `unlock.sh reseal` re-encrypts the current secrets to the current
  `recipients.txt`. `unlock.sh status` shows the recipients, and with an
  identity set, the variable names.
- **Why the outer root password is operator-only:** it is root on the real
  cluster that hosts everything, including the harness. It is in no blob and
  no CI store. The harness guard refuses to run while `PVEFORGE_PVE_PASSWORD`
  is set, and refuses a set `PVEFORGE_ROSTER` and every proxy variable. The
  nested password travels under its own name, and is mapped to
  `PVEFORGE_PVE_PASSWORD` only inside a nested bootstrap child's environment.
- The harness guard requires a TLS pin on every nested target. It refuses a
  nested pin equal to an outer target's, and two nested targets sharing one.
- No bootstrap of `qa-pve-02-harness` may run before G5's post-build checks
  (hazard H-1, `hack/harness/d5/sequence.md`).
