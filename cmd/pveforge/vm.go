package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/idempotent"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

func newVMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vm",
		Short: "Inspect and modify VMs",
	}
	cmd.AddCommand(newVMCreateCmd())
	cmd.AddCommand(newVMGetCmd())
	cmd.AddCommand(newVMSetCmd())
	cmd.AddCommand(newVMSnapshotCmd())
	return cmd
}

// newVMCreateCmd is the CLI-level owner of target-VMID resolution for
// `vm create` (pveforge-vmid-allocation-wiring). internal/idempotent's
// VMCreate Op deliberately does NOT own this: the Op takes an already-
// chosen VMID and its Satisfied reports "already there" as
// idempotent-satisfied (vmcreate.go:158-160), which is defensible for a
// library caller but is NOT the command-line contract the operator
// asked for. On the command line, a caller who names a VMID and finds it
// occupied must get an ERROR, not a silent success — so the refusal
// lives here, and the Op's shipped semantics are untouched.
//
// The VMID is REQUIRED and positional: this command honors an explicit
// request and refuses a collision. It never auto-allocates, so nothing
// here knows or cares about VMID ranges, bands, or ceilings — those are
// the operator's own workflow, enforced by the caller passing the id it
// wants.
//
// pveforge does not compare the existing VM's configuration against the
// create payload — explicitly out of scope. "Occupied" is the whole
// test.
func newVMCreateCmd() *cobra.Command {
	var jsonBody, jsonFile, uniqueTag string
	var noSSHKey bool

	cmd := &cobra.Command{
		Use:   "create <target-id> <vmid> [field=value ...]",
		Short: "Create a VM at an explicitly requested VMID, refusing a collision",
		Long: `Create a VM at the VMID you name, from raw PVE create parameters.

The VMID is explicit and required — this command never picks one for you.
If that VMID is already taken, the command FAILS and names the id; it
never quietly substitutes a different one. A caller that asked to create
one VM must never discover it created one at an id it never saw.

pveforge does NOT inspect whether the existing VM's configuration
resembles what you asked to create. "Something already answers to this
VMID" is the entire collision test.

Create parameters are raw PVE fields (cores, memory, net0, ipconfig0,
scsi0, agent, tags, ...), given exactly like ` + "`vm set`" + `: as
field=value arguments, or via --json / --json-file. Tags are not special
— pass tags=... as a create parameter and PVE applies them atomically as
part of the create itself, so the VM is never briefly untagged.

--unique-tag X (opt-in; X must be one of this create's own tags) refuses
the create if any guest in the cluster, VM or container, already carries
X. Tags are matched case-insensitively, as PVE matches them: Foo and foo
are one tag. An empty or blank X is refused.

The guests are listed as root over SSH (pvesh get /cluster/resources),
not with the roster's token: PVE leaves a guest out of a token's list
whenever the token lacks VM.Audit on that guest's own path (a NoAccess or
any narrower role there, on the token's user or group, or a NoAccess on
its pool), and no read a token can make shows that none was left out.
root's list leaves out nothing. So --unique-tag needs root SSH, as user
ensure does: the target's stored SSH key, or --no-ssh-key and the PVE
password. That read runs nothing else as root.

The check is made under a pveforge lock on the tag, taken before the VM's
own lock and held until the new VM shows up in root's list, so two
pveforge creates with the same --unique-tag on this roster target never
both succeed. Its limits:
  - it fails closed: a list that cannot be read, or that is not exactly
    what PVE returns (null, a malformed entry, an unknown guest type),
    refuses the create; so does a root read that takes more than 30s;
  - tags are folded even when the datacenter's tag-style sets
    case-sensitive=1, so pveforge then refuses more than PVE distinguishes,
    never less;
  - root's list is PVE's replicated cluster config: a guest on an offline
    node is still listed, but a node without quorum may serve a stale
    list;
  - the lock is per roster target: two targets that are nodes of one
    cluster are not serialised against each other, and neither is the
    web UI or qm;
  - PVE's resource list lags; if the new VM is not listed within 30s, the
    create still succeeds and a warning says a concurrent check may miss it.
    A signal (Ctrl-C) during that wait exits 130 (143 for SIGTERM) with an
    error saying the VM WAS created and the wait was interrupted before it
    was listed: the tag's lock was released early.
Without --unique-tag, two creates with the same tags both succeed.

After the create, the VM is read back. If that read fails, one stderr warning
says the result could not be re-read; if PVE answers that the VM just created
does not exist, one stderr warning says so. Either way stdout is unchanged and
the exit status is still 0: the create task succeeded.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			params, err := vmCreateParams(args[2:], jsonBody, jsonFile)
			if err != nil {
				return err
			}

			vmid, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("invalid vmid %q: %w", args[1], err)
			}
			// The guard is on when the flag is GIVEN, whatever its value: an
			// empty or blank --unique-tag is refused, never read as "off".
			tagGuard := cmd.Flags().Changed("unique-tag")
			if tagGuard {
				if err := uniqueTagIsOwn(uniqueTag, params); err != nil {
					return err
				}
			} else if noSSHKey {
				return errors.New("vm create: --no-ssh-key only applies with --unique-tag, whose check runs as root")
			}
			// Guard the sentinel, not a range: NextVMID reads pin == 0 as
			// "no pin, auto-allocate", and auto-allocation is explicitly
			// NOT this command's contract — a 0 reaching NextVMID would
			// silently turn "create vm 0" into "create a VM at whatever
			// id PVE suggests", the exact surprise this command exists to
			// prevent. Nothing here validates vmid against any band or
			// ceiling; PVE's own schema owns the valid range and rejects
			// the rest with its own error text.
			if vmid < 1 {
				return fmt.Errorf("invalid vmid %d: vm create requires an explicit positive vmid (it never auto-allocates)", vmid)
			}

			// With --unique-tag, root (for the guest list) and the token's
			// client come from one roster load and one passphrase; a
			// target holding no SSH key is refused, without --no-ssh-key,
			// before anything is asked for or sent.
			var client *pve.RoutedClient
			var root guestLister
			if tagGuard {
				a, _, rest, closeAll, err := openRootAccessAndREST(cmd, args[0], noSSHKey, true)
				if err != nil {
					return err
				}
				defer closeAll()
				if rest == nil {
					return fmt.Errorf("target %q holds no API token", args[0])
				}
				// Root is reached (the password asked for, when keyless, and
				// the session dialed) BEFORE the tag lock is taken, so
				// neither a prompt nor a dial is ever made holding it.
				if err := a.Connect(cmd.Context()); err != nil {
					return fmt.Errorf("vm create: --unique-tag: connect as root: %w", err)
				}
				client, root = rest, a
			} else {
				client, err = resolveRoutedClient(cmd, args[0])
				if err != nil {
					return err
				}
				defer func() { _ = client.Close() }()
			}

			rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
			if err != nil {
				return err
			}

			// --unique-tag: the tag's lock, taken BEFORE the VM's (lock order
			// is always tag, then vm), held across the check, the create and
			// the visibility wait, so no other pveforge create with this
			// --unique-tag on this target can pass its check in between. Its
			// key is the tag case-folded, as PVE matches tags: "Foo" and
			// "foo" are one tag, so they are one lock.
			if tagGuard {
				unlockTag, err := lock.Mutation(cmd.Context(), rosterPath, lock.ObjectKey{TargetID: args[0], Kind: "vm-tag", ID: strings.ToLower(uniqueTag)})
				if err != nil {
					return fmt.Errorf("vm create: acquire the lock for tag %s: %w", kvjson.QuoteValue(uniqueTag), err)
				}
				defer func() { _ = unlockTag() }()
				if err := checkTagUnique(cmd.Context(), root, uniqueTag); err != nil {
					return err
				}
			}

			// The pin path of NextVMID: returns the requested vmid
			// unchanged when free, or errors "next vmid: pin %d is already
			// taken" when not. No substitution, no walk — the walk-forward
			// search belongs to the no-pin path, which this command never
			// takes.
			resolved, err := client.NextVMID(cmd.Context(), vmid)
			if err != nil {
				return fmt.Errorf("vm create: %w", err)
			}

			// THE LOCK KEY covering the resolve-then-create span is
			// lock.ObjectKey{TargetID: <target>, Kind: "vm", ID: <resolved>} —
			// the same per-VM key `vm get` and `vm set` already use.
			//
			// Built from `resolved`, NOT from the `vmid` the caller typed,
			// and constructed AFTER the call above rather than before it.
			// The two are equal today, because NextVMID's pin path returns
			// its pin verbatim — but deriving the key from one variable
			// while the Op below is built from another is precisely the
			// shape that produces a lock on one object and a mutation on a
			// different one. No test can catch that while the values agree,
			// so it is closed structurally instead: there is exactly one
			// variable, and the lock and the Op both read it.
			//
			// It is ONE key, not two, and that is the point: allocation and
			// creation are not two independently-locked steps. The
			// AUTHORITATIVE existence check happens INSIDE this key's
			// exclusive window — idempotent.Run acquires it (lock.Mutation),
			// then calls Read/Satisfied under it — so any competing pveforge
			// mutation against this same VMID is serialized strictly before
			// or after our Read and can never interleave with it. The
			// pre-check above runs unlocked, but it is not what makes the
			// refusal safe; it only fails early with a clearer message. The
			// Changed == false backstop after Run is what closes the window.
			//
			// Why that unlocked pre-check is not the hole it looks like, and
			// why a WIDER key spanning both steps would buy nothing: this
			// command is PIN-ONLY. The caller names the vmid, so there is no
			// allocation DECISION here to protect. Nothing on this path
			// draws an id from PVE's advisory next-free counter, so the race
			// the plan's hazard section is about — two concurrent
			// allocations handed the SAME id by that counter, the loser
			// finding out only when its create collides — is structurally
			// unreachable here rather than merely mitigated. NextVMID's
			// walk-forward search belongs to the no-pin path. What remains
			// is a pure COLLISION race (someone else taking the named id),
			// and the in-lock Read/Satisfied plus the backstop handle it.
			//
			// That pin-only-ness is the REAL justification for this shape.
			// A coarser key held across both steps (say
			// {target, "vmid-alloc", node}) would also make the span atomic
			// and would not self-deadlock — it is a legitimate alternative,
			// and on an auto-allocating path it would be the RIGHT one,
			// because then there would be a counter-draw to serialize.
			// Here it would serialize a decision that does not exist while
			// needlessly blocking unrelated creates on the same node. If
			// this command ever grows auto-allocation, revisit this: the
			// wider key becomes necessary, not optional.
			//
			// Separately, re-acquiring THIS key here would not work even if
			// wanted: internal/lock is flock(2)-backed, so a second
			// acquisition of the same key from this same process blocks on
			// our own hold rather than nesting. That rules out one
			// implementation; it is not the reason for the design.
			key := lock.ObjectKey{TargetID: args[0], Kind: "vm", ID: strconv.Itoa(resolved)}

			op := &idempotent.VMCreate{Client: client, VMID: resolved, Params: params}

			// Explicit, ahead of Run, for the same reason `vm set` and
			// `network bridge create` do it: idempotent.Run calls
			// Satisfied before Apply and skips Apply entirely when the
			// vmid is already satisfied, so Apply's own internal
			// Validate() would never run and a malformed Params (an
			// orphan ipconfigN) would pass unnoticed on that path.
			if err := op.Validate(); err != nil {
				return err
			}

			res, err := idempotent.Run(cmd.Context(), rosterPath, key, op, false)
			if err != nil {
				return err
			}

			// The residual-race backstop. NextVMID reporting the id free
			// and CreateVM running are separate calls; something can take
			// the id in between (notably anything mutating PVE outside
			// pveforge's lock — a human in the web UI — which the key
			// above cannot serialize against). On THIS command's path a
			// create that changed nothing can only mean the VM already
			// existed, because we just refused that case ourselves — so
			// Changed == false is an error here even though it is a
			// legitimate no-op for a library caller of the Op. One branch,
			// and it converts the Op's silent idempotent-satisfied
			// success back into the collision error the CLI contract
			// promises.
			if !res.Changed {
				return fmt.Errorf("vm create: vm %d already exists on %s (it was taken between the vmid check and the create); refusing to create it at a different vmid", resolved, args[0])
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%s: vm %d created\n", args[0], resolved)
			// Advisory: exit 0 and stdout unchanged. The re-read's failure
			// first, then the post-create check (PVE answered that the VM
			// just created does not exist), then the tag's visibility.
			warnNotReread(cmd.ErrOrStderr(), args[0], "vm", strconv.Itoa(resolved), res.AfterErr)
			warnPostCheck(cmd.ErrOrStderr(), args[0], "vm", strconv.Itoa(resolved), res.Changed, "PVE then reported it does not exist", res.PostApplyErr)
			if tagGuard {
				visible, err := waitTagVisible(cmd.Context(), root, uniqueTag, resolved)
				if err != nil {
					return fmt.Errorf("vm create: vm %d on %s: %w: tag %s (%w)", resolved, args[0], errVMCreatedTagWaitInterrupted, kvjson.QuoteValue(uniqueTag), err)
				}
				if !visible {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s: vm %d: tag %s is not yet in PVE's cluster resource list after %s; a --unique-tag check made now may not see this VM\n", args[0], resolved, kvjson.QuoteValue(uniqueTag), tagVisibilityBound)
				}
			}
			return nil
		},
	}
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
	cmd.Flags().StringVar(&uniqueTag, "unique-tag", "", "refuse the create if any VM or container in the cluster already carries this tag (one of this create's own tags); the guests are listed as root over SSH")
	cmd.Flags().BoolVar(&noSSHKey, "no-ssh-key", false, "with --unique-tag: "+noSSHKeyAccessUsage)
	cmd.Flags().StringVar(&jsonBody, "json", "", "JSON object of create parameters (values must be JSON strings)")
	cmd.Flags().StringVar(&jsonFile, "json-file", "", "path to a JSON file of create parameters (values must be JSON strings)")
	markMutating(cmd)
	return cmd
}

func newVMGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <target-id> <vmid>",
		Short: "Get a VM's status and config",
		Args:  cobra.ExactArgs(2),
	}
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
	resolveFormat := addOutputFlag(cmd)

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		vmid, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid vmid %q: %w", args[1], err)
		}

		client, err := resolveRoutedClient(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
		if err != nil {
			return err
		}
		unlock, err := lock.Read(cmd.Context(), rosterPath, lock.ObjectKey{TargetID: args[0], Kind: "vm", ID: strconv.Itoa(vmid)})
		if err != nil {
			return fmt.Errorf("acquire read lock: %w", err)
		}
		defer func() { _ = unlock() }()

		vm, err := client.GetVM(cmd.Context(), client.Node(), vmid)
		if err != nil {
			return err
		}
		return kvjson.Render(cmd.OutOrStdout(), format, vm)
	}
	markSafe(cmd)
	return cmd
}

func newVMSetCmd() *cobra.Command {
	var jsonBody, jsonFile string
	var deleteFlags []string

	cmd := &cobra.Command{
		Use:   "set <target-id> <vmid> [field=value ...] [--delete field ...]",
		Short: "Set or delete one or more VM config fields",
		Long: `Set one or more VM config fields, via at most one of:
  - trailing field=value positional arguments
  - --json '{"field":"value",...}'
  - --json-file path/to/fields.json

--delete field (repeatable) removes field from the VM's config entirely,
through PVE's own delete parameter. That is not the same as field= (or
"field":"" in JSON), which writes an empty value and leaves the key present.
In --json/--json-file, a null value ("field":null) also deletes the key.
--delete may be used alone or together with one input mode; a field may not
be both set and deleted. Deletes are applied after the writes.

Fields are applied in order (positional: as given; JSON: sorted by key).
Applying stops at the first failure — earlier fields in the same
invocation have already been applied and are not rolled back.

The whole batch is applied as one idempotent-mutation-engine cycle
(internal/idempotent.VMFieldsEnsure), serialized against every other
pveforge-managed mutation on this VM for its full duration
(internal/lock.Mutation) — never two concurrent pveforge mutations on the
same VM in flight at once. A field already at its wanted value is left
untouched (no write attempted) and prints no confirmation line; output is
a summary of only the fields that actually changed, printed once the
whole batch resolves rather than streamed as each field applies. If the
writes succeed but the VM's config cannot be re-read afterwards, a
one-line warning is printed on stderr, stdout is unchanged and the exit
status is still 0.

Output: one line per field written, "<target>: <field>=<value>", then one
per field deleted, "<target>: delete=<field>". A field already absent prints
nothing, like a field already at its value.

On a running VM, a change PVE cannot apply live is stored as pending and
taken at the VM's next cold boot. After the batch, vm set asks PVE which of
its own changes are pending and prints one stderr notice per such field
("notice: <target>: vm N: <field> is pending: …", or "delete=<field> is
pending"); stdout is unchanged and the exit status stays 0. A cloud-init
setting (ciuser, sshkeys, ipconfigN, …) is saved at once but reaches the
guest only when the VM's cloud-init drive is regenerated at its next start:
for those, vm set asks PVE which of its own changes are not yet on the
drive and prints one stderr notice each. If a check itself fails, one
warning line says so.

A field that already reads as set may only be pending: PVE's config read
shows a pending value as applied. So a requested field left untouched
because it already matched, or a --delete of a key already absent, is also
checked: one stderr notice per such field PVE still holds pending ("… is
already set but still pending", "delete=<field> is already done but still
pending") and, when nothing needed changing, per cloud-init field not yet on
the drive. When nothing needed changing, a failed check's warning says so
rather than that a change was applied.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			kvArgs := args[2:]

			modes := 0
			if len(kvArgs) > 0 {
				modes++
			}
			if jsonBody != "" {
				modes++
			}
			if jsonFile != "" {
				modes++
			}
			if modes > 1 || (modes == 0 && len(deleteFlags) == 0) {
				return fmt.Errorf("specify exactly one of: field=value arguments, --json, or --json-file (or only --delete)")
			}

			var pairs []kvjson.Pair
			var deletes []string
			var err error
			switch {
			case len(kvArgs) > 0:
				pairs, err = kvjson.ParseKVArgs(kvArgs)
			case jsonBody != "":
				pairs, deletes, err = kvjson.ParseJSONFieldsWithDeletes([]byte(jsonBody))
			case jsonFile != "":
				var data []byte
				data, err = os.ReadFile(jsonFile)
				if err != nil {
					return fmt.Errorf("read %s: %w", jsonFile, err)
				}
				pairs, deletes, err = kvjson.ParseJSONFieldsWithDeletes(data)
			}
			if err != nil {
				return err
			}
			deletes = append(deletes, deleteFlags...)

			vmid, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("invalid vmid %q: %w", args[1], err)
			}

			// Validate before the roster, the client or the lock: a
			// malformed batch (a field both set and deleted, a repeat)
			// must never reach PVE.
			op := &idempotent.VMFieldsEnsure{VMID: vmid, Pairs: pairs, Deletes: deletes}
			if err := op.Validate(); err != nil {
				return err
			}

			client, err := resolveRoutedClient(cmd, args[0])
			if err != nil {
				return err
			}
			defer func() { _ = client.Close() }()

			rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
			if err != nil {
				return err
			}

			key := lock.ObjectKey{TargetID: args[0], Kind: "vm", ID: strconv.Itoa(vmid)}
			// op.Validate() already ran, above, and must stay explicit and
			// ahead of Run: idempotent.Run calls Satisfied before Apply, and
			// if the batch already matches current state, Apply — and
			// therefore its own internal Validate() call — never runs at
			// all, silently bypassing the documented "no duplicate field
			// name" contract for an already-satisfied batch (e.g. the same
			// field=value pair given twice, where that value already
			// matches). Never push this into idempotent.Run itself —
			// shared infrastructure VMTagEnsure/BridgeIsolationEnsure also
			// use, out of scope here.
			op.Client = client

			res, err := idempotent.Run(cmd.Context(), rosterPath, key, op, false)
			if err != nil {
				return err
			}
			if err := printAppliedFields(cmd.OutOrStdout(), args[0], op.Applied, pairs); err != nil {
				return err
			}
			if err := printDeletedFields(cmd.OutOrStdout(), args[0], op.Deleted); err != nil {
				return err
			}
			// Advisory (warnNotReread): the exit status stays 0, and stdout
			// is unchanged.
			warnNotReread(cmd.ErrOrStderr(), args[0], "vm", strconv.Itoa(vmid), res.AfterErr)
			reportPending(cmd.ErrOrStderr(), args[0], vmid, op, res.Changed, res.PostApplyErr)
			return nil
		},
	}
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
	cmd.Flags().StringVar(&jsonBody, "json", "", "JSON object of field=value pairs (values must be JSON strings)")
	cmd.Flags().StringVar(&jsonFile, "json-file", "", "path to a JSON file of field=value pairs (values must be JSON strings)")
	cmd.Flags().StringArrayVar(&deleteFlags, "delete", nil, "remove this config key entirely (PVE's delete parameter), rather than writing it empty; repeatable")
	markMutating(cmd)
	return cmd
}

// reportPending prints, on stderr, what VMFieldsEnsure's post-checks found
// (PostApply after a change, PostNoop on a no-op): one notice per change of
// this run that PVE holds as pending — stored in the VM's config but taken
// by the running guest only at its next cold boot — then one per cloud-init
// change of this run that is saved but not yet on the VM's cloud-init
// drive; then one per requested setting the run did not change because it
// already read as set, but which PVE still holds pending or has not yet
// put on the drive; and, when a check could not be made, one warning
// quoting why, after whatever was found — naming the question left open:
// whether a setting is pending, or (when only the cloud-init check failed)
// whether it has reached the cloud-init drive — and worded by changed
// (warnPostCheck), since on a no-op nothing was applied. Every line is
// advisory: the exit status stays 0 and stdout (the lines a script parses)
// is untouched. Keys and the cause are quoted like every other kv line;
// the target id is line-safe by the roster's own validation.
func reportPending(errOut io.Writer, targetID string, vmid int, op *idempotent.VMFieldsEnsure, changed bool, postErr error) {
	for _, f := range op.Pending {
		fmt.Fprintf(errOut, "notice: %s: vm %d: %s is pending: it takes effect at the VM's next cold boot\n", targetID, vmid, kvjson.QuoteKey(f))
	}
	for _, f := range op.PendingDeletes {
		fmt.Fprintf(errOut, "notice: %s: vm %d: delete=%s is pending: it takes effect at the VM's next cold boot\n", targetID, vmid, kvjson.QuoteValue(f))
	}
	for _, f := range op.CloudInitStale {
		fmt.Fprintf(errOut, "notice: %s: vm %d: %s is saved but not yet on the cloud-init drive: the guest sees it after the drive is regenerated at the VM's next start\n", targetID, vmid, kvjson.QuoteKey(f))
	}
	for _, f := range op.CloudInitStaleDeletes {
		fmt.Fprintf(errOut, "notice: %s: vm %d: delete=%s is saved but not yet on the cloud-init drive: the guest sees it after the drive is regenerated at the VM's next start\n", targetID, vmid, kvjson.QuoteValue(f))
	}
	for _, f := range op.AlreadyPending {
		fmt.Fprintf(errOut, "notice: %s: vm %d: %s is already set but still pending: it takes effect at the VM's next cold boot\n", targetID, vmid, kvjson.QuoteKey(f))
	}
	for _, f := range op.AlreadyPendingDeletes {
		fmt.Fprintf(errOut, "notice: %s: vm %d: delete=%s is already done but still pending: it takes effect at the VM's next cold boot\n", targetID, vmid, kvjson.QuoteValue(f))
	}
	for _, f := range op.AlreadyCloudInitStale {
		fmt.Fprintf(errOut, "notice: %s: vm %d: %s is already set but not yet on the cloud-init drive: the guest sees it after the drive is regenerated at the VM's next start\n", targetID, vmid, kvjson.QuoteKey(f))
	}
	for _, f := range op.AlreadyCloudInitStaleDeletes {
		fmt.Fprintf(errOut, "notice: %s: vm %d: delete=%s is already done but not yet on the cloud-init drive: the guest sees it after the drive is regenerated at the VM's next start\n", targetID, vmid, kvjson.QuoteValue(f))
	}
	question := "whether it is pending could not be checked"
	var ciErr *idempotent.CloudInitCheckError
	if errors.As(postErr, &ciErr) {
		// /pending was answered; only the cloud-init check was not.
		question = "whether it has reached the cloud-init drive could not be checked"
	}
	warnPostCheck(errOut, targetID, "vm", strconv.Itoa(vmid), changed, question, postErr)
}

// printDeletedFields prints one "<target>: delete=<field>" line per key
// VMFieldsEnsure.Deleted records, in the field=value shape vm set's stdout
// already uses. "delete" is PVE's own parameter name, which no config key
// can be, so the line cannot be mistaken for a write; and it is never
// "<field>=", which would read as a field written empty. The field is quoted
// like any kv value.
func printDeletedFields(out io.Writer, targetID string, deleted []string) error {
	for _, field := range deleted {
		if _, err := fmt.Fprintf(out, "%s: delete=%s\n", targetID, kvjson.QuoteValue(field)); err != nil {
			return err
		}
	}
	return nil
}

// printAppliedFields prints one confirmation line per field name in
// applied — VMFieldsEnsure.Applied, populated by Apply itself as it
// writes each field — looking up each one's wanted value from pairs.
// Deliberately does NOT diff idempotent.Result's Before/After: that
// used to be this function's whole approach, but Result.After silently
// falls back to equaling Result.Before whenever idempotent.Run's own
// best-effort post-Apply re-read fails (Run's own documented behavior —
// Changed stays true, the write genuinely succeeded), which made a
// diff-based reconstruction print nothing at all for a real, successful
// write — indistinguishable from a no-op, with no error either. Applied
// is populated directly by the write that happened, not reconstructed
// after the fact from two snapshots that might not disagree even when
// something changed. That failed re-read is no longer silent: Run
// reports it as Result.AfterErr, which vm set prints as a stderr warning.
//
// applied is already in the order Apply wrote them (a subset of pairs,
// in pairs' own relative order — see Apply), so no separate ordering step
// is needed here.
func printAppliedFields(out io.Writer, targetID string, applied []string, pairs []kvjson.Pair) error {
	wanted := make(map[string]string, len(pairs))
	for _, p := range pairs {
		wanted[p.Field] = p.Value
	}
	for _, field := range applied {
		// Same quoting as kv output (kvjson.QuoteKey/QuoteValue): a value
		// from --json/--json-file can carry a newline, and must not forge
		// a second "applied" line.
		if _, err := fmt.Fprintf(out, "%s: %s=%s\n", targetID, kvjson.QuoteKey(field), kvjson.QuoteValue(wanted[field])); err != nil {
			return err
		}
	}
	return nil
}

// vmCreateParams turns this command's three mutually-exclusive input
// modes into the url.Values VMCreate.Params wants, reusing kvjson's own
// field=value / JSON-object grammar so `vm create` and `vm set` accept
// parameters identically. Exactly one mode must be used; zero is an
// error too, since a create with no parameters at all is far more likely
// a mistake than a request for PVE's bare defaults.
func vmCreateParams(kvArgs []string, jsonBody, jsonFile string) (url.Values, error) {
	modes := 0
	if len(kvArgs) > 0 {
		modes++
	}
	if jsonBody != "" {
		modes++
	}
	if jsonFile != "" {
		modes++
	}
	if modes != 1 {
		return nil, fmt.Errorf("specify exactly one of: field=value arguments, --json, or --json-file")
	}

	var pairs []kvjson.Pair
	var err error
	switch {
	case len(kvArgs) > 0:
		pairs, err = kvjson.ParseKVArgs(kvArgs)
	case jsonBody != "":
		pairs, err = kvjson.ParseJSONFields([]byte(jsonBody))
	case jsonFile != "":
		var data []byte
		data, err = os.ReadFile(jsonFile)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", jsonFile, err)
		}
		pairs, err = kvjson.ParseJSONFields(data)
	}
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	for _, p := range pairs {
		// "vmid" is the positional argument, never a create parameter.
		// pve.CreateVM stamps form.Set("vmid", ...) from the Op's VMID, so
		// a vmid= given here loses silently to the positional — the SAFE
		// resolution, but a silent one, and on the single command whose
		// whole contract is that the VMID is explicit, a typed parameter
		// must not evaporate. Refuse it instead of quietly dropping it.
		if p.Field == "vmid" {
			return nil, fmt.Errorf("vmid is the positional argument, not a create parameter: drop %q and pass the vmid as the second argument", p.Field+"="+p.Value)
		}
		params.Add(p.Field, p.Value)
	}
	return params, nil
}

// tagVisibilityBound and tagVisibilityPoll bound how long a --unique-tag
// create waits, still holding the tag's lock, for its new VM to appear in
// /cluster/resources (pvestatd-cached, about 10s behind; UNVERIFIED against
// a live host). Variables so tests can shorten them.
var (
	tagVisibilityBound = 30 * time.Second
	tagVisibilityPoll  = time.Second
)

// tagReadTimeout bounds each root read of the guest list, the check's and
// every poll of the wait's, as the REST read it replaced was bounded by
// pve.DefaultTimeout: a half-open SSH connection or a hung pmxcfs must
// never hold the tag's lock without end. A variable so tests can shorten
// it.
var tagReadTimeout = pve.DefaultTimeout

// errVMCreatedTagWaitInterrupted marks a --unique-tag create whose VM WAS
// created and whose wait for it to be listed was then interrupted by a
// signal. Its text already says so; runRoot prints it as it is, never with
// its generic "may or may not have been applied", and exits 128+signum,
// like its other interrupt exemptions.
var errVMCreatedTagWaitInterrupted = errors.New("the VM WAS created; the wait for PVE to list it was interrupted before it was, and the tag's lock was released early, so a --unique-tag check made now may not see it")

// tagSplit is how PVE separates the values of a tags= parameter.
var tagSplit = regexp.MustCompile(`[;,\s]+`)

// pveTagRE is PVE's tag format (pve-common's pve-tag: ASCII, case-
// insensitive). --unique-tag is held to it, so the case-folded lock key
// (strings.ToLower) and the case-insensitive match (strings.EqualFold)
// agree exactly; a tag outside it PVE refuses anyway.
var pveTagRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_+.-]*$`)

// uniqueTagIsOwn checks --unique-tag before any request: not empty or
// blank, never containing PVE's ';' separator, in PVE's tag format, and one
// of the create's own tags= (matched case-insensitively, as PVE does).
func uniqueTagIsOwn(tag string, params url.Values) error {
	if strings.TrimSpace(tag) == "" {
		return fmt.Errorf("vm create: --unique-tag was given an empty tag; name one of this create's tags, or leave the flag out")
	}
	if strings.Contains(tag, proxmox.TagSeperator) {
		return fmt.Errorf("vm create: --unique-tag %s contains PVE's tag separator %q", kvjson.QuoteValue(tag), proxmox.TagSeperator)
	}
	if !pveTagRE.MatchString(tag) {
		return fmt.Errorf("vm create: --unique-tag %s is not a PVE tag (letters, digits, '_', '-', '+' and '.', not starting with '-', '+' or '.')", kvjson.QuoteValue(tag))
	}
	for _, t := range tagSplit.Split(params.Get("tags"), -1) {
		if strings.EqualFold(t, tag) {
			return nil
		}
	}
	return fmt.Errorf("vm create: --unique-tag %s is not one of this create's tags (tags=%s)", kvjson.QuoteValue(tag), kvjson.QuoteValue(params.Get("tags")))
}

// guestLister is what the --unique-tag check and wait need: root's list of
// every guest in the cluster (bootstrap.RootAccess.ClusterGuests).
type guestLister interface {
	ClusterGuests(ctx context.Context) ([]pve.Guest, error)
}

// checkTagUnique fails closed: only root's list, read and decoded in full,
// with no guest (VM or container) carrying tag lets the create proceed. A
// match, an ambiguous match, and a list that failed or was not what PVE
// returns all refuse.
func checkTagUnique(ctx context.Context, root guestLister, tag string) error {
	q := kvjson.QuoteValue(tag)
	rctx, cancel := context.WithTimeout(ctx, tagReadTimeout)
	defer cancel()
	guests, err := root.ClusterGuests(rctx)
	if err != nil {
		return fmt.Errorf("vm create: cannot verify tag uniqueness for %s: %w", q, err)
	}
	g, err := pve.FindGuestByTagFold(guests, tag)
	switch {
	case err == nil:
		return fmt.Errorf("vm create: tag %s is already carried by %s %d; refusing to create another (--unique-tag)", q, g.Kind(), g.VMID)
	case errors.Is(err, pve.ErrAmbiguousTag):
		return fmt.Errorf("vm create: tag %s is already carried by more than one guest; refusing to create another (--unique-tag): %w", q, err)
	case errors.Is(err, pve.ErrNotFound):
		return nil
	default:
		return fmt.Errorf("vm create: cannot verify tag uniqueness for %s: %w", q, err)
	}
}

// waitTagVisible polls root's list until the one guest carrying tag is this
// create's VM (vmid, a QEMU guest), for at most tagVisibilityBound, and
// reports whether it did. Any other answer, a read failure or another
// guest carrying the tag included, is polled past: the
// create has already succeeded, so running out of time only warns. A
// cancelled ctx (a signal) is the one error: the wait did not run its
// course, and the caller must say so rather than claim the bound elapsed.
//
// Each read has its own deadline: tagReadTimeout, cut to the time left
// before the bound. A read that runs out of time is polled past like any
// failed read, never taken for the parent's cancellation, so a hung read
// ends in the bound's warning, not in an interruption.
func waitTagVisible(ctx context.Context, root guestLister, tag string, vmid int) (bool, error) {
	deadline := time.Now().Add(tagVisibilityBound)
	for {
		if guests, err := readGuestsBy(ctx, root, deadline); err == nil {
			if g, err := pve.FindGuestByTagFold(guests, tag); err == nil && g.Type == "qemu" && g.VMID == vmid {
				return true, nil
			}
		}
		if err := ctx.Err(); err != nil {
			return false, context.Cause(ctx)
		}
		if !time.Now().Before(deadline) {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, context.Cause(ctx)
		case <-time.After(min(tagVisibilityPoll, time.Until(deadline))):
		}
	}
}

// readGuestsBy is one poll's root read, bounded by tagReadTimeout and by
// the wait's own deadline, whichever comes first.
func readGuestsBy(ctx context.Context, root guestLister, deadline time.Time) ([]pve.Guest, error) {
	by := time.Now().Add(tagReadTimeout)
	if deadline.Before(by) {
		by = deadline
	}
	rctx, cancel := context.WithDeadline(ctx, by)
	defer cancel()
	return root.ClusterGuests(rctx)
}
