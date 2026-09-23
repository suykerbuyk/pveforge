package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/idempotent"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
)

func newVMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vm",
		Short: "Inspect and modify VMs",
	}
	cmd.AddCommand(newVMCreateCmd())
	cmd.AddCommand(newVMGetCmd())
	cmd.AddCommand(newVMSetCmd())
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
	var jsonBody, jsonFile string

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
part of the create itself, so the VM is never briefly untagged.`,
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

			client, err := resolveRoutedClient(cmd, args[0])
			if err != nil {
				return err
			}
			defer func() { _ = client.Close() }()

			rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
			if err != nil {
				return err
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
			return nil
		},
	}
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
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
pending"); stdout is unchanged and the exit status stays 0. If that check
itself fails, one warning line says so instead.`,
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
			// The write succeeded, so this is advisory and the exit status
			// stays 0 — failing it would push a caller into a needless
			// retry. Stderr, not stdout, so the applied lines a script
			// parses are unchanged. The cause is quoted like runRoot's own
			// error line, because it can carry server text (a 5xx body)
			// that must not forge a second line; the target id is printed
			// bare, as printAppliedFields prints it, because the roster
			// refuses any id that would need quoting
			// (roster.ValidateTargetID).
			if res.AfterErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s: vm %d: the write was applied but its result could not be re-read: %s\n", args[0], vmid, kvjson.QuoteValue(res.AfterErr.Error()))
			}
			reportPending(cmd.ErrOrStderr(), args[0], vmid, op, res.PostApplyErr)
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

// reportPending prints, on stderr, what VMFieldsEnsure.PostApply found:
// one notice per change of this run that PVE holds as pending — stored in
// the VM's config but taken by the running guest only at its next cold
// boot — or, when that could not be checked, one warning quoting why. Every
// line is advisory: the change was made, so the exit status stays 0 and
// stdout (the lines a script parses) is untouched. Keys and the cause are
// quoted like every other kv line; the target id is line-safe by the
// roster's own validation.
func reportPending(errOut io.Writer, targetID string, vmid int, op *idempotent.VMFieldsEnsure, postErr error) {
	if postErr != nil {
		fmt.Fprintf(errOut, "warning: %s: vm %d: the change was applied but whether it is pending could not be checked: %s\n", targetID, vmid, kvjson.QuoteValue(postErr.Error()))
		return
	}
	for _, f := range op.Pending {
		fmt.Fprintf(errOut, "notice: %s: vm %d: %s is pending: it takes effect at the VM's next cold boot\n", targetID, vmid, kvjson.QuoteKey(f))
	}
	for _, f := range op.PendingDeletes {
		fmt.Fprintf(errOut, "notice: %s: vm %d: delete=%s is pending: it takes effect at the VM's next cold boot\n", targetID, vmid, kvjson.QuoteValue(f))
	}
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
