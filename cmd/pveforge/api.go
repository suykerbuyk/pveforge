package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// newAPICmd is pveforge-raw-api-escape-hatch's (PRD §3.1 / docs/prd.md
// §6 item 6) CLI entry point: `pveforge api get/post/put/delete <path>
// [--data key=value ...] <target-id>`, a raw PVE REST passthrough for any
// path with no dedicated typed command yet — the shape/idea surfaced by
// reviewing davegallant/pvectl (GPL-3.0, idea only, its code never used;
// reimplemented from scratch here against pveforge's own conventions).
func newAPICmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "api",
		Short: "Raw PVE REST API passthrough for paths with no dedicated command yet",
	}
	cmd.AddCommand(newAPIVerbCmd(http.MethodGet, "get"))
	cmd.AddCommand(newAPIVerbCmd(http.MethodPost, "post"))
	cmd.AddCommand(newAPIVerbCmd(http.MethodPut, "put"))
	cmd.AddCommand(newAPIVerbCmd(http.MethodDelete, "delete"))
	return cmd
}

// newAPIVerbCmd builds one of the four `api` subcommands. All four share
// one RunE body — the per-verb differences are the HTTP method itself and
// the locking behavior below, per the vault task's "Locking design"
// section (2026-09-14, corrected after an earlier transcription flattened
// this nuance out of the original investigation): an UNMATCHED path
// refuses by default and requires --unsafe-no-lock for post/put/delete,
// but a GET on an unmatched path always proceeds, unconditionally, no
// flag, no warning. Rationale: locking a GET exists only to honor PRD
// §3.4's "a pending mutation takes priority over a pending read" — but an
// unmatched path has no lock key anything else in the system could ever
// be queuing a mutation against, so refusing it protects nothing. It
// would only add friction (and a confusingly-named flag) to exactly the
// case this command exists for: read-only exploration of a path with no
// dedicated command yet, e.g. `pveforge api get /version`.
//
// For post/put/delete, a response that is a PVE task id (a bare JSON string
// with the "UPID:" prefix) is WAITED ON by default, and the command reports
// the task's own outcome rather than the HTTP call's: see apiMutationLong
// for the user-facing contract and waitForAPITask for the mechanism. The
// wait happens inside RunE, before the deferred unlock, so the object lock
// spans the task — PRD §6 item 6's lock-spans-the-task half.
func newAPIVerbCmd(method, use string) *cobra.Command {
	var dataPairs []string
	var unsafeNoLock bool
	var noWait bool
	var waitTimeout time.Duration

	cmd := &cobra.Command{
		Use:   use + " <path> <target-id>",
		Short: fmt.Sprintf("Raw PVE REST %s against <path>", method),
		Long:  apiLong,
		Args:  cobra.ExactArgs(2),
	}
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
	cmd.Flags().Lookup("lock-wait").Usage += apiLockWaitNote
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().StringArrayVar(&dataPairs, "data", nil, "a key=value request parameter (repeatable)")
	cmd.Flags().BoolVar(&unsafeNoLock, "unsafe-no-lock", false, "proceed without internal/lock protection when <path> doesn't match a known pveforge-managed object type")
	// The wait flags exist on the mutating verbs only: GET is never waited
	// on, so on `api get` they would be accepted and mean nothing.
	if method != http.MethodGet {
		cmd.Long = apiMutationLong
		cmd.Flags().BoolVar(&noWait, "no-wait", false, "if PVE returns a task id (UPID), print it and exit without waiting for the task; the object lock is released before the task finishes")
		cmd.Flags().DurationVar(&waitTimeout, "wait-timeout", 0, fmt.Sprintf("give up waiting for a returned task after this long (0 = the %s ceiling; may not exceed it)", pve.TaskWaitCeiling))
	}

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		// Flag validation comes before the roster, the client, the lock and
		// the dispatch: a bad value must never send the mutation first and
		// report the failure afterwards.
		if method != http.MethodGet {
			if err := validateAPIWaitFlags(noWait, waitTimeout, cmd.Flags().Changed("wait-timeout")); err != nil {
				return err
			}
		}

		format, err := resolveFormat()
		if err != nil {
			return err
		}
		rawPath, targetID := args[0], args[1]

		params, err := parseDataParams(dataPairs)
		if err != nil {
			return err
		}

		rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
		if err != nil {
			return err
		}

		client, err := resolveRoutedClient(cmd, targetID)
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		// Locking: see this function's own doc comment and the vault
		// task's "Locking design" section. A matched path always locks
		// (lock.Read for GET, lock.Mutation for post/put/delete — never
		// idempotent.Run: see that section's own reasoning, restated on
		// RawRequest/RoutedClient.RawRequest) with no opt-out. An
		// UNMATCHED path is where GET and the mutating verbs diverge: GET
		// always proceeds (nothing to lock, nothing to opt out of —
		// see this function's own doc comment); post/put/delete still
		// refuse unless --unsafe-no-lock is given, printing a stderr
		// warning naming exactly what it bypasses when it is.
		key, locked := apiObjectKey(targetID, rawPath)
		if locked {
			var unlock func() error
			if method == http.MethodGet {
				unlock, err = lock.Read(cmd.Context(), rosterPath, key)
			} else {
				unlock, err = lock.Mutation(cmd.Context(), rosterPath, key)
			}
			if err != nil {
				return fmt.Errorf("acquire lock for %s: %w", key, err)
			}
			defer func() { _ = unlock() }()
		} else if method != http.MethodGet {
			if !unsafeNoLock {
				return fmt.Errorf("path %q does not match a known pveforge-managed object type (vm/node/storage/network); pass --unsafe-no-lock to proceed without internal/lock protection", rawPath)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: path %q does not match a known pveforge-managed object type — proceeding WITHOUT internal/lock protection (--unsafe-no-lock); concurrent pveforge mutations against this target/path are not serialized\n", rawPath)
		}

		result, err := client.RawRequest(cmd.Context(), method, rawPath, params)
		if err != nil {
			return err
		}
		if upid, ok := responseUPID(method, result); ok {
			// stderr, at dispatch: the caller has the task id even while the
			// wait below blocks, and even if the wait then fails.
			fmt.Fprintf(cmd.ErrOrStderr(), "dispatched PVE task %s\n", kvjson.QuoteValue(upid))
			if noWait {
				if locked {
					fmt.Fprintf(cmd.ErrOrStderr(), "notice: --no-wait: not waiting for task %s; the lock on %s is released now, before the task finishes, so a concurrent pveforge mutation of the same object is no longer serialized against it\n", kvjson.QuoteValue(upid), key)
				} else {
					fmt.Fprintf(cmd.ErrOrStderr(), "notice: --no-wait: not waiting for task %s; its outcome is not checked\n", kvjson.QuoteValue(upid))
				}
			} else if err := waitForAPITask(cmd.Context(), client, rawPath, upid, waitTimeout); err != nil {
				return err
			}
		}
		return renderAPIResult(cmd.OutOrStdout(), format, result)
	}

	// GET is always safe (read-only, full stop). post/put/delete are ALL
	// marked destructive, not split mutating-vs-destructive by verb —
	// deliberately, and not merely to match delete's own "unbounded blast
	// radius" (mutation.go's own term): this command has ZERO per-endpoint
	// semantic awareness of what any given post/put actually does — that
	// unawareness is the entire premise of a raw escape hatch. Matching a
	// path (apiObjectKey) only tells us WHICH object to lock, never WHAT
	// operation is being performed or whether it's reversible, and that's
	// exactly as true for a MATCHED path as an unmatched one. Concrete
	// case that makes this non-hypothetical (adversarial review,
	// 2026-09-14): POST /nodes/{node}/qemu/{vmid}/snapshot/{snap}/rollback
	// matches the vm pattern and locks correctly, but is a real,
	// irreversible operation that discards VM state — indistinguishable,
	// from this command's point of view, from a routine snapshot create.
	// A matched-path exemption from "destructive" would be tracking lock
	// coverage, not actual risk; verb alone is the only honest, always-
	// conservative signal available here.
	switch method {
	case http.MethodGet:
		markSafe(cmd)
	default:
		markDestructive(cmd)
	}
	return cmd
}

// parseDataParams parses --data's repeated "field=value" strings into
// url.Values, reusing kvjson.ParseKVArgs (the same field=value grammar
// `vm set`'s positional arguments already use) rather than a second,
// independently-maintained parser.
func parseDataParams(dataPairs []string) (url.Values, error) {
	pairs, err := kvjson.ParseKVArgs(dataPairs)
	if err != nil {
		return nil, fmt.Errorf("parse --data: %w", err)
	}
	params := url.Values{}
	for _, p := range pairs {
		params.Add(p.Field, p.Value)
	}
	return params, nil
}

// apiLockWaitNote ends --lock-wait's help on the api verbs: a path that
// maps to a pveforge object key (apiObjectKey) is always locked, and
// --unsafe-no-lock does not change that; on any other path no lock is taken,
// so the flag has nothing to bound — and there post/put/delete are refused
// unless --unsafe-no-lock is given (newAPIVerbCmd).
const apiLockWaitNote = ". A path that names a pveforge-managed object is always locked, with or without --unsafe-no-lock. On any other path no lock is taken and this flag has no effect; there, post, put and delete are refused unless --unsafe-no-lock is given"

// apiLong is `api get`'s help body; apiMutationLong is post/put/delete's.
const apiLong = `Raw PVE REST passthrough for a path with no dedicated pveforge command yet.

Output: -o json prints PVE's "data" payload as-is. -o kv prints a JSON
object's top-level fields as key=value lines, and any other payload (a
string, a number, null, a list) as ONE line, data=<value>, keyed by PVE's
own envelope name. A key or string value that could be misread (a control
character or line break, leading/trailing space, a leading '"', a key with
'=', or a value that is the string "null") is written as one JSON string
starting with '"'; everything else is written as-is. kv does not preserve
JSON types: use -o json for exact data.`

var apiMutationLong = apiLong + fmt.Sprintf(`

Tasks: when PVE answers with a task id (a UPID — a bare string starting
"UPID:"), this command WAITS for the task and reports its outcome: exit 0
only if the task ends with exit status OK, or with "WARNINGS: <n>", which PVE
also counts as success (a stderr notice then says so; not yet verified on a
live host). The UPID is printed to stderr as
soon as the task is dispatched; stdout is printed only after the task
succeeds. The wait can take up to %[1]s (lower it with --wait-timeout), and
the object lock is held for the whole wait. --lock-wait bounds only
acquiring that lock; --wait-timeout bounds the task wait done while holding
it.

A wait that times out (--wait-timeout, or the %[1]s ceiling) reports an
outcome-unknown error: the task MAY STILL BE RUNNING on PVE. Ctrl-C (SIGINT)
or SIGTERM stops the wait and reports it the same way, exiting 130 or 143;
a second Ctrl-C ends pveforge at once, without a report. Either way, follow
it up with the UPID printed at dispatch:
  pveforge api get /nodes/<node>/tasks/<upid>/status <target-id>

--no-wait prints the UPID and exits without checking the task. On a path
pveforge locks, that releases the lock before the task finishes.

A task id nested inside an object (rather than returned as the bare
payload) is not recognized and is not waited on.`, pve.TaskWaitCeiling)

// validateAPIWaitFlags rejects wait-flag combinations that have no honest
// meaning, before anything is dispatched. timeoutSet is whether
// --wait-timeout was given explicitly, so "--no-wait --wait-timeout 0" is
// rejected too.
func validateAPIWaitFlags(noWait bool, waitTimeout time.Duration, timeoutSet bool) error {
	if waitTimeout < 0 {
		return fmt.Errorf("--wait-timeout must not be negative, got %s", waitTimeout)
	}
	if waitTimeout > pve.TaskWaitCeiling {
		return fmt.Errorf("--wait-timeout %s exceeds the %s ceiling on waiting for a PVE task", waitTimeout, pve.TaskWaitCeiling)
	}
	if noWait && timeoutSet {
		return errors.New("--no-wait and --wait-timeout are mutually exclusive")
	}
	return nil
}

// responseUPID reports whether a mutating verb's decoded response is a PVE
// task id: a bare JSON string with the "UPID:" prefix. GET is never a task.
// A string that claims the prefix but is malformed is still returned here —
// the wait refuses it loudly rather than this silently skipping it.
//
// NOT LIVE-VERIFIED, three ways, none checkable without a real PVE host:
// which post/put/delete endpoints actually answer with a bare UPID scalar
// is taken from PVE's documented convention, not observed, so an endpoint
// that returns a task id in some other shape keeps the old unwaited
// behaviour; the 10-minute ceiling has never been observed against a real
// long task (a large clone, a storage migration); and for a path addressing
// a node other than the target's own, which PVE proxies, whether the UPID's
// node field carries the addressed node or the proxying one is unverified —
// if it is the proxying node, the path-node check in waitForAPITask refuses
// a legitimate cross-node task as outcome-unknown, failing closed.
func responseUPID(method string, result json.RawMessage) (string, bool) {
	if method == http.MethodGet {
		return "", false
	}
	var s string
	if err := json.Unmarshal(result, &s); err != nil || !strings.HasPrefix(s, "UPID:") {
		return "", false
	}
	return s, true
}

// waitForAPITask waits on a task an `api` verb dispatched. The node is the
// raw path's own /nodes/{node} segment, so WaitForTask's check that the UPID
// names that node is a real check. Only a path with no node segment
// (/storage/{name}, or an unmatched path taken with --unsafe-no-lock) falls
// back to the UPID's own node, and there that check is tautological: on
// those paths the wait's value is the task's exit status alone. Never
// client.Node() — see apiPathNode.
func waitForAPITask(ctx context.Context, client *pve.RoutedClient, rawPath, upid string, waitTimeout time.Duration) error {
	node, ok := apiPathNode(rawPath)
	if !ok {
		// A malformed UPID yields "" here, and WaitForTask then refuses it
		// on its own shape check — as outcome-unknown, exactly as it does
		// on a path that carries a node.
		node, _ = pve.UPIDNode(upid)
	}
	// The wait takes its own context parameter, never re-bound, so lockguard can
	// see it is given the command's context (or one derived from it), which
	// carries the task-warnings reporter.
	wait := func(waitCtx context.Context) error { return client.WaitForTask(waitCtx, node, upid) }
	if waitTimeout <= 0 {
		return wait(ctx)
	}
	wctx, cancel := context.WithTimeout(ctx, waitTimeout)
	defer cancel()
	return wait(wctx)
}

// renderAPIResult renders an `api` response. kvjson.Render's kv mode is
// object-only by contract, so — as storage.go's orphan listing does — a
// non-object payload is wrapped under one field before it is rendered:
// data=<value>, PVE's own envelope key. One rule for every non-object (a
// UPID, any other string, a number, null, a list), so a script never has to
// know in advance which shape an endpoint returns. JSON mode is unchanged.
// result is never empty: RawRequest normalizes an empty body to null.
func renderAPIResult(w io.Writer, f kvjson.Format, result json.RawMessage) error {
	if f == kvjson.KV && !isJSONObject(result) {
		return kvjson.Render(w, f, map[string]json.RawMessage{"data": result})
	}
	return kvjson.Render(w, f, result)
}

// isJSONObject reports whether raw is a JSON object (not null, which
// encoding/json would happily unmarshal into a nil map).
func isJSONObject(raw json.RawMessage) bool {
	var m map[string]json.RawMessage
	return json.Unmarshal(raw, &m) == nil && m != nil
}
