package main

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
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
func newAPIVerbCmd(method, use string) *cobra.Command {
	var dataPairs []string
	var unsafeNoLock bool

	cmd := &cobra.Command{
		Use:   use + " <path> <target-id>",
		Short: fmt.Sprintf("Raw PVE REST %s against <path>", method),
		Args:  cobra.ExactArgs(2),
	}
	addRosterFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().StringArrayVar(&dataPairs, "data", nil, "a key=value request parameter (repeatable)")
	cmd.Flags().BoolVar(&unsafeNoLock, "unsafe-no-lock", false, "proceed without internal/lock protection when <path> doesn't match a known pveforge-managed object type")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
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
		if key, ok := apiObjectKey(targetID, rawPath); ok {
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
		return kvjson.Render(cmd.OutOrStdout(), format, result)
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
