package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// lockWaitUsage is --lock-wait's help text, built from the constants it
// states so it cannot drift from them.
var lockWaitUsage = fmt.Sprintf("how long to wait for another pveforge process's lock on this object before giving up (0 = the %s default; at most %s). The default exceeds the %s ceiling on waiting for a PVE task because a legitimate lock holder may be in such a wait the whole time",
	lock.DefaultWait, lock.MaxWait, pve.TaskWaitCeiling)

// addLockWaitFlag registers --lock-wait on a command that takes an
// internal/lock lock (and only on one: on any other command it would be
// accepted and mean nothing — TestLockingCommandsHaveLockWaitFlag pins
// both directions). Its PreRunE validates the value before anything else
// runs (the roster, the client, the lock), then carries it to every lock
// the command takes through cmd's context (lock.WithWait). The bound covers
// acquiring the lock only, never the work done while holding it.
func addLockWaitFlag(cmd *cobra.Command) {
	var wait time.Duration
	cmd.Flags().DurationVar(&wait, "lock-wait", 0, lockWaitUsage)
	prev := cmd.PreRunE
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if err := validateLockWait(wait); err != nil {
			return err
		}
		cmd.SetContext(lock.WithWait(cmd.Context(), wait))
		if prev != nil {
			return prev(cmd, args)
		}
		return nil
	}
}

// validateLockWait rejects a --lock-wait with no honest meaning, the way
// validateAPIWaitFlags does for --wait-timeout. 0 means lock.DefaultWait.
func validateLockWait(wait time.Duration) error {
	if wait < 0 {
		return fmt.Errorf("--lock-wait must not be negative, got %s", wait)
	}
	if wait > lock.MaxWait {
		return fmt.Errorf("--lock-wait %s exceeds the %s maximum", wait, lock.MaxWait)
	}
	return nil
}
