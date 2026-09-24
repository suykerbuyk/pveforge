package main

import (
	"fmt"
	"io"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
)

// warnNotReread prints Run's advisory Result.AfterErr, when set, as one
// stderr line: the write was applied, but its result could not be re-read,
// so nothing the command printed about the result was re-observed.
// (pveforge-run-post-apply-read-error-signal)
//
// It never fails the command: the mutation already happened, and failing it
// would push a caller into a needless retry. The cause is rendered exactly
// as runRoot renders an error's text, bounded (boundErrText) then quoted
// (kvjson.QuoteValue), because it can carry server text (a 5xx body) that
// must neither forge a second line nor run unbounded; any redaction lives in
// the error text itself, before this, as it does for runRoot. The object's
// id is quoted only when it needs to be, so a well-formed id prints bare, as
// the command's own stdout line prints it; the target id is printed bare,
// because the roster refuses any id that would need quoting
// (roster.ValidateTargetID).
//
// Each command calls it right after its own stdout line and before any
// other stderr line it prints.
func warnNotReread(w io.Writer, target, kind, id string, afterErr error) {
	if afterErr == nil {
		return
	}
	fmt.Fprintf(w, "warning: %s: %s %s: the write was applied but its result could not be re-read: %s\n",
		target, kind, kvjson.QuoteValue(id), kvjson.QuoteValue(boundErrText(afterErr.Error())))
}
