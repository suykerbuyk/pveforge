package pve

import (
	"strconv"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/sourceguard"
)

// looksLikeTaskPath: a token that could be part of a task URL path. A token
// with a slash, or the bare segment "tasks" that a split or path.Join form
// leaves behind. Identifiers cannot contain a slash and are not "tasks", so
// errNoTaskStatus — which FindForbidden's substring match does hit — is out.
func looksLikeTaskPath(tok string) bool {
	return strings.Contains(tok, "/") || tok == "tasks"
}

// isTaskCollectionPath: the task LIST path specifically, not a per-task read.
// After any query string is stripped, a collection path ENDS at tasks;
// /nodes/%s/tasks/%s/status does not.
func isTaskCollectionPath(tok string) bool {
	p, _, _ := strings.Cut(tok, "?")
	return strings.HasSuffix(p, "/tasks") || p == "tasks"
}

// R1.3, narrowed — see the invariant's own "what this owns" sentence in the
// plan. The only functions reachable from *Client's exported API that hold a
// task-path token are the two this unit ships with one: TaskList (the
// collection) and CaptureTaskExitStatus (one task's status).
//
// It extends sourceguard.ReachableTokens/FindForbidden rather than walking
// literals by hand: ReachableTokens records string-literal CONTENTS
// (sourceguard.go:65-68, :158-163, and scanValues at :200-203) and
// FindForbidden matches them by case-insensitive SUBSTRING (:218-231).
func TestTaskList_IsThePackagesOnlyTaskPathHolder(t *testing.T) {
	methods, err := sourceguard.ExportedMethods(".", "Client")
	if err != nil {
		t.Fatalf("ExportedMethods: %v", err)
	}
	roots := make([]string, 0, len(methods))
	for _, m := range methods {
		roots = append(roots, "Client."+m)
	}
	tokens, err := sourceguard.ReachableTokens(".", roots)
	if err != nil {
		t.Fatalf("ReachableTokens: %v", err)
	}

	// Stage 1 is sourceguard's own matcher; stage 2 drops the identifier hits
	// its substring match also returns.
	type hit struct{ fn, tok string }
	var hits []hit
	for _, h := range sourceguard.FindForbidden(tokens, []string{"tasks"}) {
		fn, rest, _ := strings.Cut(h, ": ")
		tok, _, _ := strings.Cut(strings.TrimPrefix(rest, `"`), `"`)
		if looksLikeTaskPath(tok) {
			hits = append(hits, hit{fn, tok})
		}
	}

	// The allow-list names the functions THIS UNIT ships holding a task path.
	// FindTaskUPID is not here and must not be: after step 4 it is a wrapper
	// over TaskList and holds no path literal of its own.
	allowed := map[string]bool{
		"Client.TaskList":              true,
		"Client.CaptureTaskExitStatus": true,
	}

	// Anti-vacuity, and it is about the READER, not about any token that
	// happens to contain "tasks". FindForbidden is a substring match, so
	// CaptureTaskExitStatus's /nodes/%s/tasks/%s/status matches the needle
	// too; a clause satisfied by that, or by a TaskList that had drifted onto
	// a per-task path, would prove nothing about the collection reader this
	// guard exists to watch. So: a COLLECTION-shaped token, attributed to
	// Client.TaskList specifically.
	if len(roots) < 20 {
		t.Fatalf("only %d exported Client methods as roots: the walk is not seeing the package", len(roots))
	}
	var sawCollection bool
	for _, h := range hits {
		if h.fn == "Client.TaskList" && isTaskCollectionPath(h.tok) {
			sawCollection = true
		}
	}
	if !sawCollection {
		var got []string
		for _, h := range hits {
			got = append(got, h.fn+": "+strconv.Quote(h.tok))
		}
		t.Fatalf("no task-COLLECTION path attributed to Client.TaskList: the walk is not seeing the reader it guards (hits=%v)", got)
	}

	var bad []string
	for _, h := range hits {
		if !allowed[h.fn] {
			bad = append(bad, h.fn+": "+strconv.Quote(h.tok))
		}
	}
	if len(bad) != 0 {
		t.Errorf("task-path tokens outside the allow-list: %v", bad)
	}
}
