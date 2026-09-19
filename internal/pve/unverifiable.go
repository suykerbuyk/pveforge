package pve

import "errors"

// ErrUnverifiableRead marks a read whose answer cannot be trusted: PVE
// answered with a nil error but a payload no healthy response carries — a
// null list, an object missing its identity field, or a snapshot list
// without the "current" pseudo-entry. It is deliberately NOT a not-found:
// an unverifiable read says nothing about whether the object exists.
// Every guard wraps it with %w and names the object it was reading, so
// callers match it with errors.Is.
var ErrUnverifiableRead = errors.New("unverifiable read")
