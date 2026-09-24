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

// nullEntry returns the index of the first nil element of list, or -1. A
// list endpoint answering [null] (or a null among real entries) decodes to
// a nil pointer in go-proxmox's []*T lists; every reader that loops over
// one refuses it as an unverifiable read before touching an element, where
// it used to nil-dereference.
func nullEntry[T any](list []*T) int {
	for i, e := range list {
		if e == nil {
			return i
		}
	}
	return -1
}
