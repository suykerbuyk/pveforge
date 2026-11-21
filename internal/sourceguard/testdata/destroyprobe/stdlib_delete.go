package probe

import (
	"slices"
	s "slices"
	"sync"
)

// CONTROL: a stdlib slices.Delete (also under an alias) is not a go-proxmox
// delete and must not be a violation. The walker DOES report it (*.Delete
// matches any selector); the guard drops it by resolving the qualifier
// through this file's imports. sync.Map.Delete cannot be resolved that way
// and is deliberately NOT here: it would need a reviewed row.
func stdlibDelete(xs []int) []int {
	var m sync.Map
	_ = m
	xs = slices.Delete(xs, 0, 1)
	return s.Delete(xs, 0, 1)
}
