//go:build never

package evasion

import u "unsafe"

var _ = u.Sizeof(0)

//go:linkname pushed
func pushed() {}
