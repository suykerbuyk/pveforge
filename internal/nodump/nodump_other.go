//go:build !linux

// Package nodump clears a process's dumpable flag before it holds a
// decrypted secret. Only Linux has PR_SET_DUMPABLE; elsewhere Set does
// nothing.
package nodump

// Set does nothing: this platform has no PR_SET_DUMPABLE.
func Set() error { return nil }
