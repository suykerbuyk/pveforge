package fixture

// Root's own doc comment mentions status/stop and forceStop at length,
// exactly as the real guarded functions' comments do. None of it may ever
// reach the scan: comments are not part of a function body's AST.
func Root() string {
	// An inline comment naming StopVM and skiplock, likewise ignored.
	docs := "https://example.invalid/api" + "plantedAfterSlashes"
	_ = docs
	_ = indirectHook
	_ = tableOfHooks
	return helperInSiblingFile() + Root2() + helperOnlyInTestFile()
}

func Root2() string { return "second-root-token" }

// Unreachable is never called from Root and must not be scanned — its
// token would otherwise make every guard fire on unrelated package code.
func Unreachable() string { return "status/stop" }

// indirectHook is a package-level var bound to a FUNCTION VALUE. Nothing
// calls IndirectlyReached by name, so a scan that only follows FuncDecl call
// sites never reaches it — the shape a review used to smuggle a hard stop
// past the guard.
var indirectHook = IndirectlyReached

// tableOfHooks is the same shape one level deeper: a composite literal of
// function values plus a plain string.
var tableOfHooks = []func() string{IndirectlyReached}

var aPlainValue = "planted-in-a-package-level-var"

// IndirectlyReached is referenced only as a value, never called by name.
func IndirectlyReached() string { return "planted-in-IndirectlyReached" + aPlainValue }
