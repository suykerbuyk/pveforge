package fixture

// helperOnlyInTestFile is CALLED by Root in root.go, but defined here in a
// _test.go file. That is what makes the parser's _test.go filter
// observable: with the filter working, this declaration is never indexed,
// so Root's call to it resolves to nothing and its token never reaches the
// scan; with the filter removed, the call resolves and "plantedInATestFile"
// shows up. An assertion that this token is ABSENT is only meaningful
// because the call exists.
//
// This fixture package is never compiled — testdata/ is invisible to the go
// tool's build — so a cross-file call from non-test to test code, which
// would not build in a real package, is fine as parser input here.
func helperOnlyInTestFile() string { return "plantedInATestFile" }
