package sourceguard

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fixtureRoot is the tree under testdata/nontestrefs. Every assertion below
// names the way of getting the walk wrong that it exists to catch, because
// this package's standing lesson is that an assertion nobody has watched fail
// has not been shown to work.
const fixtureRoot = "testdata/nontestrefs"

var (
	httpClient = Target{ImportPath: "net/http", Name: "Client"}
	anyDo      = Target{AnyQualifier: true, Name: "Do"}
	bareClient = Target{Name: "Client"}
)

// refStrings renders every ref, sorted, for a table-free comparison that
// shows the whole picture when it fails.
func refStrings(t *testing.T, res Result) []string {
	t.Helper()
	var out []string
	for _, refs := range res.Refs {
		for _, r := range refs {
			mark := " "
			if r.Allowed {
				mark = "A"
			}
			out = append(out, mark+" "+r.String())
		}
	}
	sort.Strings(out)
	return out
}

// TestNonTestReferences_QualifiedMatchingIsAliasProof is mutant W6: resolving
// a qualified target by the qualifier's text instead of through the file's
// imports makes `import nethttp "net/http"` a one-line evasion.
func TestNonTestReferences_QualifiedMatchingIsAliasProof(t *testing.T) {
	res, err := NonTestReferences(Scope{Root: fixtureRoot}, []Target{httpClient})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	got := refStrings(t, res)
	if !contains(got, "aliased.go:8: nethttp.Client") {
		t.Errorf("the aliased import was not resolved to net/http; got:\n%s", strings.Join(got, "\n"))
	}
	if !contains(got, "a.go:") {
		t.Errorf("the unaliased import was not matched; got:\n%s", strings.Join(got, "\n"))
	}
}

// TestNonTestReferences_BareNameDoesNotMatchASelectorsSel is mutant W5, and
// it is the reason Target has three forms rather than one. In the real module
// net/http.Client is 2 hits and a bare "Client" is 86.
func TestNonTestReferences_BareNameDoesNotMatchASelectorsSel(t *testing.T) {
	res, err := NonTestReferences(Scope{Root: fixtureRoot}, []Target{bareClient})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}

	// The whole answer, pinned. A partial assertion would not catch this:
	// the Ident branch reports an EMPTY qualifier whether or not it wrongly
	// descended into a selector's Sel, so "no ref has a qualifier" passes
	// even when the bug is present. Only the exact site list distinguishes
	// them — a.go's four genuine bare identifiers (the declaration, the
	// return type, the composite literal, the receiver) and nothing else.
	// a.go:13 and :19 also hold `http.Client`, whose Sel must NOT appear;
	// aliased.go, sub/b.go and allowed/c.go contain ONLY qualified
	// references, so any hit there is the bug.
	want := []string{"a.go:12", "a.go:18", "a.go:19", "a.go:26"}
	var got []string
	for _, refs := range res.Refs {
		for _, r := range refs {
			got = append(got, fmt.Sprintf("%s:%d", r.File, r.Line))
		}
	}
	sort.Strings(got)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("bare target %q matched\n  %v\nwant exactly\n  %v\n(a bare name must not match a selector's Sel)", bareClient, got, want)
	}
}

// TestNonTestReferences_SkipsNestedTestdataAndTestFiles is mutant W2, the
// defect this whole property exists for: the KDF unit's weakprobe is a
// non-test file under testdata that calls the setter its own guard forbids.
func TestNonTestReferences_SkipsNestedTestdataAndTestFiles(t *testing.T) {
	res, err := NonTestReferences(Scope{Root: fixtureRoot}, []Target{httpClient})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	if res.Reached("testdata/hidden.go") {
		t.Errorf("walked a nested testdata directory; Parsed = %v", res.Parsed)
	}
	if res.Reached("d_test.go") {
		t.Errorf("walked a _test.go file; Parsed = %v", res.Parsed)
	}
	if !res.Reached("sub/b.go") {
		t.Errorf("did not recurse into sub/; Parsed = %v", res.Parsed)
	}
	if !res.Reached("allowed/c.go") {
		t.Errorf("did not recurse into allowed/; Parsed = %v", res.Parsed)
	}
	want := []string{"a.go", "aliased.go", "allowed/c.go", "sub/b.go"}
	if len(res.Parsed) != len(want) {
		t.Fatalf("Parsed = %v, want exactly %v", res.Parsed, want)
	}
	for i := range want {
		if res.Parsed[i] != want[i] {
			t.Fatalf("Parsed = %v, want exactly %v", res.Parsed, want)
		}
	}
}

// TestNonTestReferences_RootNamedTestdataIsStillWalked is mutant W4. The skip
// must not apply to the walk root, or this package could never point the
// walker at its own fixtures.
func TestNonTestReferences_RootNamedTestdataIsStillWalked(t *testing.T) {
	res, err := NonTestReferences(Scope{Root: "testdata"}, []Target{httpClient})
	if err != nil {
		t.Fatalf("NonTestReferences with a testdata root: %v", err)
	}
	if !res.Reached("nontestrefs/a.go") {
		t.Errorf("a root named testdata was skipped; Parsed = %v", res.Parsed)
	}
	// The nested one below it is still skipped, so both halves of the rule
	// are proven by the same call.
	if res.Reached("nontestrefs/testdata/hidden.go") {
		t.Errorf("a NESTED testdata directory was walked; Parsed = %v", res.Parsed)
	}
}

// TestNonTestReferences_AllowMarksRatherThanDrops is mutant W3. If an
// allow-list dropped its hits, a caller would need a second call to prove its
// predicate still matches what it permits, and that second call is what an
// implementor forgets.
func TestNonTestReferences_AllowMarksRatherThanDrops(t *testing.T) {
	res, err := NonTestReferences(Scope{
		Root:       fixtureRoot,
		AllowDirs:  []string{"allowed"},
		AllowFiles: []string{"aliased.go"},
	}, []Target{httpClient})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	if got := res.Allowed("allowed/c.go", httpClient); len(got) == 0 {
		t.Errorf("the AllowDir hit was dropped rather than marked; Refs = %v", refStrings(t, res))
	}
	if got := res.Allowed("aliased.go", httpClient); len(got) == 0 {
		t.Errorf("the AllowFile hit was dropped rather than marked; Refs = %v", refStrings(t, res))
	}
	for _, v := range res.Violations() {
		if strings.HasPrefix(v.File, "allowed/") || v.File == "aliased.go" {
			t.Errorf("allowed ref reported as a violation: %s", v)
		}
	}
	// Violations must still contain the unpermitted files, or "no
	// violations" would be meaningless.
	var files []string
	for _, v := range res.Violations() {
		files = append(files, v.File)
	}
	if !contains(files, "a.go") || !contains(files, "sub/b.go") {
		t.Errorf("Violations lost the unpermitted hits; got %v", files)
	}
}

// TestNonTestReferences_AllowListIsPathExact keeps AllowFiles from silently
// behaving as a directory prefix, which would re-open a whole package to the
// thing being guarded against. This is the guard-side of mutant S6.
func TestNonTestReferences_AllowListIsPathExact(t *testing.T) {
	res, err := NonTestReferences(Scope{
		Root:       fixtureRoot,
		AllowFiles: []string{"sub/b.go"},
	}, []Target{httpClient})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	for _, v := range res.Violations() {
		if v.File == "sub/b.go" {
			t.Errorf("the named AllowFile was not honoured: %s", v)
		}
	}
	if len(res.Allowed("sub/b.go", httpClient)) == 0 {
		t.Fatal("AllowFile sub/b.go marked nothing; the assertion above is vacuous")
	}
	var sawSibling bool
	for _, v := range res.Violations() {
		if v.File == "a.go" {
			sawSibling = true
		}
	}
	if !sawSibling {
		t.Error("allowing sub/b.go also allowed files outside it; AllowFiles must be path-exact")
	}
}

// TestNonTestReferences_AnyQualifierReachesAMethodCall covers the form the
// transport guard needs for a call through a field, where the receiver's type
// is not knowable from the AST.
func TestNonTestReferences_AnyQualifierReachesAMethodCall(t *testing.T) {
	res, err := NonTestReferences(Scope{Root: fixtureRoot}, []Target{anyDo})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	refs := res.Refs["a.go"]
	if len(refs) != 1 {
		t.Fatalf("want exactly one *.Do hit in a.go, got %d: %s", len(refs), strings.Join(refStrings(t, res), "\n"))
	}
	// c.Doer.Do's X is itself a selector, not an identifier, so there is no
	// package qualifier to report — which is precisely the case ImportPath
	// cannot express and AnyQualifier exists for.
	if refs[0].Qualifier != "" {
		t.Errorf("Qualifier = %q, want empty: X is a field selector, not a package identifier", refs[0].Qualifier)
	}
	if refs[0].Line != 27 {
		t.Errorf("Line = %d, want 27 (the c.Doer.Do call in a.go)", refs[0].Line)
	}
}

// TestNonTestReferences_EachReferenceIsReportedOnce guards against the
// double-count that ast.Inspect invites: it visits a SelectorExpr and then
// the Sel identifier inside it.
func TestNonTestReferences_EachReferenceIsReportedOnce(t *testing.T) {
	res, err := NonTestReferences(Scope{Root: fixtureRoot}, []Target{httpClient})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	seen := map[string]int{}
	for _, refs := range res.Refs {
		for _, r := range refs {
			seen[r.String()]++
		}
	}
	for k, n := range seen {
		if n != 1 {
			t.Errorf("reference reported %d times, want 1: %s", n, k)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no references at all; the assertion above is vacuous")
	}
}

// TestNonTestReferences_ErrorsRatherThanFindingNothing is the package's own
// rule applied to every input that could make this guard pass by accident.
// Mutants W7 (skip an unparseable file) and W8 (accept a bogus AllowFile)
// both live here.
func TestNonTestReferences_ErrorsRatherThanFindingNothing(t *testing.T) {
	// A deliberately unparseable non-test file, built at run time rather
	// than committed, so `gofmt -l cmd internal` has nothing to complain
	// about.
	broken := t.TempDir()
	if err := os.WriteFile(filepath.Join(broken, "broken.go"), []byte("package x\n\nfunc ("), 0o600); err != nil {
		t.Fatal(err)
	}
	emptyDir := t.TempDir()

	cases := []struct {
		name    string
		scope   Scope
		targets []Target
		want    string
	}{
		{"empty root", Scope{}, []Target{httpClient}, "empty Root"},
		{"root is a file", Scope{Root: fixtureRoot + "/a.go"}, []Target{httpClient}, "not a directory"},
		{"root does not exist", Scope{Root: fixtureRoot + "/nope"}, []Target{httpClient}, "stat Root"},
		{"no targets", Scope{Root: fixtureRoot}, nil, "no targets"},
		{"target with no name", Scope{Root: fixtureRoot}, []Target{{ImportPath: "net/http"}}, "empty Name"},
		{"target with both forms", Scope{Root: fixtureRoot}, []Target{{ImportPath: "net/http", AnyQualifier: true, Name: "Client"}}, "both ImportPath and AnyQualifier"},
		{"unparseable file", Scope{Root: broken}, []Target{httpClient}, "parse broken.go"},
		{"no files parsed", Scope{Root: emptyDir}, []Target{httpClient}, "parsed no non-test"},
		{"bogus AllowFile", Scope{Root: fixtureRoot, AllowFiles: []string{"nope.go"}}, []Target{httpClient}, "AllowFile"},
		{"AllowFile naming a directory", Scope{Root: fixtureRoot, AllowFiles: []string{"sub"}}, []Target{httpClient}, "AllowFile"},
		{"bogus AllowDir", Scope{Root: fixtureRoot, AllowDirs: []string{"nope"}}, []Target{httpClient}, "AllowDir"},
		{"AllowDir naming a file", Scope{Root: fixtureRoot, AllowDirs: []string{"a.go"}}, []Target{httpClient}, "AllowDir"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NonTestReferences(tc.scope, tc.targets)
			if err == nil {
				t.Fatalf("want an error mentioning %q, got nil — this input makes the guard find nothing silently", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestNonTestReferences_UnresolvableQualifierIsAnError covers the case that
// would otherwise be a silent miss: a package whose name is not its directory
// (github.com/suykerbuyk/go-proxmox is package proxmox), imported without an
// alias. Parsing alone cannot learn the name, so guessing would fail to match
// and the guard would pass while the reference sat there.
func TestNonTestReferences_UnresolvableQualifierIsAnError(t *testing.T) {
	dir := t.TempDir()
	src := "package x\n\nimport \"example.com/go-thing\"\n\nvar _ = gothing.Client{}\n"
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NonTestReferences(Scope{Root: dir}, []Target{{ImportPath: "example.com/go-thing", Name: "Client"}})
	if err == nil {
		t.Fatal("want an error: the qualifier for an unaliased go-thing import cannot be resolved by parsing")
	}
	if !strings.Contains(err.Error(), "explicit alias") {
		t.Fatalf("error %q does not say what to do about it", err)
	}
	// An import path the targets do NOT care about must not trip this,
	// or every unaliased hyphenated import in the module becomes an error.
	_, err = NonTestReferences(Scope{Root: dir}, []Target{{ImportPath: "net/http", Name: "Client"}})
	if err != nil {
		t.Fatalf("an unresolvable import nothing targets must be ignored, got: %v", err)
	}
}

// TestNonTestReferences_DotImportOfAGuardedPathIsAnError closes the same
// hole TestNonTestReferences_QualifiedMatchingIsAliasProof closes from the
// other side. A dot-import strips the qualifier entirely, so `Client{}` would
// sail past an ImportPath target; refusing it loudly is the only honest
// answer, since the walker cannot know which bare identifiers came from
// which dot-imported package.
func TestNonTestReferences_DotImportOfAGuardedPathIsAnError(t *testing.T) {
	dir := t.TempDir()
	src := "package x\n\nimport . \"net/http\"\n\nvar _ = Client{}\n"
	if err := os.WriteFile(filepath.Join(dir, "dot.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NonTestReferences(Scope{Root: dir}, []Target{httpClient})
	if err == nil {
		t.Fatal("want an error: a dot-imported net/http makes Client unqualified and invisible to the guard")
	}
	if !strings.Contains(err.Error(), "dot-imports") {
		t.Fatalf("error %q does not name the problem", err)
	}

	// A dot-import of something no target cares about is not this guard's
	// business, and a BLANK import binds no identifier at all — neither may
	// be turned into an error, or half the module becomes unwalkable.
	other := t.TempDir()
	src = "package x\n\nimport (\n\t. \"errors\"\n\t_ \"net/http\"\n\t\"net/url\"\n)\n\nvar _ = New(\"x\")\nvar _ = url.URL{}\n"
	if err := os.WriteFile(filepath.Join(other, "ok.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := NonTestReferences(Scope{Root: other}, []Target{httpClient})
	if err != nil {
		t.Fatalf("an unrelated dot-import and a blank import must both be fine, got: %v", err)
	}
	if len(res.Violations()) != 0 {
		t.Errorf("a blank import of net/http is not a reference to net/http.Client: %v", res.Violations())
	}
}

// TestNonTestReferences_ViolationsIsSortedAndStable keeps the failure message
// a diffable list rather than map-iteration noise.
func TestNonTestReferences_ViolationsIsSortedAndStable(t *testing.T) {
	res, err := NonTestReferences(Scope{Root: fixtureRoot}, []Target{httpClient, anyDo, bareClient})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	v := res.Violations()
	if len(v) < 2 {
		t.Fatalf("want several violations to sort, got %d", len(v))
	}
	for i := 1; i < len(v); i++ {
		if v[i-1].File > v[i].File || (v[i-1].File == v[i].File && v[i-1].Line > v[i].Line) {
			t.Fatalf("Violations not sorted at %d: %s then %s", i, v[i-1], v[i])
		}
	}
}

// TestNonTestReferences_ReachedNeedsTheExactPath keeps Reached from being a
// prefix match, which would let a shrunken walk look complete.
func TestNonTestReferences_ReachedNeedsTheExactPath(t *testing.T) {
	res, err := NonTestReferences(Scope{Root: fixtureRoot}, []Target{httpClient})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	if !res.Reached("sub/b.go") {
		t.Fatal("Reached missed a file that was parsed")
	}
	for _, bad := range []string{"sub/", "sub/b", "b.go", "", "sub/b.go.x"} {
		if res.Reached(bad) {
			t.Errorf("Reached(%q) is true; it must be an exact match", bad)
		}
	}
}

// TestTargetString pins the rendering the guards' failure messages rely on.
func TestTargetString(t *testing.T) {
	cases := map[string]Target{
		"net/http.Client": {ImportPath: "net/http", Name: "Client"},
		"*.Do":            {AnyQualifier: true, Name: "Do"},
		"Client":          {Name: "Client"},
	}
	for want, tgt := range cases {
		if got := tgt.String(); got != want {
			t.Errorf("Target%#v.String() = %q, want %q", tgt, got, want)
		}
	}
}
