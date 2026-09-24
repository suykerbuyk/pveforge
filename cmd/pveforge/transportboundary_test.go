package main

// TRANSPORT BOUNDARY GUARD. Only internal/pve and internal/sshexec may build
// an HTTP or SSH transport. Everything else in the module goes through them.
//
// WHY THIS IS SYMBOL-LEVEL AND QUALIFIED, NOT IMPORT-LEVEL. The obvious
// version of this guard — "no package outside the boundary may import
// net/http or go-proxmox" — fails on the first file it meets. Twenty-two
// non-test files import go-proxmox and exactly ONE of them calls
// proxmox.NewClient; cmd/pveforge/api.go and five internal/idempotent files
// import net/http purely for http.MethodGet and its siblings. The import is
// not the hazard. Constructing the transport is, so the targets below name
// symbols, and they name them QUALIFIED BY IMPORT PATH: reduced to a bare
// "Client", net/http.Client's 2 sites in this module become 86.
//
// WHY THE GUARD LIVES IN cmd/pveforge. It guards two packages and is exempt
// in neither. This package's standing failure mode is the check and the
// thing checked being the same object; a guard sitting inside its own
// exemption is that mistake in its purest form. cmd/pveforge is in scope,
// clean, holds no exemption, and is the module's outermost package.
//
// ---------------------------------------------------------------------------
// WHAT THIS DOES NOT CLOSE
// ---------------------------------------------------------------------------
//
//   - //go:linkname IS INVISIBLE TO THIS GUARD, and to every other AST-based
//     guard in this repo: the directive is a COMMENT, and the `import _
//     "unsafe"` it requires binds no identifier. It is closed one layer
//     down, at the text level: internal/sourceguard's
//     TestModule_NoDirectiveEvasions refuses any linkname directive, any
//     unsafe import and any non-Go source in non-test code, module-wide.
//     Cite THAT test for linkname, never this one. A dependency linking into
//     this module stays open (pveforge-golinkname-defeats-source-guards).
//
//   - REFLECTION. reflect.Value.MethodByName("TermWebSocket") puts the name
//     in a string. A string is not an identifier.
//
//   - SHELLING OUT. exec.Command("ssh", ...) or a curl invocation builds a
//     transport no Go symbol can name. Directly relevant here, since
//     internal/sshexec exists to run commands.
//
//   - DEPENDENCY INTERNALS. The go-proxmox target fences the CALL that hands
//     you a transport, not the http.Client go-proxmox builds inside itself.
//
//   - AN ALLOWED LOCATION CAN LAUNDER A FENCED SYMBOL OUT, and this is by
//     far the easiest of these bounds to hit BY ACCIDENT — the others take
//     deliberate effort. `var DialSSH = sshexec.Dial` in the exempt
//     internal/bootstrap/deps.go, then DialSSH(...) from bootstrap.go,
//     compiles and stays green: the only reference to a fenced symbol is
//     the one inside the exemption, and the guard is right that it is
//     allowed. The same goes through a type alias — `type HTTPClient =
//     http.Client` in an AllowDir, then &pve.HTTPClient{} anywhere. This is
//     inherent to guarding symbols without type information rather than a
//     gap to be patched: re-exporting a fenced symbol widens the boundary,
//     and only review catches that. Note it when reviewing any new line in
//     an allowed file, which the entry above already asks for.
//
//   - NO TYPE INFORMATION. The walker parses; it does not typecheck. So
//     *.TermWebSocket and *.VNCWebSocket match by name alone and would fire
//     on a same-named method of an unrelated local type (there is none in
//     this module today), and (*http.Client).Do stays inexpressible — the
//     net/http.Client target subsumes it only for clients this module
//     constructs itself.

import (
	"sort"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/sourceguard"
)

// transportModuleRoot is where the walk starts. cmd/pveforge is two levels
// down, so this is the module root. It is not taken on trust:
// TestTransportBoundary_NoProductionReferences asserts the walk reached
// internal/sshexec/client.go and parsed at least transportParsedFloor files,
// so a root that ever starts pointing somewhere shallower fails loudly
// instead of quietly scanning less and finding nothing.
const transportModuleRoot = "../.."

// transportParsedFloor is a FLOOR, never an exact count. The module has 78
// walker-visible non-test files today — 75 before internal/netguard landed,
// which is the floor earning its keep. An exact value would make an
// unrelated new file break this guard and internal/roster's KDF seam guard
// at the same moment, for a reason neither is about.
const transportParsedFloor = 70

// transportBoundaryDirs are the two packages that own a transport. Every ref
// inside them is marked Allowed rather than dropped, which is what lets one
// call return both the violations and the anti-vacuity proof.
var transportBoundaryDirs = []string{
	"internal/pve",
	"internal/sshexec",
}

// transportAllowedFiles is the PATH-EXACT allow-list: non-test files outside
// the two boundary packages that legitimately build a transport anyway. A
// directory prefix here would re-open a whole PACKAGE to the thing this
// guard exists to prevent, so each entry names one file.
//
// BE PRECISE ABOUT WHAT AN ENTRY BUYS. Exact-path means exact on the FILE,
// not on the line: Scope.allows (sourceguard/nontestrefs.go) marks EVERY ref
// in a listed file Allowed, so an entry exempts the whole file forever, not
// just the call it was added for. Appending a fresh &http.Client{} to
// internal/bootstrap/deps.go compiles and this guard stays green. An entry
// here is therefore a standing grant over a file, and each one is worth
// reviewing as such. Line-scoping is filed separately and is deliberately
// NOT built here.
//
// Every entry must also be named in transportWitnesses, so that the
// exemption is shown capable of mattering rather than merely asserted. That
// pairing is a convention here, not something a test enforces — what IS
// enforced is the target-level version, by
// TestTransportBoundary_EveryTargetHasAnAntiVacuitySource. The convention
// pays off the moment an entry is dropped: this guard then goes red twice
// over, once because the exempted site becomes a violation and once because
// its witness stops matching.
var transportAllowedFiles = []string{
	// internal/bootstrap/deps.go:52 — realSSHTransport.dialPinned. First
	// contact: bootstrap must SSH to a node to install a pubkey and mint
	// an API token, which is strictly before any pve.Client can exist.
	// There is no way to route this through the boundary, because the
	// boundary is what this call is bootstrapping.
	"internal/bootstrap/deps.go",

	// internal/netguard/netguard.go:269-290 — Install(). The loopback
	// trip-wire's whole job is to REPLACE http.DefaultTransport with a
	// clone that refuses non-loopback addresses. It has to name the global
	// it is swapping, and it has to name *http.Transport to assert the
	// clone's type. A guard against building transports cannot also route
	// the thing that disarms them: netguard sits under the boundary, not
	// behind it.
	"internal/netguard/netguard.go",

	// internal/netguard/assert.go:46 — AssertHTTPSeamRefuses(). Builds a
	// real &http.Client{Transport: http.DefaultTransport} and dials a
	// deliberately non-loopback address, requiring the trip-wire to refuse
	// it. This is the companion that proves netguard's own seam is armed,
	// so its client must be real; a routed one would prove nothing. Note
	// it lives in a non-test file because it is a testing helper exported
	// to four other packages.
	"internal/netguard/assert.go",

	// internal/netguard/preinstall.go gets NO entry, checked rather than
	// assumed: it names DefaultTransport, DefaultClient and Transport only
	// in comments and in string-literal map keys, and does not import
	// net/http at all. The walker sees identifiers, not text, so it has
	// zero refs. An entry for it would be a standing grant bought for
	// nothing.
}

// The forbidden set. Seventeen targets, each in the only form that can
// actually match it.
var (
	// The HTTP transport as a thing you construct. Client and Transport
	// both have real in-boundary sites; DefaultClient has none, and is
	// fenced because reaching the package global is how you use an
	// http.Client without ever constructing one.
	tgtHTTPClient        = sourceguard.Target{ImportPath: "net/http", Name: "Client"}
	tgtHTTPTransport     = sourceguard.Target{ImportPath: "net/http", Name: "Transport"}
	tgtHTTPDefaultClient = sourceguard.Target{ImportPath: "net/http", Name: "DefaultClient"}

	// The OTHER package-level global that dials. DefaultTransport is a
	// RoundTripper, so http.DefaultTransport.RoundTrip(req) opens a
	// connection while naming neither a Client nor a Transport — the Sel
	// is "DefaultTransport", which tgtHTTPTransport above does not match.
	// It witnesses itself at newHTTPClient (internal/pve/client.go), where the
	// in-boundary code clones it.
	tgtHTTPDefaultTransport = sourceguard.Target{ImportPath: "net/http", Name: "DefaultTransport"}

	// The package-level round-trip helpers. Each one IS DefaultClient with
	// the global spelled out of existence: http.Get(u) dials without ever
	// naming a client, a transport or DefaultClient. Aggravating here,
	// because cmd/pveforge/api.go and five internal/idempotent files
	// already import net/http for the http.MethodGet constants, so
	// http.Get is a one-word change from existing idiom with the import
	// already sitting there. These four are net/http's complete set.
	tgtHTTPGet      = sourceguard.Target{ImportPath: "net/http", Name: "Get"}
	tgtHTTPPost     = sourceguard.Target{ImportPath: "net/http", Name: "Post"}
	tgtHTTPHead     = sourceguard.Target{ImportPath: "net/http", Name: "Head"}
	tgtHTTPPostForm = sourceguard.Target{ImportPath: "net/http", Name: "PostForm"}

	// go-proxmox's own constructor. The library is imported all over the
	// module for types and constants; this is the one call that builds a
	// client out of it.
	tgtProxmoxNewClient = sourceguard.Target{ImportPath: "github.com/suykerbuyk/go-proxmox", Name: "NewClient"}

	// The SSH handshake as internal/sshexec/client.go actually performs
	// it: dial with a net.Dialer, then hand the raw conn to these two.
	tgtSSHNewClientConn = sourceguard.Target{ImportPath: "golang.org/x/crypto/ssh", Name: "NewClientConn"}
	tgtSSHNewClient     = sourceguard.Target{ImportPath: "golang.org/x/crypto/ssh", Name: "NewClient"}

	// ssh.Dial IS fenced, and an earlier draft of this file was wrong to
	// leave it out. The reasoning then was that a symbol with zero matches
	// anywhere is a guard that lies green by construction — true of a
	// target with no proof behind it, but this file went on to build
	// transportFixtureOnly and testdata/transportprobe precisely so that a
	// zero-match target CAN be proven, and then applied that mechanism to
	// five others. ssh.Dial is x/crypto/ssh's canonical entry point and so
	// the single likeliest line a new caller writes.
	tgtSSHDial = sourceguard.Target{ImportPath: "golang.org/x/crypto/ssh", Name: "Dial"}

	// All THREE of this module's own SSH doors, which is sshexec's
	// complete connection-opening surface — its other exported functions
	// (GenerateEd25519Keypair, the two HostKeyCallbacks, ShellQuote,
	// TapDeviceName, IsRootOnlyWriteError) open nothing.
	//
	// DialWithPassword is called only from inside sshexec itself, by
	// install.go:30, so its qualified form has no site in the module —
	// which is exactly why fencing it is cheap. InstallPubkeyViaPassword
	// wraps that same password dial and DOES have a real qualified site,
	// at internal/bootstrap/deps.go:20, so it witnesses itself inside the
	// exemption that already covers that file.
	tgtSshexecDial    = sourceguard.Target{ImportPath: "github.com/suykerbuyk/pveforge/internal/sshexec", Name: "Dial"}
	tgtSshexecDialPW  = sourceguard.Target{ImportPath: "github.com/suykerbuyk/pveforge/internal/sshexec", Name: "DialWithPassword"}
	tgtSshexecInstall = sourceguard.Target{ImportPath: "github.com/suykerbuyk/pveforge/internal/sshexec", Name: "InstallPubkeyViaPassword"}

	// AnyQualifier, and it has to be. go-proxmox declares these ONLY as
	// methods — on *Client, *VirtualMachine, *Container and *Node — so the
	// qualifier at any call site is a receiver variable, never the package
	// name. An ImportPath target could never match them. They dial outside
	// the guarded path and are uncalled today, which is the cheapest
	// moment to fence them.
	tgtTermWebSocket = sourceguard.Target{AnyQualifier: true, Name: "TermWebSocket"}
	tgtVNCWebSocket  = sourceguard.Target{AnyQualifier: true, Name: "VNCWebSocket"}
)

func transportTargets() []sourceguard.Target {
	return []sourceguard.Target{
		tgtHTTPClient, tgtHTTPTransport, tgtHTTPDefaultClient, tgtHTTPDefaultTransport,
		tgtHTTPGet, tgtHTTPPost, tgtHTTPHead, tgtHTTPPostForm,
		tgtProxmoxNewClient,
		tgtSSHNewClientConn, tgtSSHNewClient, tgtSSHDial,
		tgtSshexecDial, tgtSshexecDialPW, tgtSshexecInstall,
		tgtTermWebSocket, tgtVNCWebSocket,
	}
}

// transportWitnesses pairs each target that has a real site in the tree with
// that site's file. These are the Layer A anti-vacuity assertions: if the
// walker stops finding them, "no violations" has stopped meaning anything.
//
// tgtSshexecDial appears twice on purpose. One witness is inside an
// AllowDir, the other inside the path-exact AllowFile, and they are the
// evidence that BOTH kinds of exemption are load-bearing rather than
// decorative.
var transportWitnesses = []struct {
	file   string
	target sourceguard.Target
}{
	{"internal/pve/client.go", tgtHTTPClient},           // the field, and newHTTPClient's literal
	{"internal/pve/client.go", tgtHTTPTransport},        // newHTTPClient's (*http.Transport) assertion
	{"internal/pve/client.go", tgtHTTPDefaultTransport}, // newHTTPClient's clone, and the guard's per-request default
	{"internal/pve/client.go", tgtProxmoxNewClient},     // NewClient, handed newHTTPClient's client
	{"internal/sshexec/client.go", tgtSSHNewClientConn}, // :119
	{"internal/sshexec/client.go", tgtSSHNewClient},     // :124
	{"internal/pve/routed.go", tgtSshexecDial},          // :528, inside an AllowDir
	{"internal/bootstrap/deps.go", tgtSshexecDial},      // :52, the AllowFile
	{"internal/bootstrap/deps.go", tgtSshexecInstall},   // :20, the AllowFile
	// U-C's keyless path: the one-shot password session. This entry is why
	// tgtSshexecDialPW is no longer fixture-only.
	{"internal/bootstrap/deps.go", tgtSshexecDialPW},
	// The two netguard files, each exempt for its own reason. Both are
	// witnessed on net/http.DefaultTransport, the target this unit added
	// on its own initiative last round -- the one that catches the
	// trip-wire is the one the reviewer's patch did not ask for.
	{"internal/netguard/netguard.go", tgtHTTPDefaultTransport}, // :269-290, Install swapping the global
	{"internal/netguard/netguard.go", tgtHTTPTransport},        // :269, the clone's type assertion
	{"internal/netguard/assert.go", tgtHTTPClient},             // :46, the companion's real client
	{"internal/netguard/assert.go", tgtHTTPDefaultTransport},   // :46, the transport handed to it
}

// transportFixtureOnly are the targets with no site anywhere in the module.
// They cannot be proven non-vacuous against the real tree — an in-boundary
// assertion is impossible for a symbol with no in-boundary use — so
// testdata/transportprobe is their proof instead.
func transportFixtureOnly() []sourceguard.Target {
	return []sourceguard.Target{
		tgtHTTPDefaultClient,
		tgtHTTPGet, tgtHTTPPost, tgtHTTPHead, tgtHTTPPostForm,
		tgtSSHDial,
		tgtTermWebSocket, tgtVNCWebSocket,
	}
}

// ---------------------------------------------------------------------------
// Layer A: the module-wide guard, and its real-tree witnesses.
// ---------------------------------------------------------------------------

// TestTransportBoundary_NoProductionReferences is the guard. No non-test file
// outside internal/pve, internal/sshexec and the path-exact allow-list may
// build an HTTP or SSH transport.
func TestTransportBoundary_NoProductionReferences(t *testing.T) {
	res, err := sourceguard.NonTestReferences(sourceguard.Scope{
		Root:       transportModuleRoot,
		AllowDirs:  transportBoundaryDirs,
		AllowFiles: transportAllowedFiles,
	}, transportTargets())
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}

	if v := res.Violations(); len(v) > 0 {
		var lines []string
		for _, ref := range v {
			lines = append(lines, "  "+ref.String())
		}
		t.Errorf("a transport is built outside %s and %s:\n%s\n"+
			"Route it through internal/pve or internal/sshexec. If a new site "+
			"genuinely has to dial for itself, it needs its own review and a "+
			"path-exact entry in transportAllowedFiles with a witness beside "+
			"it — not a directory prefix.",
			strings.Join(transportBoundaryDirs, ", "),
			strings.Join(transportAllowedFiles, ", "),
			strings.Join(lines, "\n"))
	}

	// ANTI-VACUITY, LAYER A. A guard that matches nothing passes forever.
	// This is why the allow-list MARKS rather than drops: the same call
	// that reports the violations also proves the predicate still matches
	// the sites it permits.
	for _, w := range transportWitnesses {
		if got := res.Allowed(w.file, w.target); len(got) == 0 {
			t.Errorf("target %s matched nothing in %s — the guard is no longer "+
				"looking at the code it claims to guard, or that file stopped "+
				"building the transport it is exempt for",
				w.target, w.file)
		}
	}

	// ...and the walk has to have covered the module rather than a subtree.
	if len(res.Parsed) < transportParsedFloor {
		t.Errorf("walked only %d non-test files from %s; the module has ~75 — wrong root? Parsed[0:3]=%v",
			len(res.Parsed), transportModuleRoot, transportFirstN(res.Parsed, 3))
	}
	// A file in the far corner of the tree from cmd/pveforge, and the one
	// that holds two of the witnesses above.
	if !res.Reached("internal/sshexec/client.go") {
		t.Errorf("the walk never reached internal/sshexec/client.go, so it did not cover the module; Parsed[0:3]=%v",
			transportFirstN(res.Parsed, 3))
	}
	// The probe below is a non-test file that deliberately builds every
	// forbidden transport. It must be invisible to this walk, or the guard
	// fails against its own fixture.
	if res.Reached("cmd/pveforge/testdata/transportprobe/main.go") {
		t.Error("the walk descended into testdata and will now report the positive-control probe as a violation")
	}
}

// ---------------------------------------------------------------------------
// Layer B: the positive control.
// ---------------------------------------------------------------------------

// TestTransportBoundary_EveryTargetMatchesTheProbe points the walker at
// testdata/transportprobe with NO allow-list, and requires every one of the
// ten targets to fire.
//
// It is the only possible proof for the four targets with no site in the
// module, and it re-proves the other six from an object independent of the
// real tree. The probe is written in production's own shapes and is kept
// compiling precisely so it cannot drift into proving the guard matches
// something reality never produces.
func TestTransportBoundary_EveryTargetMatchesTheProbe(t *testing.T) {
	const probe = "testdata/transportprobe"
	res, err := sourceguard.NonTestReferences(sourceguard.Scope{Root: probe}, transportTargets())
	if err != nil {
		t.Fatalf("NonTestReferences(%s): %v", probe, err)
	}
	hits := map[string]int{}
	for _, ref := range res.Violations() {
		hits[ref.Target.String()]++
	}
	for _, tgt := range transportTargets() {
		if hits[tgt.String()] == 0 {
			t.Errorf("target %s matched nothing in %s, which exists to reference every target — "+
				"the target is unmatchable, or the probe has drifted away from it", tgt, probe)
		}
	}
	// No allow-list was passed, so nothing in the probe may be marked
	// Allowed. If anything were, the loop above would be reading an empty
	// Violations() and reporting success for the wrong reason.
	for _, refs := range res.Refs {
		for _, ref := range refs {
			if ref.Allowed {
				t.Errorf("%s was marked Allowed with no allow-list in scope", ref)
			}
		}
	}
}

// TestTransportBoundary_EveryTargetHasAnAntiVacuitySource makes it
// structurally impossible to add a target with no proof behind it. Every
// target is either witnessed against the real tree or declared fixture-only,
// exactly once, and nothing may be declared fixture-only while a real
// witness exists for it.
func TestTransportBoundary_EveryTargetHasAnAntiVacuitySource(t *testing.T) {
	witnessed := map[string]bool{}
	for _, w := range transportWitnesses {
		witnessed[w.target.String()] = true
	}
	fixtureOnly := map[string]bool{}
	for _, tgt := range transportFixtureOnly() {
		fixtureOnly[tgt.String()] = true
	}
	for _, tgt := range transportTargets() {
		k := tgt.String()
		switch {
		case witnessed[k] && fixtureOnly[k]:
			t.Errorf("target %s is both witnessed and declared fixture-only; it has a real site, so drop it from transportFixtureOnly", k)
		case !witnessed[k] && !fixtureOnly[k]:
			t.Errorf("target %s has no anti-vacuity source: give it a real-tree witness in transportWitnesses, or declare it fixture-only and reference it from testdata/transportprobe", k)
		}
	}
	// And nothing may be witnessed or declared that is not a target — a
	// stale entry here would otherwise sit unnoticed, proving nothing.
	declared := map[string]bool{}
	for _, tgt := range transportTargets() {
		declared[tgt.String()] = true
	}
	var stale []string
	for k := range witnessed {
		if !declared[k] {
			stale = append(stale, "witness "+k)
		}
	}
	for k := range fixtureOnly {
		if !declared[k] {
			stale = append(stale, "fixture-only "+k)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("entries naming symbols that are not targets: %s", strings.Join(stale, ", "))
	}
}

// ---------------------------------------------------------------------------
// Layer C: the inherited refusal.
// ---------------------------------------------------------------------------

// TestTransportBoundary_DotImportOfAGuardedPathIsRefused asserts an inherited
// property of the walker holds for THIS unit's target list.
//
// A dot-import is the third evasion and the cheapest: an alias changes the
// local name, `import . "net/http"` removes it, so http.Client becomes a
// bare Client that an ImportPath target cannot see. NonTestReferences
// refuses such an import loudly instead of returning no hits, and refuses it
// only for paths a target actually cares about — so the refusal reaching
// each of this unit's four guarded paths is a property of this unit's target
// list, not only of the walker. One probe directory per path, because the
// walk stops at the first offending file.
func TestTransportBoundary_DotImportOfAGuardedPathIsRefused(t *testing.T) {
	for _, c := range []struct{ dir, path string }{
		{"nethttp", "net/http"},
		{"goproxmox", "github.com/suykerbuyk/go-proxmox"},
		{"cryptossh", "golang.org/x/crypto/ssh"},
		{"sshexec", "github.com/suykerbuyk/pveforge/internal/sshexec"},
	} {
		t.Run(c.dir, func(t *testing.T) {
			root := "testdata/dotimport/" + c.dir
			res, err := sourceguard.NonTestReferences(sourceguard.Scope{Root: root}, transportTargets())
			if err == nil {
				t.Fatalf("a dot-import of %q was accepted, and the guard found %d refs in %s — "+
					"stripping the qualifier is now a one-line way around every target on that path",
					c.path, len(res.Violations()), root)
			}
			if !strings.Contains(err.Error(), "dot-imports") || !strings.Contains(err.Error(), c.path) {
				t.Fatalf("the walk failed, but not at the dot-import refusal — check the probe rather than assuming a kill: %v", err)
			}
		})
	}
}

func transportFirstN(s []string, n int) []string {
	if len(s) < n {
		return s
	}
	return s[:n]
}
