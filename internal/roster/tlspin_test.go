package roster

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

// testPin is a well-formed pin that differs for each n.
func testPin(n byte) tlspin.Pin {
	b := bytes.Repeat([]byte{n}, 32)
	return tlspin.Pin(tlspin.Prefix + base64.StdEncoding.EncodeToString(b))
}

// fixturePinned is qa-pve-01 with ssh, token and tls subtables, and a
// second, pinned target qa-pve-02 whose bytes must never change when
// qa-pve-01 is written.
func fixturePinned(t *testing.T, pass string) string {
	t.Helper()
	return "# roster\n[[targets]]\nid = \"qa-pve-01\"\nhost = \"h1\"\nnode = \"qa-pve-01\"\ninsecure_tls = true\n\n" +
		"[targets.ssh]\nuser = \"root\"\npublic_key = \"ssh-ed25519 AAAA x\"\nhost_key_fingerprint = \"SHA256:abc\"\nprivate_key_enc = '''\n" +
		sampleArmored(t, "key", pass) + "'''\n\n" +
		"[targets.token]\nid = \"root@pam!pveforge\"\nsecret_enc = '''\n" + sampleArmored(t, "tok", pass) + "'''\n\n" +
		"[targets.tls]\nspki_sha256 = \"" + string(testPin(1)) + "\"\n\n" +
		"# second\n[[targets]]\nid = \"qa-pve-02\"\nhost = \"h2\"\nnode = \"qa-pve-02\"\n\n" +
		"[targets.tls]\nspki_sha256 = \"" + string(testPin(2)) + "\"\n"
}

func pinOf(t *testing.T, path, id string) tlspin.Pin {
	t.Helper()
	r, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	tg := r.Find(id)
	if tg == nil {
		t.Fatalf("no target %s", id)
	}
	if tg.TLS == nil {
		return ""
	}
	return tlspin.Pin(tg.TLS.SPKISHA256)
}

// secondTargetBlock is qa-pve-02's bytes, from its comment to the end.
func secondTargetBlock(t *testing.T, data []byte) string {
	t.Helper()
	i := bytes.Index(data, []byte("# second"))
	if i < 0 {
		t.Fatalf("no second target in:\n%s", data)
	}
	return string(data[i:])
}

func TestDecode_TLSPin(t *testing.T) {
	good := string(testPin(7))
	for name, doc := range map[string]string{
		"subtable": "[[targets]]\nid = \"a\"\nhost = \"h\"\nnode = \"n\"\n[targets.tls]\nspki_sha256 = \"" + good + "\"\n",
		"inline":   "[[targets]]\nid = \"a\"\nhost = \"h\"\nnode = \"n\"\ntls = { spki_sha256 = \"" + good + "\" }\n",
		"dotted":   "[[targets]]\nid = \"a\"\nhost = \"h\"\nnode = \"n\"\ntls.spki_sha256 = \"" + good + "\"\n",
	} {
		r, err := Decode([]byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if tg := r.Find("a"); tg.TLS == nil || tg.TLS.SPKISHA256 != good {
			t.Fatalf("%s: TLS = %+v, want %s", name, tg.TLS, good)
		}
	}
	// No [targets.tls]: no pin, and nothing else changes.
	r, err := Decode([]byte("[[targets]]\nid = \"a\"\nhost = \"h\"\nnode = \"n\"\n"))
	if err != nil || r.Find("a").TLS != nil {
		t.Fatalf("an unpinned target: TLS = %+v, err %v", r.Find("a").TLS, err)
	}
}

func TestDecode_TLSPin_Refusals(t *testing.T) {
	head := "[[targets]]\nid = \"a\"\nhost = \"h\"\nnode = \"n\"\n[targets.tls]\n"
	for name, c := range map[string]struct{ body, want string }{
		"empty subtable":   {"", "spki_sha256"},
		"empty value":      {"spki_sha256 = \"\"\n", "not a TLS pin"},
		"an SSH form":      {"spki_sha256 = \"SHA256:abc\"\n", "not a TLS pin"},
		"misspelled key":   {"spki_sha265 = \"" + string(testPin(1)) + "\"\n", "not a roster key in [targets.tls]"},
		"wrong case":       {"SPKI_SHA256 = \"" + string(testPin(1)) + "\"\n", "must be spelled \"spki_sha256\""},
		"a second key":     {"spki_sha256 = \"" + string(testPin(1)) + "\"\nleaf_sha256 = \"x\"\n", "not a roster key in [targets.tls]"},
		"trailing newline": {"spki_sha256 = \"" + string(testPin(1)) + "\\n\"\n", "not a TLS pin"},
	} {
		_, err := Decode([]byte(head + c.body))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one naming %q", name, err, c.want)
		}
	}
}

// A pre-T1a binary's view: "tls" was not a key, so a pinned roster is
// refused whole. This pins the premise of the rollout rule (R-b′) from the
// other side: after T1a the key IS accepted (TestDecode_TLSPin), and it is
// accepted only under [targets].
func TestDecode_TLSKeyOnlyUnderTargets(t *testing.T) {
	_, err := Decode([]byte("tls = { spki_sha256 = \"" + string(testPin(1)) + "\" }\n"))
	if err == nil || !strings.Contains(err.Error(), "not a roster key at the top level") {
		t.Fatalf("a top-level tls: err = %v", err)
	}
}

func TestWriteTLSPin_FirstPin(t *testing.T) {
	withTestWorkFactor(t)
	const pass = "p"
	path := writeTempRoster(t, fixtureTokenAndSSH(t))
	before := readFile(t, path)
	b4, _ := Decode(before)
	if err := WriteTLSPin(path, "qa-pve-01", "", testPin(3), tlspin.SourceExpect, NewPassphrase(pass)); err != nil {
		t.Fatalf("WriteTLSPin: %v", err)
	}
	after := readFile(t, path)
	if got := pinOf(t, path, "qa-pve-01"); got != testPin(3) {
		t.Fatalf("pin = %q, want %q", got, testPin(3))
	}
	if secondTargetBlock(t, before) != secondTargetBlock(t, after) {
		t.Fatalf("the other target's bytes changed:\n%s", after)
	}
	a, _ := Decode(after)
	if !tokenAuthEqual(b4.Find("qa-pve-01").Token, a.Find("qa-pve-01").Token) || !sshAuthEqual(b4.Find("qa-pve-01").SSH, a.Find("qa-pve-01").SSH) {
		t.Fatal("the token or ssh subtable changed")
	}
	if a.Find("qa-pve-02").TLS != nil {
		t.Fatal("the other target gained a pin")
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode after the write = %v (%v), want 0600", st.Mode().Perm(), err)
	}
}

func TestWriteTLSPin_CompareAndSet(t *testing.T) {
	withTestWorkFactor(t)
	const pass = "p"
	path := writeTempRoster(t, fixturePinned(t, pass))
	pw := NewPassphrase(pass)

	// A stale old value, "" against a pinned target, or the other target's
	// pin: refused, the file byte-identical.
	for name, old := range map[string]tlspin.Pin{"stale": testPin(9), "none": "", "the other target's": testPin(2)} {
		before := readFile(t, path)
		err := WriteTLSPin(path, "qa-pve-01", old, testPin(4), tlspin.SourceExpect, pw)
		if !errors.Is(err, ErrTLSPinChanged) {
			t.Fatalf("%s old: err = %v, want ErrTLSPinChanged", name, err)
		}
		if !strings.Contains(err.Error(), "nothing was written") {
			t.Fatalf("%s old: the refusal does not say nothing was written: %v", name, err)
		}
		if !bytes.Equal(before, readFile(t, path)) {
			t.Fatalf("%s old: the refused write changed the file", name)
		}
	}

	// The right old: replaced, and only that value.
	before := readFile(t, path)
	if err := WriteTLSPin(path, "qa-pve-01", testPin(1), testPin(4), tlspin.SourceExpect, pw); err != nil {
		t.Fatalf("replace with the right old: %v", err)
	}
	if got := pinOf(t, path, "qa-pve-01"); got != testPin(4) {
		t.Fatalf("pin = %q, want %q", got, testPin(4))
	}
	if secondTargetBlock(t, before) != secondTargetBlock(t, readFile(t, path)) {
		t.Fatal("the other target's bytes changed")
	}
	if got := bytes.Count(readFile(t, path), []byte("spki_sha256")); got != 2 {
		t.Fatalf("spki_sha256 appears %d times, want 2 (replaced in place, not appended)", got)
	}

	// The same pin again: a no-op, not a write.
	before = readFile(t, path)
	if err := WriteTLSPin(path, "qa-pve-01", testPin(4), testPin(4), tlspin.SourceExpect, pw); err != nil {
		t.Fatalf("an equal pin: %v", err)
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("an equal pin rewrote the file")
	}
}

func TestWriteTLSPin_Refusals(t *testing.T) {
	withTestWorkFactor(t)
	const pass = "p"
	path := writeTempRoster(t, fixturePinned(t, pass))
	pw := NewPassphrase(pass)
	before := readFile(t, path)
	for name, c := range map[string]struct {
		id        string
		old, next tlspin.Pin
		want      string
	}{
		"empty next (no removal)": {"qa-pve-01", testPin(1), "", "not a TLS pin"},
		"malformed next":          {"qa-pve-01", testPin(1), "sha256//x", "not a TLS pin"},
		"malformed old":           {"qa-pve-01", "SHA256:abc", testPin(5), "the expected pin"},
		"unknown target":          {"qa-pve-09", "", testPin(5), "no such target"},
	} {
		err := WriteTLSPin(path, c.id, c.old, c.next, tlspin.SourceExpect, pw)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one naming %q", name, err, c.want)
		}
		// Refused up front, by WriteTLSPin itself, not only later by the
		// splice's safety net re-decoding what it composed.
		if err != nil && strings.Contains(err.Error(), "safety check failed") {
			t.Errorf("%s: refused only by the safety net, not up front: %v", name, err)
		}
	}
	// The passphrase is proven, as for every subtable write.
	if err := WriteTLSPin(path, "qa-pve-01", testPin(1), testPin(5), tlspin.SourceExpect, NewPassphrase("wrong")); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("a wrong passphrase: err = %v, want ErrWrongPassphrase", err)
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("a refused write changed the file")
	}
}

// Every other roster writer keeps both targets' pins exactly.
func TestRosterWriters_PreserveTLSPins(t *testing.T) {
	withTestWorkFactor(t)
	const pass = "p"
	pw := NewPassphrase(pass)
	for name, write := range map[string]func(path string) error{
		"WriteTokenAuth": func(p string) error {
			return WriteTokenAuth(p, "qa-pve-01", TokenWrite{TokenID: "root@pam!x", SecretPlaintext: []byte("s")}, pw)
		},
		"WriteSSHAuth": func(p string) error {
			return WriteSSHAuth(p, "qa-pve-01", SSHWrite{User: "root", PublicKey: "k", HostKeyFingerprint: "SHA256:new", PrivateKeyPlaintext: []byte("x")}, pw)
		},
		"UpdateTargetFields": func(p string) error {
			return UpdateTargetFields(p, "qa-pve-01", TargetMeta{Host: "h1b", Node: "qa-pve-01", APIPort: 8443, InsecureTLS: false})
		},
		"ClearTokenAuth": func(p string) error { return ClearTokenAuth(p, "qa-pve-01") },
		"AppendTarget": func(p string) error {
			return AppendTarget(p, Target{ID: "qa-pve-03", Host: "h3", Node: "qa-pve-03"})
		},
	} {
		path := writeTempRoster(t, fixturePinned(t, pass))
		if err := write(path); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := pinOf(t, path, "qa-pve-01"); got != testPin(1) {
			t.Errorf("%s: qa-pve-01's pin = %q, want %q", name, got, testPin(1))
		}
		if got := pinOf(t, path, "qa-pve-02"); got != testPin(2) {
			t.Errorf("%s: qa-pve-02's pin = %q, want %q", name, got, testPin(2))
		}
	}
}

// dropPin and changePin are what a buggy splicer would produce: the
// fixture with qa-pve-01's (or qa-pve-02's) [targets.tls] gone or changed.
func dropPin(fix string, n byte) string {
	return strings.Replace(fix, "[targets.tls]\nspki_sha256 = \""+string(testPin(n))+"\"\n", "", 1)
}

func changePin(fix string, n, to byte) string {
	return strings.Replace(fix, string(testPin(n)), string(testPin(to)), 1)
}

// Each verifier refuses a write that drops or changes a pin it was not
// asked to write: the safety nets every writer relies on.
func TestVerifiers_CatchAPinChange(t *testing.T) {
	withTestWorkFactor(t)
	fix := fixturePinned(t, "p")
	for _, sub := range []string{"token", "ssh"} {
		for name, bad := range map[string]string{
			"own pin dropped":   dropPin(fix, 1),
			"own pin changed":   changePin(fix, 1, 6),
			"other pin dropped": dropPin(fix, 2),
			"other pin changed": changePin(fix, 2, 6),
		} {
			if err := verifyOnlyIntendedChange([]byte(fix), []byte(bad), "qa-pve-01", sub); err == nil {
				t.Errorf("verifyOnlyIntendedChange(%s): %s passed", sub, name)
			}
		}
	}
	// Writing "tls" may change the target's own pin, never the other's.
	if err := verifyOnlyIntendedChange([]byte(fix), []byte(changePin(fix, 1, 6)), "qa-pve-01", "tls"); err != nil {
		t.Errorf("verifyOnlyIntendedChange(tls): its own pin: %v", err)
	}
	if err := verifyOnlyIntendedChange([]byte(fix), []byte(changePin(fix, 2, 6)), "qa-pve-01", "tls"); err == nil {
		t.Error("verifyOnlyIntendedChange(tls): the other target's pin changed and passed")
	}
	for name, bad := range map[string]string{
		"own pin dropped":   dropPin(fix, 1),
		"own pin changed":   changePin(fix, 1, 6),
		"other pin changed": changePin(fix, 2, 6),
	} {
		if err := verifyOnlyTargetFieldsChanged([]byte(fix), []byte(bad), "qa-pve-01"); err == nil {
			t.Errorf("verifyOnlyTargetFieldsChanged: %s passed", name)
		}
	}
	appended := fix + "\n[[targets]]\nid = \"qa-pve-03\"\nhost = \"h3\"\nnode = \"qa-pve-03\"\n"
	if err := verifyAppendOnly([]byte(fix), []byte(appended), "qa-pve-03"); err != nil {
		t.Fatalf("verifyAppendOnly on a clean append: %v", err)
	}
	for name, bad := range map[string]string{
		"an existing pin changed":      changePin(appended, 2, 6),
		"the new target carries a pin": appended + "[targets.tls]\nspki_sha256 = \"" + string(testPin(8)) + "\"\n",
	} {
		if err := verifyAppendOnly([]byte(fix), []byte(bad), "qa-pve-03"); err == nil {
			t.Errorf("verifyAppendOnly: %s passed", name)
		}
	}
	if err := AppendTarget(writeTempRoster(t, fix), Target{ID: "qa-pve-03", Host: "h", Node: "n", TLS: &TLSPin{SPKISHA256: string(testPin(8))}}); err == nil || !strings.Contains(err.Error(), "TLS pin") {
		t.Errorf("AppendTarget with a pin: err = %v", err)
	}
	// ClearTokenAuth's guard is verifyOnlyIntendedChange(..., "token"): a
	// clear that also dropped the pin is refused there (covered above), and
	// the real clear keeps it (TestRosterWriters_PreserveTLSPins).
}

// WriteTLSPin's read-back: a splice that lands a pin other than the one
// asked for (a splicer bug that the other verifiers allow, since the
// target's own tls subtable is the one being written) is refused, and the
// file is left untouched.
func TestWriteTLSPin_ReadBackRefusesAWrongLanding(t *testing.T) {
	withTestWorkFactor(t)
	const pass = "p"
	path := writeTempRoster(t, fixturePinned(t, pass))
	before := readFile(t, path)
	orig := subtableSpliceFn
	t.Cleanup(func() { subtableSpliceFn = orig })
	subtableSpliceFn = func(data []byte, targetID, subKey string, fields []field) ([]byte, error) {
		out, err := orig(data, targetID, subKey, fields)
		if err != nil {
			return nil, err
		}
		// The wrong pin lands: valid, and for the right target, so every
		// other safety net passes.
		return bytes.Replace(out, []byte(testPin(4)), []byte(testPin(5)), 1), nil
	}
	err := WriteTLSPin(path, "qa-pve-01", testPin(1), testPin(4), tlspin.SourceExpect, NewPassphrase(pass))
	if err == nil || !strings.Contains(err.Error(), "does not read back as "+string(testPin(4))) {
		t.Fatalf("err = %v, want the read-back refusal", err)
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("the refused write changed the file")
	}
	// The seam as it stands (the real splice) lands the pin asked for.
	subtableSpliceFn = orig
	if err := WriteTLSPin(path, "qa-pve-01", testPin(1), testPin(4), tlspin.SourceExpect, NewPassphrase(pass)); err != nil || pinOf(t, path, "qa-pve-01") != testPin(4) {
		t.Fatalf("with the real splice: err %v, pin %q", err, pinOf(t, path, "qa-pve-01"))
	}
}

// The source is written beside the pin, read back, and validated at load.
func TestWriteTLSPin_RecordsTheSource(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTokenAndSSH(t))
	if err := WriteTLSPin(path, "qa-pve-01", "", testPin(3), tlspin.SourceSSHTOFU, NewPassphrase("p")); err != nil {
		t.Fatal(err)
	}
	r, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if tg := r.Find("qa-pve-01"); tg.TLS == nil || tg.TLS.Source != string(tlspin.SourceSSHTOFU) {
		t.Fatalf("TLS = %+v, want source ssh-tofu", tg.TLS)
	}
	// An equal pin is a no-op, whatever source this write names: the
	// source records how the pin was FIRST obtained.
	before := readFile(t, path)
	if err := WriteTLSPin(path, "qa-pve-01", testPin(3), testPin(3), tlspin.SourceSSHVerified, NewPassphrase("p")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("an equal pin with another source rewrote the roster")
	}
	for _, bad := range []tlspin.Source{"", "tofu"} {
		if err := WriteTLSPin(path, "qa-pve-01", testPin(3), testPin(4), bad, NewPassphrase("p")); !errors.Is(err, tlspin.ErrUnknownSource) {
			t.Errorf("source %q: err = %v, want ErrUnknownSource", bad, err)
		}
	}
}

func TestDecode_TLSPinSource(t *testing.T) {
	head := "[[targets]]\nid = \"a\"\nhost = \"h\"\nnode = \"n\"\n[targets.tls]\nspki_sha256 = \"" + string(testPin(1)) + "\"\n"
	if _, err := Decode([]byte(head)); err != nil {
		t.Fatalf("no source (a hand-written pin): %v", err)
	}
	if r, err := Decode([]byte(head + "source = \"ssh-verified\"\n")); err != nil || r.Find("a").TLS.Source != "ssh-verified" {
		t.Fatalf("a known source: %v", err)
	}
	for body, want := range map[string]string{
		"source = \"tofu\"\n":         "not a TLS pin source",
		"Source = \"ssh-tofu\"\n":     "must be spelled \"source\"",
		"provenance = \"ssh-tofu\"\n": "not a roster key in [targets.tls]",
	} {
		if _, err := Decode([]byte(head + body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want one naming %q", body, err, want)
		}
	}
}
