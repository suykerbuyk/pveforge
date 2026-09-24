package roster

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/pelletier/go-toml/v2/unstable"
)

// TokenWrite is the payload for WriteTokenAuth.
type TokenWrite struct {
	TokenID         string
	SecretPlaintext []byte
}

// SSHWrite is the payload for WriteSSHAuth.
type SSHWrite struct {
	User                string
	PublicKey           string
	HostKeyFingerprint  string
	PrivateKeyPlaintext []byte
}

// WriteTokenAuth encrypts w.SecretPlaintext and splices a [targets.token]
// block for the target identified by targetID into the roster at path,
// without altering any other byte of the file. If [targets.token] already
// exists, only its fields are updated (id in place if present, secret_enc
// replaced); if it doesn't exist yet, the whole subtable is appended at the
// end of the target's block.
//
// This is the only place bootstrap code should ever touch the roster's
// token fields — it never hand-assembles TOML text itself.
//
// passphrase is proven against the roster under its file lock before
// anything is written (Passphrase.prove): a passphrase that does not open a
// secret the roster already holds is ErrWrongPassphrase, and the file is
// left untouched.
func WriteTokenAuth(path, targetID string, w TokenWrite, passphrase Passphrase) error {
	if w.TokenID == "" {
		return fmt.Errorf("write token auth for %q: token id is required", targetID)
	}
	secretEnc, err := EncryptString(w.SecretPlaintext, passphrase.s)
	if err != nil {
		return fmt.Errorf("encrypt token secret for %q: %w", targetID, err)
	}
	fields := []field{
		{key: "id", value: w.TokenID},
		{key: "secret_enc", value: secretEnc, literal: true},
	}
	if err := spliceSubtable(path, targetID, "token", fields, passphrase); err != nil {
		return err
	}
	passphrase.remember(secretEnc, w.SecretPlaintext)
	return nil
}

// WriteSSHAuth encrypts w.PrivateKeyPlaintext and splices a [targets.ssh]
// block for the target identified by targetID into the roster at path.
// Same in-place-vs-append, non-clobbering and passphrase-proving behavior
// as WriteTokenAuth.
func WriteSSHAuth(path, targetID string, w SSHWrite, passphrase Passphrase) error {
	if w.User == "" {
		return fmt.Errorf("write ssh auth for %q: user is required", targetID)
	}
	keyEnc, err := EncryptString(w.PrivateKeyPlaintext, passphrase.s)
	if err != nil {
		return fmt.Errorf("encrypt ssh private key for %q: %w", targetID, err)
	}
	fields := []field{
		{key: "user", value: w.User},
		{key: "public_key", value: w.PublicKey},
		{key: "host_key_fingerprint", value: w.HostKeyFingerprint},
		{key: "private_key_enc", value: keyEnc, literal: true},
	}
	if err := spliceSubtable(path, targetID, "ssh", fields, passphrase); err != nil {
		return err
	}
	passphrase.remember(keyEnc, w.PrivateKeyPlaintext)
	return nil
}

// AppendTarget appends a new [[targets]] block for t to the roster at path,
// with no auth subtables — the starting point for a target `pveforge
// bootstrap` has not yet run against. It errors if a target with the same
// id already exists; use WriteTokenAuth/WriteSSHAuth to add credentials to
// it afterward.
func AppendTarget(path string, t Target) error {
	if t.ID == "" {
		return fmt.Errorf("append target: id is required")
	}
	// Before the lock and the read: Decode would refuse the result anyway,
	// but only after the write was composed, as a "safety check failed".
	if err := ValidateTargetID(t.ID); err != nil {
		return fmt.Errorf("append target: %w", err)
	}
	if t.Host == "" {
		return fmt.Errorf("append target %q: host is required", t.ID)
	}
	if t.Node == "" {
		return fmt.Errorf("append target %q: node is required", t.ID)
	}
	if t.Token != nil || t.SSH != nil {
		return fmt.Errorf("append target %q: must not carry auth subtables; use WriteTokenAuth/WriteSSHAuth after appending", t.ID)
	}
	if t.Export != "" {
		return fmt.Errorf("append target %q: export is set only by editing the roster by hand", t.ID)
	}

	lock := flock.New(path + ".lock")
	lockCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	locked, err := lock.TryLockContext(lockCtx, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("lock roster %s: %w", path, err)
	}
	if !locked {
		return fmt.Errorf("lock roster %s: timed out waiting for another pveforge process", path)
	}
	defer lock.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read roster %s: %w", path, err)
	}

	blocks, err := findTargetBlocks(data)
	if err != nil {
		return fmt.Errorf("append target %q: %w", t.ID, err)
	}
	for _, b := range blocks {
		if b.id == t.ID {
			return fmt.Errorf("append target %q: a target with this id already exists", t.ID)
		}
	}

	newData := appendTargetBlock(data, t)

	if err := verifyAppendOnly(data, newData, t.ID); err != nil {
		return fmt.Errorf("safety check failed, roster left untouched: %w", err)
	}

	if err := atomicWrite(path, newData); err != nil {
		return fmt.Errorf("write roster %s: %w", path, err)
	}
	return nil
}

// appendTargetBlock renders t as a new [[targets]] block and appends it to
// the end of data.
func appendTargetBlock(data []byte, t Target) []byte {
	var b strings.Builder
	if len(data) > 0 && data[len(data)-1] != '\n' {
		b.WriteString("\n")
	}
	if len(data) > 0 {
		b.WriteString("\n")
	}
	b.WriteString("[[targets]]\n")
	b.WriteString(field{key: "id", value: t.ID}.render())
	b.WriteString(field{key: "host", value: t.Host}.render())
	b.WriteString(field{key: "node", value: t.Node}.render())
	if t.APIPort != 0 {
		b.WriteString(field{key: "api_port", value: strconv.Itoa(t.APIPort), raw: true}.render())
	}
	if t.InsecureTLS {
		b.WriteString(field{key: "insecure_tls", value: strconv.FormatBool(t.InsecureTLS), raw: true}.render())
	}
	return append(append([]byte{}, data...), []byte(b.String())...)
}

// verifyAppendOnly re-decodes both the original and appended bytes and
// asserts that every original target is byte-for-byte unchanged in its
// decoded form, and that exactly one new target (targetID) was added at the
// end. Mirrors verifyOnlyIntendedChange's role for spliceSubtable: the
// safety net that catches a rendering bug before anything is written.
func verifyAppendOnly(oldData, newData []byte, targetID string) error {
	oldRoster, err := Decode(oldData)
	if err != nil {
		return fmt.Errorf("original roster no longer parses (unexpected): %w", err)
	}
	newRoster, err := Decode(newData)
	if err != nil {
		return fmt.Errorf("appended roster does not parse: %w", err)
	}
	if len(newRoster.Targets) != len(oldRoster.Targets)+1 {
		return fmt.Errorf("target count changed by %d, want +1", len(newRoster.Targets)-len(oldRoster.Targets))
	}
	for i := range oldRoster.Targets {
		if !targetDeepEqual(oldRoster.Targets[i], newRoster.Targets[i]) {
			return fmt.Errorf("existing target %q was modified", oldRoster.Targets[i].ID)
		}
	}
	last := newRoster.Targets[len(newRoster.Targets)-1]
	if last.ID != targetID {
		return fmt.Errorf("appended target has id %q, want %q", last.ID, targetID)
	}
	if last.Token != nil || last.SSH != nil {
		return fmt.Errorf("appended target %q unexpectedly carries auth subtables", targetID)
	}
	if last.Export != "" {
		return fmt.Errorf("appended target %q unexpectedly carries export", targetID)
	}
	return nil
}

// TargetMeta is the payload for UpdateTargetFields: a target's plain
// (non-secret) connection fields — the same four AppendTarget already
// writes for a brand-new target (see appendTargetBlock), now updatable in
// place after the fact.
type TargetMeta struct {
	Host        string
	Node        string
	APIPort     int
	InsecureTLS bool
}

// UpdateTargetFields splices meta's host/node/api_port/insecure_tls onto
// an EXISTING target's own top-level fields — closing the gap
// AppendTarget alone leaves: AppendTarget only ever writes these fields
// once, for a target's first-ever roster entry. A target that already had
// a bare [[targets]] block before this ran (hand-added per the roster
// template's own documented convention, or left over from a bootstrap
// that predates this fix) never gets them written at all, so e.g.
// `bootstrap --insecure-tls` against such a target silently loses that
// setting the moment bootstrap finishes — pveforge-bootstrap-insecure-
// tls-not-persisted.
//
// A true no-op — no write, no error — when meta already matches every
// field currently persisted for targetID: verify-then-skip is cheaper and
// safer than an unconditional rewrite on every bootstrap run, including
// the common retry that changed nothing. The comparison against the
// currently-persisted values happens from the SAME locked read the actual
// splice below goes on to use — not a separate, earlier, unlocked
// read-then-decide — so there's no TOCTOU window between deciding a field
// differs and actually writing it.
//
// Only fields that actually differ from what's currently persisted are
// included in the splice at all: api_port and insecure_tls are OPTIONAL
// top-level fields (AppendTarget only ever writes them when non-zero —
// see appendTargetBlock), so a field that's currently absent (decoding to
// its zero value) and whose wanted value is ALSO the zero value must stay
// untouched, never gaining a spurious "api_port = 0"/"insecure_tls =
// false" line. A field that IS currently present but needs to move back
// to the zero value is written as that explicit zero value in place
// (e.g. "insecure_tls = false") rather than removing the line — decoded
// either way, "explicitly false" and "absent" are indistinguishable, and
// writing the value in place reuses the exact same splice machinery as
// every other field update instead of needing a separate line-deletion
// mechanism for a case bootstrap realistically never hits (its own
// fields only ever move away from their zero value, never back to it).
func UpdateTargetFields(path, targetID string, meta TargetMeta) error {
	lock := flock.New(path + ".lock")
	lockCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	locked, err := lock.TryLockContext(lockCtx, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("lock roster %s: %w", path, err)
	}
	if !locked {
		return fmt.Errorf("lock roster %s: timed out waiting for another pveforge process", path)
	}
	defer lock.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read roster %s: %w", path, err)
	}

	r, err := Decode(data)
	if err != nil {
		return fmt.Errorf("update target fields for %q: %w", targetID, err)
	}
	current := r.Find(targetID)
	if current == nil {
		return fmt.Errorf("update target fields for %q: no such target in roster %s", targetID, path)
	}

	var fields []field
	if current.Host != meta.Host {
		fields = append(fields, field{key: "host", value: meta.Host})
	}
	if current.Node != meta.Node {
		fields = append(fields, field{key: "node", value: meta.Node})
	}
	if current.APIPort != meta.APIPort {
		fields = append(fields, field{key: "api_port", value: strconv.Itoa(meta.APIPort), raw: true})
	}
	if current.InsecureTLS != meta.InsecureTLS {
		fields = append(fields, field{key: "insecure_tls", value: strconv.FormatBool(meta.InsecureTLS), raw: true})
	}
	if len(fields) == 0 {
		return nil
	}

	newData, err := applyTargetFieldsSplice(data, targetID, fields)
	if err != nil {
		return fmt.Errorf("update target fields for %q: %w", targetID, err)
	}

	if err := verifyOnlyTargetFieldsChanged(data, newData, targetID); err != nil {
		return fmt.Errorf("safety check failed, roster left untouched: %w", err)
	}

	if err := atomicWrite(path, newData); err != nil {
		return fmt.Errorf("write roster %s: %w", path, err)
	}
	return nil
}

// applyTargetFieldsSplice generalizes applySubtableSplice's existing
// splice-in-place-or-append machinery from a [targets.<subKey>] subtable's
// byte span to a target block's OWN top-level field span
// ([block.start, block.ownEnd) — see targetBlock's own doc comment). The
// two shapes need separate entry points (this function decides where a
// NEW field is inserted using block.ownEnd rather than a subtable's own
// end, and never needs the "subtable doesn't exist yet, append a whole
// header" branch applySubtableSplice has, since a target's top-level
// field span always exists once the target itself does) — but both reuse
// the exact same target-lookup (findUniqueTargetBlock), field-lookup
// (findSubtableFields, which only needs a [start,end) span, not literally
// a subtable) and edit/applyEdits machinery beneath that split, per this
// task's own instruction not to invent a parallel raw-rewrite mechanism.
func applyTargetFieldsSplice(data []byte, targetID string, fields []field) ([]byte, error) {
	match, err := findUniqueTargetBlock(data, targetID)
	if err != nil {
		return nil, err
	}

	existing := findSubtableFields(data, subtableSpan{start: match.start, end: match.ownEnd})

	var edits []edit
	var appendB strings.Builder
	for _, f := range fields {
		if r, ok := existing[f.key]; ok {
			edits = append(edits, edit{Start: r.Offset, End: r.Offset + r.Length, Replacement: []byte(f.renderValue())})
		} else {
			appendB.WriteString(f.render())
		}
	}
	if appendB.Len() > 0 {
		insertAt := match.ownEnd
		var b strings.Builder
		if insertAt > 0 && data[insertAt-1] != '\n' {
			b.WriteString("\n")
		}
		b.WriteString(appendB.String())
		edits = append(edits, edit{Start: insertAt, End: insertAt, Replacement: []byte(b.String())})
	}

	return applyEdits(data, edits)
}

// verifyOnlyTargetFieldsChanged mirrors verifyOnlyIntendedChange's role
// for applyTargetFieldsSplice: re-decodes both the original and spliced
// bytes and asserts every target OTHER than targetID is byte-identical in
// decoded form, and that targetID's own id and BOTH auth subtables (this
// splice never touches either) are unchanged — the safety net catching a
// splicer bug before anything is written. Deliberately does NOT assert
// host/node/api_port/insecure_tls are unchanged for targetID: those are
// exactly what this splice intends to change.
func verifyOnlyTargetFieldsChanged(oldData, newData []byte, targetID string) error {
	oldRoster, err := Decode(oldData)
	if err != nil {
		return fmt.Errorf("original roster no longer parses (unexpected): %w", err)
	}
	newRoster, err := Decode(newData)
	if err != nil {
		return fmt.Errorf("spliced roster does not parse: %w", err)
	}
	if len(oldRoster.Targets) != len(newRoster.Targets) {
		return fmt.Errorf("target count changed: %d -> %d", len(oldRoster.Targets), len(newRoster.Targets))
	}
	for i := range oldRoster.Targets {
		ot := oldRoster.Targets[i]
		nt := newRoster.Targets[i]
		if ot.ID != nt.ID {
			return fmt.Errorf("target #%d id changed: %q -> %q", i, ot.ID, nt.ID)
		}
		if ot.ID == targetID {
			if ot.Export != nt.Export {
				return fmt.Errorf("target %q: export changed unexpectedly while updating fields", targetID)
			}
			if !tokenAuthEqual(ot.Token, nt.Token) {
				return fmt.Errorf("target %q: token auth changed unexpectedly while updating fields", targetID)
			}
			if !sshAuthEqual(ot.SSH, nt.SSH) {
				return fmt.Errorf("target %q: ssh auth changed unexpectedly while updating fields", targetID)
			}
			continue
		}
		if !targetDeepEqual(ot, nt) {
			return fmt.Errorf("target %q was modified but was not the intended target %q", ot.ID, targetID)
		}
	}
	return nil
}

// field is one key/value pair to write into a subtable or onto a target's
// own top-level fields. Non-literal, non-raw values are rendered as a
// quoted TOML basic string; literal values (armored ciphertext) are
// rendered as a multi-line TOML literal string (”'...”') since age armor
// output is itself multi-line ASCII text; raw values are written verbatim,
// unquoted — for a non-string TOML type (api_port's bare integer,
// insecure_tls's bare boolean), where value already holds the exact TOML
// syntax text (via strconv.Itoa/FormatBool), not a Go string that needs
// quoting.
type field struct {
	key     string
	value   string
	literal bool
	raw     bool
}

func (f field) render() string {
	if f.literal {
		return fmt.Sprintf("%s = '''\n%s'''\n", f.key, ensureTrailingNewline(f.value))
	}
	if f.raw {
		return fmt.Sprintf("%s = %s\n", f.key, f.value)
	}
	return fmt.Sprintf("%s = %s\n", f.key, quoteTOMLBasicString(f.value))
}

func (f field) renderValue() string {
	if f.literal {
		return fmt.Sprintf("'''\n%s'''", ensureTrailingNewline(f.value))
	}
	if f.raw {
		return f.value
	}
	return quoteTOMLBasicString(f.value)
}

func ensureTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

// quoteTOMLBasicString renders s as a TOML basic string that decodes back
// to s for every input. TOML forbids raw control characters in a basic
// string (all of U+0000-U+001F except tab, and U+007F), so each one is
// escaped: by its short form where TOML has one (\b \t \n \f \r), else as
// \uXXXX. Anything else, including U+0080-U+009F and U+2028, is legal raw.
func quoteTOMLBasicString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// spliceSubtable performs the full locked read-modify-write cycle for one
// [targets.<subKey>] block, whose fields hold a secret encrypted under
// passphrase: it proves passphrase against the roster as read under the
// lock, so a secret another process wrote since ProvePassphrase is judged
// too, and a proof still standing costs no derivation.
func spliceSubtable(path, targetID, subKey string, fields []field, passphrase Passphrase) error {
	lock := flock.New(path + ".lock")
	lockCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	locked, err := lock.TryLockContext(lockCtx, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("lock roster %s: %w", path, err)
	}
	if !locked {
		return fmt.Errorf("lock roster %s: timed out waiting for another pveforge process", path)
	}
	defer lock.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read roster %s: %w", path, err)
	}
	current, err := Decode(data)
	if err != nil {
		return fmt.Errorf("read roster %s: %w", path, err)
	}
	if err := passphrase.prove(current, targetID); err != nil {
		return fmt.Errorf("write %s for %q: %w", subKey, targetID, err)
	}

	newData, err := applySubtableSplice(data, targetID, subKey, fields)
	if err != nil {
		return fmt.Errorf("splice %s into target %q: %w", subKey, targetID, err)
	}

	if err := verifyOnlyIntendedChange(data, newData, targetID, subKey); err != nil {
		return fmt.Errorf("safety check failed, roster left untouched: %w", err)
	}

	if err := atomicWrite(path, newData); err != nil {
		return fmt.Errorf("write roster %s: %w", path, err)
	}
	return nil
}

// verifyOnlyIntendedChange re-decodes both the original and spliced bytes
// and asserts that every target other than targetID is byte-identical in
// its decoded form; that targetID's own non-auth fields are unchanged; and
// that targetID's OTHER auth subtable (the one modifiedSubtable is not
// writing) is unchanged too — a splicer bug that corrupts or wipes a
// sibling subtable on the very target being edited must be caught here,
// not just damage to unrelated targets. This is the safety net for the
// splicer: a bug in applySubtableSplice that touches the wrong bytes is
// caught here before anything is written.
func verifyOnlyIntendedChange(oldData, newData []byte, targetID, modifiedSubtable string) error {
	oldRoster, err := Decode(oldData)
	if err != nil {
		return fmt.Errorf("original roster no longer parses (unexpected): %w", err)
	}
	newRoster, err := Decode(newData)
	if err != nil {
		return fmt.Errorf("spliced roster does not parse: %w", err)
	}
	if len(oldRoster.Targets) != len(newRoster.Targets) {
		return fmt.Errorf("target count changed: %d -> %d", len(oldRoster.Targets), len(newRoster.Targets))
	}
	for i := range oldRoster.Targets {
		ot := oldRoster.Targets[i]
		nt := newRoster.Targets[i]
		if ot.ID != nt.ID {
			return fmt.Errorf("target #%d id changed: %q -> %q", i, ot.ID, nt.ID)
		}
		if ot.ID == targetID {
			// Only modifiedSubtable may differ for the target we intended to
			// change; every other field, including the OTHER auth subtable,
			// must be identical.
			if ot.Host != nt.Host || ot.Node != nt.Node || ot.APIPort != nt.APIPort || ot.InsecureTLS != nt.InsecureTLS || ot.Export != nt.Export {
				return fmt.Errorf("target %q: non-auth fields changed unexpectedly", targetID)
			}
			if modifiedSubtable != "token" && !tokenAuthEqual(ot.Token, nt.Token) {
				return fmt.Errorf("target %q: token auth changed unexpectedly while writing %s", targetID, modifiedSubtable)
			}
			if modifiedSubtable != "ssh" && !sshAuthEqual(ot.SSH, nt.SSH) {
				return fmt.Errorf("target %q: ssh auth changed unexpectedly while writing %s", targetID, modifiedSubtable)
			}
			continue
		}
		if !targetDeepEqual(ot, nt) {
			return fmt.Errorf("target %q was modified but was not the intended target %q", ot.ID, targetID)
		}
	}
	return nil
}

func targetDeepEqual(a, b Target) bool {
	if a.ID != b.ID || a.Host != b.Host || a.Node != b.Node || a.APIPort != b.APIPort || a.InsecureTLS != b.InsecureTLS || a.Export != b.Export {
		return false
	}
	return tokenAuthEqual(a.Token, b.Token) && sshAuthEqual(a.SSH, b.SSH)
}

func tokenAuthEqual(a, b *TokenAuth) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}

func sshAuthEqual(a, b *SSHAuth) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".pveforge-roster-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once renamed

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	info, statErr := os.Stat(path)
	mode := os.FileMode(0o600)
	if statErr == nil {
		mode = info.Mode()
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file into place: %w", err)
	}
	return nil
}

// --- AST-range splicing -----------------------------------------------

// edit is a single splice operation: replace data[Start:End] with Replacement.
// End == Start represents a pure insertion at that offset.
type edit struct {
	Start, End  uint32
	Replacement []byte
}

func applySubtableSplice(data []byte, targetID, subKey string, fields []field) ([]byte, error) {
	match, err := findUniqueTargetBlock(data, targetID)
	if err != nil {
		return nil, err
	}

	sub := findSubtable(data, *match, subKey)

	var edits []edit
	if sub == nil {
		// Subtable doesn't exist yet: append the whole thing at the end of
		// the target's block.
		var b strings.Builder
		if match.end > 0 && data[match.end-1] != '\n' {
			b.WriteString("\n")
		}
		b.WriteString("\n[targets." + subKey + "]\n")
		for _, f := range fields {
			b.WriteString(f.render())
		}
		edits = append(edits, edit{Start: match.end, End: match.end, Replacement: []byte(b.String())})
	} else {
		existing := findSubtableFields(data, *sub)
		var appendB strings.Builder
		for _, f := range fields {
			if r, ok := existing[f.key]; ok {
				edits = append(edits, edit{Start: r.Offset, End: r.Offset + r.Length, Replacement: []byte(f.renderValue())})
			} else {
				appendB.WriteString(f.render())
			}
		}
		if appendB.Len() > 0 {
			edits = append(edits, edit{Start: sub.end, End: sub.end, Replacement: []byte(appendB.String())})
		}
	}

	return applyEdits(data, edits)
}

func applyEdits(data []byte, edits []edit) ([]byte, error) {
	if len(edits) == 0 {
		return data, nil
	}
	sorted := append([]edit(nil), edits...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j-1].Start > sorted[j].Start; j-- {
			sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
		}
	}
	var out bytes.Buffer
	cursor := uint32(0)
	for _, e := range sorted {
		if e.Start < cursor {
			return nil, fmt.Errorf("internal error: overlapping edits at offset %d", e.Start)
		}
		out.Write(data[cursor:e.Start])
		out.Write(e.Replacement)
		cursor = e.End
	}
	out.Write(data[cursor:])
	return out.Bytes(), nil
}

// targetBlock is the byte span of one [[targets]] entry: [start, end).
// ownEnd marks where the entry's own scalar fields end and its first
// subtable ([targets.token], [targets.ssh], ...) begins (== end if none).
type targetBlock struct {
	id         string
	start, end uint32
	ownEnd     uint32
}

func findTargetBlocks(data []byte) ([]targetBlock, error) {
	exprs, err := flattenExpressions(data)
	if err != nil {
		return nil, fmt.Errorf("parse roster: %w", err)
	}

	var blocks []targetBlock
	var cur *targetBlock
	closeCurrent := func(end uint32) {
		if cur == nil {
			return
		}
		cur.end = end
		if cur.ownEnd == 0 {
			cur.ownEnd = end
		}
		blocks = append(blocks, *cur)
		cur = nil
	}

	for _, e := range exprs {
		switch e.kind {
		case unstable.ArrayTable:
			if len(e.path) == 1 && e.path[0] == "targets" {
				closeCurrent(backOffLeadingBlankOrComments(data, e.lineStart))
				cur = &targetBlock{start: e.lineStart}
				continue
			}
			if cur != nil && !(len(e.path) > 1 && e.path[0] == "targets") {
				closeCurrent(backOffLeadingBlankOrComments(data, e.lineStart))
			}
		case unstable.Table:
			if cur != nil {
				if len(e.path) > 1 && e.path[0] == "targets" {
					if cur.ownEnd == 0 {
						cur.ownEnd = backOffLeadingBlankOrComments(data, e.lineStart)
					}
				} else {
					closeCurrent(backOffLeadingBlankOrComments(data, e.lineStart))
				}
			}
		case unstable.KeyValue:
			if cur != nil && cur.ownEnd == 0 && len(e.path) == 1 && e.path[0] == "id" {
				if cur.id == "" {
					cur.id = e.valueData
				}
			}
		}
	}
	closeCurrent(uint32(len(data)))

	for i, b := range blocks {
		if b.id == "" {
			return nil, fmt.Errorf("target #%d: missing required field id", i)
		}
	}
	return blocks, nil
}

// findUniqueTargetBlock locates the single target block with id targetID.
// Shared by applyTargetFieldsSplice and applySubtableSplice: the "ambiguous"
// case is live for applySubtableSplice's callers (WriteTokenAuth/WriteSSHAuth
// splice raw bytes without ever calling Decode's own validate()), even though
// it's unreachable via applyTargetFieldsSplice's only caller, UpdateTargetFields
// (which does call Decode first).
func findUniqueTargetBlock(data []byte, targetID string) (*targetBlock, error) {
	blocks, err := findTargetBlocks(data)
	if err != nil {
		return nil, err
	}

	var match *targetBlock
	matches := 0
	for i := range blocks {
		if blocks[i].id == targetID {
			matches++
			match = &blocks[i]
		}
	}
	if matches == 0 {
		return nil, fmt.Errorf("no target with id %q found in roster", targetID)
	}
	if matches > 1 {
		return nil, fmt.Errorf("ambiguous: %d targets with id %q found in roster", matches, targetID)
	}
	return match, nil
}

// subtableSpan is the byte span of one [targets.<key>] table: [start, end).
type subtableSpan struct {
	start, end uint32
}

func findSubtable(data []byte, block targetBlock, subKey string) *subtableSpan {
	exprs, err := flattenExpressionsInRange(data, block.start, block.end)
	if err != nil {
		return nil
	}
	want := []string{"targets", subKey}
	for i, e := range exprs {
		if e.kind != unstable.Table || !pathEqual(e.path, want) {
			continue
		}
		end := block.end
		for _, next := range exprs[i+1:] {
			if next.kind == unstable.Table || next.kind == unstable.ArrayTable {
				end = backOffLeadingBlankOrComments(data, next.lineStart)
				break
			}
		}
		return &subtableSpan{start: e.lineStart, end: end}
	}
	return nil
}

func findSubtableFields(data []byte, sub subtableSpan) map[string]unstable.Range {
	out := map[string]unstable.Range{}
	exprs, err := flattenExpressionsInRange(data, sub.start, sub.end)
	if err != nil {
		return out
	}
	for _, e := range exprs {
		if e.kind == unstable.KeyValue && len(e.path) == 1 {
			out[e.path[0]] = e.valueRaw
		}
	}
	return out
}

func pathEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- flat parse pass -----------------------------------------------

type flatExpr struct {
	kind      unstable.Kind
	path      []string
	lineStart uint32         // headers: start of the header's own line
	valueRaw  unstable.Range // KeyValue only: the value node's raw range
	valueData string         // KeyValue only: decoded string value, if the value is a string
}

func flattenExpressions(data []byte) ([]flatExpr, error) {
	p := &unstable.Parser{}
	p.Reset(data)
	var out []flatExpr
	for p.NextExpression() {
		n := p.Expression()
		switch n.Kind {
		case unstable.Table, unstable.ArrayTable:
			path, first := keyPath(n)
			out = append(out, flatExpr{kind: n.Kind, path: path, lineStart: lineStart(data, first)})
		case unstable.KeyValue:
			path, _ := keyPath(n)
			v := n.Value()
			fe := flatExpr{kind: unstable.KeyValue, path: path, valueRaw: v.Raw}
			if v.Kind == unstable.String {
				fe.valueData = string(v.Data)
			}
			out = append(out, fe)
		}
	}
	if err := p.Error(); err != nil {
		return nil, err
	}
	return out, nil
}

// flattenExpressionsInRange re-parses the whole document (the unstable
// parser has no sub-range entry point) and returns only expressions whose
// KeyValue falls within [start,end), or whose header line starts within
// it. This keeps every call site working in the same coordinate space as
// findTargetBlocks without a second parsing strategy to keep in sync.
func flattenExpressionsInRange(data []byte, start, end uint32) ([]flatExpr, error) {
	p := &unstable.Parser{}
	p.Reset(data)
	var out []flatExpr
	for p.NextExpression() {
		n := p.Expression()
		switch n.Kind {
		case unstable.Table, unstable.ArrayTable:
			path, first := keyPath(n)
			ls := lineStart(data, first)
			if ls < start || ls >= end {
				continue
			}
			out = append(out, flatExpr{kind: n.Kind, path: path, lineStart: ls})
		case unstable.KeyValue:
			path, _ := keyPath(n)
			v := n.Value()
			if v.Raw.Offset < start || v.Raw.Offset >= end {
				continue
			}
			fe := flatExpr{kind: unstable.KeyValue, path: path, valueRaw: v.Raw}
			if v.Kind == unstable.String {
				fe.valueData = string(v.Data)
			}
			out = append(out, fe)
		}
	}
	if err := p.Error(); err != nil {
		return nil, err
	}
	return out, nil
}

func keyPath(n *unstable.Node) ([]string, uint32) {
	it := n.Key()
	var path []string
	var first uint32
	firstSet := false
	for it.Next() {
		kn := it.Node()
		if !firstSet {
			first = kn.Raw.Offset
			firstSet = true
		}
		path = append(path, string(kn.Data))
	}
	return path, first
}

func lineStart(data []byte, offset uint32) uint32 {
	i := int(offset)
	for i > 0 && data[i-1] != '\n' {
		i--
	}
	return uint32(i)
}

// backOffLeadingBlankOrComments takes end, the start offset of a header
// line, and walks it backward over any run of immediately preceding blank
// or comment-only lines. In well-formed TOML the gap between the end of
// one expression and the start of the next header consists only of
// whitespace and full-line comments, and such a comment conventionally
// describes the header that FOLLOWS it (e.g. a note directly above
// "[[targets]]"). Without this, a block/subtable's computed end would
// land after that comment and immediately before the next header — so an
// appended field or subtable would be spliced in between a comment and
// the very thing it describes, which reads as corruption even though no
// existing byte was altered.
func backOffLeadingBlankOrComments(data []byte, end uint32) uint32 {
	for end > 0 {
		i := int(end) - 1
		if data[i] != '\n' {
			// end is not a clean line boundary; nothing more to back off.
			return end
		}
		start := i
		for start > 0 && data[start-1] != '\n' {
			start--
		}
		line := bytes.TrimSpace(data[start:i])
		if len(line) != 0 && line[0] != '#' {
			return end
		}
		end = uint32(start)
	}
	return end
}
