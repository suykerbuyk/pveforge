package roster

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
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
func WriteTokenAuth(path, targetID string, w TokenWrite, passphrase string) error {
	if w.TokenID == "" {
		return fmt.Errorf("write token auth for %q: token id is required", targetID)
	}
	secretEnc, err := EncryptString(w.SecretPlaintext, passphrase)
	if err != nil {
		return fmt.Errorf("encrypt token secret for %q: %w", targetID, err)
	}
	fields := []field{
		{key: "id", value: w.TokenID},
		{key: "secret_enc", value: secretEnc, literal: true},
	}
	return spliceSubtable(path, targetID, "token", fields)
}

// WriteSSHAuth encrypts w.PrivateKeyPlaintext and splices a [targets.ssh]
// block for the target identified by targetID into the roster at path.
// Same in-place-vs-append and non-clobbering behavior as WriteTokenAuth.
func WriteSSHAuth(path, targetID string, w SSHWrite, passphrase string) error {
	if w.User == "" {
		return fmt.Errorf("write ssh auth for %q: user is required", targetID)
	}
	keyEnc, err := EncryptString(w.PrivateKeyPlaintext, passphrase)
	if err != nil {
		return fmt.Errorf("encrypt ssh private key for %q: %w", targetID, err)
	}
	fields := []field{
		{key: "user", value: w.User},
		{key: "public_key", value: w.PublicKey},
		{key: "private_key_enc", value: keyEnc, literal: true},
	}
	return spliceSubtable(path, targetID, "ssh", fields)
}

// field is one key/value pair to write into a subtable. Non-literal values
// are rendered as a quoted TOML basic string; literal values (armored
// ciphertext) are rendered as a multi-line TOML literal string (”'...”')
// since age armor output is itself multi-line ASCII text.
type field struct {
	key     string
	value   string
	literal bool
}

func (f field) render() string {
	if f.literal {
		return fmt.Sprintf("%s = '''\n%s'''\n", f.key, ensureTrailingNewline(f.value))
	}
	return fmt.Sprintf("%s = %s\n", f.key, quoteTOMLBasicString(f.value))
}

func (f field) renderValue() string {
	if f.literal {
		return fmt.Sprintf("'''\n%s'''", ensureTrailingNewline(f.value))
	}
	return quoteTOMLBasicString(f.value)
}

func ensureTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

func quoteTOMLBasicString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// spliceSubtable performs the full locked read-modify-write cycle for one
// [targets.<subKey>] block.
func spliceSubtable(path, targetID, subKey string, fields []field) error {
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
			if ot.Host != nt.Host || ot.Node != nt.Node || ot.APIPort != nt.APIPort || ot.InsecureTLS != nt.InsecureTLS {
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
	if a.ID != b.ID || a.Host != b.Host || a.Node != b.Node || a.APIPort != b.APIPort || a.InsecureTLS != b.InsecureTLS {
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
						cur.ownEnd = e.lineStart
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
