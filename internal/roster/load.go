package roster

import (
	"fmt"
	"os"
	"strings"

	"filippo.io/age/armor"
	toml "github.com/pelletier/go-toml/v2"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
)

// Load reads and validates the roster file at path.
func Load(path string) (*Roster, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read roster %s: %w", path, err)
	}
	return Decode(data)
}

// Decode parses and validates raw roster TOML bytes.
func Decode(data []byte) (*Roster, error) {
	var r Roster
	if err := toml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse roster: %w", err)
	}
	if err := checkKeys(data); err != nil {
		return nil, fmt.Errorf("parse roster: %w", err)
	}
	if err := validate(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ValidateTargetID reports whether id is usable as a target id beyond
// being non-empty: commands print a target id unquoted at the start of
// output lines (vm set's "<target>: field=value"), so an id that kv output
// would have to quote to keep on one line — a control character or line
// break, U+2028/U+2029, leading or trailing whitespace, a leading double
// quote (kvjson.LineUnsafe) — could forge a second line and is refused.
// Applied when a roster is loaded and when a target is appended, so no
// roster pveforge reads or writes can hold one.
func ValidateTargetID(id string) error {
	if kvjson.LineUnsafe(id) {
		return fmt.Errorf("target id %q: must not contain a control character or line break, begin or end with whitespace, or begin with a double quote", id)
	}
	return nil
}

func validate(r *Roster) error {
	seen := make(map[string]bool, len(r.Targets))
	for i, t := range r.Targets {
		if t.ID == "" {
			return fmt.Errorf("target #%d: missing required field id", i)
		}
		if err := ValidateTargetID(t.ID); err != nil {
			return fmt.Errorf("target #%d: %w", i, err)
		}
		if seen[t.ID] {
			return fmt.Errorf("duplicate target id %q", t.ID)
		}
		seen[t.ID] = true
		if t.Host == "" {
			return fmt.Errorf("target %q: missing required field host", t.ID)
		}
		if t.Node == "" {
			return fmt.Errorf("target %q: missing required field node", t.ID)
		}
		if t.Export != "" && t.Export != ExportToken {
			return fmt.Errorf("target %q: export = %q: the only value is %q", t.ID, t.Export, ExportToken)
		}
		if t.Token != nil {
			if t.Token.SecretEnc == "" {
				return fmt.Errorf("target %q: [targets.token] present without secret_enc", t.ID)
			}
			if !looksArmored(t.Token.SecretEnc) {
				return fmt.Errorf("target %q: token secret_enc is not age-armored ciphertext", t.ID)
			}
		}
		if t.SSH != nil {
			if t.SSH.PrivateKeyEnc == "" {
				return fmt.Errorf("target %q: [targets.ssh] present without private_key_enc", t.ID)
			}
			if !looksArmored(t.SSH.PrivateKeyEnc) {
				return fmt.Errorf("target %q: ssh private_key_enc is not age-armored ciphertext", t.ID)
			}
		}
	}
	return nil
}

// looksArmored reports whether s appears to be age's ASCII-armored
// ciphertext format (filippo.io/age/armor), rather than plaintext or some
// other value that was never actually encrypted.
func looksArmored(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), armor.Header)
}

// Find returns the target with the given id, or nil if not present.
func (r *Roster) Find(id string) *Target {
	for i := range r.Targets {
		if r.Targets[i].ID == id {
			return &r.Targets[i]
		}
	}
	return nil
}
