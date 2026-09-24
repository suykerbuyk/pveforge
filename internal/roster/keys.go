package roster

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2/unstable"
)

// rosterKeys is every key a roster may contain, by the table it sits in
// ("" is the document's top level). It must match the toml tags in
// types.go; TestRosterKeys_MatchTheTypes pins that.
var rosterKeys = map[string][]string{
	"":              {"targets"},
	"targets":       {"id", "host", "node", "api_port", "insecure_tls", "export", "token", "ssh"},
	"targets.token": {"id", "secret_enc"},
	"targets.ssh":   {"user", "public_key", "host_key_fingerprint", "private_key_enc"},
}

// checkKeys refuses a roster holding a key that is not one of rosterKeys,
// spelled exactly. go-toml matches keys to fields case-insensitively, and
// the last of several spellings wins: without this, `Export = "token"`
// would open a target, and `export = ""` followed by `Export = "token"`
// would open one that reads as closed. The same trick would silently
// replace host_key_fingerprint or any other field. An unknown key is
// refused too, so a misspelled field (a pin that silently does not apply)
// is never read as absent. Every key is checked, wherever it is written: a
// table header, a dotted key, or an inline table.
func checkKeys(data []byte) error {
	p := &unstable.Parser{}
	p.Reset(data)
	var table []string // the canonical path of the current table header
	for p.NextExpression() {
		n := p.Expression()
		switch n.Kind {
		case unstable.Table, unstable.ArrayTable:
			path, err := checkKeyPath(data, nil, n.Key())
			if err != nil {
				return err
			}
			table = path
		case unstable.KeyValue:
			if err := checkKeyValue(data, table, n); err != nil {
				return err
			}
		}
	}
	return p.Error()
}

// checkKeyValue checks a key/value's key under table, then the keys of an
// inline-table value, or of each inline table in an array value.
func checkKeyValue(data []byte, table []string, kv *unstable.Node) error {
	path, err := checkKeyPath(data, table, kv.Key())
	if err != nil {
		return err
	}
	v := kv.Value()
	switch v.Kind {
	case unstable.InlineTable:
		return checkInlineTable(data, path, v)
	case unstable.Array:
		for it := v.Children(); it.Next(); {
			if c := it.Node(); c.Kind == unstable.InlineTable {
				if err := checkInlineTable(data, path, c); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func checkInlineTable(data []byte, table []string, t *unstable.Node) error {
	for it := t.Children(); it.Next(); {
		if c := it.Node(); c.Kind == unstable.KeyValue {
			if err := checkKeyValue(data, table, c); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkKeyPath checks each part of a (possibly dotted) key under table and
// returns the full canonical path.
func checkKeyPath(data []byte, table []string, key unstable.Iterator) ([]string, error) {
	path := append([]string(nil), table...)
	for key.Next() {
		k := key.Node()
		name := string(k.Data)
		parent := strings.Join(path, ".")
		allowed := rosterKeys[parent] // nil under a scalar: every key is unknown there
		line := 1 + bytes.Count(data[:k.Raw.Offset], []byte("\n"))
		if !slices.Contains(allowed, name) {
			for _, a := range allowed {
				if strings.EqualFold(a, name) {
					return nil, fmt.Errorf("roster line %d: key %q must be spelled %q: roster keys are case-sensitive", line, name, a)
				}
			}
			where := "at the top level"
			if parent != "" {
				where = "in [" + parent + "]"
			}
			return nil, fmt.Errorf("roster line %d: key %q is not a roster key %s", line, name, where)
		}
		path = append(path, name)
	}
	return path, nil
}
