package pve

import (
	"errors"
	"testing"
)

// ParseClusterStatusQuorate: quorate is corosync's majority bit; a clustered
// node reports it, a standalone node (no cluster entry) is treated quorate, and
// anything a healthy PVE never prints fails closed.
func TestParseClusterStatusQuorate(t *testing.T) {
	good := func(quorate int) string {
		return `[{"type":"cluster","name":"pvh","nodes":2,"quorate":` +
			itoa(quorate) + `},{"type":"node","name":"pvh-n1","local":1}]`
	}
	for name, tc := range map[string]struct {
		body string
		want bool
	}{
		"clustered quorate":             {good(1), true},
		"clustered not quorate":         {good(0), false},
		"standalone (node, no cluster)": {`[{"type":"node","name":"solo","local":1}]`, true},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseClusterStatusQuorate([]byte(tc.body))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("quorate = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseClusterStatusQuorate_FailsClosed(t *testing.T) {
	for name, bad := range map[string]string{
		"null":                 `null`,
		"empty array":          `[]`,                                     // no cluster AND no node entry -> fail-closed, never standalone-quorate
		"nodes only no node":   `[{"type":"storage","storage":"local"}]`, // neither cluster nor node
		"not json":             `pvesh: 596 no quorum`,
		"data envelope":        `{"data":[{"type":"cluster","quorate":1}]}`,
		"an object":            `{"type":"cluster","quorate":1}`,
		"trailing data":        `[{"type":"cluster","quorate":1}] []`,
		"a null entry":         `[null]`,
		"two cluster entries":  `[{"type":"cluster","quorate":1},{"type":"cluster","quorate":0}]`,
		"quorate flag absent":  `[{"type":"cluster","name":"pvh"}]`,
		"quorate not numeric":  `[{"type":"cluster","quorate":"1"}]`,
		"quorate fractional":   `[{"type":"cluster","quorate":1.5}]`,
		"quorate out of range": `[{"type":"cluster","quorate":2}]`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseClusterStatusQuorate([]byte(bad))
			if err == nil || !errors.Is(err, ErrUnverifiableRead) || got {
				t.Fatalf("ParseClusterStatusQuorate(%q) = %v, %v; want false + ErrUnverifiableRead", bad, got, err)
			}
		})
	}
}

// itoa avoids a strconv import in the fixture builder.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	return "1"
}
