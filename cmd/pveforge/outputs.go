package main

// outputSchema is a command's rendered report. Kind is "object" (Keys lists
// what the verb renders) or "passthrough" (PVE's own object, whose shape is
// PVE's, not pveforge's).
type outputSchema struct {
	Kind string      `json:"kind"`
	Keys []outputKey `json:"keys,omitempty"`
}

// outputKey is one key of a rendered report: its JSON kind, whether it is
// optional (omitempty: absent when empty), and, for an object or an array of
// objects, its nested keys.
type outputKey struct {
	Name     string      `json:"name"`
	Kind     string      `json:"kind"`
	Optional bool        `json:"optional,omitempty"`
	Keys     []outputKey `json:"keys,omitempty"`
}

// outputOf is a command's golden output (outputs_table.go), nil for a command
// that renders nothing; Kind "none" is a verb with no structured output.
func outputOf(path string) *outputSchema {
	o, ok := outputTable[path]
	if !ok {
		return nil
	}
	return &o
}
