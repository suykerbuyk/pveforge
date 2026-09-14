package main

import "testing"

func TestNewRootCmd_RegistersSubcommands(t *testing.T) {
	root := newRootCmd()
	names := map[string]bool{}
	for _, c := range root.Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{"roster", "bootstrap", "vm", "node", "storage", "network"} {
		if !names[want] {
			t.Errorf("expected root command to register a %q subcommand, got: %v", want, names)
		}
	}
}
