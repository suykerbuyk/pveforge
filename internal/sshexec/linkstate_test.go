package sshexec

import (
	"context"
	"strings"
	"testing"
)

func TestLinkState_ExistsAndUp_Operstate(t *testing.T) {
	fs := newFakeServer(t)
	var receivedCmd string
	fs.handleExec = func(cmd string) (string, string, int) {
		receivedCmd = cmd
		return `[{"ifindex":2,"ifname":"vmbr0","flags":["BROADCAST","MULTICAST"],"operstate":"UP"}]` + "\n", "", 0
	}
	client := dialForBridgeTest(t, fs)

	state, err := client.LinkState(context.Background(), "vmbr0")
	if err != nil {
		t.Fatalf("LinkState: %v", err)
	}
	if !state.Exists || !state.Up {
		t.Errorf("state = %+v, want {Exists:true Up:true}", state)
	}
	if !strings.Contains(receivedCmd, "ip -j link show dev 'vmbr0'") {
		t.Errorf("unexpected remote command: %q", receivedCmd)
	}
	if strings.Contains(receivedCmd, "bridge -j") {
		t.Errorf("expected ip -j, not bridge -j: %q", receivedCmd)
	}
}

func TestLinkState_ExistsAndUp_FlagsOnly(t *testing.T) {
	fs := newFakeServer(t)
	fs.handleExec = func(cmd string) (string, string, int) {
		return `[{"ifindex":2,"ifname":"vmbr0","flags":["BROADCAST","MULTICAST","UP"],"operstate":"UNKNOWN"}]` + "\n", "", 0
	}
	client := dialForBridgeTest(t, fs)

	state, err := client.LinkState(context.Background(), "vmbr0")
	if err != nil {
		t.Fatalf("LinkState: %v", err)
	}
	if !state.Exists || !state.Up {
		t.Errorf("state = %+v, want {Exists:true Up:true}", state)
	}
}

func TestLinkState_ExistsButDown(t *testing.T) {
	fs := newFakeServer(t)
	fs.handleExec = func(cmd string) (string, string, int) {
		return `[{"ifindex":3,"ifname":"vmbr1","flags":["BROADCAST","MULTICAST"],"operstate":"DOWN"}]` + "\n", "", 0
	}
	client := dialForBridgeTest(t, fs)

	state, err := client.LinkState(context.Background(), "vmbr1")
	if err != nil {
		t.Fatalf("LinkState: %v", err)
	}
	if !state.Exists {
		t.Errorf("state = %+v, want Exists:true", state)
	}
	if state.Up {
		t.Errorf("state = %+v, want Up:false", state)
	}
}

func TestLinkState_DoesNotExist_NonZeroExit(t *testing.T) {
	fs := newFakeServer(t)
	fs.handleExec = func(cmd string) (string, string, int) {
		return "", `Device "vmbr9" does not exist.` + "\n", 1
	}
	client := dialForBridgeTest(t, fs)

	state, err := client.LinkState(context.Background(), "vmbr9")
	if err != nil {
		t.Fatalf("LinkState: %v", err)
	}
	if state.Exists {
		t.Errorf("state = %+v, want Exists:false", state)
	}
}

func TestLinkState_DoesNotExist_EmptyArray(t *testing.T) {
	fs := newFakeServer(t)
	fs.handleExec = func(cmd string) (string, string, int) {
		return "[]\n", "", 0
	}
	client := dialForBridgeTest(t, fs)

	state, err := client.LinkState(context.Background(), "vmbr9")
	if err != nil {
		t.Fatalf("LinkState: %v", err)
	}
	if state.Exists {
		t.Errorf("state = %+v, want Exists:false", state)
	}
}

func TestLinkState_OtherFailureIsAnError(t *testing.T) {
	fs := newFakeServer(t)
	fs.handleExec = func(cmd string) (string, string, int) {
		return "", "ip: command not found\n", 127
	}
	client := dialForBridgeTest(t, fs)

	_, err := client.LinkState(context.Background(), "vmbr0")
	if err == nil {
		t.Fatal("expected an error for a failure unrelated to a missing interface")
	}
	if !strings.Contains(err.Error(), "command not found") {
		t.Errorf("expected the error to surface remote stderr, got: %v", err)
	}
}

func TestLinkState_RequiresIfaceName(t *testing.T) {
	c := &Client{}
	if _, err := c.LinkState(context.Background(), ""); err == nil {
		t.Fatal("expected an error for an empty interface name")
	}
}
