package sshexec

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTapDeviceName(t *testing.T) {
	if got, want := TapDeviceName(100, 0), "tap100i0"; got != want {
		t.Errorf("TapDeviceName(100, 0) = %q, want %q", got, want)
	}
	if got, want := TapDeviceName(205, 3), "tap205i3"; got != want {
		t.Errorf("TapDeviceName(205, 3) = %q, want %q", got, want)
	}
}

func dialForBridgeTest(t *testing.T, fs *fakeServer) *Client {
	t.Helper()
	kp, pub := clientKeypair(t)
	fs.allowPublicKey(pub)
	fs.Start(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, fs.addr, "root", kp.PrivateKeyPEM, acceptAnyHostKey())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestTapLinkState_ExistsAndIsolated(t *testing.T) {
	fs := newFakeServer(t)
	var receivedCmd string
	fs.handleExec = func(cmd string) (string, string, int) {
		receivedCmd = cmd
		return `[{"ifindex":42,"ifname":"tap100i0","isolated":true}]` + "\n", "", 0
	}
	client := dialForBridgeTest(t, fs)

	state, err := client.TapLinkState(context.Background(), "tap100i0")
	if err != nil {
		t.Fatalf("TapLinkState: %v", err)
	}
	if !state.Exists || !state.Isolated {
		t.Errorf("state = %+v, want {Exists:true Isolated:true}", state)
	}
	if !strings.Contains(receivedCmd, "bridge -j link show dev 'tap100i0'") {
		t.Errorf("unexpected remote command: %q", receivedCmd)
	}
}

func TestTapLinkState_ExistsNotIsolated(t *testing.T) {
	fs := newFakeServer(t)
	fs.handleExec = func(cmd string) (string, string, int) {
		return `[{"ifindex":42,"ifname":"tap100i0","isolated":false}]` + "\n", "", 0
	}
	client := dialForBridgeTest(t, fs)

	state, err := client.TapLinkState(context.Background(), "tap100i0")
	if err != nil {
		t.Fatalf("TapLinkState: %v", err)
	}
	if !state.Exists || state.Isolated {
		t.Errorf("state = %+v, want {Exists:true Isolated:false}", state)
	}
}

func TestTapLinkState_DoesNotExist_NonZeroExit(t *testing.T) {
	fs := newFakeServer(t)
	fs.handleExec = func(cmd string) (string, string, int) {
		return "", `Device "tap100i0" does not exist.` + "\n", 1
	}
	client := dialForBridgeTest(t, fs)

	state, err := client.TapLinkState(context.Background(), "tap100i0")
	if err != nil {
		t.Fatalf("TapLinkState: %v", err)
	}
	if state.Exists {
		t.Errorf("state = %+v, want Exists:false", state)
	}
}

func TestTapLinkState_DoesNotExist_EmptyArray(t *testing.T) {
	fs := newFakeServer(t)
	fs.handleExec = func(cmd string) (string, string, int) {
		return "[]\n", "", 0
	}
	client := dialForBridgeTest(t, fs)

	state, err := client.TapLinkState(context.Background(), "tap100i0")
	if err != nil {
		t.Fatalf("TapLinkState: %v", err)
	}
	if state.Exists {
		t.Errorf("state = %+v, want Exists:false", state)
	}
}

func TestTapLinkState_OtherFailureIsAnError(t *testing.T) {
	fs := newFakeServer(t)
	fs.handleExec = func(cmd string) (string, string, int) {
		return "", "bridge: command not found\n", 127
	}
	client := dialForBridgeTest(t, fs)

	_, err := client.TapLinkState(context.Background(), "tap100i0")
	if err == nil {
		t.Fatal("expected an error for a failure unrelated to a missing tap")
	}
	if !strings.Contains(err.Error(), "command not found") {
		t.Errorf("expected the error to surface remote stderr, got: %v", err)
	}
}

func TestTapLinkState_RequiresTapName(t *testing.T) {
	c := &Client{}
	if _, err := c.TapLinkState(context.Background(), ""); err == nil {
		t.Fatal("expected an error for an empty tap name")
	}
}

func TestSetBridgePortIsolated_On(t *testing.T) {
	fs := newFakeServer(t)
	var receivedCmd string
	fs.handleExec = func(cmd string) (string, string, int) {
		receivedCmd = cmd
		return "", "", 0
	}
	client := dialForBridgeTest(t, fs)

	if err := client.SetBridgePortIsolated(context.Background(), "tap100i0", true); err != nil {
		t.Fatalf("SetBridgePortIsolated: %v", err)
	}
	if !strings.Contains(receivedCmd, "bridge link set dev 'tap100i0' isolated on") {
		t.Errorf("unexpected remote command: %q", receivedCmd)
	}
}

func TestSetBridgePortIsolated_Off(t *testing.T) {
	fs := newFakeServer(t)
	var receivedCmd string
	fs.handleExec = func(cmd string) (string, string, int) {
		receivedCmd = cmd
		return "", "", 0
	}
	client := dialForBridgeTest(t, fs)

	if err := client.SetBridgePortIsolated(context.Background(), "tap100i0", false); err != nil {
		t.Fatalf("SetBridgePortIsolated: %v", err)
	}
	if !strings.Contains(receivedCmd, "bridge link set dev 'tap100i0' isolated off") {
		t.Errorf("unexpected remote command: %q", receivedCmd)
	}
}

func TestSetBridgePortIsolated_RemoteFailure(t *testing.T) {
	fs := newFakeServer(t)
	fs.handleExec = func(cmd string) (string, string, int) {
		return "", `Device "tap100i0" does not exist.` + "\n", 1
	}
	client := dialForBridgeTest(t, fs)

	err := client.SetBridgePortIsolated(context.Background(), "tap100i0", true)
	if err == nil {
		t.Fatal("expected an error when the remote bridge command fails")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("expected the error to surface remote stderr, got: %v", err)
	}
}

func TestSetBridgePortIsolated_RequiresTapName(t *testing.T) {
	c := &Client{}
	if err := c.SetBridgePortIsolated(context.Background(), "", true); err == nil {
		t.Fatal("expected an error for an empty tap name")
	}
}
