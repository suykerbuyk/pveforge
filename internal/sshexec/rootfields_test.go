package sshexec

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRootOnlyFields_SeededWithOnlyArgs(t *testing.T) {
	if !RootOnlyFields["args"] {
		t.Fatal(`expected "args" in RootOnlyFields`)
	}
	if len(RootOnlyFields) != 1 {
		t.Fatalf("RootOnlyFields should be seeded with only the empirically verified field, got: %+v", RootOnlyFields)
	}
}

func TestIsRootOnlyWriteError(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("HTTP 500: only root can set 'args' config"), true},
		{errors.New("HTTP 500: only root can set 'rng' config"), true},
		{errors.New("some unrelated failure"), false},
	}
	for _, c := range cases {
		if got := IsRootOnlyWriteError(c.err); got != c.want {
			t.Errorf("IsRootOnlyWriteError(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestSetVMConfigField(t *testing.T) {
	fs := newFakeServer(t)
	kp, pub := clientKeypair(t)
	fs.allowPublicKey(pub)

	var receivedCmd string
	fs.handleExec = func(cmd string) (string, string, int) {
		receivedCmd = cmd
		return "", "", 0
	}
	fs.Start(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, fs.addr, "root", kp.PrivateKeyPEM, acceptAnyHostKey())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if err := client.SetVMConfigField(ctx, 100, "args", "-device foo"); err != nil {
		t.Fatalf("SetVMConfigField: %v", err)
	}
	if receivedCmd != `qm set '100' --args '-device foo'` {
		t.Fatalf("unexpected remote command: %q", receivedCmd)
	}
}

func TestSetVMConfigField_RemoteFailure(t *testing.T) {
	fs := newFakeServer(t)
	kp, pub := clientKeypair(t)
	fs.allowPublicKey(pub)
	fs.handleExec = func(cmd string) (string, string, int) {
		return "", "only root can set 'args' config\n", 1
	}
	fs.Start(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, fs.addr, "root", kp.PrivateKeyPEM, acceptAnyHostKey())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	err = client.SetVMConfigField(ctx, 100, "args", "-device foo")
	if err == nil {
		t.Fatal("expected error from non-zero remote exit")
	}
	if !IsRootOnlyWriteError(err) {
		t.Fatalf("expected IsRootOnlyWriteError to recognize this failure: %v", err)
	}
}

func TestSetVMConfigField_RejectsUnsafeFieldName(t *testing.T) {
	fs := newFakeServer(t)
	kp, pub := clientKeypair(t)
	fs.allowPublicKey(pub)
	fs.Start(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, fs.addr, "root", kp.PrivateKeyPEM, acceptAnyHostKey())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	cases := []string{"args; rm -rf /", "args'; echo pwned", "", "with space"}
	for _, field := range cases {
		if err := client.SetVMConfigField(ctx, 100, field, "value"); err == nil {
			t.Fatalf("expected rejection of unsafe field name %q", field)
		}
	}
}

func TestIsValidFieldName(t *testing.T) {
	valid := []string{"args", "rng0", "some_field", "A1"}
	for _, v := range valid {
		if !isValidFieldName(v) {
			t.Errorf("isValidFieldName(%q) = false, want true", v)
		}
	}
	invalid := []string{"", "has space", "semi;colon", "quote'", "dash-name"}
	for _, v := range invalid {
		if isValidFieldName(v) {
			t.Errorf("isValidFieldName(%q) = true, want false", v)
		}
	}
}
