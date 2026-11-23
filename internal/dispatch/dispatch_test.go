package dispatch

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestGate_ClosedThenOpen(t *testing.T) {
	ctx, g := With(context.Background())
	if Opened(ctx) || g.open.Load() {
		t.Fatal("a new gate must be closed")
	}
	base := errors.New("x")
	err := Refuse(ctx, base)
	if !IsRefused(err) || !errors.Is(err, base) {
		t.Fatalf("closed gate: %v", err)
	}
	Open(ctx)
	if !Opened(ctx) {
		t.Fatal("Open did not open")
	}
	if got := Refuse(ctx, base); IsRefused(got) || got != base {
		t.Fatalf("an open gate must return the error unchanged, got %v", got)
	}
	Open(ctx) // idempotent
	if !Opened(ctx) {
		t.Fatal("idempotence")
	}
}

func TestRefuse_NoGateAndNil(t *testing.T) {
	e := errors.New("x")
	if got := Refuse(context.Background(), e); IsRefused(got) {
		t.Fatal("a context with no gate must not claim a refusal")
	}
	ctx, _ := With(context.Background())
	if Refuse(ctx, nil) != nil {
		t.Fatal("nil stays nil")
	}
	Open(context.Background()) // no gate: no panic
	if Opened(context.Background()) || Has(context.Background()) {
		t.Fatal("no gate")
	}
}

func TestUnobserve(t *testing.T) {
	e := Unobserve(errors.New("timed out"))
	if !IsUnobserved(fmt.Errorf("wrap: %w", e)) || e.Error() != "timed out" {
		t.Fatal("unobserved")
	}
	if IsUnobserved(errors.New("plain")) {
		t.Fatal("plain error is not unobserved")
	}
	if Unobserve(nil) != nil {
		t.Fatal("nil stays nil")
	}
	cause := errors.New("cause")
	if !errors.Is(Unobserve(cause), cause) {
		t.Fatal("the chain survives")
	}
}

// G2: the mechanism is CLOSED. A foreign type that happens to have a method
// named DispatchUnobserved (what the old open interface read) is not an
// unobserved dispatch: it is an ordinary error, exit 1.
type foreignMarker struct{}

func (foreignMarker) Error() string       { return "foreign" }
func (foreignMarker) DispatchUnobserved() {}

func TestIsUnobserved_AForeignTypeIsNotOne(t *testing.T) {
	if IsUnobserved(foreignMarker{}) || IsUnobserved(fmt.Errorf("w: %w", foreignMarker{})) {
		t.Fatal("a foreign type with a DispatchUnobserved method was read as an unobserved dispatch")
	}
	if !IsUnobserved(Unobserve(foreignMarker{})) {
		t.Fatal("control: Unobserve of the same error is one")
	}
}
