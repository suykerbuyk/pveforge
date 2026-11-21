package probe

import "github.com/suykerbuyk/pveforge/internal/idempotent"

// B1: a VMDestroy built in an ALLOWED function escapes as an idempotent.Op and
// is Applied (destroy with no determination and no gone-proof) while every
// (file, func, target) count stays the same. vmDestroyEscapes must accept
// okUse alone and find at least one problem in every other function.

func okUse(ctx context.Context, client idempotent.VMDestroyClient, vmid int) error {
	op := &idempotent.VMDestroy{Client: client, VMID: vmid}
	if _, err := op.Read(ctx); err != nil {
		return err
	}
	return op.StatusGatedStop(ctx)
}

func applyDirect(ctx context.Context, client idempotent.VMDestroyClient, vmid int) error {
	op := &idempotent.VMDestroy{Client: client, VMID: vmid}
	return op.Apply(ctx)
}

func helperEscape(ctx context.Context, client idempotent.VMDestroyClient, vmid int) error {
	op := &idempotent.VMDestroy{Client: client, VMID: vmid}
	return applyOp(ctx, op)
}

func runEscape(ctx context.Context, client idempotent.VMDestroyClient, vmid int, rp, key string) error {
	op := &idempotent.VMDestroy{Client: client, VMID: vmid}
	return idempotent.Run(ctx, rp, key, op, false)
}

func methodValueEscape(ctx context.Context, client idempotent.VMDestroyClient, vmid int) error {
	op := &idempotent.VMDestroy{Client: client, VMID: vmid}
	f := op.Apply
	_ = f
	return nil
}

func ifaceEscape(client idempotent.VMDestroyClient, vmid int) idempotent.Op {
	op := &idempotent.VMDestroy{Client: client, VMID: vmid}
	var o idempotent.Op
	o = op
	return o
}

func returnEscape(client idempotent.VMDestroyClient, vmid int) *idempotent.VMDestroy {
	op := &idempotent.VMDestroy{Client: client, VMID: vmid}
	return op
}

func newShape(client idempotent.VMDestroyClient) error {
	op := new(idempotent.VMDestroy)
	_ = client
	return op.StatusGatedStop(context.Background())
}

func directPass(ctx context.Context, client idempotent.VMDestroyClient, vmid int) error {
	return applyOp(ctx, &idempotent.VMDestroy{Client: client, VMID: vmid})
}

func storeEscape(h *holder, client idempotent.VMDestroyClient, vmid int) {
	op := &idempotent.VMDestroy{Client: client, VMID: vmid}
	h.op = op
}

func applyOp(ctx context.Context, o idempotent.Op) error { return o.Apply(ctx) }
