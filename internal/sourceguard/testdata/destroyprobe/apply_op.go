package probe

import idem "github.com/suykerbuyk/pveforge/internal/idempotent"

// op.Apply from a new command: StatusGatedStop + DELETE + a nil wait taken as
// success, with no determination and no gone-proof. The idempotent import is
// ALIASED to prove the ImportPath target is alias-proof.
func applyOp(ctx context.Context, c idem.VMDestroyClient, v int, roster, key string) error {
	op := &idem.VMDestroy{Client: c, VMID: v}
	if err := op.Apply(ctx); err != nil {
		return err
	}
	return idem.Run(ctx, roster, key, &idem.VMDestroy{Client: c, VMID: v}, false)
}
