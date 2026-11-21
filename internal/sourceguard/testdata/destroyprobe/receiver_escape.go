package idempotent

// FO-1: VMDestroy's own methods reaching Apply through the receiver, with no
// new T-ref and no count change. vmDestroyReceiverEscapes must accept Read
// alone and flag every other non-Apply method here.

func (op *VMDestroy) Read(ctx context.Context) (string, error) {
	cfg, ok, err := op.fetchVMConfig(ctx)
	_, _ = cfg, ok
	return fmt.Sprint(op.VMID, op.Client), err
}

func (op *VMDestroy) ReadApply(ctx context.Context) (string, error) {
	return "", op.Apply(ctx)
}

func (op *VMDestroy) ReadRun(ctx context.Context) (string, error) {
	_, err := Run(ctx, "", lock.ObjectKey{}, op, false)
	return "", err
}

func (op *VMDestroy) StopApply(ctx context.Context) error {
	if err := op.Apply(ctx); err != nil {
		return err
	}
	return nil
}

func (op *VMDestroy) PassReceiver(ctx context.Context) error {
	return applyOp(ctx, op)
}

func (op *VMDestroy) ReturnReceiver() Op {
	return op
}

func (op *VMDestroy) MethodValue() func(context.Context) error {
	return op.Apply
}

func (op *VMDestroy) Apply(ctx context.Context) error { return nil }
