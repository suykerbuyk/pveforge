package probe

// The pinned funnels: a new caller of the verb's body (which never takes the
// object lock), and a re-registration of a destroying command tree.
func funnels(ctx context.Context, root *cobra.Command, d destroyDeps, in destroyInput) {
	_ = runVMDestroy(ctx, d, in)
	root.AddCommand(newVMDestroyCmd())
	root.AddCommand(newAPICmd())
	root.AddCommand(newHarnessVMDestroyCmd())
}
