package probe

import nethttp "net/http"

// cmd/pveforge/harness_vm.go's destroy, pasted into a new command, with
// net/http ALIASED to prove the ImportPath target is alias-proof.
func harnessPaste(ctx context.Context, client *pve.RoutedClient, node string, vmid int) {
	params := url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"1"}}
	_, _ = rawUPID(ctx, client, nethttp.MethodDelete, vmSubPath(node, vmid, ""), params)
}
