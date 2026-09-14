package pve

import (
	"context"
	"fmt"
	"time"

	proxmox "github.com/luthermonson/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// sshPort is the SSH port RoutedClient dials for the standing root-only
// field vector. roster.Target has no per-target SSH port field today (the
// bootstrap flow's own --ssh-port is a CLI-only input, never persisted) —
// hardcoded to the standard port rather than adding roster schema for a
// case nobody has hit yet; a real future need should add SSHPort to
// roster.Target instead of working around it here.
//
// A var, not a const, purely so this package's own tests can point it at
// an in-process fake SSH server's ephemeral port; production code never
// changes it.
var sshPort = 22

// RoutedClient is pveforge's single entry point for mutating one target's
// VM config: callers call SetVMConfigField and never need to know or care
// whether a given field went over the REST API or the standing SSH vector
// (per the auth-bootstrap task's resolved design) — RoutedClient decides
// via sshexec.RootOnlyFields.
type RoutedClient struct {
	rest       *Client
	target     *roster.Target
	passphrase string

	// ssh is dialed lazily, only on first root-only-field write — most
	// callers never touch one, and dialing SSH eagerly for every
	// operation would be wasted work and unnecessary root-credential
	// exposure.
	ssh *sshexec.Client
}

// NewRoutedClient builds the REST side eagerly (needed for the large
// majority of operations) and defers the SSH connection until a
// root-only field actually needs it.
func NewRoutedClient(t *roster.Target, passphrase string) (*RoutedClient, error) {
	rest, err := NewClientForTarget(t, passphrase)
	if err != nil {
		return nil, err
	}
	return &RoutedClient{rest: rest, target: t, passphrase: passphrase}, nil
}

// Close releases the lazily-dialed SSH connection, if one was opened. A
// no-op otherwise (the REST side has no persistent connection to close).
func (c *RoutedClient) Close() error {
	if c.ssh != nil {
		return c.ssh.Close()
	}
	return nil
}

// Node returns the PVE node name this client is scoped to (its target's
// roster.Target.Node). Needed by callers that call one of the node-
// parameterized typed getters (GetVM, GetStorage, ...) against the same
// target a RoutedClient already wraps — e.g. internal/device's resolvers,
// which read a VM's current config via GetVM before writing a merged
// value back via SetVMConfigField (which, unlike GetVM, resolves the node
// internally and takes no node parameter).
func (c *RoutedClient) Node() string {
	return c.target.Node
}

// --- typed reads: thin pass-throughs to the REST client ------------------
//
// None of nodes.go/vms.go/storage.go/networks.go's getters can ever hit a
// root-only field (that restriction is REST-write-specific — see
// vmconfig.go), so there is nothing for RoutedClient to route: every read
// always goes over REST. These exist so a caller holding a *RoutedClient
// (the common case — one object per target, for both reads and routed
// writes) never needs to reach into an unexported field to get at them.

func (c *RoutedClient) GetNode(ctx context.Context, node string) (*proxmox.Node, error) {
	return c.rest.GetNode(ctx, node)
}

func (c *RoutedClient) GetNodes(ctx context.Context) (proxmox.NodeStatuses, error) {
	return c.rest.GetNodes(ctx)
}

func (c *RoutedClient) GetVM(ctx context.Context, node string, vmid int) (*proxmox.VirtualMachine, error) {
	return c.rest.GetVM(ctx, node, vmid)
}

func (c *RoutedClient) GetVMs(ctx context.Context, node string) (proxmox.VirtualMachines, error) {
	return c.rest.GetVMs(ctx, node)
}

func (c *RoutedClient) GetStorage(ctx context.Context, node, name string) (*proxmox.Storage, error) {
	return c.rest.GetStorage(ctx, node, name)
}

func (c *RoutedClient) GetStorages(ctx context.Context, node string) (proxmox.Storages, error) {
	return c.rest.GetStorages(ctx, node)
}

func (c *RoutedClient) GetStorageVolumes(ctx context.Context, node, storage string) ([]*proxmox.StorageContent, error) {
	return c.rest.GetStorageVolumes(ctx, node, storage)
}

func (c *RoutedClient) GetNetworkInterface(ctx context.Context, node, iface string) (*proxmox.NodeNetwork, error) {
	return c.rest.GetNetworkInterface(ctx, node, iface)
}

func (c *RoutedClient) GetNetworkInterfaces(ctx context.Context, node string, ifaceType ...string) (proxmox.NodeNetworks, error) {
	return c.rest.GetNetworkInterfaces(ctx, node, ifaceType...)
}

// SetVMConfigField sets one VM config field on this target's VM, routing
// over REST or the standing SSH vector depending on
// sshexec.RootOnlyFields — the caller never chooses.
//
// A REST write that unexpectedly comes back with PVE's own root-only
// error text (sshexec.IsRootOnlyWriteError) — a field not yet in that
// registry — is retried once over SSH as a safety net, rather than
// surfacing a hard failure for a case the registry just hasn't caught up
// with yet. If the SSH retry also fails, the ORIGINAL REST error is
// returned, since that's the one carrying PVE's own diagnostic text.
func (c *RoutedClient) SetVMConfigField(ctx context.Context, vmid int, field, value string) error {
	if sshexec.RootOnlyFields[field] {
		return c.setViaSSH(ctx, vmid, field, value)
	}

	err := c.rest.SetVMConfigField(ctx, c.target.Node, vmid, field, value)
	if err != nil && sshexec.IsRootOnlyWriteError(err) {
		if sshErr := c.setViaSSH(ctx, vmid, field, value); sshErr == nil {
			return nil
		}
	}
	return err
}

// setViaSSH dials the standing SSH vector on first use and reuses it for
// every subsequent root-only-field write on this RoutedClient — but never
// reuses a connection once it's found to be dead (see sshConnectionHealthy).
func (c *RoutedClient) setViaSSH(ctx context.Context, vmid int, field, value string) error {
	if c.ssh == nil {
		if err := c.dialSSH(ctx); err != nil {
			return fmt.Errorf("set vm %d field %q: %w", vmid, field, err)
		}
	}

	err := c.ssh.SetVMConfigField(ctx, vmid, field, value)
	if err != nil && !c.sshConnectionHealthy() {
		// The cached connection is presumed dead — a transient network
		// drop, a NAT idle timeout, sshd's ClientAliveInterval, or a
		// remote reboot after this connection was established. Without
		// this, every later write on this RoutedClient would keep
		// reusing the same known-broken *sshexec.Client forever (a new
		// SSH channel over a dead client fails NewSession every time,
		// self-healing never happens). Discarding it here means the next
		// call's c.ssh == nil check redials from scratch.
		_ = c.ssh.Close()
		c.ssh = nil
	}
	return err
}

// dialSSH establishes c.ssh from the target's persisted, pinned SSH auth.
func (c *RoutedClient) dialSSH(ctx context.Context) error {
	if c.target.SSH == nil {
		return fmt.Errorf("requires the standing SSH vector, but target %q has no ssh auth; run `pveforge bootstrap` first", c.target.ID)
	}
	if c.target.SSH.HostKeyFingerprint == "" {
		return fmt.Errorf("target %q has ssh auth but no pinned host key fingerprint on file; re-bootstrap to establish one", c.target.ID)
	}

	// Deliberately decrypts ONLY the SSH key, not via t.Resolve — see
	// NewClientForTarget's doc comment for the same reasoning in the
	// other direction (an unrelated token-decrypt failure must not block
	// an SSH-only operation).
	privateKeyPEM, err := roster.DecryptString(c.target.SSH.PrivateKeyEnc, c.passphrase)
	if err != nil {
		return fmt.Errorf("decrypt ssh key for %q: %w", c.target.ID, err)
	}
	cb, err := sshexec.PinnedHostKeyCallback(c.target.SSH.HostKeyFingerprint)
	if err != nil {
		return err
	}
	addr := fmt.Sprintf("%s:%d", c.target.Host, sshPort)
	sshClient, err := sshexec.Dial(ctx, addr, c.target.SSH.User, privateKeyPEM, cb)
	if err != nil {
		return fmt.Errorf("connect to %q via ssh: %w", c.target.ID, err)
	}
	c.ssh = sshClient
	return nil
}

// sshConnectionHealthy probes c.ssh with a trivial, harmless remote
// command on a short, INDEPENDENT context — deliberately not the caller's
// ctx, so a caller deadline that already expired isn't misread as "the
// connection is dead" (and doesn't limit how long the caller's own
// SetVMConfigField was willing to wait). Used only on SetVMConfigField's
// failure path, to distinguish "the connection itself is unusable"
// (discard it, redial next time) from "the remote command failed on its
// own merits — e.g. a bad VMID, an invalid value — and the connection is
// perfectly fine" (keep reusing it).
func (c *RoutedClient) sshConnectionHealthy() bool {
	probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := c.ssh.Run(probeCtx, "true")
	return err == nil
}
