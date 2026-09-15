package pve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
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

func (c *RoutedClient) FindByTag(ctx context.Context, tag string) (*proxmox.ClusterResource, error) {
	return c.rest.FindByTag(ctx, tag)
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

// WaitForTask polls a PVE task (identified by the UPID a mutating call
// returned) to completion — see Client.WaitForTask's own doc comment. A
// thin pass-through like the typed getters above; node is kept as an
// explicit parameter, matching GetVM and the other typed getters in this
// section, even though RoutedClient already knows its own target node.
func (c *RoutedClient) WaitForTask(ctx context.Context, node, upid string) error {
	return c.rest.WaitForTask(ctx, node, upid)
}

// APIDocTree fetches this target's PVE host's own static API-doc schema
// tree — see Client.APIDocTree's own doc comment. A thin pass-through
// like the typed getters above: schema discovery can never hit a
// root-only field, so there is nothing for RoutedClient to route: it
// always goes over REST. This is what makes *RoutedClient satisfy
// internal/discover.Client (structurally — no explicit assertion needed),
// which is what cmd/pveforge's discover commands actually hold.
func (c *RoutedClient) APIDocTree(ctx context.Context) (json.RawMessage, error) {
	return c.rest.APIDocTree(ctx)
}

// RawRequest issues a raw PVE REST call — see Client.RawRequest's own doc
// comment. A thin pass-through, deliberately: pveforge-raw-api-escape-
// hatch's own recorded design (vault task pveforge-raw-api-escape-hatch,
// "Locking design") scopes this to plain REST only, with NO standing-SSH
// root-only-field fallback the way SetVMConfigField has — that fallback is
// keyed to individual VM CONFIG FIELD NAMES (sshexec.RootOnlyFields), and
// a raw passthrough's --data params are opaque key=value pairs with no
// guarantee they even target a VM config write at all, let alone which of
// possibly several fields in one call might be root-only. Building that
// generalization was explicitly out of this task's scope ("no new
// transport"); a root-only rejection surfaces as PVE's own verbatim error
// text instead (RawRequest's own doc comment on why that text is
// preserved) — which is itself useful signal telling the caller to reach
// for the dedicated `vm set` command instead, since THAT command has the
// fallback this one deliberately doesn't.
func (c *RoutedClient) RawRequest(ctx context.Context, method, path string, params url.Values) (json.RawMessage, error) {
	return c.rest.RawRequest(ctx, method, path, params)
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

// SetVMConfigFieldCAS is SetVMConfigField with the digest-based
// compare-and-swap guard described on Client.SetVMConfigFieldCAS's own
// doc comment (internal/pve's defense-in-depth alongside internal/lock's
// per-object serialization).
//
// Refuses outright — rather than silently falling back to an
// unconditional write — for any field in sshexec.RootOnlyFields. Those
// fields are routed over the standing SSH vector (`qm set`), which has no
// digest/compare-and-swap concept at all: honoring expectDigest there
// would be impossible, and silently ignoring it would let a caller believe
// it got the CAS guarantee it asked for when it didn't. A caller that
// needs to mutate a root-only field still has internal/lock's own
// per-object serialization; it just doesn't get this second, independent
// layer of protection for that field.
func (c *RoutedClient) SetVMConfigFieldCAS(ctx context.Context, vmid int, field, value, expectDigest string) error {
	if sshexec.RootOnlyFields[field] {
		// Deliberately does not use the word "digest" anywhere in this
		// message: IsDigestConflictError matches on that substring to
		// recognize a genuine PVE compare-and-swap rejection, and this is
		// a permanent, purely local refusal (never sent to PVE at all) —
		// if this text tripped that same substring check, a caller like
		// internal/idempotent would misread it as a transient conflict
		// worth retrying, uselessly repeating an error that can never
		// succeed no matter how many times it's retried.
		return fmt.Errorf("set vm %d field %q: root-only fields routed over the standing SSH vector have no compare-and-swap mechanism to honor an expected prior value with", vmid, field)
	}
	return c.rest.SetVMConfigFieldCAS(ctx, c.target.Node, vmid, field, value, expectDigest)
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

// UploadSnippet writes content to PVE's "snippets" storage content type on
// storageID, as filename — e.g. so a VM's VirtualMachineConfig.Hookscript
// can point at "<storageID>:snippets/<filename>".
//
// Proxmox's REST API has NO upload endpoint for the snippets content type
// (unlike iso/vztmpl/import — confirmed directly in go-proxmox's own
// source: its Storage.upload's validContent allowlist excludes "snippets",
// with a doc comment stating there is no REST upload path for it as of PVE
// 9.x; snippets must be written to the storage's filesystem path directly).
// This necessarily goes over the standing SSH vector, not REST: it
// resolves storageID's configured filesystem path via REST
// (Client.GetStorageConfigPath), then writes the file directly via
// sshexec.Client.WriteFile.
//
// filename is restricted to a safe character set (see
// isSafeSnippetFilename) before being joined onto the resolved storage
// path — it is software-generated today (an idempotent.Op's own naming
// scheme, not free-form user input), but a stray '/' or ".." must not be
// able to escape the snippets directory.
//
// Concurrency: the underlying sshexec.Client.WriteFile provides atomic
// REPLACEMENT of remotePath, not atomic SERIALIZATION of concurrent
// writers to the SAME remotePath (see its own doc comment) — UploadSnippet
// adds no locking of its own on top of that. This is safe today because
// its one real caller, idempotent.BridgeIsolationEnsure.Apply, always runs
// under idempotent.Run's internal/lock.Mutation held for the whole
// read-compare-mutate cycle, keyed by VMID — two calls that could target
// the same filename (which is itself derived from VMID) are therefore
// already serialized before either reaches here. A future caller invoking
// UploadSnippet OUTSIDE that lock would need its own serialization for the
// same guarantee.
func (c *RoutedClient) UploadSnippet(ctx context.Context, storageID, filename string, content []byte) error {
	if !isSafeSnippetFilename(filename) {
		return fmt.Errorf("upload snippet: filename %q is empty or contains unsafe characters", filename)
	}

	basePath, err := c.rest.GetStorageConfigPath(ctx, storageID)
	if err != nil {
		return fmt.Errorf("upload snippet %q: %w", filename, err)
	}
	remotePath := path.Join(basePath, "snippets", filename)

	if err := c.withSSH(ctx, func(ssh *sshexec.Client) error {
		return ssh.WriteFile(ctx, remotePath, content, "0755")
	}); err != nil {
		return fmt.Errorf("upload snippet %q: %w", filename, err)
	}
	return nil
}

// isSafeSnippetFilename reports whether s is non-empty, contains only a
// small safe character set (no path separator, so it can never introduce
// an extra directory component when joined onto the snippets path), and
// isn't exactly "." or ".." (which, even without any '/' of their own,
// would resolve to the snippets directory itself or its parent once
// path.Join cleans the result).
func isSafeSnippetFilename(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// TapLinkState reports one VM network interface's live tap-device
// bridge-port state (see sshexec.Client.TapLinkState) — only meaningful
// while the owning VM is actually running; see sshexec.TapLinkState's own
// doc comment on its Exists field for the expected not-running case.
func (c *RoutedClient) TapLinkState(ctx context.Context, tap string) (sshexec.TapLinkState, error) {
	var state sshexec.TapLinkState
	err := c.withSSH(ctx, func(ssh *sshexec.Client) error {
		var innerErr error
		state, innerErr = ssh.TapLinkState(ctx, tap)
		return innerErr
	})
	return state, err
}

// SetBridgePortIsolated immediately sets or clears tap's live bridge-port
// isolation flag (see sshexec.Client.SetBridgePortIsolated) — affects only
// the CURRENT boot's ephemeral tap device; it does not persist across a
// VM restart on its own (that's what a hookscript pointed at an
// UploadSnippet-deployed script is for).
func (c *RoutedClient) SetBridgePortIsolated(ctx context.Context, tap string, isolated bool) error {
	return c.withSSH(ctx, func(ssh *sshexec.Client) error {
		return ssh.SetBridgePortIsolated(ctx, tap, isolated)
	})
}

// withSSH ensures c.ssh is dialed, then runs fn against it — discarding
// the connection and forcing a redial next time if fn's failure indicates
// the connection itself is no longer usable, per sshConnectionHealthy's
// own doc comment on why that's checked independently of fn's own error
// (which might just be a normal remote-command failure on an otherwise
// healthy connection). The same self-healing behavior setViaSSH has always
// had for SetVMConfigField, factored out here so UploadSnippet/
// TapLinkState/SetBridgePortIsolated share it instead of each
// reimplementing it. setViaSSH itself is deliberately left as its own
// separate, already-tested implementation rather than rewritten on top of
// this — no functional reason it couldn't be, just minimizing churn to
// working code this task doesn't need to touch.
func (c *RoutedClient) withSSH(ctx context.Context, fn func(ssh *sshexec.Client) error) error {
	if c.ssh == nil {
		if err := c.dialSSH(ctx); err != nil {
			return err
		}
	}
	err := fn(c.ssh)
	if err != nil && !c.sshConnectionHealthy() {
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
