// Command transportprobe is the POSITIVE CONTROL for the transport boundary
// guard in ../../transportboundary_test.go. It is never built by ./... — it
// lives under testdata, which sourceguard.NonTestReferences skips — and the
// guard points the walker at this directory DIRECTLY.
//
// WHY IT EXISTS. Four of the guard's ten targets match nothing in the module
// today: net/http.DefaultClient, sshexec.DialWithPassword, TermWebSocket and
// VNCWebSocket. That is precisely why fencing them now is cheap, and it is
// also why none of them can serve as its own anti-vacuity proof — there is no
// real site to point at. This file is the site. The guard asserts that EVERY
// target, not just the four, matches here, so the target list has a second
// independent observer besides the real tree.
//
// WHY IT MUST COMPILE, AND WHY THE SHAPES ARE REAL. A fixture written to suit
// the guard rather than to mirror production is vacuity wearing a fixture's
// clothes: it would prove the predicate fires on a shape reality never
// produces. Two rules follow, and both are load-bearing.
//
//  1. TermWebSocket and VNCWebSocket are declared ONLY as methods in
//     go-proxmox — on *Client, *VirtualMachine, *Container and *Node. There
//     is no package-level proxmox.TermWebSocket, so a call written that way
//     would not compile against the real library, and a target matching it
//     would be matching a fiction. They are called here on a RECEIVER, which
//     is also why their targets use AnyQualifier rather than ImportPath.
//
//  2. go-proxmox is imported under an explicit alias, because its package
//     name (proxmox) is not its last path segment (go-proxmox). That is the
//     case NonTestReferences refuses to guess at.
//
// `go build` and `go vet` both pass on this package. Keep it that way: an
// unbuildable fixture cannot be trusted to mirror anything.
package main

import (
	"context"
	"net"
	"net/http"

	proxmox "github.com/suykerbuyk/go-proxmox"
	"golang.org/x/crypto/ssh"

	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// httpClient mirrors internal/pve/client.go's own construction: an
// http.Client literal whose Transport is built rather than defaulted.
// Matches net/http.Client and net/http.Transport.
var httpClient = &http.Client{Transport: &http.Transport{}}

// defaultClient is the bypass the guard's net/http.DefaultClient target
// exists for: reaching the package-global client builds no literal at all.
var defaultClient = http.DefaultClient

// roundTrips matches net/http's four package-level helpers. Each dials
// through http.DefaultClient while naming neither it nor any transport.
func roundTrips(u string) error {
	if _, err := http.Get(u); err != nil {
		return err
	}
	if _, err := http.Head(u); err != nil {
		return err
	}
	if _, err := http.Post(u, "application/json", nil); err != nil {
		return err
	}
	_, err := http.PostForm(u, nil)
	return err
}

// viaDefaultTransport matches net/http.DefaultTransport. The global is a
// RoundTripper, so this opens a connection while naming neither Client nor
// Transport — the Sel is DefaultTransport, which the Transport target does
// not match. newHTTPClient (internal/pve/client.go) clones this same global in-boundary.
func viaDefaultTransport(req *http.Request) (*http.Response, error) {
	return http.DefaultTransport.RoundTrip(req)
}

// sshDirectDial matches ssh.Dial, x/crypto/ssh's canonical entry point and
// the one door with no site in this module at all.
func sshDirectDial(addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, cfg)
}

// installPubkey matches sshexec.InstallPubkeyViaPassword, the third SSH
// door. It has a real site at internal/bootstrap/deps.go:20; it appears here
// too because this probe must reference every target, witnessed or not.
func installPubkey(ctx context.Context) error {
	_, err := sshexec.InstallPubkeyViaPassword(ctx, "example.invalid:22", "root", "pw", "ssh-ed25519 AAAAtest", "")
	return err
}

// pc matches go-proxmox.NewClient, the one package-level constructor of the
// two the boundary owns.
var pc = proxmox.NewClient("https://example.invalid/api2/json")

// sshHandshake mirrors internal/sshexec/client.go's dial: ssh.NewClientConn
// then ssh.NewClient. Neither is ssh.Dial, which this module never calls.
func sshHandshake(conn net.Conn, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// viaSshexec matches sshexec.Dial, the qualified form every out-of-package
// caller uses.
func viaSshexec(ctx context.Context, cb ssh.HostKeyCallback) (*sshexec.Client, error) {
	return sshexec.Dial(ctx, "example.invalid:22", "root", nil, cb)
}

// viaSshexecPassword matches sshexec.DialWithPassword — the second SSH door.
// Its only real caller, internal/sshexec/install.go, is a bare same-package
// call, so the qualified form has no site in the module and needs this one.
func viaSshexecPassword(ctx context.Context, cb ssh.HostKeyCallback) (*sshexec.Client, error) {
	return sshexec.DialWithPassword(ctx, "example.invalid:22", "root", "pw", cb)
}

// term and vnc are the receiver-qualified WebSocket calls. See rule 1 above.
func term(vm *proxmox.VirtualMachine, t *proxmox.Term) error {
	_, _, _, _, err := vm.TermWebSocket(t)
	return err
}

func vnc(n *proxmox.Node, v *proxmox.VNC) error {
	_, _, _, _, err := n.VNCWebSocket(v)
	return err
}

func main() {
	_, _, _, _ = httpClient, defaultClient, pc, sshHandshake
	_, _, _, _ = viaSshexec, viaSshexecPassword, term, vnc
	_, _, _, _ = roundTrips, viaDefaultTransport, sshDirectDial, installPubkey
}
