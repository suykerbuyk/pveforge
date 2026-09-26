package bootstrap

import (
	"context"
	"errors"
	"fmt"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

// ErrTLSCapture: the certificate the node serves could not be read over
// the SSH session. Nothing was written.
var ErrTLSCapture = errors.New("could not capture the node's TLS certificate over SSH")

// ErrTLSPinMismatch: two views of the target's TLS key disagree, the one
// captured over SSH (or given with --expect) and the one the target's
// address serves over the network. Nothing was written and no token was
// sent.
var ErrTLSPinMismatch = errors.New("the target's address does not serve the TLS key the node serves")

// ErrTLSPinDiffers: the roster already pins another TLS key for the
// target. pveforge never replaces a pin silently.
var ErrTLSPinDiffers = errors.New("the roster pins another TLS key for this target")

// ErrHostKeyFingerprintRequired: a password session would capture a TLS
// pin, and nothing vouches for its host key (operator ruling RQ3, B′).
var ErrHostKeyFingerprintRequired = errors.New("a TLS pin captured over a password SSH session needs --host-key-fingerprint (or --ssh-tofu to accept trust on first use)")

// capturePin reads the TLS key over session and checks the network half:
// the key the node serves on its own pveproxy port (captured over SSH)
// must be the key host:apiPort serves (api.ServedPin). It writes nothing.
func capturePin(ctx context.Context, session SSHSession, api APIValidator, host string, apiPort, capturePort int, verifyChain bool) (tlspin.Pin, error) {
	if capturePort == 0 {
		capturePort = tlspin.DefaultCapturePort
	}
	res, err := session.Run(ctx, tlspin.CaptureCommand(capturePort))
	if err != nil {
		return "", fmt.Errorf("%w: run the capture: %w", ErrTLSCapture, err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("%w: the capture exited %d (is openssl on the node, and is pveproxy listening on 127.0.0.1:%d? pass --capture-port if not)", ErrTLSCapture, res.ExitCode, capturePort)
	}
	captured, _, err := tlspin.ParseCapture([]byte(res.Stdout))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrTLSCapture, err)
	}
	return checkServed(ctx, api, host, apiPort, captured, verifyChain)
}

// checkServed requires host:apiPort to serve want's key. apiPort is read
// as REST reads it (pve.EffectiveAPIPort: 0 is 8006), so the cross-check
// dials exactly the address every REST request of the target will.
func checkServed(ctx context.Context, api APIValidator, host string, apiPort int, want tlspin.Pin, verifyChain bool) (tlspin.Pin, error) {
	apiPort = pve.EffectiveAPIPort(apiPort)
	served, _, err := api.ServedPin(ctx, host, apiPort, verifyChain)
	if err != nil {
		return "", fmt.Errorf("read the TLS key %s:%d serves: %w", host, apiPort, err)
	}
	if served != want {
		return "", fmt.Errorf("%w: %s:%d serves %s, the node %s; this run wrote no TLS pin, SSH auth or token to the roster, and sent no token (something else answers at this address, or a TLS-terminating proxy fronts the node: connect to the node directly)", ErrTLSPinMismatch, host, apiPort, served, want)
	}
	return want, nil
}

// differsError is ErrTLSPinDiffers, naming the one T1b command that can
// replace the pin when SSH vouches for the new key (keyful), and, for a
// target without SSH auth, the hand edit (no pveforge command replaces
// such a pin).
func differsError(targetID string, stored, captured tlspin.Pin, keyful bool) error {
	rebuilt := "if the node was rebuilt, read its SSH host key on the node's CONSOLE (" + sshexec.ConsoleHostKeyCommand + ") and run pveforge bootstrap " + targetID
	if !keyful {
		rebuilt += " --no-ssh-key"
	}
	rebuilt += " --reprovisioned --host-key-fingerprint <the console value>"
	fix := rebuilt
	if keyful {
		fix = "if only its TLS key changed deliberately, run pveforge roster pin-tls " + targetID + " --repin, which captures the new key over the pinned SSH session; " + rebuilt
	}
	return fmt.Errorf("%w: %s pins %s, the node now serves %s; this run wrote no TLS pin, SSH auth or token to the roster; %s", ErrTLSPinDiffers, targetID, stored, captured, fix)
}

// PinTLSOptions configures PinTLS (pveforge roster pin-tls).
type PinTLSOptions struct {
	TargetID   string
	RosterPath string
	Passphrase roster.Passphrase
	// Expect, for a target with no SSH auth, is the pin the operator
	// verified by other means: the target must serve exactly it.
	Expect tlspin.Pin
	// Repin replaces a different stored pin; only for a target with SSH
	// auth, whose pinned session vouches for the new key.
	Repin bool
	// Print captures and checks, and writes nothing.
	Print       bool
	SSHPort     int // 0 => 22
	CapturePort int // 0 => tlspin.DefaultCapturePort
}

// PinTLSResult reports what PinTLS found and did.
type PinTLSResult struct {
	TargetID string
	Pin      tlspin.Pin
	Source   tlspin.Source
	// Previous is the pin the roster held before, "" for none.
	Previous tlspin.Pin
	// Written reports that the roster was changed.
	Written bool
}

// PinTLS pins a target's TLS key without touching its token: the
// migration path for a target bootstrapped before TLS pins existed.
//
// For a target with SSH auth, the key is captured over an SSH session
// pinned to the roster's stored host key, and the target's address must
// serve the same key (source ssh-stored). For a target without SSH auth,
// Expect is required, and the address must serve exactly it (source
// expect). There is no trust-on-first-use path. A different stored pin is
// refused unless Repin (SSH auth only). Print writes nothing and takes no
// lock; otherwise the per-target bootstrap lock is held, so a bootstrap of
// the same target cannot interleave, and the pin is written with
// roster.WriteTLSPin's compare-and-set against the value read under it.
func PinTLS(ctx context.Context, opts PinTLSOptions, transport SSHTransport, api APIValidator) (*PinTLSResult, error) {
	if opts.Expect != "" {
		if _, err := tlspin.Parse(string(opts.Expect)); err != nil {
			return nil, fmt.Errorf("pin-tls %s: --expect: %w", opts.TargetID, err)
		}
	}
	if opts.SSHPort == 0 {
		// The roster stores no SSH port: dial the one every RoutedClient
		// dials for this target's stored SSH pin.
		opts.SSHPort = pve.RoutedSSHPort()
	}
	if !opts.Print {
		unlock, err := lock.Mutation(ctx, opts.RosterPath, lock.ObjectKey{TargetID: opts.TargetID, Kind: "bootstrap", ID: "token"})
		if err != nil {
			return nil, fmt.Errorf("pin-tls %s: acquire the per-target bootstrap lock: %w", opts.TargetID, err)
		}
		defer func() { _ = unlock() }()
	}
	r, err := roster.Load(opts.RosterPath)
	if err != nil {
		return nil, fmt.Errorf("pin-tls %s: %w", opts.TargetID, err)
	}
	tg := r.Find(opts.TargetID)
	if tg == nil {
		return nil, fmt.Errorf("pin-tls %s: no such target in roster %s", opts.TargetID, opts.RosterPath)
	}
	apiPort := pve.EffectiveAPIPort(tg.APIPort)
	res := &PinTLSResult{TargetID: opts.TargetID}
	var recorded tlspin.Source
	if tg.TLS != nil {
		res.Previous = tlspin.Pin(tg.TLS.SPKISHA256)
		recorded = tlspin.Source(tg.TLS.Source)
	}
	keyful := tg.SSH != nil && tg.SSH.HostKeyFingerprint != ""

	switch {
	case !tg.InsecureTLS && opts.Expect == "":
		// Ruling 5 and D4: a CA-verified target's chain is its identity, and
		// pinning it as well is the operator's explicit choice, never a
		// capture.
		return nil, fmt.Errorf("pin-tls %s: the target verifies its certificate against the system CAs (insecure_tls is false), so it is pinned only explicitly: pass the pin you verified with --expect", opts.TargetID)
	case !tg.InsecureTLS && opts.Repin:
		return nil, fmt.Errorf("pin-tls %s: --repin needs an insecure_tls target with SSH auth to vouch for the new key", opts.TargetID)
	case !tg.InsecureTLS:
		pin, err := checkServed(ctx, api, tg.Host, apiPort, opts.Expect, true)
		if err != nil {
			return nil, fmt.Errorf("pin-tls %s: --expect: %w", opts.TargetID, err)
		}
		res.Pin, res.Source = pin, tlspin.SourceExpect
	case keyful && opts.Expect != "":
		return nil, fmt.Errorf("pin-tls %s: the target has SSH auth, so its pin is captured over the pinned SSH session; drop --expect", opts.TargetID)
	case !keyful && opts.Repin:
		return nil, fmt.Errorf("pin-tls %s: --repin needs SSH auth to vouch for the new key, and the target has none", opts.TargetID)
	case keyful:
		keyPEM, err := opts.Passphrase.Decrypt(tg.SSH.PrivateKeyEnc)
		if err != nil {
			return nil, fmt.Errorf("pin-tls %s: decrypt the ssh key: %w", opts.TargetID, err)
		}
		addr := fmt.Sprintf("%s:%d", tg.Host, opts.SSHPort)
		session, err := transport.ReconnectWithPinnedKey(ctx, addr, tg.SSH.User, keyPEM, tg.SSH.HostKeyFingerprint)
		if err != nil {
			return nil, fmt.Errorf("pin-tls %s: connect with the pinned ssh key: %w", opts.TargetID, err)
		}
		defer func() { _ = session.Close() }()
		pin, err := capturePin(ctx, session, api, tg.Host, apiPort, opts.CapturePort, false)
		if err != nil {
			return nil, fmt.Errorf("pin-tls %s: %w", opts.TargetID, err)
		}
		res.Pin, res.Source = pin, tlspin.SourceSSHStored
	case opts.Expect != "":
		pin, err := checkServed(ctx, api, tg.Host, apiPort, opts.Expect, false)
		if err != nil {
			return nil, fmt.Errorf("pin-tls %s: --expect: %w", opts.TargetID, err)
		}
		res.Pin, res.Source = pin, tlspin.SourceExpect
	default:
		return nil, fmt.Errorf("pin-tls %s: the target has no SSH auth to capture its key over; verify its pin by other means and pass it with --expect", opts.TargetID)
	}

	if res.Previous == res.Pin {
		// Already pinned: report how the pin was FIRST obtained.
		res.Source = recorded
		return res, nil
	}
	if res.Previous != "" && !opts.Repin {
		return res, differsError(opts.TargetID, res.Previous, res.Pin, keyful)
	}
	if opts.Print {
		return res, nil
	}
	if err := roster.WriteTLSPin(opts.RosterPath, opts.TargetID, res.Previous, res.Pin, res.Source, opts.Passphrase); err != nil {
		return res, fmt.Errorf("pin-tls %s: %w", opts.TargetID, err)
	}
	res.Written = true
	return res, nil
}
