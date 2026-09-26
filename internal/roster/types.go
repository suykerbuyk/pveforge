// Package roster loads and edits the pveforge target roster: a TOML file
// listing Proxmox hosts and, once bootstrapped, their auth credentials. Only
// credential values are secret; everything else stays plaintext so the file
// remains diffable and reviewable in source control.
package roster

// DefaultPath is the roster file location pveforge uses when neither
// --roster nor PVEFORGE_ROSTER override it.
const DefaultPath = "pveforge.toml"

// PassphraseEnvVar names the environment variable holding the roster's
// master passphrase. Per the project's standing no-secrets-on-cli rule,
// there is deliberately no flag for this.
const PassphraseEnvVar = "PVEFORGE_ROSTER_PASSPHRASE"

// Roster is the top-level roster document.
type Roster struct {
	Targets []Target `toml:"targets"`
}

// ExportToken is the one value of Target.Export: the target's API token may
// be handed to another program by `pveforge exec`.
const ExportToken = "token"

// Target describes one Proxmox host/cluster entry. Token and SSH are nil
// until the auth-bootstrap flow has run for this target.
//
// Export is the operator's opt-in for letting a credential leave pveforge:
// "" (the default) keeps every secret inside pveforge, and ExportToken lets
// `pveforge exec` hand the API token (never the SSH key) to a command. It is
// set only by editing the roster by hand: no pveforge command writes it, and
// every roster writer refuses a write that would change it.
type Target struct {
	ID          string     `toml:"id"`
	Host        string     `toml:"host"`
	Node        string     `toml:"node"`
	APIPort     int        `toml:"api_port"`
	InsecureTLS bool       `toml:"insecure_tls"`
	Export      string     `toml:"export"`
	Token       *TokenAuth `toml:"token"`
	SSH         *SSHAuth   `toml:"ssh"`
	// TLS pins the REST peer's certificate key, as SSH.HostKeyFingerprint
	// pins the SSH peer's host key. nil means no pin: the target's REST
	// client then behaves as it always has.
	TLS *TLSPin `toml:"tls"`
}

// TLSPin is a target's [targets.tls] subtable. SPKISHA256 is a
// tlspin.Pin ("sha256//<base64>"), checked when the roster is loaded. It
// is not secret. It is written only by WriteTLSPin, a compare-and-set, so
// no writer can replace a pin it did not first read.
type TLSPin struct {
	SPKISHA256 string `toml:"spki_sha256"`
	// Source is how the pin was first obtained (tlspin.Source:
	// ssh-verified, ssh-stored, ssh-tofu or expect). It is recorded by
	// every pveforge writer; a hand-written pin may omit it.
	Source string `toml:"source"`
}

// TokenAuth is the primary auth path: a Proxmox API token. ID is the token's
// name (e.g. "pveforge@pve!automation") and is not secret. SecretEnc is the
// age-armored, encrypted token secret.
type TokenAuth struct {
	ID        string `toml:"id"`
	SecretEnc string `toml:"secret_enc"`
}

// SSHAuth is the narrow root-authenticated path used only for the handful
// of Proxmox config fields no API token can set (args, and similar), and/or
// for hookscript deployment. User, PublicKey, and HostKeyFingerprint are not
// secret.
type SSHAuth struct {
	User      string `toml:"user"`
	PublicKey string `toml:"public_key"`
	// HostKeyFingerprint pins the target's SSH host key, captured on first
	// connect (trust-on-first-use) during bootstrap and verified on every
	// subsequent connection. Without it, the SSH client has no way to
	// detect a MITM'd connection on later invocations other than trusting
	// the network every time.
	HostKeyFingerprint string `toml:"host_key_fingerprint"`
	PrivateKeyEnc      string `toml:"private_key_enc"`
}
