// Package pve is pveforge's thin wrapper over github.com/suykerbuyk/
// go-proxmox, plus a raw-HTTP path (RawRequest) for what that library does
// not cover well. It began with what the bootstrap flow needs: a
// token-authenticated client and the grant validation that asks PVE for a
// token's effective permissions (validate.go). Later tasks (the
// object-model get/set layer, hookscript deployment via the storage
// snippets content type) extend this same client rather than introduce a
// second one.
package pve

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

// DefaultAPIPort is Proxmox's default API port when a target doesn't
// override it.
const DefaultAPIPort = 8006

// DefaultTimeout bounds every request this client makes, so a
// network-partitioned or hung node fails a call rather than blocking the
// caller forever.
const DefaultTimeout = 30 * time.Second

// ClientConfig configures a new token-authenticated Client.
type ClientConfig struct {
	Host        string
	APIPort     int // 0 => DefaultAPIPort
	InsecureTLS bool
	// TLSPin, when set, is the SPKI pin every connection's peer must
	// present ([targets.tls], tlspin.Pin), checked in the handshake before
	// any request byte, the token included, is sent. With InsecureTLS it
	// replaces chain verification; without it, the chain AND the pin must
	// both hold. Empty: no pin, and the client behaves exactly as it
	// always has. With a pin, an https:// proxy is unsupported (every
	// request fails closed); an http:// CONNECT proxy is fine. See
	// newHTTPClient.
	TLSPin      tlspin.Pin
	TokenID     string // full "userid!tokenname", e.g. "root@pam!pveforge"
	TokenSecret string
	Timeout     time.Duration // 0 => DefaultTimeout

	// BaseURLOverride constructs the client against this URL directly
	// instead of deriving "https://Host:APIPort/api2/json" from Host and
	// APIPort. Used by tests to point the client at an httptest server;
	// production callers should leave it empty.
	BaseURLOverride string
}

// Client is a token-authenticated Proxmox API client, narrowed to the
// small surface pveforge currently needs.
//
// It holds two parallel things on purpose: pc (go-proxmox) for reads and
// anything else that library covers well, and baseURL/authHeader/httpClient
// for the raw-HTTP write path in vmconfig.go — see that file's doc comment
// for why the write path deliberately does NOT go through go-proxmox.
type Client struct {
	pc *proxmox.Client

	baseURL    string
	authHeader string // "PVEAPIToken=<tokenid>=<secret>"
	httpClient *http.Client
}

// NewClient builds a Client for cfg.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Host == "" && cfg.BaseURLOverride == "" {
		return nil, fmt.Errorf("pve client: host is required")
	}
	if cfg.TokenID == "" || cfg.TokenSecret == "" {
		return nil, fmt.Errorf("pve client: token id and secret are required")
	}

	baseURL := cfg.BaseURLOverride
	if baseURL == "" {
		port := cfg.APIPort
		if port == 0 {
			port = DefaultAPIPort
		}
		baseURL = fmt.Sprintf("https://%s:%d/api2/json", cfg.Host, port)
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if cfg.TLSPin != "" {
		if _, err := tlspin.Parse(string(cfg.TLSPin)); err != nil {
			return nil, fmt.Errorf("pve client: %w", err)
		}
	}

	// One *http.Client serves every request this Client makes: RawRequest,
	// the direct writers (vmconfig.go, schema.go), and go-proxmox itself,
	// which is handed it (WithHTTPClient). Its transport is the
	// accessWriteGuard, so no request of any of them can write PVE's
	// /access API with the roster's token.
	httpClient, err := newHTTPClient(timeout, cfg.InsecureTLS, cfg.TLSPin)
	if err != nil {
		return nil, fmt.Errorf("pve client: %w", err)
	}
	opts := []proxmox.Option{
		proxmox.WithAPIToken(cfg.TokenID, cfg.TokenSecret),
		proxmox.WithHTTPClient(httpClient),
	}

	return &Client{
		pc:         proxmox.NewClient(baseURL, opts...),
		baseURL:    baseURL,
		authHeader: fmt.Sprintf("PVEAPIToken=%s=%s", cfg.TokenID, cfg.TokenSecret),
		httpClient: httpClient,
	}, nil
}

// newHTTPClient is the one constructor of an HTTP client in pveforge's
// production code (cmd/pveforge's transport guard holds that): its
// transport is always the accessWriteGuard, in front of
// http.DefaultTransport resolved per request, or, with insecureTLS or a
// pin, a clone of it built once, here, at construction.
//
// With a pin, the clone's VerifyConnection checks the peer's leaf key on
// every handshake, resumed or not, before any request byte is sent. With
// insecureTLS it is the only check (chain verification is skipped: the pin
// is the identity); without insecureTLS Go verifies the chain first and
// the pin must hold as well. Session resumption stays at Go's default (no
// ClientSessionCache): VerifyConnection runs on a resumed session anyway.
// Proxies: an http:// proxy is honoured as before. The client sends it a
// CONNECT and runs TLS with the target through the tunnel, so the pin is
// checked against the target end to end and the proxy cannot answer as
// it. An https:// proxy is NOT supported for a pinned target: net/http
// runs this transport's TLSClientConfig, VerifyConnection included, on the
// TLS leg to the proxy as well (transport.go, dialConn and addTLS), so the
// proxy's own certificate is checked against the target's pin and every
// request fails closed with a pin mismatch. A second TLS config for the
// proxy leg is deliberately not built.
func newHTTPClient(timeout time.Duration, insecureTLS bool, pin tlspin.Pin) (*http.Client, error) {
	var next http.RoundTripper // nil: http.DefaultTransport, at request time
	if insecureTLS || pin != "" {
		transport := baseTransport()
		cfg := &tls.Config{InsecureSkipVerify: insecureTLS} //nolint:gosec // explicit opt-in via cfg.InsecureTLS, mirrors go-proxmox's own WithInsecureSkipVerify; with a pin, VerifyConnection is the identity
		if pin != "" {
			verify, err := tlspin.VerifyConnection(pin)
			if err != nil {
				return nil, err
			}
			cfg.VerifyConnection = verify
			cfg.MinVersion = tls.VersionTLS12
		}
		transport.TLSClientConfig = cfg
		next = transport
	}
	return &http.Client{Timeout: timeout, Transport: accessWriteGuard{next: next}}, nil
}

// baseTransport is the one clone site: http.DefaultTransport, cloned
// rather than built from a bare &http.Transport{} literal. DefaultTransport
// carries Proxy: http.ProxyFromEnvironment (HTTP_PROXY/HTTPS_PROXY/
// NO_PROXY support) among other sane defaults, matching go-proxmox's own
// WithInsecureSkipVerify/ensureTransport approach. A bare literal has a nil
// Proxy, which would silently drop proxy support for the raw-HTTP write
// path (vmconfig.go) specifically — while reads through go-proxmox
// (ListNodes etc.) kept working via the proxy, since only go-proxmox's own
// transport was ever affected. Clone also copies DialContext, which is
// what netguard's test hook rides on. newHTTPClient and ServedPin share it.
func baseTransport() *http.Transport {
	return http.DefaultTransport.(*http.Transport).Clone()
}

// ErrProxiedProbe: ServedPin was asked to probe a host:port that the
// REST transport would reach through a proxy. The probe dials directly, so
// it could not compare what REST will reach; it refuses rather than
// report a pin of the wrong peer.
var ErrProxiedProbe = errors.New("a proxy is configured for this address (HTTPS_PROXY/NO_PROXY); the served-pin probe dials directly, so it cannot compare what REST will reach; set NO_PROXY for this host")

// ServedPin reports the pin of the certificate that answers TLS at
// host:port, with a handshake and nothing else: no HTTP request is made,
// so no token or header is ever sent. It does not verify the certificate
// (reading it is the point); a caller compares the pin it returns.
//
// It dials through the same clone of http.DefaultTransport that REST uses
// (baseTransport), so its dialer and its proxy decision are REST's own,
// and netguard's test hook sees the dial. When that transport would send
// a request for https://host:port/ through a proxy, it refuses with
// ErrProxiedProbe before dialing.
func ServedPin(ctx context.Context, host string, port int) (tlspin.Pin, *x509.Certificate, error) {
	return servedPin(ctx, baseTransport(), host, port)
}

// servedPin is ServedPin on a given transport: tests hand it a clone whose
// Proxy and DialContext they control, since http.ProxyFromEnvironment
// reads the environment once per process and never proxies loopback.
func servedPin(ctx context.Context, tr *http.Transport, host string, port int) (tlspin.Pin, *x509.Certificate, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if tr.Proxy != nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/", nil)
		if err != nil {
			return "", nil, fmt.Errorf("served pin of %s: %w", addr, err)
		}
		u, err := tr.Proxy(req)
		if err != nil {
			return "", nil, fmt.Errorf("served pin of %s: resolve the proxy: %w", addr, err)
		}
		if u != nil {
			return "", nil, fmt.Errorf("served pin of %s: %w", addr, ErrProxiedProbe)
		}
	}
	if tr.DialContext == nil {
		// Never fall back to a dialer of its own: that is the dial netguard
		// could not see.
		return "", nil, fmt.Errorf("served pin of %s: the transport has no dialer", addr)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}
	conn, err := tr.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", nil, fmt.Errorf("served pin of %s: %w", addr, err)
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS12}) //nolint:gosec // the certificate is read, not trusted: the caller compares its pin
	if err := tc.HandshakeContext(ctx); err != nil {
		return "", nil, fmt.Errorf("served pin of %s: TLS handshake: %w", addr, err)
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", nil, fmt.Errorf("served pin of %s: the peer presented no certificate", addr)
	}
	return tlspin.FromCertificate(certs[0]), certs[0], nil
}

// ErrAccessWriteRefused: a request that would write PVE's /access API
// (users, groups, tokens, ACLs, roles, realms, passwords) with the roster's
// token. pveforge writes those only as root over SSH (6a); the token must
// never be able to, whatever code path builds the request.
var ErrAccessWriteRefused = errors.New("refusing to write PVE's /access API with the roster's token")

// AccessWriteError is the refusal, naming the request. It matches
// ErrAccessWriteRefused.
type AccessWriteError struct {
	Method, Path string
}

func (e *AccessWriteError) Error() string {
	return fmt.Sprintf("%s %s: %s; principals and ACLs are written as root over SSH", e.Method, e.Path, ErrAccessWriteRefused)
}

func (e *AccessWriteError) Is(target error) bool { return target == ErrAccessWriteRefused }

// accessWriteGuard is the RoundTripper every pveforge HTTP request passes
// through. It refuses, before the request leaves the process, any method
// other than GET or HEAD whose path is /access or below it. The static
// guards cannot see every way to spell such a path or reach such a call
// (concatenation, formatting, dot segments, doubled slashes, method values,
// go-proxmox's own request methods); this sees the request itself.
type accessWriteGuard struct {
	next http.RoundTripper
}

func (g accessWriteGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	if isAccessWrite(req) {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, &AccessWriteError{Method: req.Method, Path: req.URL.Path}
	}
	next := g.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(req)
}

// accessPathRE matches a cleaned path addressing /access: at the root, or
// below an API format prefix (/api2/json/access, /api2/extjs/access, …),
// wherever that prefix sits under a base path.
var accessPathRE = regexp.MustCompile(`(^|/)api2/[^/]+/access(/|$)|^/access(/|$)`)

// isAccessWrite reports whether req writes /access: a method other than
// GET or HEAD, and a path that, unescaped (repeatedly, so an encoded
// segment cannot hide) and cleaned of dot segments and doubled slashes,
// addresses /access. Case is ignored, which only ever refuses more.
func isAccessWrite(req *http.Request) bool {
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		return false
	}
	candidates := []string{req.URL.Path, req.URL.EscapedPath()}
	for p := req.URL.EscapedPath(); ; {
		u, err := url.PathUnescape(p)
		if err != nil || u == p {
			break
		}
		candidates, p = append(candidates, u), u
	}
	for _, p := range candidates {
		if accessPathRE.MatchString(strings.ToLower(path.Clean("/" + p))) {
			return true
		}
	}
	return false
}

// ErrNotAuthorized is returned (wrapped) when PVE rejects a request as
// unauthorized/forbidden (HTTP 401/403, through go-proxmox or RawRequest) —
// distinct from a network/transport failure, and from a token that
// authenticates but holds no grants (ErrNoGrants in validate.go).
var ErrNotAuthorized = proxmox.ErrNotAuthorized

// ListNodes returns the cluster's node names, as seen through this
// client's token. Any authenticated caller may list nodes (PVE's
// Nodes.pm index declares permissions user => 'all'), so this proves a
// node name exists and says nothing about a token's grants.
func (c *Client) ListNodes(ctx context.Context) ([]string, error) {
	ns, err := c.pc.Nodes(ctx)
	if err != nil {
		if proxmox.IsNotAuthorized(err) {
			return nil, fmt.Errorf("list nodes: %w", ErrNotAuthorized)
		}
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	if ns == nil {
		return nil, fmt.Errorf("list nodes: %w: list payload was null", ErrUnverifiableRead)
	}
	if i := nullEntry(ns); i >= 0 {
		return nil, fmt.Errorf("list nodes: %w: entry %d is null", ErrUnverifiableRead, i)
	}
	names := make([]string, 0, len(ns))
	for _, n := range ns {
		names = append(names, n.Node)
	}
	return names, nil
}

// EffectivePermissions reads the caller's own effective permission tree,
// GET /access/permissions with no userid and no path: path → privilege →
// propagate. It covers PVE's default top paths, every ACL path and every
// pool member; PVE drops paths where the caller holds nothing, so a token
// with no grants reads as an empty (non-nil) map. Any payload a healthy
// PVE does not produce (no data, null, a non-object, a flag other than
// 0/1/true/false, a path or privilege name outside PVE's charset) is
// ErrUnverifiableRead, never an empty tree.
func (c *Client) EffectivePermissions(ctx context.Context) (map[string]map[string]bool, error) {
	raw, err := c.RawRequest(ctx, http.MethodGet, "/access/permissions", nil)
	if err != nil {
		return nil, fmt.Errorf("read effective permissions: %w", err)
	}
	tree, err := decodePermTree(raw)
	if err != nil {
		return nil, fmt.Errorf("read effective permissions: %w", err)
	}
	return tree, nil
}

// PathPermissions reads the caller's effective privileges at exactly path,
// GET /access/permissions?path=<path>: privilege → propagate. PVE's own
// answer carries pool-derived and privsep-intersection effects. The answer
// must be keyed by exactly path; an empty object is zero privileges.
func (c *Client) PathPermissions(ctx context.Context, path string) (map[string]bool, error) {
	if !aclPathRE.MatchString(path) {
		return nil, fmt.Errorf("read permissions at %q: %w: not an ACL path", path, ErrInvalidGrant)
	}
	raw, err := c.RawRequest(ctx, http.MethodGet, "/access/permissions", url.Values{"path": {path}})
	if err != nil {
		return nil, fmt.Errorf("read permissions at %s: %w", path, err)
	}
	tree, err := decodePermTree(raw)
	if err != nil {
		return nil, fmt.Errorf("read permissions at %s: %w", path, err)
	}
	perms, ok := tree[path]
	if len(tree) != 1 || !ok {
		return nil, fmt.Errorf("read permissions at %s: %w: the answer is not keyed by exactly the requested path (%d keys)", path, ErrUnverifiableRead, len(tree))
	}
	return perms, nil
}

// RolePrivileges reads role's privileges, GET /access/roles/<role>, sorted.
// A role id outside PVE's format is refused before any request. A role
// with no privileges is ErrUnverifiableRead: nothing can be validated
// against it.
func (c *Client) RolePrivileges(ctx context.Context, role string) ([]string, error) {
	if !roleIDRE.MatchString(role) {
		return nil, fmt.Errorf("read role %q: %w: not a role id", role, ErrInvalidGrant)
	}
	raw, err := c.RawRequest(ctx, http.MethodGet, "/access/roles/"+role, nil)
	if err != nil {
		return nil, fmt.Errorf("read role %s: %w", role, err)
	}
	set, err := decodePrivSet(raw)
	if err != nil {
		return nil, fmt.Errorf("read role %s: %w", role, err)
	}
	privs := make([]string, 0, len(set))
	for p, v := range set {
		if !v {
			return nil, fmt.Errorf("read role %s: %w: privilege %s is present but not set", role, ErrUnverifiableRead, p)
		}
		privs = append(privs, p)
	}
	if len(privs) == 0 {
		return nil, fmt.Errorf("read role %s: %w: the role has no privileges", role, ErrUnverifiableRead)
	}
	sort.Strings(privs)
	return privs, nil
}

// decodePermTree strictly decodes a {"<path>":{"<Priv>":flag}} payload.
// Error text never echoes a server-supplied name that failed its check.
func decodePermTree(raw json.RawMessage) (map[string]map[string]bool, error) {
	var tree map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tree); err != nil {
		return nil, fmt.Errorf("%w: the permission tree is not a JSON object", ErrUnverifiableRead)
	}
	if tree == nil {
		return nil, fmt.Errorf("%w: the permission tree is null", ErrUnverifiableRead)
	}
	out := make(map[string]map[string]bool, len(tree))
	for path, v := range tree {
		if !aclPathRE.MatchString(path) {
			return nil, fmt.Errorf("%w: the permission tree holds a key that is not an ACL path", ErrUnverifiableRead)
		}
		set, err := decodePrivSet(v)
		if err != nil {
			return nil, fmt.Errorf("%w (at %s)", err, path)
		}
		out[path] = set
	}
	return out, nil
}

// decodePrivSet strictly decodes a {"<Priv>":flag} object, flag one of
// 0, 1, true, false.
func decodePrivSet(raw json.RawMessage) (map[string]bool, error) {
	var set map[string]json.RawMessage
	if err := json.Unmarshal(raw, &set); err != nil || set == nil {
		return nil, fmt.Errorf("%w: a privilege set is not a JSON object", ErrUnverifiableRead)
	}
	out := make(map[string]bool, len(set))
	for name, v := range set {
		if !privNameRE.MatchString(name) {
			return nil, fmt.Errorf("%w: a privilege set holds a name that is not a privilege name", ErrUnverifiableRead)
		}
		switch string(v) {
		case "1", "true":
			out[name] = true
		case "0", "false":
			out[name] = false
		default:
			return nil, fmt.Errorf("%w: privilege %s has a flag that is not 0/1/true/false", ErrUnverifiableRead, name)
		}
	}
	return out, nil
}
