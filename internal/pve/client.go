// Package pve is pveforge's thin wrapper over github.com/luthermonson/
// go-proxmox, scoped for now to exactly what the bootstrap flow needs: a
// token-authenticated client and the ACL-grant validation step that proves
// a freshly minted token actually has working grants. Later tasks (the
// object-model get/set layer, hookscript deployment via the storage
// snippets content type) are expected to extend this same client rather
// than introduce a second one.
package pve

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	proxmox "github.com/luthermonson/go-proxmox"
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

	opts := []proxmox.Option{
		proxmox.WithAPIToken(cfg.TokenID, cfg.TokenSecret),
		proxmox.WithTimeout(timeout),
	}
	if cfg.InsecureTLS {
		opts = append(opts, proxmox.WithInsecureSkipVerify())
	}

	httpClient := &http.Client{Timeout: timeout}
	if cfg.InsecureTLS {
		// Clone http.DefaultTransport rather than starting from a bare
		// &http.Transport{} literal: DefaultTransport carries
		// Proxy: http.ProxyFromEnvironment (HTTP_PROXY/HTTPS_PROXY/
		// NO_PROXY support) among other sane defaults, matching
		// go-proxmox's own WithInsecureSkipVerify/ensureTransport
		// approach. A bare literal has a nil Proxy, which would silently
		// drop proxy support for this raw-HTTP write path (vmconfig.go)
		// specifically — while reads through go-proxmox (ListNodes etc.)
		// kept working via the proxy, since only go-proxmox's own
		// transport was ever affected.
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in via cfg.InsecureTLS, mirrors go-proxmox's own WithInsecureSkipVerify
		httpClient.Transport = transport
	}

	return &Client{
		pc:         proxmox.NewClient(baseURL, opts...),
		baseURL:    baseURL,
		authHeader: fmt.Sprintf("PVEAPIToken=%s=%s", cfg.TokenID, cfg.TokenSecret),
		httpClient: httpClient,
	}, nil
}

// ErrNotAuthorized is returned (wrapped) when PVE rejects a request as
// unauthorized/forbidden — distinct from a network/transport failure, and
// from a successful-but-empty resource list (ErrNoGrants in validate.go).
var ErrNotAuthorized = proxmox.ErrNotAuthorized

// ListNodes returns the cluster's node names, as seen through this
// client's token. This is a real, ACL-gated resource (unlike /version),
// which is exactly why bootstrap validation uses it rather than a
// version-class endpoint — see validate.go.
func (c *Client) ListNodes(ctx context.Context) ([]string, error) {
	ns, err := c.pc.Nodes(ctx)
	if err != nil {
		if proxmox.IsNotAuthorized(err) {
			return nil, fmt.Errorf("list nodes: %w", ErrNotAuthorized)
		}
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	names := make([]string, 0, len(ns))
	for _, n := range ns {
		names = append(names, n.Node)
	}
	return names, nil
}
