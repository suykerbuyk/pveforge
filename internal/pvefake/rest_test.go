package pvefake

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDescribeWrite pins how a mutating request is recorded: query string
// and body each decoded and re-encoded with sorted keys, a non-form body kept
// verbatim, and a request carrying nothing rendered as just "METHOD path".
// The query half matters because RawRequest sends a DELETE's parameters in
// the query string, not the body.
func TestDescribeWrite(t *testing.T) {
	for name, c := range map[string]struct {
		method, target, body, want string
	}{
		"form body, keys sorted": {"POST", "/api2/json/nodes/n/network", "type=bridge&iface=vmbr1&bridge_ports=eth1",
			"POST /api2/json/nodes/n/network bridge_ports=eth1&iface=vmbr1&type=bridge"},
		"query string, keys sorted": {"DELETE", "/api2/json/nodes/n/network/vmbr1?z=1&a=2", "",
			"DELETE /api2/json/nodes/n/network/vmbr1 ?a=2&z=1"},
		"query and body":  {"PUT", "/p?q=1", "b=2", "PUT /p ?q=1 b=2"},
		"nothing carried": {"PUT", "/api2/json/nodes/n/network", "", "PUT /api2/json/nodes/n/network"},
		"non-form body":   {"PUT", "/p", "%zz", "PUT /p raw:%zz"},
	} {
		r := httptest.NewRequest(c.method, c.target, strings.NewReader(c.body))
		if got := describeWrite(r); got != c.want {
			t.Errorf("%s: describeWrite = %q, want %q", name, got, c.want)
		}
	}
}
