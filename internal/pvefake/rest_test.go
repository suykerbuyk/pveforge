package pvefake

import (
	"io"
	"net/http"
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

// IfaceServerError answers its interface GET with HTTP 500 and the given
// body as it is, and the entries around it are answered as before.
func TestBridgeREST_IfaceServerError(t *testing.T) {
	rest := NewBridgeREST(t, "n1")
	rest.IfaceResponses = []string{IfaceAbsent, IfaceServerError("boom\nwarning: forged")}
	srv := rest.Server()
	defer srv.Close()
	get := func() (int, string) {
		res, err := srv.Client().Get(srv.URL + "/api2/json/nodes/n1/network/vmbr1")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, _ := get(); code != http.StatusBadRequest {
		t.Fatalf("IfaceAbsent answered %d, want 400", code)
	}
	if code, body := get(); code != http.StatusInternalServerError || body != "boom\nwarning: forged" {
		t.Fatalf("IfaceServerError answered %d %q, want 500 and the body as given", code, body)
	}
}
