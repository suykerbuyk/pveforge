package pve

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// pveforge-unify-notfound-classifiers: one helper, NotFound, over PVE's
// typed answer only.

var (
	vmSubject    = Subject{Fragment: "qemu-server/100.conf"}
	ifaceSubject = Subject{Param: "iface", Name: "vmbr1", Nouns: []string{"iface", "interface"}}
)

const (
	vmMissingText    = "Configuration file 'nodes/qa-pve-01/qemu-server/100.conf' does not exist"
	ifaceMissingBody = `{"errors":{"iface":"interface does not exist"},"data":null}`
)

// rawStatusServer answers every request on a loopback listener with exactly
// statusLine (e.g. "500 Configuration file ... does not exist") and body,
// over HTTP/1.1, the way PVE's own server does. httptest cannot send a
// reason phrase of its own. The listener and every connection are closed
// by t.Cleanup, and the accept loop is waited for.
func rawStatusServer(t *testing.T, statusLine, body string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var conns []net.Conn
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				r := bufio.NewReader(c)
				req, err := http.ReadRequest(r)
				if err != nil {
					return
				}
				_ = req.Body.Close()
				_, _ = fmt.Fprintf(c, "HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", statusLine, len(body), body)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return "http://" + ln.Addr().String()
}

func rawAnswer(t *testing.T, statusLine, body string) error {
	t.Helper()
	c, err := NewClient(ClientConfig{BaseURLOverride: rawStatusServer(t, statusLine, body), TokenID: "root@pam!pveforge", TokenSecret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.RawRequest(context.Background(), http.MethodGet, "/nodes/qa-pve-01/qemu/100/config", nil)
	if err == nil {
		t.Fatal("want an error")
	}
	return err
}

// N4: PVE may put the message in the reason phrase (its die() does, with
// only {"data":null} in the body) or in the body (with a canonical reason
// phrase, as HTTP/2 leaves it). Either is PVE saying so; neither is not.
// Driven through a real RawRequest over a real HTTP/1.1 status line.
func TestNotFound_N4_MessageInTheStatusLineOrTheBody(t *testing.T) {
	for _, tc := range []struct {
		name, status, body string
		subject            Subject
		want               bool
	}{
		{"vm: reason phrase, null body", "500 " + vmMissingText, `{"data":null}`, vmSubject, true},
		{"vm: canonical reason, message in body", "500 Internal Server Error", `{"data":null,"message":"` + vmMissingText + `\n"}`, vmSubject, true},
		{"vm: neither", "500 Internal Server Error", `{"data":null}`, vmSubject, false},
		{"iface: parameter map, 400", "400 Parameter verification failed.", ifaceMissingBody, ifaceSubject, true},
		{"iface: reason phrase names it", "500 iface 'vmbr1' does not exist", `{"data":null}`, ifaceSubject, true},
		{"iface: neither", "500 Internal Server Error", `{"data":null}`, ifaceSubject, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := rawAnswer(t, tc.status, tc.body)
			if code, ok := HTTPStatus(err); !ok || code != 500 && code != 400 {
				t.Fatalf("not a typed answer: %v", err)
			}
			if got := NotFound(fmt.Errorf("caller: %w", err), tc.subject); got != tc.want {
				t.Errorf("NotFound = %v, want %v, for %v", got, tc.want, err)
			}
		})
	}
}

// N2: untyped text is never a PVE answer, even carrying a genuine
// not-found's exact text; N3: nor is a real transport failure, whose text
// quotes the request URL.
func TestNotFound_N2_N3_OnlyATypedAnswerCounts(t *testing.T) {
	genuine := NewStatusError("raw request", 500, "500 Internal Server Error", []byte(vmMissingText))
	if !NotFound(genuine, vmSubject) {
		t.Fatal("control: the typed genuine answer must classify")
	}
	if NotFound(errors.New(genuine.Error()), vmSubject) {
		t.Error("N2: untyped text with a genuine answer's exact text classified as absent")
	}
	iface := NewStatusError("raw request", 400, "400 Parameter verification failed.", []byte(ifaceMissingBody))
	if !NotFound(iface, ifaceSubject) || NotFound(errors.New(iface.Error()), ifaceSubject) {
		t.Error("N2: the iface subject must classify the typed answer and only it")
	}

	c, err := NewClient(ClientConfig{BaseURLOverride: rawStatusServer(t, "200 OK", "{}"), TokenID: "root@pam!pveforge", TokenSecret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	c.baseURL = "http://127.0.0.1:1/api2/json" // nothing listens: a transport error
	_, transport := c.RawRequest(context.Background(), http.MethodGet, "/nodes/qa-pve-01/network/vmbr1/qemu-server/100.conf/does not exist", nil)
	if transport == nil || !strings.Contains(transport.Error(), "vmbr1") {
		t.Fatalf("want a transport error quoting the URL, got %v", transport)
	}
	if NotFound(transport, vmSubject) || NotFound(transport, ifaceSubject) {
		t.Error("N3: a transport error was classified as absent")
	}
	if NotFound(nil, vmSubject) {
		t.Error("nil classified as absent")
	}
}

// N5: near misses for the VM subject: PVE saying "does not exist" about
// something else — a user, another VM, a volume or bridge the config
// names — is not this VM missing.
func TestNotFound_N5_VMNearMisses(t *testing.T) {
	for _, body := range []string{
		"user 'root@pve' does not exist",
		"Configuration file 'nodes/qa-pve-01/qemu-server/101.conf' does not exist",
		"Configuration file 'nodes/qa-pve-01/qemu-server/1000.conf' does not exist",
		"Configuration file 'nodes/qa-pve-01/qemu-server/2100.conf' does not exist",
		"volume 'local-lvm:vm-100-disk-0' does not exist",
		"bridge 'vmbr9' does not exist",
		"storage 'local-lvm' does not exist",
		"Configuration file 'nodes/qa-pve-01/qemu-server/100.conf' is locked",
	} {
		if NotFound(NewStatusError("raw request", 500, "500 Internal Server Error", []byte(body)), vmSubject) {
			t.Errorf("classified as vm 100 missing: %q", body)
		}
	}
}

// N6: go-proxmox's own typed answer, with the same status line and body,
// classifies exactly as a *StatusError does (P3 of
// pveforge-post-apply-verification-and-pending can adopt NotFound for the
// GetVM paths without another helper).
func TestNotFound_N6_GoProxmoxStatusError(t *testing.T) {
	for _, tc := range []struct {
		status, body string
		want         bool
	}{
		{"500 " + vmMissingText, `{"data":null}`, true},
		{"500 Internal Server Error", "user 'root@pve' does not exist", false},
	} {
		err := fmt.Errorf("get vm: %w", &proxmox.StatusError{StatusCode: 500, Status: tc.status, Body: []byte(tc.body)})
		if got := NotFound(err, vmSubject); got != tc.want {
			t.Errorf("proxmox.StatusError %q: NotFound = %v, want %v", tc.status, got, tc.want)
		}
	}
}

// N7: a Subject that picks out nothing matches nothing, even a genuine
// not-found: the shared helper cannot become a shared widening.
func TestNotFound_N7_AnEmptySubjectMatchesNothing(t *testing.T) {
	genuine := NewStatusError("raw request", 500, "500 "+vmMissingText, []byte(ifaceMissingBody))
	for name, s := range map[string]Subject{
		"empty":        {},
		"param only":   {Param: "iface"},
		"no nouns":     {Param: "iface", Name: "vmbr1"},
		"no name":      {Param: "iface", Nouns: []string{"iface"}},
		"nouns only":   {Nouns: []string{"iface"}},
		"name only":    {Name: "vmbr1"},
		"name + nouns": {Name: "vmbr1", Nouns: []string{"iface"}},
	} {
		if NotFound(genuine, s) {
			t.Errorf("%s: Subject %+v matched", name, s)
		}
	}
}

// NewStatusError builds exactly what RawRequest returns for the same answer.
func TestNewStatusError_MatchesRawRequest(t *testing.T) {
	err := rawAnswer(t, "500 "+vmMissingText, " {\"data\":null}\n")
	var got *StatusError
	if !errors.As(err, &got) {
		t.Fatal("not a *StatusError")
	}
	built := NewStatusError("raw request", got.Code, got.Status, got.Body)
	if built.Error() != got.Error() || built.Code != got.Code || built.Status != got.Status || string(built.Body) != string(got.Body) {
		t.Errorf("NewStatusError = %#v, RawRequest = %#v", built, got)
	}
}

// N9: the phrase, C1's fragment and C2's nouns match in any case, as they
// always have (C1 lower-cased the whole text; C2's regexes are (?i)); only
// C2's name is exact.
func TestNotFound_N9_CaseInsensitivePhraseAndAnchors(t *testing.T) {
	for _, tc := range []struct {
		body    string
		subject Subject
		want    bool
	}{
		{"CONFIGURATION FILE 'nodes/n/QEMU-SERVER/100.CONF' DOES NOT EXIST", vmSubject, true},
		{"IFACE 'vmbr1' DOES NOT EXIST", ifaceSubject, true},
		{`{"errors":{"iface":"INTERFACE DOES NOT EXIST"},"data":null}`, ifaceSubject, true},
		{"iface 'VMBR1' does not exist", ifaceSubject, false},
	} {
		if got := NotFound(NewStatusError("raw request", 500, "500 Internal Server Error", []byte(tc.body)), tc.subject); got != tc.want {
			t.Errorf("%q: NotFound = %v, want %v", tc.body, got, tc.want)
		}
	}
}
