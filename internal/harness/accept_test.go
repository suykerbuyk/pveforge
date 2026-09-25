package harness

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// acceptFake answers Accept's reads by path. It satisfies liveClient so a
// Harness can hold it.
type acceptFake struct {
	answers map[string]string
	errs    map[string]error
	calls   []string
}

func (f *acceptFake) RawRequest(_ context.Context, method, path string, _ url.Values) (json.RawMessage, error) {
	f.calls = append(f.calls, method+" "+path)
	if err := f.errs[path]; err != nil {
		return nil, err
	}
	a, ok := f.answers[path]
	if !ok {
		return nil, errors.New("no answer for " + path)
	}
	return json.RawMessage(a), nil
}
func (f *acceptFake) GetNodes(context.Context) (proxmox.NodeStatuses, error) { return nil, nil }
func (f *acceptFake) LinkState(context.Context, string) (sshexec.LinkState, error) {
	return sshexec.LinkState{}, nil
}
func (f *acceptFake) Close() error { return nil }

// wholeNode is a node whose every Accept read passes.
func wholeNode(node string) *acceptFake {
	return &acceptFake{answers: map[string]string{
		"/cluster/status":                               goodStatus,
		"/cluster/config/qdevice":                       `{"Algorithm":"Fifty-Fifty split","Model":"Net","QNetd host":"198.51.100.13:5403","State":"Connected","Tie-breaker":"Node with lowest node ID"}`,
		"/nodes/" + node + "/storage/pvh-shared/status": `{"active":1,"enabled":1,"type":"nfs","total":1,"used":0,"avail":1}`,
		"/nodes/" + node + "/status":                    `{"uptime":42,"cpu":0.01}`,
	}}
}

func wholeHarness() (*Harness, map[string]*acceptFake) {
	fakes := map[string]*acceptFake{}
	h := &Harness{clients: map[string]liveClient{}}
	for _, n := range NodeNames {
		fakes[n] = wholeNode(n)
		h.clients[n] = fakes[n]
	}
	return h, fakes
}

func TestAccept_AWholeClusterPasses(t *testing.T) {
	h, fakes := wholeHarness()
	if err := h.Accept(context.Background()); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	// Anti-vacuity: every check was asked of every node, through its own client.
	for _, n := range NodeNames {
		want := []string{"GET /cluster/status", "GET /cluster/config/qdevice", "GET /nodes/" + n + "/storage/pvh-shared/status", "GET /nodes/" + n + "/status"}
		if strings.Join(fakes[n].calls, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s calls:\n%s\nwant:\n%s", n, strings.Join(fakes[n].calls, "\n"), strings.Join(want, "\n"))
		}
	}
}

// Each check fails Accept on its own, on either node, naming the node.
func TestAccept_EachCheckFailsAlone(t *testing.T) {
	storage := func(n string) string { return "/nodes/" + n + "/storage/pvh-shared/status" }
	status := func(n string) string { return "/nodes/" + n + "/status" }
	for _, node := range NodeNames {
		for _, c := range []struct {
			name, path, answer, want string
			err                      error
		}{
			{name: "not quorate", path: "/cluster/status", answer: strings.Replace(goodStatus, `"quorate":1`, `"quorate":0`, 1), want: "not quorate"},
			{name: "no quorate flag", path: "/cluster/status", answer: strings.Replace(goodStatus, `"quorate":1,`, ``, 1), want: "no quorate flag"},
			{name: "no cluster entry", path: "/cluster/status", answer: `[{"type":"node","name":"pvh-n1","ip":"198.51.100.11"}]`, want: "0 cluster entries"},
			{name: "two cluster entries", path: "/cluster/status", answer: `[{"type":"cluster","name":"pvh","quorate":1},{"type":"cluster","name":"pvh","quorate":1}]`, want: "2 cluster entries"},
			{name: "status not an array", path: "/cluster/status", answer: `{}`, want: "not a JSON array"},
			{name: "status unreadable", path: "/cluster/status", err: errors.New("595 no route"), want: "595 no route"},
			{name: "no qdevice", path: "/cluster/config/qdevice", answer: `{}`, want: "no QDevice runs"},
			{name: "qdevice disconnected", path: "/cluster/config/qdevice", answer: `{"State":"Disconnected"}`, want: `"Disconnected"`},
			{name: "qdevice without state", path: "/cluster/config/qdevice", answer: `{"Model":"Net"}`, want: "no State"},
			{name: "qdevice not an object", path: "/cluster/config/qdevice", answer: `[]`, want: "not a JSON object"},
			{name: "qdevice null", path: "/cluster/config/qdevice", answer: `null`, want: "not a JSON object"},
			{name: "shared storage inactive", path: storage(node), answer: `{"active":0,"enabled":1}`, want: "not active"},
			{name: "shared storage without active", path: storage(node), answer: `{"enabled":1}`, want: "not active"},
			{name: "shared storage unreadable", path: storage(node), err: errors.New("storage 'pvh-shared' does not exist"), want: "does not exist"},
			{name: "node without uptime", path: status(node), answer: `{"cpu":0.01}`, want: "no uptime"},
			{name: "node uptime zero", path: status(node), answer: `{"uptime":0}`, want: "no uptime"},
			{name: "node status null", path: status(node), answer: `null`, want: "not a JSON object"},
		} {
			t.Run(node+" "+c.name, func(t *testing.T) {
				h, fakes := wholeHarness()
				f := fakes[node]
				if c.err != nil {
					f.errs = map[string]error{c.path: c.err}
				} else {
					f.answers[c.path] = c.answer
				}
				err := h.Accept(context.Background())
				if err == nil || !strings.Contains(err.Error(), c.want) || !strings.HasPrefix(err.Error(), node+": ") {
					t.Fatalf("Accept = %v, want an error from %s containing %q", err, node, c.want)
				}
			})
		}
	}
}

func TestAccept_ANodeWithoutAClient(t *testing.T) {
	h, _ := wholeHarness()
	delete(h.clients, "pvh-n2")
	if err := h.Accept(context.Background()); err == nil || !strings.Contains(err.Error(), "pvh-n2: no vetted client") {
		t.Fatalf("Accept = %v", err)
	}
}

func TestAwait_RetriesWholeAttemptsUntilOnePasses(t *testing.T) {
	var reported []int
	n := 0
	err := Await(context.Background(), time.Second, time.Millisecond, func(context.Context) error {
		n++
		if n < 3 {
			return errors.New("still booting")
		}
		return nil
	}, func(i int, err error) { reported = append(reported, i) })
	if err != nil || n != 3 {
		t.Fatalf("Await = %v after %d attempts, want nil after 3", err, n)
	}
	if len(reported) != 2 || reported[0] != 1 || reported[1] != 2 {
		t.Errorf("reported %v, want [1 2]", reported)
	}
}

func TestAwait_TheDeadlineEndsIt(t *testing.T) {
	last := errors.New("the QDevice is \"Disconnected\"")
	n := 0
	start := time.Now()
	// A watchdog: an Await that ignored its deadline ends here, late.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := Await(ctx, 50*time.Millisecond, 5*time.Millisecond, func(context.Context) error { n++; return last }, func(int, error) {})
	if !errors.Is(err, ErrNotAccepted) || !errors.Is(err, last) {
		t.Fatalf("Await = %v, want ErrNotAccepted wrapping the last failure", err)
	}
	if n < 2 {
		t.Errorf("%d attempts before the deadline, want several", n)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Await took %s past a 50ms deadline", d)
	}
}

func TestAwait_ACanceledContextEndsIt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	err := Await(ctx, time.Minute, time.Millisecond, func(context.Context) error { cancel(); return errors.New("x") }, func(int, error) {})
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrNotAccepted) {
		t.Fatalf("Await = %v, want context.Canceled", err)
	}
}

// The attempt sees the deadline: a read that would hang past it is cut.
func TestAwait_TheAttemptCarriesTheDeadline(t *testing.T) {
	// A watchdog, so an Await without its deadline cannot hang the package.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := Await(ctx, 30*time.Millisecond, time.Millisecond, func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("the attempt's context has no deadline")
		}
		<-ctx.Done()
		return ctx.Err()
	}, func(int, error) {})
	if !errors.Is(err, ErrNotAccepted) {
		t.Fatalf("Await = %v", err)
	}
}

// One attempt is Open, then Accept: an Open refusal is the attempt's
// failure, and so is an Accept failure on a harness Open vetted.
func TestAcceptOnce_OpenThenAccept(t *testing.T) {
	refused := errors.New("harness guard: the roster is the operator's")
	if err := acceptOnce(context.Background(), func(context.Context) (*Harness, error) { return nil, refused }); !errors.Is(err, refused) {
		t.Fatalf("acceptOnce = %v, want Open's refusal", err)
	}
	h, fakes := wholeHarness()
	fakes["pvh-n1"].answers["/cluster/config/qdevice"] = `{"State":"Disconnected"}`
	if err := acceptOnce(context.Background(), func(context.Context) (*Harness, error) { return h, nil }); err == nil || !strings.Contains(err.Error(), "Disconnected") {
		t.Fatalf("acceptOnce = %v, want Accept's failure", err)
	}
	h, _ = wholeHarness()
	if err := acceptOnce(context.Background(), func(context.Context) (*Harness, error) { return h, nil }); err != nil {
		t.Fatalf("acceptOnce = %v, want nil", err)
	}
}

// With no harness environment, the real attempt is refused by the guard
// before any request.
func TestAcceptOnce_RefusedWithoutTheHarnessEnvironment(t *testing.T) {
	t.Setenv(RosterVar, "")
	t.Setenv(OuterRostersVar, "")
	if err := AcceptOnce(context.Background()); !errors.Is(err, ErrGuard) {
		t.Fatalf("AcceptOnce = %v, want a guard refusal", err)
	}
}
