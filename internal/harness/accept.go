package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Acceptance (pveforge-harness-golden-reset, P1): the nested cluster is
// whole, read from the nested API through the guard, never from the outer
// cluster's cache. Open's own checks come first (the rosters, the identity
// of the cluster and of every node, a pinned SSH dial); Accept then asks,
// of every node, through that node's own client:
//
//   - its /cluster/status reports the cluster quorate;
//   - its QDevice is connected (GET /cluster/config/qdevice, which is {}
//     when the node runs none);
//   - the shared storage is active on it;
//   - its own status reads (GET /nodes/<node>/status).
//
// Await repeats the whole attempt, Open included, until one passes or the
// deadline: a cluster that is still booting fails an attempt, never the run.

// SharedStorage is the NFS storage every nested node must have active.
const SharedStorage = "pvh-shared"

// qdeviceConnected is the State corosync-qdevice-tool reports for a
// QDevice that is voting (pve-cluster API2/ClusterConfig.pm passes the
// tool's "State" line through).
const qdeviceConnected = "Connected"

// acceptClient is what Accept needs of a node's client.
type acceptClient interface {
	RawRequest(ctx context.Context, method, path string, params url.Values) (json.RawMessage, error)
}

// Accept checks every vetted node; the first failure is returned, naming the
// node and the check.
func (h *Harness) Accept(ctx context.Context) error {
	for _, node := range NodeNames {
		c, ok := h.clients[node]
		if !ok {
			return fmt.Errorf("%s: no vetted client", node)
		}
		if err := acceptNode(ctx, node, c); err != nil {
			return err
		}
	}
	return nil
}

func acceptNode(ctx context.Context, node string, c acceptClient) error {
	get := func(path string) (json.RawMessage, error) {
		raw, err := c.RawRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, fmt.Errorf("%s: read %s: %w", node, path, err)
		}
		return raw, nil
	}
	raw, err := get("/cluster/status")
	if err != nil {
		return err
	}
	if err := decodeQuorate(raw); err != nil {
		return fmt.Errorf("%s: /cluster/status: %w", node, err)
	}
	if raw, err = get("/cluster/config/qdevice"); err != nil {
		return err
	}
	if err := decodeQdevice(raw); err != nil {
		return fmt.Errorf("%s: /cluster/config/qdevice: %w", node, err)
	}
	storagePath := "/nodes/" + node + "/storage/" + SharedStorage + "/status"
	if raw, err = get(storagePath); err != nil {
		return err
	}
	if err := decodeActive(raw); err != nil {
		return fmt.Errorf("%s: %s: %w", node, storagePath, err)
	}
	nodePath := "/nodes/" + node + "/status"
	if raw, err = get(nodePath); err != nil {
		return err
	}
	if err := decodeNodeUp(raw); err != nil {
		return fmt.Errorf("%s: %s: %w", node, nodePath, err)
	}
	return nil
}

// decodeQuorate: exactly one cluster entry, and it is quorate. The rest of
// the answer's shape is Open's (decodeClusterStatus) to judge.
func decodeQuorate(raw json.RawMessage) error {
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || entries == nil {
		return errors.New("not a JSON array")
	}
	clusters := 0
	for _, e := range entries {
		var typ string
		if e == nil || json.Unmarshal(e["type"], &typ) != nil || typ != "cluster" {
			continue
		}
		clusters++
		var q int
		if json.Unmarshal(e["quorate"], &q) != nil {
			return errors.New("the cluster entry carries no quorate flag")
		}
		if q != 1 {
			return errors.New("the cluster is not quorate")
		}
	}
	if clusters != 1 {
		return fmt.Errorf("%d cluster entries, want exactly 1", clusters)
	}
	return nil
}

// decodeQdevice: an object whose State is Connected. {} means the node runs
// no QDevice, which a two-node harness must have.
func decodeQdevice(raw json.RawMessage) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return errors.New("not a JSON object")
	}
	if len(m) == 0 {
		return errors.New("no QDevice runs on this node")
	}
	var state string
	if json.Unmarshal(m["State"], &state) != nil {
		return errors.New("the QDevice reports no State")
	}
	if state != qdeviceConnected {
		return fmt.Errorf("the QDevice is %q, not %q", state, qdeviceConnected)
	}
	return nil
}

// decodeActive: a storage status object with active 1.
func decodeActive(raw json.RawMessage) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return errors.New("not a JSON object")
	}
	var active int
	if json.Unmarshal(m["active"], &active) != nil || active != 1 {
		return errors.New("the storage is not active")
	}
	return nil
}

// decodeNodeUp: a node status object carrying a positive uptime.
func decodeNodeUp(raw json.RawMessage) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return errors.New("not a JSON object")
	}
	var uptime float64
	if json.Unmarshal(m["uptime"], &uptime) != nil || uptime <= 0 {
		return errors.New("the node reports no uptime")
	}
	return nil
}

// ErrNotAccepted is Await's error when the deadline passed before any
// attempt passed.
var ErrNotAccepted = errors.New("the nested cluster was not accepted before the deadline")

// Await runs attempt until it passes or deadline has passed, waiting every
// between attempts. Each failure is reported to report. It returns nil on
// the first passing attempt, ErrNotAccepted (wrapping the last failure) at
// the deadline, or ctx's error if ctx ends first.
func Await(ctx context.Context, deadline, every time.Duration, attempt func(context.Context) error, report func(n int, err error)) error {
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	for n := 1; ; n++ {
		err := attempt(ctx)
		if err == nil {
			return nil
		}
		report(n, err)
		t := time.NewTimer(every)
		select {
		case <-ctx.Done():
			t.Stop()
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("%w: %d attempts, the last: %w", ErrNotAccepted, n, err)
			}
			return ctx.Err()
		case <-t.C:
		}
	}
}

// AcceptOnce is one whole attempt: Open (every guard check), then Accept.
func AcceptOnce(ctx context.Context) error {
	return acceptOnce(ctx, Open)
}

func acceptOnce(ctx context.Context, open func(context.Context) (*Harness, error)) error {
	h, err := open(ctx)
	if err != nil {
		return err
	}
	defer h.Close()
	return h.Accept(ctx)
}
