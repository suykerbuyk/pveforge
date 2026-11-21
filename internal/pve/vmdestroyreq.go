package pve

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// This file is the requirement table behind `pveforge doctor`: for one verb,
// what a token must hold, and the READ that decides whether it does.
//
// The verdict is never read off the permission tree. The tree is a HINT shown
// beside it. A requirement is judged by the same read the verb itself makes, so
// doctor can never say "held" for a privilege the verb's own read would refuse:
//
//   - Sys.Audit on /nodes/<node>: GET /nodes/<node>/status, the visibility probe
//     the first destroy makes (nodeDestroyView). Classified by NodeStatusRead,
//     which inflight.go calls too: 200 held, 403 missing, anything else unknown.
//   - Sys.Audit on /: ClusterNodes, the member-list read behind the gone-proof's
//     retry scan (GET /cluster/config/nodes). 403 names the privilege.
//   - VM.PowerMgmt and VM.Allocate on /vms/<id>: the destroy's own checks are
//     per call, so the tree at that path is the only read available, and it is
//     only taken when the operator names a vmid. Without one the row is
//     "not checked", never "missing".

// Verdict is one requirement's outcome. The set is closed.
type Verdict string

const (
	VerdictHeld       Verdict = "held"
	VerdictMissing    Verdict = "missing"
	VerdictUnknown    Verdict = "unknown"
	VerdictNotChecked Verdict = "not checked"
)

// ProbeKind names which read decides a requirement.
type ProbeKind int

const (
	ProbeNodeStatus ProbeKind = iota // GET /nodes/<node>/status
	ProbeMemberList                  // ClusterNodes: GET /cluster/config/nodes
	ProbeVMTree                      // GET /access/permissions?path=/vms/<id>
)

// Requirement is one privilege a verb needs, on one path.
type Requirement struct {
	ID        string
	Privilege string
	// Path is the ACL path; {node} and {vmid} are filled in by CheckVerb.
	Path  string
	Probe ProbeKind
}

// requirementsByVerb is the table, keyed by verb. v1 knows `vm destroy`; a
// later verb is a new row here, not a new mechanism.
var requirementsByVerb = map[string][]Requirement{
	"vm destroy": {
		{ID: "node-audit", Privilege: "Sys.Audit", Path: "/nodes/{node}", Probe: ProbeNodeStatus},
		{ID: "cluster-audit", Privilege: "Sys.Audit", Path: "/", Probe: ProbeMemberList},
		{ID: "vm-powermgmt", Privilege: "VM.PowerMgmt", Path: "/vms/{vmid}", Probe: ProbeVMTree},
		{ID: "vm-allocate", Privilege: "VM.Allocate", Path: "/vms/{vmid}", Probe: ProbeVMTree},
	},
}

// RequirementsFor returns a copy of verb's requirements, or nil for an unknown
// verb.
func RequirementsFor(verb string) []Requirement {
	return append([]Requirement(nil), requirementsByVerb[verb]...)
}

// RequirementResult is one row of the report.
type RequirementResult struct {
	ID        string
	Privilege string
	Path      string // with {node}/{vmid} filled in; "/vms/<id>" when not checked
	Verdict   Verdict
	// Hint is what the permission tree says, shown beside the verdict and never
	// deciding it. Empty when the tree was not read.
	Hint string
	// Detail is a status code or a fixed phrase, never a PVE response body.
	Detail string
}

// NodeStatusRead is the ONE implementation of the visibility probe: GET
// /nodes/<node>/status, classified by STATUS CODE only (a 401 is a bad token,
// not a missing privilege, so it is unknown). inflight.go's nodeDestroyView and
// doctor both call it. It returns the path it read, and the error, so the
// caller can report the read it made.
func (c *Client) NodeStatusRead(ctx context.Context, node string) (path string, v Verdict, err error) {
	path = fmt.Sprintf("/nodes/%s/status", url.PathEscape(node))
	_, err = c.RawRequest(ctx, http.MethodGet, path, nil)
	if err == nil {
		return path, VerdictHeld, nil
	}
	if code, ok := HTTPStatus(err); ok && code == http.StatusForbidden {
		return path, VerdictMissing, err
	}
	return path, VerdictUnknown, err
}

// CheckVerb judges every requirement of verb. vmid 0 means "none named": the
// per-VM rows are VerdictNotChecked and read nothing. Every request it makes is
// a GET. An unknown verb is an error.
func (c *Client) CheckVerb(ctx context.Context, verb, node string, vmid int) ([]RequirementResult, error) {
	reqs := RequirementsFor(verb)
	if len(reqs) == 0 {
		return nil, fmt.Errorf("doctor: no requirement table for %q", verb)
	}
	out := make([]RequirementResult, 0, len(reqs))
	for _, rq := range reqs {
		res := RequirementResult{ID: rq.ID, Privilege: rq.Privilege}
		path := strings.ReplaceAll(rq.Path, "{node}", node)
		if vmid > 0 {
			path = strings.ReplaceAll(path, "{vmid}", strconv.Itoa(vmid))
		} else {
			path = strings.ReplaceAll(path, "{vmid}", "<id>")
		}
		res.Path = path

		switch rq.Probe {
		case ProbeNodeStatus:
			_, v, err := c.NodeStatusRead(ctx, node)
			res.Verdict, res.Detail = v, readDetail(v, err)
			res.Hint = c.treeHint(ctx, path, rq.Privilege, v)
		case ProbeMemberList:
			ns := c.ClusterNodes(ctx, node)
			switch {
			case ns.Privilege == "Sys.Audit on /":
				res.Verdict, res.Detail = VerdictMissing, "HTTP 403"
			case ns.Complete:
				res.Verdict = VerdictHeld
			default:
				res.Verdict, res.Detail = VerdictUnknown, "member list not established: "+ns.Read
			}
			res.Hint = c.treeHint(ctx, path, rq.Privilege, res.Verdict)
		case ProbeVMTree:
			if vmid <= 0 {
				res.Verdict = VerdictNotChecked
				res.Detail = "pass --vmid to check the privileges on a VM"
				break
			}
			perms, err := c.PathPermissions(ctx, path)
			switch {
			case err != nil:
				res.Verdict, res.Detail = VerdictUnknown, readDetail(VerdictUnknown, err)
			case hasKey(perms, rq.Privilege):
				res.Verdict = VerdictHeld
			default:
				res.Verdict = VerdictMissing
			}
		}
		out = append(out, res)
	}
	return out, nil
}

func hasKey(m map[string]bool, k string) bool { _, ok := m[k]; return ok }

// readDetail names a failed read by status code only, never by body.
func readDetail(v Verdict, err error) string {
	if v == VerdictHeld || err == nil {
		return ""
	}
	if code, ok := HTTPStatus(err); ok {
		return fmt.Sprintf("HTTP %d", code)
	}
	return "request failed"
}

// treeHint reads the permission tree at path and says what it shows for priv,
// flagging a disagreement with the probe's verdict. A failed tree read is only
// "unreadable": it never changes the verdict.
func (c *Client) treeHint(ctx context.Context, path, priv string, probe Verdict) string {
	perms, err := c.PathPermissions(ctx, path)
	if err != nil {
		return "tree: unreadable"
	}
	_, held := perms[priv]
	hint := "tree: absent"
	if held {
		hint = "tree: held"
	}
	if (held && probe == VerdictMissing) || (!held && probe == VerdictHeld) {
		hint += " (disagrees with the probe; the probe wins)"
	}
	return hint
}
