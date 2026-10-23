//go:build harness

// Batch A item-67 read-swallow-shape captures, plus the item-66 corroborator
// (pveforge-nested-pve-test-harness). Same rules as capture_harness.go: built
// only under the `harness` tag, in package pve so it can reach the production
// client, matcher and decode paths; adds no production behaviour.
//
// Item 67 has two halves. The ABSENCE half asks whether PVE's "object does not
// exist" answer is classified by the production matcher (NotFound, notfound.go)
// on its subject-named TEXT, which is code-agnostic — a missing VM config is a
// 500, a missing interface a 400 (notfound.go:54-55) — and crucially that a
// 401/403 auth rejection is NEVER read as an absence. The FIELD-PRESENCE half
// asks whether the fields the guards assume are always present really are
// (storage `type`, storage.go:25-29; VM config `digest`, vms.go:33-35; VM run
// `status`, vms.go:27-28), decoding exactly as those guards do.

package pve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// Subject constructors that mirror the production call sites, so the capture
// classifies with the SAME subject the guard would, not a re-derived one.

// VMConfigMissingSubject is the subject VMDestroy uses to read a missing VM
// config as absent (internal/idempotent/vmdestroy.go:125).
func VMConfigMissingSubject(vmid int) Subject {
	return Subject{Fragment: fmt.Sprintf("qemu-server/%d.conf", vmid)}
}

// IfaceMissingSubject is the subject NetworkBridgeEnsure uses for a missing
// interface (internal/idempotent/networkbridge.go:104).
func IfaceMissingSubject(iface string) Subject {
	return Subject{Param: "iface", Name: iface, Nouns: []string{"iface", "interface"}}
}

// StorageMissingSubject is a best-effort subject for a missing storage — no
// production call site defines one yet, so the live capture is what confirms
// PVE's exact wording. Recorded, not load-bearing.
func StorageMissingSubject(name string) Subject {
	return Subject{Param: "storage", Name: name, Nouns: []string{"storage"}}
}

// AbsenceProbe is one item-67 "missing object" leg: the GET path and the
// production Subject NotFound classifies its answer by. A zero Subject records
// the leg raw only — its absence grammar is still being discovered (e.g. an
// unknown UPID is a validation error, not a "does not exist").
type AbsenceProbe struct {
	Name    string
	Path    string
	Subject Subject
}

// AbsenceCapture is one recorded item-67 absence answer.
type AbsenceCapture struct {
	Name            string `json:"name"`
	Path            string `json:"path"`
	Code            int    `json:"code"`
	AnswerText      string `json:"answer_text"`
	MatcherNotFound bool   `json:"matcher_not_found"` // NotFound(err, subject): text-based, code-agnostic
	Auth            bool   `json:"auth"`              // errors.Is(err, ErrNotAuthorized): a 401/403
	Absence         bool   `json:"absence"`           // the item-67 decision: NotFound AND not auth
}

// classifyAbsence is item-67's absence decision and a mutation target. A typed
// PVE answer is this subject's absence ONLY if the production NotFound matcher
// (by subject-named TEXT, code-agnostic) says so AND it is not an auth
// rejection: a 401/403 (ErrNotAuthorized, rawrequest.go:169-170) is never an
// "object does not exist", however its body happens to read.
func classifyAbsence(err error, s Subject) bool {
	if errors.Is(err, ErrNotAuthorized) {
		return false
	}
	return NotFound(err, s)
}

// CaptureAbsence issues the probe's GET through the production RawRequest path,
// expects a typed PVE error answer, and records the status code, the error's
// own text, and the matcher/auth/absence classification. A 2xx (no error) or a
// non-typed error is itself the finding — returned as an error so it is never
// silently recorded as "not an absence".
func (c *Client) CaptureAbsence(ctx context.Context, p AbsenceProbe) (*AbsenceCapture, error) {
	_, err := c.RawRequest(ctx, http.MethodGet, p.Path, nil)
	if err == nil {
		return nil, fmt.Errorf("item-67 absence probe %q: expected a PVE error answer, got success", p.Name)
	}
	var se *StatusError
	if !errors.As(err, &se) {
		return nil, fmt.Errorf("item-67 absence probe %q: not a typed PVE answer: %w", p.Name, err)
	}
	return &AbsenceCapture{
		Name:            p.Name,
		Path:            p.Path,
		Code:            se.Code,
		AnswerText:      se.Error(),
		MatcherNotFound: NotFound(err, p.Subject),
		Auth:            errors.Is(err, ErrNotAuthorized),
		Absence:         classifyAbsence(err, p.Subject),
	}, nil
}

// FieldPresence is one item-67 field-presence capture: whether a field the
// guards assume is always present was in fact present in PVE's payload.
type FieldPresence struct {
	Path    string `json:"path"`
	Field   string `json:"field"`
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
}

// CaptureStorageType decodes a storage status exactly as GetStorage does
// (storage.go) and records whether `type` was present — the field the orphan
// scan's guard (storage.go:25-29) assumes always is.
func (c *Client) CaptureStorageType(ctx context.Context, node, name string) (*FieldPresence, error) {
	path := fmt.Sprintf("/nodes/%s/storage/%s/status", url.PathEscape(node), url.PathEscape(name))
	var storage proxmox.Storage
	if err := c.pc.Get(ctx, path, &storage); err != nil {
		return nil, fmt.Errorf("capture storage type on %q/%q: %w", node, name, err)
	}
	return &FieldPresence{Path: path, Field: "type", Present: storage.Type != "", Value: storage.Type}, nil
}

// CaptureVMStatusField decodes a VM's current status exactly as GetVM does
// (vms.go) and records whether the run `status` field was present (vms.go:27-28).
func (c *Client) CaptureVMStatusField(ctx context.Context, node string, vmid int) (*FieldPresence, error) {
	path := fmt.Sprintf("/nodes/%s/qemu/%d/status/current", url.PathEscape(node), vmid)
	var vm proxmox.VirtualMachine
	if err := c.pc.Get(ctx, path, &vm); err != nil {
		return nil, fmt.Errorf("capture vm status field on %q/%d: %w", node, vmid, err)
	}
	return &FieldPresence{Path: path, Field: "status", Present: vm.Status != "", Value: vm.Status}, nil
}

// CaptureVMConfigDigest decodes a VM's config exactly as GetVM does (vms.go) and
// records whether the `digest` field was present — the field the guard
// (vms.go:33-35) keys "a nil config is {\"data\":null}" on.
func (c *Client) CaptureVMConfigDigest(ctx context.Context, node string, vmid int) (*FieldPresence, error) {
	path := fmt.Sprintf("/nodes/%s/qemu/%d/config", url.PathEscape(node), vmid)
	var cfg *proxmox.VirtualMachineConfig
	if err := c.pc.Get(ctx, path, &cfg); err != nil {
		return nil, fmt.Errorf("capture vm config digest on %q/%d: %w", node, vmid, err)
	}
	present := cfg != nil && cfg.Digest != ""
	value := ""
	if cfg != nil {
		value = cfg.Digest
	}
	return &FieldPresence{Path: path, Field: "digest", Present: present, Value: value}, nil
}

// ClassifyRawListEnvelope is the item-66 corroborator (N2): it reports a list
// payload's shape from its RAW bytes, NOT by a guard decode — the deterministic
// Go rule only, data:null -> ShapeNull, data:[] -> ShapeEmpty, a non-empty
// array -> ShapeItems. It corroborates findbytag.go:60-62's cluster.Resources
// nil-guard for /cluster/resources?type=vm without re-running it.
func ClassifyRawListEnvelope(body []byte) (ListShape, error) {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "", fmt.Errorf("corroborator: body is not a JSON envelope: %w", err)
	}
	trimmed := bytes.TrimSpace(env.Data)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return ShapeNull, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(trimmed, &arr); err != nil {
		return "", fmt.Errorf("corroborator: data is not a JSON array: %w", err)
	}
	if len(arr) == 0 {
		return ShapeEmpty, nil
	}
	return ShapeItems, nil
}
