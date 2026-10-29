package pve

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"errors"
)

// storageStatus is the shared/unshared GetStorage reply a scenario serves.
func writeStorageStatus(w http.ResponseWriter, shared int) {
	w.Header().Set("Content-Type", "application/json")
	if shared != 0 {
		_, _ = w.Write([]byte(`{"data":{"storage":"local-lvm","type":"lvmthin","shared":1}}`))
		return
	}
	_, _ = w.Write([]byte(`{"data":{"storage":"local-lvm","type":"lvmthin","shared":0}}`))
}

// TestOrphanVolumesForVMIDWithVMList_FailsClosedOnTokenConfigRefusal is the
// CENTRAL Unit-2 invariant (§2): the per-VM config reads stay on the token, and
// a 401/403 (or an unverifiable read) on a VMID the ROOT list named ABORTS the
// whole determination — never a skip, which would make VM 690's LIVE disk read
// as a false orphan and get deleted by the destructive free.
//
// Mutation target: turning the ClaimedVolumes abort (storageorphans.go ~:404)
// into a per-VM "continue on error" returns local-lvm:vm-690-disk-0 as an orphan.
func TestOrphanVolumesForVMIDWithVMList_FailsClosedOnTokenConfigRefusal(t *testing.T) {
	cases := map[string]struct {
		configStatus int
		configBody   string
		wantIsAuth   bool
		wantIsUnver  bool
	}{
		"403 config": {configStatus: http.StatusForbidden, configBody: "no VM.Audit on 690", wantIsAuth: true},
		"401 config": {configStatus: http.StatusUnauthorized, configBody: "unauthorized", wantIsAuth: true},
		// A 200 with no digest is a config a healthy PVE never returns for a live
		// VM — ClaimedVolumes refuses it as an unverifiable read.
		"200 no digest": {configStatus: http.StatusOK, configBody: `{"data":{}}`, wantIsUnver: true},
		// A 500 aborts too, but is neither ErrNotAuthorized nor ErrUnverifiableRead.
		"500 config": {configStatus: http.StatusInternalServerError, configBody: "boom"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var configHits int32
			srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/nodes/qa-pve-01/storage/local-lvm/status":
					writeStorageStatus(w, 0)
				case "/nodes/qa-pve-01/storage/local-lvm/content":
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"data":[{"volid":"local-lvm:vm-690-disk-0","vmid":690,"content":"images"}]}`))
				case "/nodes/qa-pve-01/qemu/690/config":
					atomic.AddInt32(&configHits, 1)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.configStatus)
					_, _ = w.Write([]byte(tc.configBody))
				default:
					http.NotFound(w, r)
				}
			})
			c := testClient(t, srv)

			orphans, err := c.OrphanVolumesForVMIDWithVMList(context.Background(), "qa-pve-01", "local-lvm", 690, []int{690})
			if err == nil {
				t.Fatalf("expected a refusal, got orphans %+v (a skip-on-config-error would return 690's LIVE disk here)", orphans)
			}
			if orphans != nil {
				t.Errorf("expected a nil list alongside the refusal, got %+v", orphans)
			}
			if tc.wantIsAuth && !errors.Is(err, ErrNotAuthorized) {
				t.Errorf("expected errors.Is ErrNotAuthorized, got %v", err)
			}
			if tc.wantIsUnver && !errors.Is(err, ErrUnverifiableRead) {
				t.Errorf("expected errors.Is ErrUnverifiableRead, got %v", err)
			}
			if atomic.LoadInt32(&configHits) == 0 {
				t.Errorf("expected the token config read for the root-listed VM 690 to be attempted")
			}
		})
	}
}

// TestOrphanVolumesForVMIDWithVMList_CompleteListClaimsLiveDisk is the
// completeness win: given the COMPLETE root-sourced list, VM 690's live disk is
// claimed and is NOT an orphan — even though the TOKEN's GetVMs is SHORT (omits
// 690). Mutation target: "ignore completeVMIDs and call GetVMs" would enumerate
// only [100] (the short token list), leave vm-690-disk-0 unclaimed, and return
// it as a concrete false orphan.
func TestOrphanVolumesForVMIDWithVMList_CompleteListClaimsLiveDisk(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/qa-pve-01/storage/local-lvm/status":
			writeStorageStatus(w, 0)
		case "/nodes/qa-pve-01/storage/local-lvm/content":
			_, _ = w.Write([]byte(`{"data":[{"volid":"local-lvm:vm-690-disk-0","vmid":690,"content":"images"}]}`))
		// The TOKEN's VM list is SHORT: it omits 690 (the measured ACL/NoAccess
		// omission). A mutant that ignores completeVMIDs and calls GetVMs sees
		// only 100 and mis-reports 690's disk as an orphan.
		case "/nodes/qa-pve-01/qemu":
			_, _ = w.Write([]byte(`{"data":[{"vmid":100}]}`))
		case "/nodes/qa-pve-01/qemu/100/config":
			_, _ = w.Write([]byte(`{"data":{"digest":"d100"}}`))
		case "/nodes/qa-pve-01/qemu/100/snapshot":
			_, _ = w.Write([]byte(`{"data":[{"name":"current"}]}`))
		case "/nodes/qa-pve-01/qemu/690/config":
			_, _ = w.Write([]byte(`{"data":{"digest":"d690","scsi0":"local-lvm:vm-690-disk-0,size=32G"}}`))
		case "/nodes/qa-pve-01/qemu/690/snapshot":
			_, _ = w.Write([]byte(`{"data":[{"name":"current"}]}`))
		default:
			http.NotFound(w, r)
		}
	})
	c := testClient(t, srv)

	orphans, err := c.OrphanVolumesForVMIDWithVMList(context.Background(), "qa-pve-01", "local-lvm", 690, []int{100, 690})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(orphans) != 0 {
		t.Fatalf("vm-690-disk-0 is claimed by the complete list's VM 690 and must NOT be an orphan; got %+v", orphans)
	}
}

// TestOrphanVolumesForVMIDWithVMList_NarrowsToPrefix pins the prefix narrowing:
// with an empty (zero-VM) list nothing is claimed, so every images volume is a
// candidate, but the result for vmid 690 is ONLY local-lvm:vm-690-disk-0 —
// vm-700-disk-0 (a different VMID's disk) and the iso are excluded. The
// drop-prefix mutant's red line is vm-700-disk-0 (the iso is excluded by
// claimableContentTypes, not by the prefix).
func TestOrphanVolumesForVMIDWithVMList_NarrowsToPrefix(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/qa-pve-01/storage/local-lvm/status":
			writeStorageStatus(w, 0)
		case "/nodes/qa-pve-01/storage/local-lvm/content":
			_, _ = w.Write([]byte(`{"data":[` +
				`{"volid":"local-lvm:vm-690-disk-0","vmid":690,"content":"images"},` +
				`{"volid":"local-lvm:vm-700-disk-0","vmid":700,"content":"images"},` +
				`{"volid":"local-lvm:iso/x.iso","content":"iso"}]}`))
		default:
			http.NotFound(w, r)
		}
	})
	c := testClient(t, srv)

	orphans, err := c.OrphanVolumesForVMIDWithVMList(context.Background(), "qa-pve-01", "local-lvm", 690, []int{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(orphans) != 1 || orphans[0].Volid != "local-lvm:vm-690-disk-0" {
		t.Fatalf("expected only local-lvm:vm-690-disk-0 after prefix narrowing, got %+v", orphans)
	}
}

// TestOrphanVolumesWithVMList_NilVsEmpty pins the completeVMIDs contract: a nil
// list is refused (a dropped NodeVMIDs error), a non-nil empty slice is a
// genuine zero-QEMU node and yields the orphans. The guard is `== nil`, NOT
// `len() == 0`; constructing the two cases as nil vs []int{} catches a len==0
// shipment.
func TestOrphanVolumesWithVMList_NilVsEmpty(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/qa-pve-01/storage/local-lvm/status":
			writeStorageStatus(w, 0)
		case "/nodes/qa-pve-01/storage/local-lvm/content":
			_, _ = w.Write([]byte(`{"data":[{"volid":"local-lvm:vm-690-disk-0","vmid":690,"content":"images"}]}`))
		default:
			http.NotFound(w, r)
		}
	}

	// nil → refuse.
	c := testClient(t, newFakeAPIServer(t, handler))
	var nilList []int
	if orphans, err := c.OrphanVolumesWithVMList(context.Background(), "qa-pve-01", "local-lvm", nilList); err == nil {
		t.Fatalf("expected a nil VM list to be refused, got %+v", orphans)
	}

	// non-nil empty → a zero-QEMU node: vm-690-disk-0 IS an orphan.
	c = testClient(t, newFakeAPIServer(t, handler))
	orphans, err := c.OrphanVolumesWithVMList(context.Background(), "qa-pve-01", "local-lvm", []int{})
	if err != nil {
		t.Fatalf("a non-nil empty list is a valid zero-QEMU node, got error: %v", err)
	}
	if len(orphans) != 1 || orphans[0].Volid != "local-lvm:vm-690-disk-0" {
		t.Fatalf("expected vm-690-disk-0 as an orphan on a zero-QEMU node, got %+v", orphans)
	}
}

// TestOrphanVolumesWithVMList_EdgeRefusals: the new entrypoint does its OWN
// shared-storage refusal (it does not call OrphanVolumes), and refuses an empty
// node/storage.
func TestOrphanVolumesWithVMList_EdgeRefusals(t *testing.T) {
	var contentHits int32
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nodes/qa-pve-01/storage/local-lvm/status":
			writeStorageStatus(w, 1) // shared
		case "/nodes/qa-pve-01/storage/local-lvm/content":
			atomic.AddInt32(&contentHits, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[]}`))
		default:
			http.NotFound(w, r)
		}
	})
	c := testClient(t, srv)

	orphans, err := c.OrphanVolumesWithVMList(context.Background(), "qa-pve-01", "local-lvm", []int{100})
	if err == nil || orphans != nil {
		t.Fatalf("expected a shared-storage refusal with a nil list, got %+v / %v", orphans, err)
	}
	if atomic.LoadInt32(&contentHits) != 0 {
		t.Errorf("content endpoint must never be hit for a shared storage")
	}

	noNet := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach the network for a missing node/storage")
	}))
	if _, err := noNet.OrphanVolumesWithVMList(context.Background(), "", "local-lvm", []int{1}); err == nil {
		t.Error("expected an error for an empty node")
	}
	if _, err := noNet.OrphanVolumesWithVMList(context.Background(), "qa-pve-01", "", []int{1}); err == nil {
		t.Error("expected an error for an empty storage")
	}
}

// TestOrphanVolumes_TokenPathOrderAndNullList pins RULING 1 on the token path:
// (i) the shared-storage refusal fires BEFORE any GetVMs/config enumeration
//
//	(covered by TestOrphanVolumes_RefusesSharedStorage's qemuHits==0), and
//
// (ii) a null /nodes/{node}/qemu body makes OrphanVolumes return
// ErrUnverifiableRead with a nil list and NEVER call a /config read. A mutant
// that converts the GetVMs error to vmids=nil-and-continue would instead report
// every claimable volume as an orphan.
func TestOrphanVolumes_TokenPathNullListRefuses(t *testing.T) {
	var configHits int32
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/qa-pve-01/storage/local-lvm/status":
			writeStorageStatus(w, 0)
		case "/nodes/qa-pve-01/storage/local-lvm/content":
			_, _ = w.Write([]byte(`{"data":[{"volid":"local-lvm:vm-690-disk-0","vmid":690,"content":"images"}]}`))
		case "/nodes/qa-pve-01/qemu":
			_, _ = w.Write([]byte(`{"data":null}`)) // the null-list shape GetVMs refuses
		default:
			if len(r.URL.Path) > len("/config") && r.URL.Path[len(r.URL.Path)-len("/config"):] == "/config" {
				atomic.AddInt32(&configHits, 1)
			}
			http.NotFound(w, r)
		}
	})
	c := testClient(t, srv)

	orphans, err := c.OrphanVolumes(context.Background(), "qa-pve-01", "local-lvm")
	if err == nil || orphans != nil {
		t.Fatalf("a null qemu list must refuse with a nil result, got %+v / %v", orphans, err)
	}
	if !errors.Is(err, ErrUnverifiableRead) {
		t.Errorf("expected errors.Is ErrUnverifiableRead for a null qemu list, got %v", err)
	}
	if atomic.LoadInt32(&configHits) != 0 {
		t.Errorf("no /config read may happen once the VM list is refused, got %d", atomic.LoadInt32(&configHits))
	}
}
