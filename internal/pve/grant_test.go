package pve

import (
	"errors"
	"strings"
	"testing"
)

func TestGrantCheck(t *testing.T) {
	ok := []Grant{
		{Path: "/", Role: "PVEVMAdmin", Propagate: true},
		{Path: "/pool/p", Role: "R"},
		{Path: "/sdn/zones/localnetwork/vmbr0", Role: "PveforgeHarnessNet", Privs: []string{"SDN.Use"}},
		{Path: "/storage/local", Role: "R.x-y_z", Privs: []string{"Datastore.Audit", "VM.GuestAgent.FileSystemMgmt"}},
	}
	for _, g := range ok {
		if err := g.Check(); err != nil {
			t.Errorf("%+v: %v", g, err)
		}
	}
	for name, tc := range map[string]struct {
		g    Grant
		name string
	}{
		"empty path":            {Grant{Role: "R"}, "path"},
		"relative path":         {Grant{Path: "pool/p", Role: "R"}, "path"},
		"trailing slash":        {Grant{Path: "/pool/p/", Role: "R"}, "normalized"},
		"doubled slash":         {Grant{Path: "//pool", Role: "R"}, "normalized"},
		"path charset":          {Grant{Path: "/pool/a b", Role: "R"}, "path"},
		"no role":               {Grant{Path: "/pool/p"}, "role"},
		"no role though pinned": {Grant{Path: "/pool/p", Privs: []string{"A"}}, "role"},
		"role charset":          {Grant{Path: "/pool/p", Role: "R/x"}, "role"},
		"empty pinned privs":    {Grant{Path: "/pool/p", Role: "R", Privs: []string{}}, "empty"},
		"bad privilege":         {Grant{Path: "/pool/p", Role: "R", Privs: []string{"A\nB"}}, "privilege"},
		"privilege digit lead":  {Grant{Path: "/pool/p", Role: "R", Privs: []string{"1A"}}, "privilege"},
		"duplicate privilege":   {Grant{Path: "/pool/p", Role: "R", Privs: []string{"A", "B", "A"}}, "twice"},
	} {
		err := tc.g.Check()
		if !errors.Is(err, ErrInvalidGrant) || !strings.Contains(err.Error(), tc.name) {
			t.Errorf("%s: want ErrInvalidGrant naming %q, got %v", name, tc.name, err)
		}
	}
}

// Every privilege name in PVE 9.2.11's live role list (qa-pve-02) is
// accepted by the privilege-name check.
func TestGrantCheck_AcceptsEveryLivePrivilegeName(t *testing.T) {
	live := "Datastore.Allocate,Datastore.AllocateSpace,Datastore.AllocateTemplate,Datastore.Audit,Group.Allocate,Mapping.Audit,Mapping.Modify,Mapping.Use,Permissions.Modify,Pool.Allocate,Pool.Audit,Realm.Allocate,Realm.AllocateUser,SDN.Allocate,SDN.Audit,SDN.Use,Sys.AccessNetwork,Sys.Audit,Sys.Console,Sys.Incoming,Sys.Modify,Sys.PowerMgmt,Sys.Syslog,User.Modify,VM.Allocate,VM.Audit,VM.Backup,VM.Clone,VM.Config.CDROM,VM.Config.CPU,VM.Config.Cloudinit,VM.Config.Disk,VM.Config.HWType,VM.Config.Memory,VM.Config.Network,VM.Config.Options,VM.Console,VM.GuestAgent.Audit,VM.GuestAgent.FileRead,VM.GuestAgent.FileSystemMgmt,VM.GuestAgent.FileWrite,VM.GuestAgent.Unrestricted,VM.Migrate,VM.PowerMgmt,VM.Replicate,VM.Snapshot,VM.Snapshot.Rollback"
	g := Grant{Path: "/", Role: "Administrator", Privs: strings.Split(live, ",")}
	if err := g.Check(); err != nil {
		t.Fatal(err)
	}
	if len(g.Privs) != 47 {
		t.Fatalf("parsed %d names", len(g.Privs))
	}
}

func TestCheckGrants(t *testing.T) {
	if err := CheckGrants([]Grant{{Path: "/pool/p", Role: "R"}, {Path: "/storage/s", Role: "S"}}); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]Grant{
		"nil":             nil,
		"empty":           {},
		"a bad grant":     {{Path: "/pool/p", Role: "R"}, {Path: "/x/", Role: "R"}},
		"same path twice": {{Path: "/pool/p", Role: "R"}, {Path: "/pool/p", Role: "S"}},
	} {
		if err := CheckGrants(want); !errors.Is(err, ErrInvalidGrant) {
			t.Errorf("%s: want ErrInvalidGrant, got %v", name, err)
		}
	}
}
