package pve

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseAccessUsers(t *testing.T) {
	got, err := ParseAccessUsers([]byte(`[
		{"userid":"root@pam","enable":1},
		{"userid":"alice@pve","enable":0,"comment":"ops","email":"a@example.com","groups":"ops,dev"},
		{"userid":"bob@pve","enable":true,"groups":["dev"]},
		{"userid":"carol@pve","enable":1,"groups":""}
	]`))
	want := []AccessUser{
		{UserID: "root@pam", Enabled: true},
		{UserID: "alice@pve", Comment: "ops", Email: "a@example.com", Groups: []string{"ops", "dev"}, GroupsListed: true},
		{UserID: "bob@pve", Enabled: true, Groups: []string{"dev"}, GroupsListed: true},
		{UserID: "carol@pve", Enabled: true, GroupsListed: true},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("ParseAccessUsers = %+v, %v\nwant %+v", got, err, want)
	}
}

// Every answer pveforge cannot decide on is an unverifiable read, never a
// default: null, a non-array, a null entry, an entry with no id, and a user
// whose enable state is missing or not 0/1.
func TestParseAccess_RefusesWhatItCannotDecideOn(t *testing.T) {
	for name, c := range map[string]struct {
		parse func([]byte) error
		raw   string
	}{
		"users null":             {usersErr, `null`},
		"users object":           {usersErr, `{"userid":"a@pve"}`},
		"users null entry":       {usersErr, `[null]`},
		"user without id":        {usersErr, `[{"enable":1}]`},
		"user without enable":    {usersErr, `[{"userid":"a@pve"}]`},
		"user enable 2":          {usersErr, `[{"userid":"a@pve","enable":2}]`},
		"user groups a number":   {usersErr, `[{"userid":"a@pve","enable":1,"groups":3}]`},
		"user listed twice":      {usersErr, `[{"userid":"a@pve","enable":1},{"userid":"a@pve","enable":0}]`},
		"user group twice":       {usersErr, `[{"userid":"a@pve","enable":1,"groups":"ops,dev,ops"}]`},
		"user group twice, list": {usersErr, `[{"userid":"a@pve","enable":1,"groups":["ops","ops"]}]`},
		"groups null":            {groupsErr, `null`},
		"group listed twice":     {groupsErr, `[{"groupid":"ops"},{"groupid":"ops","users":""}]`},
		"group without id":       {groupsErr, `[{"comment":"x"}]`},
		"acl without propagate":  {aclErr, `[{"path":"/","roleid":"R","type":"user","ugid":"a@pve"}]`},
		"acl unknown type":       {aclErr, `[{"path":"/","roleid":"R","type":"role","ugid":"a@pve","propagate":0}]`},
		"acl without ugid":       {aclErr, `[{"path":"/","roleid":"R","type":"user","propagate":0}]`},
	} {
		if err := c.parse([]byte(c.raw)); !errors.Is(err, ErrUnverifiableRead) {
			t.Errorf("%s: err = %v, want an unverifiable read", name, err)
		}
	}
}

func usersErr(b []byte) error  { _, err := ParseAccessUsers(b); return err }
func groupsErr(b []byte) error { _, err := ParseAccessGroups(b); return err }
func aclErr(b []byte) error    { _, err := ParseACLEntries(b); return err }

func TestParseACLEntries(t *testing.T) {
	got, err := ParseACLEntries([]byte(`[{"path":"/vms/100","roleid":"PVEVMUser","type":"group","ugid":"ops","propagate":1},{"path":"/","roleid":"PVEAuditor","type":"token","ugid":"u@pve!t","propagate":0}]`))
	want := []ACLEntry{{Path: "/vms/100", Role: "PVEVMUser", Type: "group", UGID: "ops", Propagate: true}, {Path: "/", Role: "PVEAuditor", Type: "token", UGID: "u@pve!t"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("ParseACLEntries = %+v, %v", got, err)
	}
	if got, err := ParseACLEntries([]byte(`[]`)); err != nil || len(got) != 0 {
		t.Errorf("an empty list: %+v, %v", got, err)
	}
}
