package idempotent

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// UserEnsure and GroupEnsure over an in-memory fake that applies each write
// to its own lists, so a second Run reads what the first wrote. Nothing here
// can return ErrConflict (/access objects carry no digest), so there is no
// conflict-retry case.

type fakeAccess struct {
	users   []pve.AccessUser
	groups  []pve.AccessGroup
	listErr error
	writes  []string

	// listErrAfterWrite fails every list read once a write has been made:
	// the re-read after a write that succeeded (P3).
	listErrAfterWrite error
	// dropWrites records each write but does not apply it, as a pveum flag
	// that PVE accepted but did not act on would (P3's read-back check).
	dropWrites bool
}

func (f *fakeAccess) listErrNow() error {
	if f.listErrAfterWrite != nil && len(f.writes) > 0 {
		return f.listErrAfterWrite
	}
	return f.listErr
}

func (f *fakeAccess) ListUsers(context.Context) ([]pve.AccessUser, error) {
	return slices.Clone(f.users), f.listErrNow()
}

func (f *fakeAccess) ListGroups(context.Context) ([]pve.AccessGroup, error) {
	return slices.Clone(f.groups), f.listErrNow()
}

func str(p *string) string {
	if p == nil {
		return "<unset>"
	}
	return *p
}

func (f *fakeAccess) AddUser(_ context.Context, s UserSpec) error {
	f.writes = append(f.writes, fmt.Sprintf("add %s enable=%t comment=%s email=%s groups=%s", s.UserID, s.Enable, str(s.Comment), str(s.Email), strings.Join(s.Groups, ",")))
	if f.dropWrites {
		return nil
	}
	u := pve.AccessUser{UserID: s.UserID, Enabled: s.Enable, Groups: slices.Clone(s.Groups)}
	if s.Comment != nil {
		u.Comment = *s.Comment
	}
	if s.Email != nil {
		u.Email = *s.Email
	}
	f.users = append(f.users, u)
	return nil
}

func (f *fakeAccess) ModifyUser(_ context.Context, s UserSpec) error {
	f.writes = append(f.writes, fmt.Sprintf("modify %s enable=%t comment=%s email=%s append=%s", s.UserID, s.Enable, str(s.Comment), str(s.Email), strings.Join(s.Groups, ",")))
	if f.dropWrites {
		return nil
	}
	for i := range f.users {
		if f.users[i].UserID == s.UserID {
			f.users[i].Enabled = s.Enable
			if s.Comment != nil {
				f.users[i].Comment = *s.Comment
			}
			if s.Email != nil {
				f.users[i].Email = *s.Email
			}
			f.users[i].Groups = append(f.users[i].Groups, s.Groups...)
		}
	}
	return nil
}

func (f *fakeAccess) AddGroup(_ context.Context, id string, comment *string) error {
	f.writes = append(f.writes, fmt.Sprintf("add group %s comment=%s", id, str(comment)))
	if f.dropWrites {
		return nil
	}
	g := pve.AccessGroup{GroupID: id}
	if comment != nil {
		g.Comment = *comment
	}
	f.groups = append(f.groups, g)
	return nil
}

func (f *fakeAccess) ModifyGroup(_ context.Context, id, comment string) error {
	f.writes = append(f.writes, fmt.Sprintf("modify group %s comment=%s", id, comment))
	if f.dropWrites {
		return nil
	}
	for i := range f.groups {
		if f.groups[i].GroupID == id {
			f.groups[i].Comment = comment
		}
	}
	return nil
}

func ptr[T any](v T) *T { return &v }

func runUser(t *testing.T, f *fakeAccess, op *UserEnsure) Result {
	t.Helper()
	op.Client = f
	res, err := Run(context.Background(), t.TempDir()+"/roster.toml", lock.ObjectKey{TargetID: "qa-pve-01", Kind: "user", ID: op.UserID}, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

func TestUserEnsure(t *testing.T) {
	others := []pve.AccessUser{{UserID: "root@pam", Enabled: true}, {UserID: "zed@pve", Enabled: true}}
	with := func(u pve.AccessUser) []pve.AccessUser {
		// The target sits mid-list: Read must scan, not assume a position.
		return []pve.AccessUser{others[0], u, others[1]}
	}
	cases := []struct {
		name      string
		users     []pve.AccessUser
		op        UserEnsure
		wantWrite []string
	}{
		{"create, enabled by default", others,
			UserEnsure{UserID: "alice@pve", Comment: ptr("ops"), Groups: []string{"ops", "dev", "ops"}},
			[]string{"add alice@pve enable=true comment=ops email=<unset> groups=dev,ops"}},
		{"create disabled", others,
			UserEnsure{UserID: "alice@pve", Enable: ptr(false)},
			[]string{"add alice@pve enable=false comment=<unset> email=<unset> groups="}},
		{"already as asked", with(pve.AccessUser{UserID: "alice@pve", Enabled: true, Comment: "ops", Groups: []string{"dev", "ops", "extra"}}),
			UserEnsure{UserID: "alice@pve", Enable: ptr(true), Comment: ptr("ops"), Groups: []string{"ops"}},
			nil},
		{"enable a disabled user", with(pve.AccessUser{UserID: "alice@pve"}),
			UserEnsure{UserID: "alice@pve", Enable: ptr(true)},
			[]string{"modify alice@pve enable=true comment=<unset> email=<unset> append="}},
		{"disable an enabled user", with(pve.AccessUser{UserID: "alice@pve", Enabled: true}),
			UserEnsure{UserID: "alice@pve", Enable: ptr(false)},
			[]string{"modify alice@pve enable=false comment=<unset> email=<unset> append="}},
		// The re-enable trap: a change that does not ask for a state
		// sends the user's own, so a disabled user stays disabled.
		{"a comment change keeps a disabled user disabled", with(pve.AccessUser{UserID: "alice@pve", Comment: "old"}),
			UserEnsure{UserID: "alice@pve", Comment: ptr("new")},
			[]string{"modify alice@pve enable=false comment=new email=<unset> append="}},
		{"email drift", with(pve.AccessUser{UserID: "alice@pve", Enabled: true, Email: "a@old"}),
			UserEnsure{UserID: "alice@pve", Email: ptr("a@new")},
			[]string{"modify alice@pve enable=true comment=<unset> email=a@new append="}},
		// Membership is only added: the missing groups are appended, and
		// the user's other groups are never named in the write.
		{"groups are appended, never replaced", with(pve.AccessUser{UserID: "alice@pve", Enabled: true, Groups: []string{"keep", "ops"}}),
			UserEnsure{UserID: "alice@pve", Groups: []string{"ops", "dev", "audit"}},
			[]string{"modify alice@pve enable=true comment=<unset> email=<unset> append=audit,dev"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeAccess{users: slices.Clone(c.users)}
			op := c.op
			res := runUser(t, f, &op)
			if !slices.Equal(f.writes, c.wantWrite) {
				t.Errorf("writes = %q\nwant     %q", f.writes, c.wantWrite)
			}
			if res.Changed != (c.wantWrite != nil) {
				t.Errorf("Changed = %t", res.Changed)
			}
			// The fake applies its writes, so the read-back check is clean.
			if res.AfterErr != nil || res.PostApplyErr != nil {
				t.Errorf("AfterErr %v, PostApplyErr %v; want both nil", res.AfterErr, res.PostApplyErr)
			}
			// A second run finds it done.
			f.writes = nil
			op2 := c.op
			if res := runUser(t, f, &op2); res.Changed || f.writes != nil {
				t.Errorf("second run: Changed %t, writes %q", res.Changed, f.writes)
			}
		})
	}
}

// A user list that cannot be read is an error, never "absent": nothing is
// created.
func TestUserEnsure_ListErrorIsHard(t *testing.T) {
	f := &fakeAccess{listErr: errors.New("list users: pve returned 500")}
	op := &UserEnsure{Client: f, UserID: "alice@pve"}
	_, err := Run(context.Background(), t.TempDir()+"/roster.toml", lock.ObjectKey{TargetID: "t", Kind: "user", ID: "alice@pve"}, op, false)
	if err == nil || f.writes != nil {
		t.Errorf("err %v, writes %q; want an error and no write", err, f.writes)
	}
}

func TestUserEnsure_ReadRendersTheDecidedFields(t *testing.T) {
	f := &fakeAccess{users: []pve.AccessUser{{UserID: "alice@pve", Enabled: true, Comment: "c", Email: "e", Groups: []string{"b", "a"}}}}
	op := &UserEnsure{Client: f, UserID: "alice@pve"}
	got, err := op.Read(context.Background())
	if want := `enable=true comment="c" email="e" groups="a,b"`; err != nil || got != want {
		t.Errorf("Read = %q, %v; want %q", got, err, want)
	}
	op.UserID = "nobody@pve"
	if got, _ := op.Read(context.Background()); got != "absent" {
		t.Errorf("Read of a missing user = %q", got)
	}
}

func TestGroupEnsure(t *testing.T) {
	cases := []struct {
		name      string
		groups    []pve.AccessGroup
		op        GroupEnsure
		wantWrite []string
	}{
		{"create", nil, GroupEnsure{GroupID: "ops", Comment: ptr("Ops")}, []string{"add group ops comment=Ops"}},
		{"create without a comment", nil, GroupEnsure{GroupID: "ops"}, []string{"add group ops comment=<unset>"}},
		{"already there", []pve.AccessGroup{{GroupID: "dev"}, {GroupID: "ops", Comment: "Ops"}}, GroupEnsure{GroupID: "ops", Comment: ptr("Ops")}, nil},
		{"already there, no comment asked", []pve.AccessGroup{{GroupID: "ops", Comment: "x"}}, GroupEnsure{GroupID: "ops"}, nil},
		{"comment drift", []pve.AccessGroup{{GroupID: "ops", Comment: "old"}}, GroupEnsure{GroupID: "ops", Comment: ptr("new")}, []string{"modify group ops comment=new"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeAccess{groups: slices.Clone(c.groups)}
			op := c.op
			op.Client = f
			res, err := Run(context.Background(), t.TempDir()+"/roster.toml", lock.ObjectKey{TargetID: "t", Kind: "group", ID: op.GroupID}, &op, false)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(f.writes, c.wantWrite) || res.Changed != (c.wantWrite != nil) {
				t.Errorf("writes %q Changed %t; want %q", f.writes, res.Changed, c.wantWrite)
			}
			if res.AfterErr != nil || res.PostApplyErr != nil {
				t.Errorf("AfterErr %v, PostApplyErr %v; want both nil", res.AfterErr, res.PostApplyErr)
			}
		})
	}
	// Under force, an existing group with no comment asked has nothing to
	// write, and must not dereference the unset comment.
	f := &fakeAccess{groups: []pve.AccessGroup{{GroupID: "ops"}}}
	op := &GroupEnsure{Client: f, GroupID: "ops"}
	if _, err := Run(context.Background(), t.TempDir()+"/roster.toml", lock.ObjectKey{TargetID: "t", Kind: "group", ID: "ops"}, op, true); err != nil || f.writes != nil {
		t.Errorf("forced no-op: %v, writes %q", err, f.writes)
	}
	f = &fakeAccess{listErr: errors.New("boom")}
	op = &GroupEnsure{Client: f, GroupID: "ops"}
	if _, err := Run(context.Background(), t.TempDir()+"/roster.toml", lock.ObjectKey{TargetID: "t", Kind: "group", ID: "ops"}, op, false); err == nil || f.writes != nil {
		t.Errorf("list error: %v, writes %q", err, f.writes)
	}
}

// SR1: BeforeJoin is asked, before the write, with exactly the groups the
// write adds; its refusal sends nothing; and it is not asked when nothing is
// joined.
func TestUserEnsure_BeforeJoin(t *testing.T) {
	existing := []pve.AccessUser{{UserID: "alice@pve", Enabled: true, Groups: []string{"ops"}}}
	cases := []struct {
		name      string
		users     []pve.AccessUser
		groups    []string
		refuse    bool
		wantAsked [][]string
		wantWrite bool
	}{
		{"create asks with every group", nil, []string{"ops", "dev"}, false, [][]string{{"dev", "ops"}}, true},
		{"modify asks with only the missing groups", existing, []string{"ops", "admins"}, false, [][]string{{"admins"}}, true},
		{"a refusal sends nothing", existing, []string{"admins"}, true, [][]string{{"admins"}}, false},
		{"nothing to join, not asked", existing, []string{"ops"}, false, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeAccess{users: slices.Clone(c.users)}
			var asked [][]string
			op := &UserEnsure{Client: f, UserID: "alice@pve", Groups: c.groups, BeforeJoin: func(_ context.Context, g []string) error {
				asked = append(asked, slices.Clone(g))
				if c.refuse {
					return errors.New("refused")
				}
				return nil
			}}
			_, err := Run(context.Background(), t.TempDir()+"/roster.toml", lock.ObjectKey{TargetID: "t", Kind: "user", ID: "alice@pve"}, op, false)
			if c.refuse != (err != nil) {
				t.Errorf("err = %v", err)
			}
			if !reflect.DeepEqual(asked, c.wantAsked) {
				t.Errorf("asked %q, want %q", asked, c.wantAsked)
			}
			if (len(f.writes) > 0) != c.wantWrite {
				t.Errorf("writes %q", f.writes)
			}
		})
	}
}
