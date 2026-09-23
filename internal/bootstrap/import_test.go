package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// importValidator records what Import asked PVE to prove, and answers with
// errs in order (nil once they run out).
type importValidator struct {
	cfgs  []APIConfig
	wants [][]Grant
	errs  []error
}

func (v *importValidator) ValidateTokenGrants(_ context.Context, cfg APIConfig, want []Grant) error {
	v.cfgs = append(v.cfgs, cfg)
	v.wants = append(v.wants, want)
	if i := len(v.cfgs) - 1; i < len(v.errs) {
		return v.errs[i]
	}
	return nil
}

const importPass = "import-roster-pass"

func importRoster(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "roster.toml")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func importOpts(rosterPath, tokenID, secret string) ImportOptions {
	return ImportOptions{
		TargetID: "qa-imp", Host: "h.example", Node: "n1", TokenID: tokenID, Secret: secret,
		Grants:     []Grant{{Path: "/vms/100", Role: "PVEVMUser", Propagate: true}},
		RosterPath: rosterPath, Passphrase: importPass,
	}
}

func heldFor(t *testing.T, rosterPath string) heldToken {
	t.Helper()
	h, err := loadHeldToken(Options{RosterPath: rosterPath, TargetID: "qa-imp", Passphrase: importPass})
	if err != nil {
		t.Fatalf("loadHeldToken: %v", err)
	}
	return h
}

// TestImport_ValidatesThenPersists: a new target is added, the token is
// validated with exactly the given id, secret, endpoint and grants, and the
// roster then holds it, decryptable.
func TestImport_ValidatesThenPersists(t *testing.T) {
	rp := importRoster(t)
	v := &importValidator{}
	res, err := Import(context.Background(), importOpts(rp, "ops@pve!ci", "s3cr3t-0001"), v)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if res.TokenOutcome != OutcomeImported || res.Validation != ValidationVerified || res.OrphanedToken != "" {
		t.Errorf("result = %+v", res)
	}
	if len(v.cfgs) != 1 {
		t.Fatalf("validations = %d, want 1", len(v.cfgs))
	}
	if c := v.cfgs[0]; c.TokenID != "ops@pve!ci" || c.TokenSecret != "s3cr3t-0001" || c.Host != "h.example" || c.APIPort != 8006 {
		t.Errorf("validated with %+v", c)
	}
	if h := heldFor(t, rp); h.ID != "ops@pve!ci" || h.Secret != "s3cr3t-0001" {
		t.Errorf("roster holds %+v", h)
	}
}

// TestImport_FailureWritesNothing: a verdict and a non-verdict alike leave
// the roster byte-identical — an import never writes an unproven token.
func TestImport_FailureWritesNothing(t *testing.T) {
	for name, verr := range map[string]error{
		"scope too wide": ErrScopeTooWide,
		"wrong scope":    ErrWrongScope,
		"no grants":      ErrNoGrants,
		"not authorized": ErrNotAuthorized,
		"unverifiable":   errors.New("read effective permissions: connection reset"),
	} {
		t.Run(name, func(t *testing.T) {
			rp := importRoster(t)
			before, _ := os.ReadFile(rp)
			v := &importValidator{errs: []error{verr, verr, verr}}
			orig := postMintRetryDelay
			postMintRetryDelay = 0
			t.Cleanup(func() { postMintRetryDelay = orig })
			res, err := Import(context.Background(), importOpts(rp, "ops@pve!ci", "s3cr3t-0001"), v)
			if err == nil {
				t.Fatal("Import succeeded")
			}
			if res == nil || res.TokenOutcome != OutcomeNotImported {
				t.Errorf("result = %+v, want not_imported", res)
			}
			if after, _ := os.ReadFile(rp); !bytes.Equal(before, after) {
				t.Errorf("roster changed:\n%s", after)
			}
			if strings.Contains(err.Error(), "s3cr3t-0001") {
				t.Errorf("error leaks the secret: %v", err)
			}
		})
	}
}

// TestImport_ReadBackCatchesAWrongWrite: the token must read back exactly as
// imported, or the import fails loudly instead of reporting success.
func TestImport_ReadBackCatchesAWrongWrite(t *testing.T) {
	rp := importRoster(t)
	orig := writeTokenAuthFn
	writeTokenAuthFn = func(path, target string, w roster.TokenWrite, pass string) error {
		w.SecretPlaintext = []byte("not-what-was-imported")
		return orig(path, target, w, pass)
	}
	t.Cleanup(func() { writeTokenAuthFn = orig })
	_, err := Import(context.Background(), importOpts(rp, "ops@pve!ci", "s3cr3t-0001"), &importValidator{})
	if err == nil || !strings.Contains(err.Error(), "did not read back") {
		t.Fatalf("Import = %v, want a read-back failure", err)
	}
}

// TestImport_HeldTokenReplaceAndIdempotence: the same token again is a no-op
// (already_held, roster untouched); a different one is refused without
// Replace and, with it, written with the old one reported orphaned — never
// revoked (Import holds no transport to revoke with).
func TestImport_HeldTokenReplaceAndIdempotence(t *testing.T) {
	rp := importRoster(t)
	if _, err := Import(context.Background(), importOpts(rp, "ops@pve!ci", "s3cr3t-0001"), &importValidator{}); err != nil {
		t.Fatalf("first Import: %v", err)
	}
	before, _ := os.ReadFile(rp)

	res, err := Import(context.Background(), importOpts(rp, "ops@pve!ci", "s3cr3t-0001"), &importValidator{})
	if err != nil || res.TokenOutcome != OutcomeAlreadyHeld {
		t.Fatalf("same token again = %+v, %v; want already_held", res, err)
	}
	if after, _ := os.ReadFile(rp); !bytes.Equal(before, after) {
		t.Error("already_held rewrote the roster")
	}

	_, err = Import(context.Background(), importOpts(rp, "ops@pve!ci2", "s3cr3t-0002"), &importValidator{})
	if !errors.Is(err, ErrTokenAlreadyHeld) {
		t.Fatalf("different token without Replace = %v, want ErrTokenAlreadyHeld", err)
	}
	if after, _ := os.ReadFile(rp); !bytes.Equal(before, after) {
		t.Error("a refused import rewrote the roster")
	}

	o := importOpts(rp, "ops@pve!ci2", "s3cr3t-0002")
	o.Replace = true
	res, err = Import(context.Background(), o, &importValidator{})
	if err != nil || res.TokenOutcome != OutcomeImported || res.OrphanedToken != "ops@pve!ci" {
		t.Fatalf("Replace = %+v, %v; want imported with ops@pve!ci orphaned", res, err)
	}
	if h := heldFor(t, rp); h.ID != "ops@pve!ci2" || h.Secret != "s3cr3t-0002" {
		t.Errorf("roster holds %+v", h)
	}
}

// TestImport_UndecryptableHeldTokenIsRefused (RI1): a held token that will
// not decrypt — a mistyped passphrase — is refused before validating, even
// with Replace, so the only roster copy of a live token's secret is never
// overwritten.
func TestImport_UndecryptableHeldTokenIsRefused(t *testing.T) {
	rp := importRoster(t)
	if _, err := Import(context.Background(), importOpts(rp, "ops@pve!ci", "s3cr3t-0001"), &importValidator{}); err != nil {
		t.Fatalf("first Import: %v", err)
	}
	before, _ := os.ReadFile(rp)

	for _, replace := range []bool{false, true} {
		o := importOpts(rp, "ops@pve!ci2", "s3cr3t-0002")
		o.Passphrase = "a-mistyped-passphrase"
		o.Replace = replace
		v := &importValidator{}
		_, err := Import(context.Background(), o, v)
		if !errors.Is(err, ErrTokenUndecryptable) || !strings.Contains(err.Error(), roster.PassphraseEnvVar) {
			t.Errorf("replace=%v: Import = %v, want ErrTokenUndecryptable naming %s", replace, err, roster.PassphraseEnvVar)
		}
		if len(v.cfgs) != 0 {
			t.Errorf("replace=%v: validated %d time(s), want none", replace, len(v.cfgs))
		}
		if after, _ := os.ReadFile(rp); !bytes.Equal(before, after) {
			t.Errorf("replace=%v: the roster changed", replace)
		}
	}
	if h := heldFor(t, rp); h.ID != "ops@pve!ci" || h.Secret != "s3cr3t-0001" {
		t.Errorf("the original token is not intact: %+v", h)
	}
}

// TestImport_ErrorsNeverCarryTheSecret (RI2): a validator error whose text
// echoes the secret — PVE or a proxy echoing the Authorization header — is
// returned with the secret redacted, and errors.Is still reaches the cause.
func TestImport_ErrorsNeverCarryTheSecret(t *testing.T) {
	const secret = "s3cr3t-ECHOED-9"
	for name, verr := range map[string]error{
		"verdict":     fmt.Errorf("%w: pve returned 400: Authorization: PVEAPIToken=ops@pve!ci=%s", ErrScopeTooWide, secret),
		"non-verdict": fmt.Errorf("proxy returned 502 for request with Authorization: PVEAPIToken=ops@pve!ci=%s", secret),
	} {
		t.Run(name, func(t *testing.T) {
			rp := importRoster(t)
			_, err := Import(context.Background(), importOpts(rp, "ops@pve!ci", secret), &importValidator{errs: []error{verr}})
			if err == nil {
				t.Fatal("Import succeeded")
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("the error carries the secret: %v", err)
			}
			if !strings.Contains(err.Error(), "PVEAPIToken=ops@pve!ci=<redacted>") {
				t.Errorf("the error lost its context: %v", err)
			}
			if !errors.Is(err, verr) {
				t.Errorf("errors.Is no longer reaches the cause: %v", err)
			}
			if name == "verdict" && !errors.Is(err, ErrScopeTooWide) {
				t.Errorf("errors.Is(ErrScopeTooWide) lost through the redaction")
			}
		})
	}
}
