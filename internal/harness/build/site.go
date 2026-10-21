// Package build is the Go port of hack/harness/build/build.sh + env.sh
// (U-BUILD, the final Go-port unit): it creates the three outer VMs of the
// nested cluster (690 pvh-n1, 691 pvh-n2, 692 pvh-nfs) on the harness node,
// through pveforge as the pool token, with the full create-field matrix. It
// CONSUMES U-CORE/U-PROBE (outer's guard, ledger, gone-proof, the create screen
// outer.ScreenCreate/ScreenConfig, outer.VMPath/RawUPID, the static storage
// layer and leftover detector) and reads the outer-host from the roster
// in-process (internal/roster) — no pins subprocess. Additive, lock-free
// driver; the command's RunE holds the three per-VM locks. It never accepts the
// nested cluster (that is a later step) and never destroys a VM except in
// cleanup, only VMs this run created and recorded.
package build

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// siteKey is one env.sh HB_PATTERN entry (env.sh:31-56): the key and the
// regexp its value must match. The site file is READ, never sourced (O1).
type siteKey struct {
	name string
	re   *regexp.Regexp
}

var (
	reIP        = regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$`)
	reMAC       = regexp.MustCompile(`^[0-9a-f][26ae](:[0-9a-f]{2}){5}$`)
	reCount     = regexp.MustCompile(`^[1-9][0-9]{0,5}$`)
	reUser      = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	reDomain    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	rePrefix    = regexp.MustCompile(`^([1-9]|[12][0-9]|3[0-2])$`)
	reKeyboard  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)?$`)
	reCountry   = regexp.MustCompile(`^[a-z]{2}$`)
	reTimezone  = regexp.MustCompile(`^[A-Za-z]+(/[A-Za-z0-9_+-]+)*$`)
	reMailto    = regexp.MustCompile(`^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+$`)
	reSourceISO = regexp.MustCompile(`^(/[A-Za-z0-9._+-]+)+\.iso$`)
	reImage     = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*\.(qcow2|raw)$`)
	reContainer = regexp.MustCompile(`^[a-z0-9][a-z0-9./-]*(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?$`)
	reSHA512    = regexp.MustCompile(`^[0-9a-f]{128}$`)
	reLine      = regexp.MustCompile(`^([A-Z][A-Z0-9_]*)=(.*)$`) // env.sh:106
)

// siteKeys is env.sh's HB_PATTERN, in no particular order; every key is
// required (env.sh:121-123).
var siteKeys = []siteKey{
	{"DOMAIN", reDomain},
	{"N1_IP", reIP}, {"N2_IP", reIP}, {"NFS_IP", reIP}, {"GATEWAY", reIP}, {"DNS", reIP},
	{"PREFIX", rePrefix},
	{"N1_MAC", reMAC}, {"N2_MAC", reMAC}, {"NFS_MAC", reMAC},
	{"KEYBOARD", reKeyboard}, {"COUNTRY", reCountry}, {"TIMEZONE", reTimezone}, {"MAILTO", reMailto},
	{"SOURCE_ISO", reSourceISO}, {"NFS_IMAGE", reImage}, {"NFS_USER", reUser},
	{"CONTAINER_IMAGE", reContainer}, {"PVE_KEYRING_SHA512", reSHA512},
	{"NODE_CORES", reCount}, {"NODE_MEMORY_MIB", reCount}, {"NODE_DISK_GIB", reCount},
	{"NFS_CORES", reCount}, {"NFS_MEMORY_MIB", reCount}, {"NFS_DATA_GIB", reCount},
}

func sitePattern(name string) *regexp.Regexp {
	for _, k := range siteKeys {
		if k.name == name {
			return k.re
		}
	}
	return nil
}

// Site is the loaded, validated harness-build.env (env.sh's HB array).
type Site map[string]string

// LoadSite reads and validates ~/.config/pveforge/harness-build.env, a faithful
// port of hb_read_env (env.sh:98-127): 0600, not a symlink, each line blank /
// a # comment / KEY=value (never sourced); the key must be known and unrepeated;
// the value must match its pattern; NFS_USER is never root; every key is
// present; the five addresses and the three MACs are each distinct.
func LoadSite(path string) (Site, error) {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("the site file %s does not exist (copy hack/harness/build/harness-build.env.example there, mode 0600, and fill it in)", path)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		return nil, fmt.Errorf("the site file %s has mode %o, want 600", path, perm)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s", path)
	}
	defer func() { _ = f.Close() }()

	hb := Site{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := reLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("%s:%d: not KEY=value", path, n)
		}
		key, value := m[1], m[2]
		pat := sitePattern(key)
		if pat == nil {
			return nil, fmt.Errorf("%s:%d: unknown key %s", path, n, key)
		}
		if _, dup := hb[key]; dup {
			return nil, fmt.Errorf("%s:%d: %s is set twice", path, n, key)
		}
		if !pat.MatchString(value) {
			return nil, fmt.Errorf("%s:%d: %s=%q is not a valid value", path, n, key, value)
		}
		if key == "NFS_USER" && value == "root" {
			return nil, fmt.Errorf("%s:%d: %s=%q is not a valid value: never root", path, n, key, value)
		}
		hb[key] = value
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("cannot read %s", path)
	}
	for _, k := range siteKeys {
		if _, ok := hb[k.name]; !ok {
			return nil, fmt.Errorf("%s: %s is missing", path, k.name)
		}
	}
	if err := distinct(path, hb, "N1_IP", "N2_IP", "NFS_IP", "GATEWAY", "DNS"); err != nil {
		return nil, err
	}
	if err := distinct(path, hb, "N1_MAC", "N2_MAC", "NFS_MAC"); err != nil {
		return nil, err
	}
	return hb, nil
}

// distinct refuses two of the named keys holding one value (hb_distinct,
// env.sh:132-142).
func distinct(path string, hb Site, keys ...string) error {
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if hb[keys[i]] == hb[keys[j]] {
				return fmt.Errorf("%s: %s and %s are both %s: each must be distinct", path, keys[i], keys[j], hb[keys[i]])
			}
		}
	}
	return nil
}
