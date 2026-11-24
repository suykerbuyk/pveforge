package main

import (
	"bytes"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
)

// schemaVersion is `pveforge schema`'s own format version. Version 1 was the
// implicit format before releases (name, use, aliases, short, mutation, flags);
// version 2 adds the contract surfaces a consumer pins (contract plan §3.3).
// Raising it is a contract change: the diff tool reads both.
const schemaVersion = 2

// versionReport is what `pveforge version` and `pveforge --version` print, and
// what `pveforge schema` embeds as contract.pveforge. Every field comes from
// debug.ReadBuildInfo (the toolchain's own stamp): there are no ldflags, so there
// is no second source of truth that could disagree with the VCS data the
// harness's provenance check (hack/harness/lib.sh) already reads.
//
// The build time is the COMMIT time (vcs.time), never the wall clock: a wall
// clock would make two builds of one tag differ.
type versionReport struct {
	Version       string `json:"version"`
	Stamped       bool   `json:"stamped"`
	Commit        string `json:"commit,omitempty"`
	CommitTime    string `json:"commit_time,omitempty"`
	Dirty         *bool  `json:"dirty,omitempty"` // absent when the build carries no VCS information
	Release       bool   `json:"release"`
	Prerelease    bool   `json:"prerelease"`
	Go            string `json:"go"`
	GOOS          string `json:"goos"`
	GOARCH        string `json:"goarch"`
	Static        bool   `json:"static"`
	Trimpath      bool   `json:"trimpath"`
	SchemaVersion int    `json:"schema_version"`
}

// releaseVersionRE is the one grammar of a pveforge release version: a clean
// semver tag. A pseudo-version (v0.0.0-<time>-<rev>), +dirty, +incompatible and
// every pre-release suffix fail it.
var releaseVersionRE = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// prereleaseVersionRE is the ONE prerelease rule: -rc.N and nothing else. Any
// other pre-release suffix is not a valid pveforge release tag (make release
// refuses it), so no pveforge release can be "release=false, prerelease=false".
var prereleaseVersionRE = regexp.MustCompile(`^v\d+\.\d+\.\d+-rc\.\d+$`)

// versionInfo derives the report from a BuildInfo. It is a pure function so the
// table of near-misses (AC-V4) can drive it; ONE end-to-end test builds real
// binaries in a throwaway git repository, because only the toolchain can say
// how it stamps a tag, a dirty tree, an export or a replace.
func versionInfo(bi *debug.BuildInfo, ok bool) versionReport {
	rep := versionReport{
		Version:       "(devel)",
		Go:            runtime.Version(),
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		SchemaVersion: schemaVersion,
	}
	if !ok || bi == nil {
		return rep
	}
	if bi.GoVersion != "" {
		rep.Go = bi.GoVersion
	}
	if bi.Main.Version != "" {
		rep.Version = bi.Main.Version
	}
	var modified *bool
	for _, s := range bi.Settings {
		switch {
		case s.Key == "vcs.revision":
			rep.Commit = s.Value
		case s.Key == "vcs.time":
			rep.CommitTime = s.Value
		case s.Key == "vcs.modified":
			v := s.Value == "true"
			modified = &v
		case s.Key == "GOOS" && s.Value != "":
			rep.GOOS = s.Value
		case s.Key == "GOARCH" && s.Value != "":
			rep.GOARCH = s.Value
		case s.Key == "CGO_ENABLED":
			rep.Static = s.Value == "0"
		case s.Key == "-trimpath":
			rep.Trimpath = s.Value == "true"
		}
		if strings.HasPrefix(s.Key, "vcs") {
			rep.Stamped = true
		}
	}
	// dirty is only ever stated when the build says so: a build with no VCS
	// information must never print dirty=false ("I know it is clean").
	rep.Dirty = modified
	if modified != nil && !*modified && strings.HasSuffix(rep.Version, "+dirty") {
		// the version string and vcs.modified disagree: fail closed
		t := true
		rep.Dirty = &t
	}
	rep.Prerelease = prereleaseVersionRE.MatchString(rep.Version)
	rep.Release = rep.Stamped && rep.Dirty != nil && !*rep.Dirty &&
		releaseVersionRE.MatchString(rep.Version) && !hasReplace(bi)
	return rep
}

// hasReplace reports a replace directive anywhere in the build: a build that
// replaces a module is not the tagged source the version string names.
func hasReplace(bi *debug.BuildInfo) bool {
	if bi.Main.Replace != nil {
		return true
	}
	for _, d := range bi.Deps {
		if d != nil && d.Replace != nil {
			return true
		}
	}
	return false
}

// readVersion is the ONE place the build info is read (AC-V6: pinned by the
// sourceguard test TestRelease_BuildInfoIsReadInOnePlace).
func readVersion() versionReport {
	bi, ok := debug.ReadBuildInfo()
	return versionInfo(bi, ok)
}

// versionKV is the report as kv text, for the root --version flag.
func versionKV() string {
	var b bytes.Buffer
	if err := kvjson.Render(&b, kvjson.KV, readVersion()); err != nil {
		return "version=(unreadable)"
	}
	return strings.TrimRight(b.String(), "\n")
}

func newVersionCmd() *cobra.Command {
	var resolveFormat func() (kvjson.Format, error)
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print this binary's version identity: version, commit, clean or dirty, static, Go",
		Long: `Print what this binary is, from the build information the Go toolchain stamped
into it (no ldflags). release=true only for a clean build of a semver tag with no
replace directive: the check a consumer pins on. An unstamped build (a source
export, -buildvcs=false) says stamped=false and prints no dirty field rather
than guess; a build from a modified tree says dirty=true. commit_time is the
commit's time, never the build's. The exit status is always 0: this is
information, not a refusal.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := resolveFormat()
			if err != nil {
				return err
			}
			return kvjson.Render(cmd.OutOrStdout(), format, readVersion())
		},
	}
	resolveFormat = addOutputFlag(cmd)
	markSafe(cmd)
	return cmd
}
