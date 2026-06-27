// Package buildinfo exposes the binary version shared by orlop-control and
// orlop-server. The release workflow injects an exact version at build time via
//
//	-ldflags "-X github.com/liu1700/orlop/internal/buildinfo.version=X.Y.Z"
//
// Local/dev builds (plain `go build`/`go run`) carry no injected value and fall
// back to the VCS revision Go embeds automatically, then to "dev".
package buildinfo

import "runtime/debug"

// version is set via -ldflags at release build time; empty otherwise.
var version = ""

// Version returns the build version string. Precedence:
//  1. the -ldflags-injected release version (e.g. "0.2.0");
//  2. the module version or short VCS revision embedded by `go build`
//     (e.g. "dev+a1b2c3d4e5f6" or "...-dirty");
//  3. "dev" when nothing is available (e.g. `go test` binaries).
func Version() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			return v
		}
		var rev string
		var dirty bool
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
		if rev != "" {
			if len(rev) > 12 {
				rev = rev[:12]
			}
			if dirty {
				rev += "-dirty"
			}
			return "dev+" + rev
		}
	}
	return "dev"
}
