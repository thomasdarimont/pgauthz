package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// version is stamped at build time via -ldflags "-X main.version=...".
// Plain `go build` produces "dev" plus the VCS revision from build info.
var version = "dev"

func cmdVersion() {
	rev, dirty := "", ""
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if len(s.Value) >= 12 {
					rev = s.Value[:12]
				}
			case "vcs.modified":
				if s.Value == "true" {
					dirty = "-dirty"
				}
			}
		}
	}
	out := "pgauthzctl " + version
	if rev != "" {
		out += fmt.Sprintf(" (commit %s%s)", rev, dirty)
	}
	fmt.Println(out + " " + runtime.Version())
}
