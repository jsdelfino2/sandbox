package doctor

import (
	"slices"
	"strings"
)

// gvisorGroup reports what the gvisor engine needs beyond podman (SPEC §11.6):
// a Linux host, the pinned runsc in the cache, and systemd-run to hold each
// sandbox's limits.
func gvisorGroup(d Deps) Group {
	g := Group{Title: "gVisor runtime (Linux)"}
	if d.IsMacOS {
		g.add(NO, "gVisor runs on Linux only — on macOS use:  cs-sandbox doctor --engine podman")
		return g
	}
	if slices.Contains(d.GVisorReleases, d.GVisorPin) {
		g.add(OK, "gVisor "+d.GVisorPin+" cached")
	} else {
		g.add(HM, "gVisor "+d.GVisorPin+" not downloaded yet — fetched and checked against its pinned digest "+
			"by the first 'cs-sandbox create --engine gvisor', or now with:  "+d.buildHint("gvisor"))
	}
	var others []string
	for _, r := range d.GVisorReleases {
		if r != d.GVisorPin {
			others = append(others, r)
		}
	}
	if len(others) > 0 {
		g.add(HM, "also cached, for the sandboxes created under them: gVisor "+strings.Join(others, ", "))
	}
	if have("systemd-run") {
		g.add(OK, "systemd-run present, to hold each gVisor sandbox's limits")
	} else {
		g.add(HM, "systemd-run not found, so gVisor sandboxes run without limits — it ships with systemd")
	}
	return g
}
