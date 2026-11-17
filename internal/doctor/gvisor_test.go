package doctor

import (
	"strings"
	"testing"
)

func checks(g Group) string {
	var b strings.Builder
	for _, c := range g.Checks {
		b.WriteString(map[Status]string{OK: "ok ", NO: "NO ", HM: "?? "}[c.Status] + c.Message + "\n")
	}
	return b.String()
}

// The gVisor group says whether the pinned runsc is here and, where it is not,
// the command that fetches it; and whether systemd-run is there to hold limits.
func TestGVisorGroup(t *testing.T) {
	stubLookPath(t, "systemd-run")
	d := Deps{GVisorPin: "20261109.0", GVisorReleases: []string{"20261001.0", "20261109.0"},
		ImageIsDefault: true, DefaultEngine: "firecracker"}
	got := checks(gvisorGroup(d))
	for _, want := range []string{
		"ok gVisor 20261109.0 cached",
		"?? also cached, for the sandboxes created under them: gVisor 20261001.0",
		"ok systemd-run present",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}

	stubLookPath(t)
	d.GVisorReleases = nil
	got = checks(gvisorGroup(d))
	for _, want := range []string{
		"?? gVisor 20261109.0 not downloaded yet",
		"cs-sandbox build --engine gvisor",
		"?? systemd-run not found, so gVisor sandboxes run without limits",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}

	d.IsMacOS = true
	if got := checks(gvisorGroup(d)); !strings.HasPrefix(got, "NO gVisor runs on Linux only") {
		t.Errorf("macOS:\n%s", got)
	}
}
