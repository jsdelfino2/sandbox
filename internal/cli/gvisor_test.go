package cli

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/codesweep-ai/sandbox/internal/engine"
	"github.com/codesweep-ai/sandbox/internal/state"
)

// gVisor runs on Linux only and has no --privileged to give (R173). Both are
// refused before anything is provisioned.
func TestGVisorCreatable(t *testing.T) {
	if err := gvisorCreatable(true, false); err == nil || !strings.Contains(err.Error(), "Linux only") {
		t.Errorf("macOS: err = %v", err)
	}
	if runtime.GOOS != "linux" {
		return
	}
	if err := gvisorCreatable(false, true); !errors.Is(err, engine.ErrGVisorPrivileged) {
		t.Errorf("--privileged: err = %v", err)
	}
	if err := gvisorCreatable(false, false); err != nil {
		t.Errorf("Linux: err = %v", err)
	}
}

// What create says of a gVisor sandbox (R178): what runs it, each limit it
// applied, and what nested containers share. A limit the engine recorded as not
// applied is not named, and a sandbox with none says so rather than saying
// nothing.
func TestGVisorLines(t *testing.T) {
	got := strings.Join(gvisorLines(&state.Instance{Engine: state.GVisor, Pids: 8192, CPUs: 2, MemMiB: 4096}, "20261109.0"), "\n")
	for _, want := range []string{
		"gVisor 20261109.0",
		"limits:   8192 host tasks, 2 CPUs, 4096 MiB of memory; reaching the task or memory cap stops the whole sandbox",
		"nested containers: share this sandbox's network",
		"-p publishes nothing",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	got = strings.Join(gvisorLines(&state.Instance{Engine: state.GVisor, Pids: 8192}, "20261109.0"), "\n")
	if strings.Contains(got, "CPUs") || strings.Contains(got, "MiB") {
		t.Errorf("a cap that was not applied is named:\n%s", got)
	}
	got = strings.Join(gvisorLines(&state.Instance{Engine: state.GVisor}, "20261109.0"), "\n")
	if !strings.Contains(got, "limits:   none: nothing caps") {
		t.Errorf("an uncapped sandbox must say so:\n%s", got)
	}
}

// gVisor is fetched by `build` only when named, because it is never a default
// (R173), and an unknown engine is refused by name.
func TestBuildEngines(t *testing.T) {
	app := &App{}
	for _, c := range []struct {
		engines []string
		fc, gv  bool
		err     string
	}{
		{[]string{"podman"}, false, false, ""},
		{[]string{"gvisor"}, false, true, ""},
		{[]string{"firecracker", "gvisor"}, true, true, ""},
		{[]string{"kata"}, false, false, "podman, firecracker or gvisor"},
	} {
		fc, gv, err := buildEngines(app, c.engines)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%v: err = %v", c.engines, err)
			}
			continue
		}
		if err != nil || fc != c.fc || gv != c.gv {
			t.Errorf("%v = fc %v, gv %v, %v; want %v, %v", c.engines, fc, gv, err, c.fc, c.gv)
		}
	}
	if _, gv, _ := buildEngines(app, nil); gv {
		t.Error("a bare build fetched gVisor")
	}
}
