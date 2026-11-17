package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/codesweep-ai/sandbox/internal/gvisor"
	"github.com/codesweep-ai/sandbox/internal/run"
	"github.com/codesweep-ai/sandbox/internal/state"
)

// NewGVisor constructs the gvisor engine: the podman adapter with the sandbox's
// container run by gVisor's runsc at the release this build pins (SPEC §11.6).
func NewGVisor(d Deps) *Podman { return &Podman{d: d, gvisor: gvisor.Version()} }

// ErrGVisorPrivileged is a create asking gVisor for --privileged (R173).
var ErrGVisorPrivileged = errors.New("--privileged cannot apply under gVisor: its kernel gives a container no host devices to unmask, " +
	"and runsc refuses the run — drop it, or use --engine podman")

// gvCache is the part of the artifact cache that holds runsc.
func (p *Podman) gvCache() gvisor.Cache {
	return gvisor.Cache{Dir: gvisor.Dir(p.d.FCCache), Progress: p.d.Progress}
}

// prepareGVisor fetches the pinned runsc where the cache lacks it (R174).
func (p *Podman) prepareGVisor(ctx context.Context) error {
	if runtime.GOOS != "linux" || p.d.Host.IsMacOS {
		return errors.New("gVisor runs on Linux only — use --engine podman here")
	}
	return p.gvCache().Ensure(ctx, p.d.Runner, p.gvisor)
}

// gvisorLimits decides which of a create's limits a gVisor sandbox's scope
// carries, and the scope to run it in (R176). They are the limits R171a gives a
// podman sandbox, decided the same way, and they apply only where a user
// manager is there to hold a scope.
func (d Deps) gvisorLimits(s CreateSpec) (l containerLimits, notes []string, scope string) {
	if !d.Cgroups.Slice || !haveSystemdRun() {
		return containerLimits{}, nil, ""
	}
	l, notes = podmanLimits(s, d.Cgroups, "")
	l.Parent = ""
	return l, notes, scopeName(obj(d.group(), s.Name))
}

// haveSystemdRun is a var so a unit test can stand in for the host.
var haveSystemdRun = func() bool { _, err := exec.LookPath("systemd-run"); return err == nil }

// scopeName names a gVisor sandbox's scope. The suffix is fresh each time, so a
// start never meets the scope of a stop whose conmon has not quite exited.
func scopeName(object string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "cs-sandbox-gvisor-" + object + "-" + hex.EncodeToString(b) + ".scope"
}

// scopeArgv runs argv inside a new systemd user scope under SliceName that
// carries l. The scope holds conmon and everything gVisor starts, so its
// limits are the sandbox's. Pids of -1 lifts the task cap, as it lifts podman's.
func scopeArgv(unit string, l containerLimits, argv []string) []string {
	a := []string{"systemd-run", "--user", "--scope", "--quiet", "--collect",
		"--unit=" + unit, "--slice=" + SliceName}
	switch {
	case l.Pids > 0:
		a = append(a, "-p", "TasksMax="+strconv.Itoa(l.Pids))
	case l.Pids < 0:
		a = append(a, "-p", "TasksMax=infinity")
	}
	if l.CPUs > 0 {
		a = append(a, "-p", "CPUQuota="+strconv.Itoa(l.CPUs*100)+"%")
	}
	if l.MemMiB > 0 {
		// No swap, for the reason the slice allows none.
		a = append(a, "-p", "MemoryMax="+strconv.Itoa(l.MemMiB)+"M", "-p", "MemorySwapMax=0")
	}
	a = append(a, "--")
	return append(a, argv...)
}

// procCgroup reads a process's cgroup. A var so a unit test can stand in for
// /proc.
var procCgroup = func(pid string) (string, error) {
	b, err := os.ReadFile("/proc/" + pid + "/cgroup")
	return string(b), err
}

// inScope reports whether a running gVisor sandbox is in the scope it was
// started in. It is what create and start report limits from, so a limit is
// named only where it was seen to apply (R178).
func (d Deps) inScope(ctx context.Context, name, unit string) bool {
	pid := run.Output(ctx, d.Runner, "podman", "inspect", "--format", "{{.State.ConmonPid}}", obj(d.group(), name))
	if pid == "" || pid == "0" {
		return false
	}
	cg, err := procCgroup(pid)
	return err == nil && strings.Contains(cg, "/"+SliceName+"/"+unit)
}

// startGVisor is Start for a gVisor sandbox: the container again, inside a new
// scope carrying the limits its record holds. A scope is a runtime unit, gone
// when the sandbox stops, so every start makes one.
func (p *Podman) startGVisor(ctx context.Context, name string) error {
	d := p.d
	o := obj(d.group(), name)
	if run.Output(ctx, d.Runner, "podman", "inspect", "--format", "{{.State.Running}}", o) == "true" {
		return d.waitReady(ctx, name)
	}
	in, err := state.Load(d.InstDir, d.group(), name)
	if err != nil {
		return err
	}
	argv := []string{"podman", "start", o}
	var unit string
	if d.Cgroups.Slice && haveSystemdRun() {
		unit = scopeName(o)
		l := containerLimits{Pids: in.Pids, CPUs: in.CPUs, MemMiB: in.MemMiB}
		if l.Pids == 0 {
			l.Pids = -1 // recorded as none; podman's own default does not reach a gVisor container
		}
		argv = scopeArgv(unit, l, argv)
	}
	d.ensureSlice(ctx)
	if _, err := d.Runner.Run(ctx, run.Opts{}, argv...); err != nil {
		return err
	}
	if err := d.waitReady(ctx, name); err != nil {
		return err
	}
	if unit != "" && !d.DryRun && !d.inScope(ctx, name, unit) {
		d.note(name + " runs outside its scope, so it runs without limits")
	}
	return nil
}
