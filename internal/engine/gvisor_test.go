package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/codesweep-ai/sandbox/internal/gvisor"
	"github.com/codesweep-ai/sandbox/internal/hostenv"
	"github.com/codesweep-ai/sandbox/internal/run"
	"github.com/codesweep-ai/sandbox/internal/state"
)

// TestBuildRunArgsGVisor pins what a gVisor sandbox's run adds to a podman
// one's (R172): the runtime, conmon kept in the caller's scope, and the
// variable that tells the guest. Nothing else may change, and a podman
// sandbox's run carries none of the three.
func TestBuildRunArgsGVisor(t *testing.T) {
	plain := buildRunArgs(baseParams())
	p := baseParams()
	p.Runtime = "/cache/gvisor/20261109.0/runsc"
	got := buildRunArgs(p)

	added := map[string]bool{
		"--runtime": true, "/cache/gvisor/20261109.0/runsc": true, "--cgroups=no-conmon": true,
		"CS_SANDBOX_GVISOR=1": true,
	}
	var rest []string
	for i, a := range got {
		if added[a] {
			continue
		}
		if a == "-e" && i+1 < len(got) && got[i+1] == "CS_SANDBOX_GVISOR=1" {
			continue
		}
		rest = append(rest, a)
	}
	if strings.Join(rest, " ") != strings.Join(plain, " ") {
		t.Errorf("a gVisor run must be a podman run plus its own arguments only\n gvisor: %s\n podman: %s",
			strings.Join(got, " "), strings.Join(plain, " "))
	}
	line := strings.Join(got, " ")
	for _, want := range []string{
		"--runtime /cache/gvisor/20261109.0/runsc --cgroups=no-conmon",
		"-e CS_SANDBOX_GVISOR=1",
		// R102's capability set and R141's devices are the same whatever runs the container.
		"--cap-add=SYS_ADMIN", "--cap-add=SETFCAP", "--device /dev/net/tun", "--security-opt label=disable",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("gVisor argv missing %q:\n%s", want, line)
		}
	}
	for _, a := range plain {
		if a == "--runtime" || a == "--cgroups=no-conmon" || a == "CS_SANDBOX_GVISOR=1" {
			t.Errorf("a podman sandbox's run carries %q:\n%s", a, strings.Join(plain, " "))
		}
	}
}

// TestScopeArgv pins the scope a gVisor sandbox runs in (R176): under the
// slice, collected when it ends, and carrying each limit as systemd spells it.
func TestScopeArgv(t *testing.T) {
	inner := []string{"podman", "run", "-d", "img"}
	got := strings.Join(scopeArgv("cs-sandbox-gvisor-x.default-1.scope",
		containerLimits{Pids: 8192, CPUs: 2, MemMiB: 4096}, inner), " ")
	want := "systemd-run --user --scope --quiet --collect --unit=cs-sandbox-gvisor-x.default-1.scope " +
		"--slice=cs-sandbox.slice -p TasksMax=8192 -p CPUQuota=200% -p MemoryMax=4096M -p MemorySwapMax=0 " +
		"-- podman run -d img"
	if got != want {
		t.Errorf("scope argv\n got: %s\nwant: %s", got, want)
	}
	// --pids 0 lifts the cap, and the unasked ones are not named.
	got = strings.Join(scopeArgv("u.scope", containerLimits{Pids: -1}, inner), " ")
	if !strings.Contains(got, "-p TasksMax=infinity --") || strings.Contains(got, "CPUQuota") || strings.Contains(got, "MemoryMax") {
		t.Errorf("an uncapped scope: %s", got)
	}
}

// gvisorFake is a host whose podman answers a gVisor create, and whose /proc
// puts conmon in whichever scope inScope asks about when inside is true.
func gvisorFake(t *testing.T, inside bool) (*run.Fake, Deps) {
	t.Helper()
	f := run.NewFake().OnStdout("{{.State.ConmonPid}}", "4242").
		OnStdout("Gateway", "10.89.0.1\n").OnStdout("network inspect", "true|1\n")
	oldRun, oldCG := haveSystemdRun, procCgroup
	haveSystemdRun = func() bool { return true }
	procCgroup = func(pid string) (string, error) {
		if pid != "4242" {
			return "", errors.New("no such pid")
		}
		for _, c := range f.Calls {
			for _, a := range c {
				if unit, ok := strings.CutPrefix(a, "--unit="); ok && inside {
					return "0::/user.slice/cs.slice/cs-sandbox.slice/" + unit + "\n", nil
				}
			}
		}
		return "0::/user.slice/app.slice/tmux.scope\n", nil
	}
	t.Cleanup(func() { haveSystemdRun, procCgroup = oldRun, oldCG })
	dir := t.TempDir()
	for _, k := range []string{"id_cs-sandbox_agent", "id_cs-sandbox_agent.pub", "id_cs-sandbox_user.pub"} {
		if err := os.WriteFile(filepath.Join(dir, k), []byte("key\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	d := Deps{
		Runner: f, InstDir: dir, TierDir: dir, FCCache: dir, Network: "cs-sandbox-net", Image: "img",
		Host:    hostenv.Host{User: "dev", UID: 1000, GID: 1000, Home: dir},
		Cgroups: Cgroups{Slice: true, Controllers: []string{"cpu", "memory", "pids"}},
	}
	return f, d
}

func call(f *run.Fake, prefix string) string {
	i := slices.IndexFunc(f.Rendered(), func(c string) bool { return strings.HasPrefix(c, prefix) })
	if i < 0 {
		return ""
	}
	return f.Rendered()[i]
}

// A gVisor create runs podman inside a scope carrying the limits, sets the slice
// first, and records the limits it saw applied.
func TestGVisorCreateRunsInsideAScope(t *testing.T) {
	f, d := gvisorFake(t, true)
	inst, err := NewGVisor(d).Create(context.Background(),
		CreateSpec{Name: "box", Type: "agent", Pids: DefaultPids, CPUs: 2, MemMiB: 2048})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	runCall := call(f, "systemd-run")
	for _, want := range []string{
		"--slice=cs-sandbox.slice", "-p TasksMax=8192", "-p CPUQuota=200%", "-p MemoryMax=2048M",
		"-- podman run -d --name box.default",
		"--runtime " + gvisor.Cache{Dir: gvisor.Dir(d.FCCache)}.Runtime(gvisor.Version()),
	} {
		if !strings.Contains(runCall, want) {
			t.Errorf("scoped run missing %q:\n%s", want, runCall)
		}
	}
	// The limits are the scope's: none may reach the container, where runsc would drop them.
	for _, gone := range []string{"--pids-limit", "--cgroup-parent", "--memory=", "--cpus="} {
		if strings.Contains(runCall, gone) {
			t.Errorf("a gVisor run carries %s, which applies to nothing:\n%s", gone, runCall)
		}
	}
	set := slices.IndexFunc(f.Rendered(), func(c string) bool { return strings.HasPrefix(c, "systemctl --user set-property") })
	scoped := slices.IndexFunc(f.Rendered(), func(c string) bool { return strings.HasPrefix(c, "systemd-run") })
	if set < 0 || set > scoped {
		t.Errorf("the slice must be capped before the sandbox starts in it: %s", f)
	}
	if inst.Engine != state.GVisor || inst.Pids != DefaultPids || inst.CPUs != 2 || inst.MemMiB != 2048 {
		t.Errorf("instance = engine %s, pids %d, cpus %d, mem %d", inst.Engine, inst.Pids, inst.CPUs, inst.MemMiB)
	}
	saved, err := state.Load(d.InstDir, state.DefaultGroup, "box")
	if err != nil || saved.Engine != state.GVisor {
		t.Errorf("saved record: %+v, %v", saved, err)
	}
}

// A limit is named only where it was seen to apply (R178): a sandbox found
// outside its scope is recorded with none, and the caller is told.
func TestGVisorCreateClaimsNoLimitItDidNotSee(t *testing.T) {
	f, d := gvisorFake(t, false)
	var notes []string
	d.Note = func(s string) { notes = append(notes, s) }
	inst, err := NewGVisor(d).Create(context.Background(), CreateSpec{Name: "box", Type: "agent", Pids: DefaultPids, MemMiB: 2048})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if call(f, "systemd-run") == "" {
		t.Fatalf("expected a scoped run: %s", f)
	}
	if inst.Pids != 0 || inst.MemMiB != 0 {
		t.Errorf("limits recorded that were not seen: pids %d mem %d", inst.Pids, inst.MemMiB)
	}
	if saved, _ := state.Load(d.InstDir, state.DefaultGroup, "box"); saved == nil || saved.Pids != 0 || saved.MemMiB != 0 {
		t.Errorf("the saved record still claims limits: %+v", saved)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "without limits") {
		t.Errorf("notes = %q", notes)
	}
}

// Where no user manager can hold a scope, the sandbox still starts, outside one,
// and records no limit (R176).
func TestGVisorCreateWithoutAUserManager(t *testing.T) {
	f, d := gvisorFake(t, true)
	d.Cgroups = Cgroups{}
	inst, err := NewGVisor(d).Create(context.Background(), CreateSpec{Name: "box", Type: "agent", Pids: DefaultPids})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if f.Contains("systemd-run") || call(f, "podman run") == "" {
		t.Errorf("want a bare podman run: %s", f)
	}
	if inst.Pids != 0 {
		t.Errorf("no scope, so no limit, but pids = %d", inst.Pids)
	}
}

func TestGVisorRefusesPrivileged(t *testing.T) {
	f, d := gvisorFake(t, true)
	_, err := NewGVisor(d).Create(context.Background(), CreateSpec{Name: "box", Type: "agent", Privileged: true})
	if !errors.Is(err, ErrGVisorPrivileged) {
		t.Fatalf("err = %v", err)
	}
	if f.Contains("podman run") {
		t.Errorf("a refused create ran podman: %s", f)
	}
}

// Start makes a fresh scope from the limits the record holds, because a scope is
// gone once its sandbox stops. A sandbox already running is left where it is.
func TestGVisorStartMakesAFreshScope(t *testing.T) {
	f, d := gvisorFake(t, true)
	if err := state.Save(d.InstDir, &state.Instance{Name: "box", Group: state.DefaultGroup, Type: "agent",
		Engine: state.GVisor, Pids: 8192, MemMiB: 1024}); err != nil {
		t.Fatal(err)
	}
	if err := NewGVisor(d).Start(context.Background(), "box"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	start := call(f, "systemd-run")
	for _, want := range []string{"-p TasksMax=8192", "-p MemoryMax=1024M", "-- podman start box.default"} {
		if !strings.Contains(start, want) {
			t.Errorf("start missing %q:\n%s", want, start)
		}
	}

	f2, d2 := gvisorFake(t, true)
	f2.OnStdout("{{.State.Running}}", "true")
	if err := NewGVisor(d2).Start(context.Background(), "box"); err != nil {
		t.Fatalf("Start of a running sandbox: %v", err)
	}
	if f2.Contains("systemd-run") || f2.Contains("podman start") {
		t.Errorf("a running sandbox was started again: %s", f2)
	}
}

// Verify asks for the release as well as the image, so a create on a host
// without runsc prepares it rather than failing at podman run.
func TestGVisorVerifyNamesTheMissingRuntime(t *testing.T) {
	_, d := gvisorFake(t, true)
	err := NewGVisor(d).Verify(context.Background())
	if err == nil || !strings.Contains(err.Error(), "cs-sandbox build --engine gvisor") {
		t.Errorf("Verify = %v", err)
	}
	if err := NewPodman(d).Verify(context.Background()); err != nil {
		t.Errorf("a podman sandbox needs no runsc: %v", err)
	}
}
