//go:build integration || smoke

package cli

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/codesweep-ai/sandbox/internal/engine"
	"github.com/codesweep-ai/sandbox/internal/gvisor"
	"github.com/codesweep-ai/sandbox/internal/paths"
	"github.com/codesweep-ai/sandbox/internal/run"
)

// requireGVisor skips unless the pinned runsc is in the artifact cache. A create
// would fetch it, but a test run is not the place to download 65 MB nobody asked
// for: `cs-sandbox build --engine gvisor` is, and `make setup-smoke` runs it on
// every Linux host with podman.
func requireGVisor(t *testing.T) {
	t.Helper()
	if err := (gvisor.Cache{Dir: gvisor.Dir(paths.FCCache())}).Verify(gvisor.Version()); err != nil {
		t.Skipf("gVisor is not set up here: %v", err)
	}
}

// scopeFile reads one of a running sandbox's cgroup files: the cgroup conmon is
// in, which under gVisor holds the whole sandbox (R176).
func scopeFile(ctx context.Context, t *testing.T, r *run.Exec, name, file string) string {
	t.Helper()
	pid := run.Output(ctx, r, "podman", "inspect", "--format", "{{.State.ConmonPid}}", objName(name))
	cg, err := os.ReadFile("/proc/" + pid + "/cgroup")
	if err != nil {
		t.Fatalf("conmon's cgroup: %v", err)
	}
	_, path, _ := strings.Cut(strings.TrimSpace(string(cg)), "::")
	if !strings.Contains(path, "/"+engine.SliceName+"/cs-sandbox-gvisor-") {
		t.Fatalf("conmon is in %s, not a gVisor scope under %s", path, engine.SliceName)
	}
	b, err := os.ReadFile("/sys/fs/cgroup" + path + "/" + file)
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return strings.TrimSpace(string(b))
}

// TestCLIGVisorLive drives a gVisor sandbox through what SPEC §11.6 promises:
// gVisor runs it, sudo works (R175), its limits hold on its scope and come back
// on start (R176), and a nested container runs on the sandbox's own network
// (R177). A restart keeps the home and loses the root filesystem's changes,
// which is the one difference §11.6 lists that a test can see.
func TestCLIGVisorLive(t *testing.T) {
	r, host := liveSetup(t)
	requireGVisor(t)
	ctx := context.Background()
	name := boxName("gvisor")
	t.Cleanup(func() { _, _ = destroyBox(t, name) })

	out, err := execRoot(t, "create", name, "--engine", "gvisor", "--mem", "2048")
	if err != nil {
		t.Fatalf("create: %v\n%s", err, out)
	}
	limited := engine.HostCgroups(host).Slice
	want := []string{"engine=gvisor", "runtime:  gVisor " + gvisor.Version(), "nested containers: share this sandbox's network"}
	if limited {
		want = append(want, "limits:   8192 host tasks, 2048 MiB of memory")
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("create's output lacks %q:\n%s", w, out)
		}
	}
	if got := run.Output(ctx, r, "podman", "inspect", "--format", "{{.OCIRuntime}}", objName(name)); got !=
		(gvisor.Cache{Dir: gvisor.Dir(paths.FCCache())}).Runtime(gvisor.Version()) {
		t.Errorf("the container's runtime is %q, not the cached release's wrapper", got)
	}

	checkRunning := func(t *testing.T) {
		t.Helper()
		if k := inBox(ctx, r, host, name, "uname -r"); !strings.Contains(k, "gvisor") {
			t.Errorf("uname -r = %q, want gVisor's kernel", k)
		}
		if got := inBox(ctx, r, host, name, "sudo -n true && echo sudo-ok"); got != "sudo-ok" {
			t.Errorf("sudo inside a gVisor sandbox = %q, want it to work (R175's --allow-suid)", got)
		}
		if !limited {
			return
		}
		if got := scopeFile(ctx, t, r, name, "pids.max"); got != "8192" {
			t.Errorf("pids.max = %s, want 8192", got)
		}
		if got := scopeFile(ctx, t, r, name, "memory.max"); got != "2147483648" {
			t.Errorf("memory.max = %s, want 2 GiB", got)
		}
	}
	t.Run("running", checkRunning)

	t.Run("nested", func(t *testing.T) {
		const workload = "docker.io/library/busybox"
		requireWorkloadImage(t, workload)
		got := inBox(ctx, r, host, name, "podman run --rm "+workload+" readlink /proc/self/ns/net 2>/dev/null; readlink /proc/self/ns/net")
		lines := strings.Fields(got)
		if len(lines) != 2 || lines[0] != lines[1] {
			t.Errorf("a nested container should run on the sandbox's network namespace (R177); inner then outer: %q", got)
		}
	})

	t.Run("restart", func(t *testing.T) {
		inBox(ctx, r, host, name, "echo kept > ~/home-marker; echo gone | sudo tee /etc/cs-marker >/dev/null")
		if out, err := execRoot(t, "stop", ref(name)); err != nil {
			t.Fatalf("stop: %v\n%s", err, out)
		}
		if out, err := execRoot(t, "start", ref(name)); err != nil {
			t.Fatalf("start: %v\n%s", err, out)
		}
		if got := inBox(ctx, r, host, name, "cat ~/home-marker"); got != "kept" {
			t.Errorf("the home did not survive a restart: %q", got)
		}
		if got := inBox(ctx, r, host, name, "cat /etc/cs-marker 2>/dev/null || echo fresh"); got != "fresh" {
			t.Errorf("the root filesystem kept a change across a restart (%q); SPEC §11.6 says it starts fresh", got)
		}
		checkRunning(t)
	})
}
