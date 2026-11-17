package gvisor

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codesweep-ai/sandbox/internal/run"
	"github.com/klauspost/compress/zstd"
)

type entry struct {
	name string
	body string // "" with dir set makes a directory
	dir  bool
}

// release builds a gvisor.tar.zstd shaped like the one gVisor publishes.
func release(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o755, Size: int64(len(e.body)), Typeflag: tar.TypeReg}
		if e.dir {
			h.Typeflag, h.Size = tar.TypeDir, 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func published(t *testing.T) []byte {
	t.Helper()
	return release(t,
		entry{name: "containerd-shim-runsc-v1", body: "shim"},
		entry{name: "runsc", body: "#!/bin/sh\necho runsc\n"},
		entry{name: "gvisor-bin/", dir: true},
		entry{name: "gvisor-bin/gvisor_sentry", body: "sentry"},
	)
}

func sum(b []byte) string {
	s := sha512.Sum512(b)
	return hex.EncodeToString(s[:])
}

// pin makes the test's archive the pinned one, for this test only.
func pin(t *testing.T, digest string) {
	t.Helper()
	arch, err := Arch()
	if err != nil {
		t.Skip(err)
	}
	old := digests[arch]
	digests[arch] = digest
	t.Cleanup(func() { digests[arch] = old })
}

func TestEnsureUnpacksThePinnedRelease(t *testing.T) {
	arc := published(t)
	pin(t, sum(arc))
	c := Cache{Dir: t.TempDir()}
	r := run.NewFake().OnStdout("/gvisor.tar.zstd", string(arc))
	if err := c.Ensure(context.Background(), r, DefaultVersion); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := c.Verify(DefaultVersion); err != nil {
		t.Errorf("Verify after Ensure: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(c.ReleaseDir(DefaultVersion), "bin", "gvisor-bin", "gvisor_sentry")); string(b) != "sentry" {
		t.Errorf("runsc's helpers must sit beside it in gvisor-bin/, got %q", b)
	}
	// Only what runs a container is kept: the containerd shim is 24 MB nobody here calls.
	if _, err := os.Stat(filepath.Join(c.ReleaseDir(DefaultVersion), "bin", "containerd-shim-runsc-v1")); err == nil {
		t.Error("the containerd shim was unpacked")
	}
	if b, _ := os.ReadFile(filepath.Join(c.ReleaseDir(DefaultVersion), "release")); string(b) != DefaultVersion+" pinned\n" {
		t.Errorf("the release must record itself and that its digest was the pinned one, got %q", b)
	}
	if r.Contains(".sha512") {
		t.Error("the pinned release must not be checked against the checksum served beside it")
	}
	// A second Ensure finds it there and downloads nothing.
	r2 := run.NewFake()
	if err := c.Ensure(context.Background(), r2, DefaultVersion); err != nil {
		t.Fatal(err)
	}
	if len(r2.Calls) != 0 {
		t.Errorf("a cached release was fetched again: %v", r2.Rendered())
	}
	if got := c.Releases(); len(got) != 1 || got[0] != DefaultVersion {
		t.Errorf("Releases() = %v", got)
	}
}

// The committed digest is the trust anchor (R117): an archive that does not match
// it is refused, and nothing of it is left where a sandbox would find it.
func TestEnsureRefusesAnArchiveThatMissesThePinnedDigest(t *testing.T) {
	pin(t, strings.Repeat("0", 128))
	c := Cache{Dir: t.TempDir()}
	r := run.NewFake().OnStdout("/gvisor.tar.zstd", string(published(t)))
	err := c.Ensure(context.Background(), r, DefaultVersion)
	if err == nil || !strings.Contains(err.Error(), "digest pinned in this build") {
		t.Fatalf("want a refusal naming the pinned digest, got %v", err)
	}
	if _, err := os.Stat(c.ReleaseDir(DefaultVersion)); err == nil {
		t.Error("a release that failed its digest was left in the cache")
	}
	if c.Verify(DefaultVersion) == nil {
		t.Error("Verify passed a release that was refused")
	}
}

// An overridden release has no committed digest, so it is checked against the
// one gVisor publishes and the caller is told that is all it was (R118).
func TestEnsureChecksAnOverrideAgainstThePublishedChecksum(t *testing.T) {
	arc := published(t)
	var said []string
	c := Cache{Dir: t.TempDir(), Progress: func(s string) { said = append(said, s) }}
	r := run.NewFake().
		OnStdout(".sha512", strings.ToUpper(sum(arc))+"  gvisor.tar.zstd\n").
		OnStdout("/gvisor.tar.zstd", string(arc))
	if err := c.Ensure(context.Background(), r, "20990101.0"); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !strings.Contains(strings.Join(said, "\n"), "not a trust anchor") {
		t.Errorf("an override must say what its check is worth, said: %q", said)
	}
	if b, _ := os.ReadFile(filepath.Join(c.ReleaseDir("20990101.0"), "release")); string(b) != "20990101.0 published\n" {
		t.Errorf("release record = %q", b)
	}
}

// An entry naming a path outside runsc and its helpers is not written, wherever
// it points.
func TestUnpackWritesOnlyRunscAndItsHelpers(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.tar.zstd")
	if err := os.WriteFile(archive, release(t,
		entry{name: "runsc", body: "r"},
		entry{name: "../escape", body: "x"},
		entry{name: "gvisor-bin/../../escape2", body: "x"},
		entry{name: "./gvisor-bin/ok", body: "ok"},
	), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out", "bin")
	if err := unpack(archive, out); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(dir, "escape"), filepath.Join(dir, "out", "escape2"), filepath.Join(dir, "escape2")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("unpack wrote %s, outside its set", p)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(out, "gvisor-bin", "ok")); string(b) != "ok" {
		t.Errorf("gvisor-bin/ok = %q", b)
	}
}

// The wrapper is what podman runs for every start, stop and exec, so it must
// carry every flag R175 names, and run whatever the cache's path holds.
func TestWrapperRunsTheReleaseWithEveryFlag(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "it's a dir")
	bin := filepath.Join(dir, "runsc")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := filepath.Join(dir, "wrapper")
	if err := os.WriteFile(w, []byte(Wrapper(bin)), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(w, "create", "--bundle", "x y").Output()
	if err != nil {
		t.Fatalf("running the wrapper: %v", err)
	}
	want := []string{"--ignore-cgroups", "--allow-suid", "--net-raw", "--oci-seccomp", "create", "--bundle", "x y"}
	if got := strings.Split(strings.TrimSpace(string(out)), "\n"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("runsc got %q, want %q", got, want)
	}
}

func TestVersionHonoursTheOverride(t *testing.T) {
	t.Setenv("CS_SANDBOX_GVISOR_VERSION", "")
	if Version() != DefaultVersion {
		t.Errorf("Version() = %q, want the pin", Version())
	}
	t.Setenv("CS_SANDBOX_GVISOR_VERSION", "20990101.0")
	if Version() != "20990101.0" {
		t.Errorf("Version() = %q, want the override", Version())
	}
}
