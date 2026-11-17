// Package gvisor fetches and keeps gVisor's runsc, the runtime a gvisor sandbox's
// container runs under (SPEC §11.6).
//
// Each release gets a directory of its own in the artifact cache:
//
//	<cache>/gvisor/<release>/bin/runsc          the release's runsc
//	<cache>/gvisor/<release>/bin/gvisor-bin/…   the helpers runsc starts
//	<cache>/gvisor/<release>/runsc              the wrapper podman's --runtime names
//	<cache>/gvisor/<release>/release            the release, and where its digest came from
//
// A sandbox records the wrapper's path with its container, so it keeps the
// release it was created with however the pin moves (R174).
package gvisor

import (
	"archive/tar"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/codesweep-ai/sandbox/internal/lock"
	"github.com/codesweep-ai/sandbox/internal/run"
	"github.com/klauspost/compress/zstd"
)

// DefaultVersion is the gVisor release runsc is pinned to when
// CS_SANDBOX_GVISOR_VERSION is unset. Bump digests in the same commit.
const DefaultVersion = "20261109.0"

// digests pins the SHA-512 of DefaultVersion's gvisor.tar.zstd, keyed by
// gVisor's arch name. SHA-512 because it is the digest gVisor publishes, so a
// bump is checked against the published file by eye. Committed here because a
// checksum served beside the archive proves nothing about an origin that served
// both (R117).
var digests = map[string]string{
	"x86_64":  "0a0041fd862f4ea3042a9db8d41c742f48a01f909699adc2a0256e46d85e53f97b82b9fd154b3dce636f62b8d557677639f91c77d13f3f875ff9fa535275393c",
	"aarch64": "a0b5d911512ef5fe70e833821e653a90c4d06c7027246ee49423f1d2fe2b2a509389a637797248958b90e49a069bb079ecde860efe1871b1d980ec0fe17e18ac",
}

// Flags are what runsc runs every sandbox with (R175). Each answers a measured
// failure: rootless runsc cannot reach systemd's system bus for cgroups, gVisor
// ignores set-user-ID bits, drops CAP_NET_RAW, and skips the container's
// seccomp filter unless told otherwise.
var Flags = []string{"--ignore-cgroups", "--allow-suid", "--net-raw", "--oci-seccomp"}

// baseURL is where gVisor publishes its releases. A var so a test can serve one.
var baseURL = "https://storage.googleapis.com/gvisor/releases/release"

// Version is the release this build runs: CS_SANDBOX_GVISOR_VERSION, or the pin.
func Version() string {
	if v := os.Getenv("CS_SANDBOX_GVISOR_VERSION"); v != "" {
		return v
	}
	return DefaultVersion
}

// Arch is gVisor's name for this host's architecture.
func Arch() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64", nil
	case "arm64":
		return "aarch64", nil
	}
	return "", fmt.Errorf("gVisor publishes no runsc for %s", runtime.GOARCH)
}

// Dir is where runsc lives inside the artifact cache.
func Dir(artifactCache string) string { return filepath.Join(artifactCache, "gvisor") }

// Cache is the part of the artifact cache that holds runsc.
type Cache struct {
	Dir string // <artifact cache>/gvisor
	// Progress takes the lines a download says as it goes. nil says nothing.
	Progress func(string)
}

func (c Cache) say(format string, a ...any) {
	if c.Progress != nil {
		c.Progress(fmt.Sprintf(format, a...))
	}
}

// ReleaseDir is the directory one release lives in.
func (c Cache) ReleaseDir(version string) string { return filepath.Join(c.Dir, version) }

// Runtime is the wrapper podman's --runtime names for a release.
func (c Cache) Runtime(version string) string {
	return filepath.Join(c.ReleaseDir(version), "runsc")
}

// Binary is a release's runsc itself.
func (c Cache) Binary(version string) string {
	return filepath.Join(c.ReleaseDir(version), "bin", "runsc")
}

// Releases lists the releases the cache holds, oldest name first.
func (c Cache) Releases() []string {
	entries, err := os.ReadDir(c.Dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") && isExecutable(c.Binary(e.Name())) {
			out = append(out, e.Name())
		}
	}
	return out
}

// Verify reports whether a release is ready to run a sandbox, in a sentence that
// says what fixes it. It builds nothing.
func (c Cache) Verify(version string) error {
	for _, p := range []string{c.Binary(version), c.Runtime(version)} {
		if !isExecutable(p) {
			return fmt.Errorf("gVisor %s is not in the artifact cache (%s) — run: cs-sandbox build --engine gvisor", version, p)
		}
	}
	return nil
}

// Ensure makes a release ready: downloaded, checked against its digest, unpacked,
// and given its wrapper. A release already there costs only a stat and the
// wrapper's rewrite where its flags have changed.
//
// It holds a lock on the cache while it works, so two creates do not download
// one release into each other.
func (c Cache) Ensure(ctx context.Context, r run.Runner, version string) error {
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return err
	}
	l := lock.NewAt(filepath.Join(c.Dir, ".lock"))
	if err := l.Acquire(); err != nil {
		return err
	}
	defer l.Release()
	if !isExecutable(c.Binary(version)) {
		if err := c.download(ctx, r, version); err != nil {
			return err
		}
	}
	return c.writeWrapper(version)
}

// download fetches a release, checks it, and unpacks it under a temporary name
// that is renamed into place, so a release directory either is complete or is
// not there.
func (c Cache) download(ctx context.Context, r run.Runner, version string) error {
	arch, err := Arch()
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/%s/%s/gvisor.tar.zstd", baseURL, version, arch)
	c.say("downloading gVisor %s…", version)
	archive := filepath.Join(c.Dir, ".gvisor-"+version+"-"+arch+".tar.zstd")
	defer func() { _ = os.Remove(archive) }()
	if _, err := r.Run(ctx, run.Opts{StdoutFile: archive}, "curl", "-fsSL", url); err != nil {
		return fmt.Errorf("gVisor %s: download failed (%s): %w", version, url, err)
	}
	want, pinned, err := c.wantDigest(ctx, r, version, arch, url)
	if err != nil {
		return err
	}
	got, err := sha512File(archive)
	if err != nil {
		return err
	}
	if got != want {
		src := "checksum gVisor published with it"
		if pinned {
			src = "digest pinned in this build"
		}
		return fmt.Errorf("gVisor %s (%s) does not match the %s (want=%s got=%s)", version, arch, src, want, got)
	}
	tmp, err := os.MkdirTemp(c.Dir, ".unpack-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := os.Chmod(tmp, 0o755); err != nil { // MkdirTemp makes it 0700, and it becomes the release
		return err
	}
	if err := unpack(archive, filepath.Join(tmp, "bin")); err != nil {
		return fmt.Errorf("gVisor %s: %w", version, err)
	}
	if !isExecutable(filepath.Join(tmp, "bin", "runsc")) {
		return fmt.Errorf("gVisor %s: the archive carries no runsc", version)
	}
	how := "pinned"
	if !pinned {
		how = "published"
	}
	if err := os.WriteFile(filepath.Join(tmp, "release"), []byte(version+" "+how+"\n"), 0o644); err != nil {
		return err
	}
	dst := c.ReleaseDir(version)
	_ = os.RemoveAll(dst) // a directory with no runsc in it is what an older, interrupted unpack left
	return os.Rename(tmp, dst)
}

// wantDigest is the SHA-512 a release's archive must have, and whether it is the
// one pinned here. Any release but the pin is checked against the checksum
// published beside it, which catches corruption and nothing else, so that path
// says so (R118).
func (c Cache) wantDigest(ctx context.Context, r run.Runner, version, arch, url string) (string, bool, error) {
	why := version + " is not the pinned release (" + DefaultVersion + ")"
	if version == DefaultVersion {
		if d := digests[arch]; d != "" {
			return d, true, nil
		}
		why = "no digest is pinned for " + arch
	}
	c.say("warning: %s — checking gVisor against the checksum published with it, which is not a trust anchor", why)
	res, err := r.Run(ctx, run.Opts{ReadOnly: true}, "curl", "-fsSL", url+".sha512")
	if err != nil {
		return "", false, fmt.Errorf("gVisor %s: could not fetch its published checksum: %w", version, err)
	}
	if f := strings.Fields(res.Stdout); len(f) > 0 {
		return strings.ToLower(f[0]), false, nil
	}
	return "", false, fmt.Errorf("gVisor %s: its published checksum is empty", version)
}

// unpack writes runsc and the gvisor-bin helpers runsc starts into dir. Nothing
// else in the archive is needed to run a container, so nothing else is written,
// and no entry can name a path outside dir.
func unpack(archive, dir string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		return fmt.Errorf("reading the archive: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading the archive: %w", err)
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		if name != "runsc" && !strings.HasPrefix(name, "gvisor-bin/") {
			continue
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := writeFile(dst, tr, h.FileInfo().Mode().Perm()); err != nil {
				return err
			}
		}
	}
}

func writeFile(dst string, src io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, src); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// Wrapper is the script podman's --runtime names: the release's runsc, with
// the flags every sandbox runs with. Podman records the runtime with the
// container and calls it again for start, stop and exec, which a flag passed to
// podman itself would not reach.
func Wrapper(binary string) string {
	return "#!/bin/sh\n" +
		"# The runtime cs-sandbox runs gVisor sandboxes under (SPEC R175).\n" +
		"exec " + shellQuote(binary) + " " + strings.Join(Flags, " ") + " \"$@\"\n"
}

// writeWrapper writes a release's wrapper where its content differs, by a
// rename, so a runtime call in flight never reads half a script.
func (c Cache) writeWrapper(version string) error {
	want := Wrapper(c.Binary(version))
	p := c.Runtime(version)
	if have, err := os.ReadFile(p); err == nil && string(have) == want && isExecutable(p) {
		return nil
	}
	tmp := p + ".new"
	if err := os.WriteFile(tmp, []byte(want), 0o755); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, p)
}

// shellQuote quotes s for sh, whatever it holds.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func sha512File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}
