# Transitive Reachability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable function-level reachability analysis for vulnerabilities sitting inside transitive dependencies in Python and JavaScript projects, producing stitched call-path VEX evidence from the application through intermediate dep packages to the vulnerable function. Hermetic: no venv / `node_modules` required.

**Architecture:** New `pkg/vex/reachability/transitive/` package that orchestrates a pairwise reverse walk along an SBOM-version-pinned dependency chain. Each hop reuses the existing tree-sitter extractors and BFS primitives. Dependency structure is derived from PyPI JSON API / npm registry manifests (never from SBOM `dependsOn` edges). Package source is fetched from registry tarballs into a content-addressed cache under `~/.cache/cra-toolkit/pkgs/<sha256>/` and verified against SBOM digests. Short-circuit any hop that has no caller of its downstream neighbor's tainted exports. Existing `pkg/vex/reachability/python/python.go` and `.../javascript/javascript.go` consult the new analyzer before their current "direct-only" behavior.

**Tech Stack:** Go 1.23, tree-sitter-go, tree-sitter grammars for Python/JavaScript/TypeScript (already in repo), PyPI JSON API (`https://pypi.org/pypi/<pkg>/<version>/json`), npm registry (`https://registry.npmjs.org/<pkg>/<version>`), urfave/cli v3, existing `pkg/formats/`, `pkg/vex/reachability/treesitter/`. No new third-party dependencies.

**Reference spec:** `docs/superpowers/specs/2026-04-10-transitive-reachability-design.md`

---

## File Structure

### New files under `pkg/vex/reachability/transitive/`

| File | Responsibility |
|---|---|
| `config.go` | `Config` struct with bounds; default constants; YAML tags for product-config. |
| `degradation.go` | `Degradation` type; structured reason constants (`transitive_not_applicable`, `manifest_fetch_failed`, `tarball_fetch_failed`, `digest_mismatch`, `source_unavailable`, `bound_exceeded`, `extractor_error`, `path_broken`, `no_application_root`). |
| `cache.go` | Content-addressed cache with single-flight. `(*Cache).Get(digest)`, `(*Cache).Put(digest, src)`, `NewCache(dir)`. |
| `cache_test.go` | Cache unit tests. |
| `fetcher.go` | `Fetcher` interface, `FetchResult`, `PackageManifest`, `Digest` types. |
| `fetcher_pypi.go` | `PyPIFetcher` implementation. |
| `fetcher_pypi_test.go` | PyPI fetcher unit tests (httptest server + canned tarballs). |
| `fetcher_npm.go` | `NPMFetcher` implementation. |
| `fetcher_npm_test.go` | npm fetcher unit tests. |
| `sbom_graph.go` | `BuildDepGraph`, `PruneReverseReachable`, `DepGraph` type. |
| `sbom_graph_test.go` | Graph construction & pruning tests. |
| `hop.go` | `RunHop` primitive: given source dir + target symbols + language, return reaching symbols & call paths via reverse-BFS. |
| `hop_test.go` | Hop unit tests against small source fixtures. |
| `walker.go` | `Walker` type driving pairwise walk over SBOM paths with short-circuit. |
| `walker_test.go` | Walker tests (orchestration + short-circuit + bound enforcement). |
| `evidence.go` | `StitchCallPaths` concatenates per-hop paths into one continuous `CallPath`. |
| `evidence_test.go` | Evidence stitching tests. |
| `transitive.go` | Top-level `Analyzer` struct; `Analyze` entry point; applicability check. |
| `transitive_test.go` | End-to-end unit tests. |

### Files to modify

| File | Change |
|---|---|
| `pkg/vex/reachability/result.go` | Add `Degradations []string` field. |
| `pkg/vex/reachability/python/python.go` | Embed `*transitive.Analyzer`; pre-check before existing logic. |
| `pkg/vex/reachability/javascript/javascript.go` | Same pre-check pattern. |
| `pkg/vex/vex.go` | Parse SBOM once; construct `transitive.Analyzer` with bounds from product-config; wire into per-language analyzers. |
| `internal/cli/vex.go` | Add `--transitive` bool and `--transitive-cache-dir` string flags. |
| `pkg/toolkit/product_config.go` (or equivalent struct holder) | Add `Reachability.Transitive` stanza. |
| `Taskfile.yml` | Add `test:transitive:realworld` task. |
| `pkg/vex/reachability/python/llm_judge_test.go` | Extend with transitive cases. |
| `pkg/vex/reachability/javascript/llm_judge_test.go` | Extend with transitive cases. |
| `site/docs/tools/vex.md` | Document the transitive analysis. |

### New test fixtures

| Directory | Purpose |
|---|---|
| `testdata/integration/python-realworld-cross-package/source/` | Flask-style mini-app that transitively reaches a real Python CVE. |
| `testdata/integration/python-realworld-cross-package/sbom.cdx.json` | SBOM pinning exact vulnerable versions. |
| `testdata/integration/python-realworld-cross-package/trivy.json` | Scan result for the CVE. |
| `testdata/integration/python-realworld-cross-package/expected.json` | Expected reachable verdict + provenance. |
| `testdata/integration/python-realworld-cross-package-safe/` | Same deps, different app code that does not reach the CVE. |
| `testdata/integration/javascript-realworld-cross-package/` | Express app reaching CVE through transitive dep. |
| `testdata/integration/javascript-realworld-cross-package-safe/` | Safe variant. |
| `testdata/transitive/pypi/<pkg>-<version>.tar.gz` | Real sdists captured from PyPI for deterministic fetcher tests. |
| `testdata/transitive/npm/<pkg>-<version>.tgz` | Real tarballs captured from npm. |
| `testdata/transitive/pypi/<pkg>_<version>.json` | Real PyPI JSON metadata. |
| `testdata/transitive/npm/<pkg>_<version>.json` | Real npm registry metadata. |

---

## Task 1: Add `Degradations` field to `reachability.Result`

**Files:**
- Modify: `pkg/vex/reachability/result.go`
- Test: `pkg/vex/reachability/result_test.go`

- [ ] **Step 1: Write the failing test**

Add the following test to `pkg/vex/reachability/result_test.go` (append to whatever exists; create the file if it does not exist yet with the same package header as `result.go`):

```go
func TestResult_Degradations(t *testing.T) {
	r := Result{
		Reachable:  true,
		Confidence: formats.ConfidenceLow,
		Degradations: []string{
			"source_unavailable",
			"bound_exceeded",
		},
	}
	if len(r.Degradations) != 2 {
		t.Fatalf("expected 2 degradations, got %d", len(r.Degradations))
	}
	if r.Degradations[0] != "source_unavailable" {
		t.Errorf("unexpected first degradation: %q", r.Degradations[0])
	}
}
```

Ensure the test file imports `"testing"` and `"github.com/ravan/cra-toolkit/pkg/formats"`.

- [ ] **Step 2: Run the test and verify it fails**

```
go test ./pkg/vex/reachability/ -run TestResult_Degradations -v
```

Expected: FAIL with compilation error `unknown field Degradations in struct literal`.

- [ ] **Step 3: Add the field**

In `pkg/vex/reachability/result.go`, extend the `Result` struct:

```go
type Result struct {
	Reachable    bool               // whether the vulnerable code is reachable
	Confidence   formats.Confidence // confidence level of the determination
	Evidence     string             // human-readable evidence description
	Symbols      []string           // symbols found to be reachable (if any)
	Paths        []formats.CallPath // call paths from entry points to vulnerable symbols
	Degradations []string           // structured degradation reasons surfaced as VEX evidence
}
```

- [ ] **Step 4: Run the test and verify it passes**

```
go test ./pkg/vex/reachability/ -run TestResult_Degradations -v
```

Expected: PASS.

- [ ] **Step 5: Run the full test suite to verify no regressions**

```
task test
```

Expected: all tests pass. No other test should reference `Degradations` yet.

- [ ] **Step 6: Commit**

```
git add pkg/vex/reachability/result.go pkg/vex/reachability/result_test.go
git commit -m "feat(reachability): add Degradations field to Result"
```

---

## Task 2: Create transitive package skeleton, degradation reasons, and Config

**Files:**
- Create: `pkg/vex/reachability/transitive/degradation.go`
- Create: `pkg/vex/reachability/transitive/config.go`
- Create: `pkg/vex/reachability/transitive/config_test.go`

- [ ] **Step 1: Write the failing test**

Create `pkg/vex/reachability/transitive/config_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"testing"
	"time"
)

func TestDefaultConfig_Bounds(t *testing.T) {
	c := DefaultConfig()
	if c.MaxHopsPerPath != 8 {
		t.Errorf("MaxHopsPerPath: expected 8, got %d", c.MaxHopsPerPath)
	}
	if c.MaxPathsPerFinding != 16 {
		t.Errorf("MaxPathsPerFinding: expected 16, got %d", c.MaxPathsPerFinding)
	}
	if c.MaxTargetSymbolsPerHop != 256 {
		t.Errorf("MaxTargetSymbolsPerHop: expected 256, got %d", c.MaxTargetSymbolsPerHop)
	}
	if c.HopTimeout != 30*time.Second {
		t.Errorf("HopTimeout: expected 30s, got %s", c.HopTimeout)
	}
	if c.FindingBudget != 5*time.Minute {
		t.Errorf("FindingBudget: expected 5m, got %s", c.FindingBudget)
	}
	if c.CacheDir == "" {
		t.Errorf("CacheDir should have a default")
	}
}

func TestDegradationReasons_AreDistinct(t *testing.T) {
	reasons := []string{
		ReasonTransitiveNotApplicable,
		ReasonManifestFetchFailed,
		ReasonTarballFetchFailed,
		ReasonDigestMismatch,
		ReasonSourceUnavailable,
		ReasonBoundExceeded,
		ReasonExtractorError,
		ReasonPathBroken,
		ReasonNoApplicationRoot,
	}
	seen := make(map[string]bool)
	for _, r := range reasons {
		if r == "" {
			t.Errorf("reason should not be empty")
		}
		if seen[r] {
			t.Errorf("duplicate reason: %q", r)
		}
		seen[r] = true
	}
}
```

- [ ] **Step 2: Run test, verify fail**

```
go test ./pkg/vex/reachability/transitive/ -v
```

Expected: FAIL with package not found.

- [ ] **Step 3: Create `degradation.go`**

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package transitive implements transitive dependency reachability analysis
// by walking SBOM-derived dependency paths in reverse and running per-hop
// tree-sitter reachability checks against fetched package source.
package transitive

// Degradation reason constants surfaced as VEX evidence when analysis cannot
// proceed cleanly. Each reason is a stable identifier that appears in
// reachability.Result.Degradations.
const (
	ReasonTransitiveNotApplicable = "transitive_not_applicable"
	ReasonManifestFetchFailed     = "manifest_fetch_failed"
	ReasonTarballFetchFailed      = "tarball_fetch_failed"
	ReasonDigestMismatch          = "digest_mismatch"
	ReasonSourceUnavailable       = "source_unavailable"
	ReasonBoundExceeded           = "bound_exceeded"
	ReasonExtractorError          = "extractor_error"
	ReasonPathBroken              = "path_broken"
	ReasonNoApplicationRoot       = "no_application_root"
)
```

- [ ] **Step 4: Create `config.go`**

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"os"
	"path/filepath"
	"time"
)

// Config controls bounds, caching, and timeout behavior for transitive analysis.
// Defaults are chosen to terminate in reasonable time on real-world applications
// while allowing walks deep enough for realistic dependency chains.
type Config struct {
	MaxHopsPerPath         int           `yaml:"max_hops,omitempty"`
	MaxPathsPerFinding     int           `yaml:"max_paths,omitempty"`
	MaxTargetSymbolsPerHop int           `yaml:"max_target_symbols_per_hop,omitempty"`
	HopTimeout             time.Duration `yaml:"hop_timeout,omitempty"`
	FindingBudget          time.Duration `yaml:"finding_budget,omitempty"`
	CacheDir               string        `yaml:"cache_dir,omitempty"`
	Enabled                bool          `yaml:"enabled,omitempty"`
}

// DefaultConfig returns Config populated with the defaults documented in the
// transitive reachability design spec.
func DefaultConfig() Config {
	cacheDir := ""
	if home, err := os.UserCacheDir(); err == nil {
		cacheDir = filepath.Join(home, "cra-toolkit", "pkgs")
	} else {
		cacheDir = filepath.Join(os.TempDir(), "cra-toolkit-pkgs")
	}
	return Config{
		MaxHopsPerPath:         8,
		MaxPathsPerFinding:     16,
		MaxTargetSymbolsPerHop: 256,
		HopTimeout:             30 * time.Second,
		FindingBudget:          5 * time.Minute,
		CacheDir:               cacheDir,
		Enabled:                true,
	}
}

// Merge overlays any non-zero fields from override onto c and returns the result.
// Used to apply product-config YAML values on top of DefaultConfig().
func (c Config) Merge(override Config) Config {
	if override.MaxHopsPerPath > 0 {
		c.MaxHopsPerPath = override.MaxHopsPerPath
	}
	if override.MaxPathsPerFinding > 0 {
		c.MaxPathsPerFinding = override.MaxPathsPerFinding
	}
	if override.MaxTargetSymbolsPerHop > 0 {
		c.MaxTargetSymbolsPerHop = override.MaxTargetSymbolsPerHop
	}
	if override.HopTimeout > 0 {
		c.HopTimeout = override.HopTimeout
	}
	if override.FindingBudget > 0 {
		c.FindingBudget = override.FindingBudget
	}
	if override.CacheDir != "" {
		c.CacheDir = override.CacheDir
	}
	return c
}
```

- [ ] **Step 5: Run the tests and verify they pass**

```
go test ./pkg/vex/reachability/transitive/ -v
```

Expected: both tests PASS.

- [ ] **Step 6: Add a Merge test**

Append to `config_test.go`:

```go
func TestConfig_Merge(t *testing.T) {
	base := DefaultConfig()
	override := Config{
		MaxHopsPerPath: 20,
		HopTimeout:     time.Minute,
		CacheDir:       "/tmp/custom",
	}
	got := base.Merge(override)
	if got.MaxHopsPerPath != 20 {
		t.Errorf("MaxHopsPerPath: expected 20, got %d", got.MaxHopsPerPath)
	}
	if got.HopTimeout != time.Minute {
		t.Errorf("HopTimeout: expected 1m, got %s", got.HopTimeout)
	}
	if got.CacheDir != "/tmp/custom" {
		t.Errorf("CacheDir: expected /tmp/custom, got %q", got.CacheDir)
	}
	if got.MaxPathsPerFinding != base.MaxPathsPerFinding {
		t.Errorf("MaxPathsPerFinding: expected %d (unchanged), got %d", base.MaxPathsPerFinding, got.MaxPathsPerFinding)
	}
}
```

Run tests again:

```
go test ./pkg/vex/reachability/transitive/ -v
```

Expected: three tests PASS.

- [ ] **Step 7: Commit**

```
git add pkg/vex/reachability/transitive/
git commit -m "feat(transitive): add Config and degradation reason constants"
```

---

## Task 3: Content-addressed cache with single-flight

**Files:**
- Create: `pkg/vex/reachability/transitive/cache.go`
- Create: `pkg/vex/reachability/transitive/cache_test.go`

- [ ] **Step 1: Write the failing test**

Create `pkg/vex/reachability/transitive/cache_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCache_PutAndGet(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	digest := "sha256:abc123"
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := c.Put(digest, src)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got == "" {
		t.Fatal("Put returned empty path")
	}
	data, err := os.ReadFile(filepath.Join(got, "hello.txt"))
	if err != nil {
		t.Fatalf("file not present in cache: %v", err)
	}
	if string(data) != "hi" {
		t.Errorf("expected 'hi', got %q", data)
	}

	got2, ok := c.Get(digest)
	if !ok {
		t.Fatal("Get: miss after Put")
	}
	if got2 != got {
		t.Errorf("Get returned different path: %q vs %q", got, got2)
	}
}

func TestCache_SingleFlight(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	var calls atomic.Int32
	var wg sync.WaitGroup
	digest := "sha256:deadbeef"
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Do(digest, func() (string, error) {
				calls.Add(1)
				src := t.TempDir()
				_ = os.WriteFile(filepath.Join(src, "data"), []byte("x"), 0o644)
				return c.Put(digest, src)
			})
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Errorf("expected exactly one work invocation, got %d", got)
	}
}
```

- [ ] **Step 2: Run test, verify fail**

```
go test ./pkg/vex/reachability/transitive/ -run TestCache -v
```

Expected: FAIL with `undefined: NewCache`.

- [ ] **Step 3: Implement `cache.go`**

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Cache is a content-addressed directory cache keyed by digest strings.
// Entries are laid out as <root>/<hex>/, with the "sha256:" prefix stripped
// and replaced by the raw hex when computing the directory name.
type Cache struct {
	root   string
	mu     sync.Mutex
	inProg map[string]*flight
}

type flight struct {
	done chan struct{}
	path string
	err  error
}

// NewCache returns a Cache rooted at dir. The directory is created on demand.
func NewCache(dir string) *Cache {
	return &Cache{
		root:   dir,
		inProg: make(map[string]*flight),
	}
}

// Get returns the cache path for digest and true if the entry exists.
func (c *Cache) Get(digest string) (string, bool) {
	p := c.pathFor(digest)
	if _, err := os.Stat(p); err == nil {
		return p, true
	}
	return "", false
}

// Put copies the contents of srcDir into the cache under digest. If the
// destination already exists, Put returns the existing path without copying.
func (c *Cache) Put(digest, srcDir string) (string, error) {
	dst := c.pathFor(digest)
	if _, err := os.Stat(dst); err == nil {
		return dst, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", fmt.Errorf("mkdir cache parent: %w", err)
	}
	tmp, err := os.MkdirTemp(filepath.Dir(dst), ".tmp-*")
	if err != nil {
		return "", fmt.Errorf("mkdir tmp: %w", err)
	}
	if err := copyTree(srcDir, tmp); err != nil {
		os.RemoveAll(tmp)
		return "", err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.RemoveAll(tmp)
		return "", fmt.Errorf("rename cache: %w", err)
	}
	return dst, nil
}

// Do runs fn exactly once per digest across concurrent callers. Subsequent
// callers for the same digest block until the first invocation returns, then
// receive the same result. This prevents duplicate fetches when many findings
// need the same package.
func (c *Cache) Do(digest string, fn func() (string, error)) (string, error) {
	c.mu.Lock()
	if f, ok := c.inProg[digest]; ok {
		c.mu.Unlock()
		<-f.done
		return f.path, f.err
	}
	f := &flight{done: make(chan struct{})}
	c.inProg[digest] = f
	c.mu.Unlock()

	f.path, f.err = fn()

	c.mu.Lock()
	delete(c.inProg, digest)
	c.mu.Unlock()
	close(f.done)
	return f.path, f.err
}

// pathFor maps a digest string to its on-disk directory path.
func (c *Cache) pathFor(digest string) string {
	id := strings.TrimPrefix(digest, "sha256:")
	if id == "" {
		// Fall back to hashing the input so we never produce a collision at the root.
		h := sha256.Sum256([]byte(digest))
		id = hex.EncodeToString(h[:])
	}
	return filepath.Join(c.root, id[:2], id)
}

// copyTree recursively copies src into dst. dst must not exist.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
}
```

- [ ] **Step 4: Run tests, verify pass**

```
go test ./pkg/vex/reachability/transitive/ -run TestCache -v
```

Expected: PASS for both cache tests.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/cache.go pkg/vex/reachability/transitive/cache_test.go
git commit -m "feat(transitive): add content-addressed cache with single-flight"
```

---

## Task 4: Fetcher interface and shared types

**Files:**
- Create: `pkg/vex/reachability/transitive/fetcher.go`
- Create: `pkg/vex/reachability/transitive/fetcher_test.go`

- [ ] **Step 1: Write the failing test**

Create `pkg/vex/reachability/transitive/fetcher_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"testing"
)

func TestDigest_String(t *testing.T) {
	d := Digest{Algorithm: "sha256", Hex: "abc"}
	if d.String() != "sha256:abc" {
		t.Errorf("got %q", d.String())
	}
}

func TestDigest_Equals(t *testing.T) {
	a := Digest{Algorithm: "sha256", Hex: "ABC"}
	b := Digest{Algorithm: "SHA256", Hex: "abc"}
	if !a.Equals(b) {
		t.Errorf("digests should be equal (case-insensitive)")
	}
}

func TestFetchResult_SourceUnavailable(t *testing.T) {
	r := FetchResult{SourceUnavailable: true}
	if !r.SourceUnavailable {
		t.Error("expected SourceUnavailable true")
	}
}

func TestPackageManifest_Dependencies(t *testing.T) {
	m := PackageManifest{
		Dependencies: map[string]string{
			"requests": ">=2.0",
			"urllib3":  "1.26.5",
		},
	}
	if len(m.Dependencies) != 2 {
		t.Errorf("expected 2 deps, got %d", len(m.Dependencies))
	}
}
```

- [ ] **Step 2: Run, verify fail**

```
go test ./pkg/vex/reachability/transitive/ -run 'TestDigest|TestFetchResult|TestPackageManifest' -v
```

Expected: FAIL with undefined symbols.

- [ ] **Step 3: Implement `fetcher.go`**

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"strings"
)

// Fetcher acquires package source code and metadata from an ecosystem registry.
// Implementations are registered per ecosystem key ("pypi", "npm", ...).
type Fetcher interface {
	// Ecosystem returns the ecosystem key, e.g. "pypi" or "npm".
	Ecosystem() string

	// Fetch retrieves the source tarball for (name, version) and returns a
	// directory containing readable source. If expectedDigest is non-nil,
	// the fetched artifact's digest must match; otherwise the result is an
	// error with Digest mismatch semantics.
	Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error)

	// Manifest returns the package's declared metadata for (name, version)
	// without downloading the tarball.
	Manifest(ctx context.Context, name, version string) (PackageManifest, error)
}

// FetchResult describes the outcome of a package fetch.
type FetchResult struct {
	// SourceDir is the absolute path to the unpacked source tree, if available.
	SourceDir string

	// SourceUnavailable is true when the registry reported the package exists
	// at the requested version but no source form was available. This is the
	// case for Python packages with only binary (compiled) wheels and no sdist.
	SourceUnavailable bool

	// Digest is the digest of the fetched artifact (for audit and cache
	// indexing). May be the zero value when SourceUnavailable is true.
	Digest Digest
}

// PackageManifest captures the registry-declared metadata for one package version.
// Only fields required by the dependency graph builder are populated.
type PackageManifest struct {
	// Dependencies maps dependency name → version constraint as declared by the
	// package (pyproject.toml's requires_dist, package.json's dependencies).
	Dependencies map[string]string
}

// Digest is a content digest with a named algorithm.
type Digest struct {
	Algorithm string
	Hex       string
}

// String returns the digest in "alg:hex" form.
func (d Digest) String() string {
	return strings.ToLower(d.Algorithm) + ":" + strings.ToLower(d.Hex)
}

// Equals compares two digests case-insensitively on algorithm and hex.
func (d Digest) Equals(other Digest) bool {
	return strings.EqualFold(d.Algorithm, other.Algorithm) &&
		strings.EqualFold(d.Hex, other.Hex)
}

// IsZero reports whether the digest is unset.
func (d Digest) IsZero() bool {
	return d.Algorithm == "" && d.Hex == ""
}
```

- [ ] **Step 4: Run, verify pass**

```
go test ./pkg/vex/reachability/transitive/ -run 'TestDigest|TestFetchResult|TestPackageManifest' -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/fetcher.go pkg/vex/reachability/transitive/fetcher_test.go
git commit -m "feat(transitive): add Fetcher interface and shared types"
```

---

## Task 5: PyPI fetcher

**Files:**
- Create: `pkg/vex/reachability/transitive/fetcher_pypi.go`
- Create: `pkg/vex/reachability/transitive/fetcher_pypi_test.go`
- Create: `testdata/transitive/pypi/` (captured fixtures)

**Capturing fixtures (do this first, before step 1):** Run these commands to capture real fixtures once. The tests will then run offline against the captured files:

```
mkdir -p testdata/transitive/pypi
curl -sSL -o testdata/transitive/pypi/urllib3_1.26.5.json \
  https://pypi.org/pypi/urllib3/1.26.5/json
curl -sSL -o testdata/transitive/pypi/urllib3-1.26.5.tar.gz \
  "$(jq -r '.urls[] | select(.packagetype=="sdist") | .url' testdata/transitive/pypi/urllib3_1.26.5.json)"
curl -sSL -o testdata/transitive/pypi/requests_2.26.0.json \
  https://pypi.org/pypi/requests/2.26.0/json
curl -sSL -o testdata/transitive/pypi/requests-2.26.0.tar.gz \
  "$(jq -r '.urls[] | select(.packagetype=="sdist") | .url' testdata/transitive/pypi/requests_2.26.0.json)"
```

Commit these fixtures in Step 6.

- [ ] **Step 1: Write the failing test**

Create `pkg/vex/reachability/transitive/fetcher_pypi_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newPyPITestServer serves fixtures from testdata/transitive/pypi/.
// Routes:
//
//	/pypi/<pkg>/<version>/json      → <pkg>_<version>.json
//	/packages/<path>/<pkg>-<ver>.tar.gz → <pkg>-<ver>.tar.gz
func newPyPITestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/pypi/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 4 {
			http.NotFound(w, r)
			return
		}
		pkg := parts[1]
		ver := parts[2]
		path := filepath.Join("..", "..", "..", "..", "testdata", "transitive", "pypi", pkg+"_"+ver+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		// Rewrite URLs so the test can fetch through the httptest server.
		var obj map[string]interface{}
		_ = json.Unmarshal(data, &obj)
		if urls, ok := obj["urls"].([]interface{}); ok {
			for _, u := range urls {
				if m, ok := u.(map[string]interface{}); ok {
					if rel, _ := m["filename"].(string); rel != "" {
						m["url"] = "http://" + r.Host + "/files/" + rel
					}
				}
			}
		}
		out, _ := json.Marshal(obj)
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	})
	mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/files/")
		path := filepath.Join("..", "..", "..", "..", "testdata", "transitive", "pypi", name)
		data, err := os.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(data)
	})
	return httptest.NewServer(mux)
}

func TestPyPIFetcher_Manifest(t *testing.T) {
	srv := newPyPITestServer(t)
	defer srv.Close()

	f := &PyPIFetcher{BaseURL: srv.URL + "/pypi", HTTPClient: srv.Client()}
	m, err := f.Manifest(context.Background(), "urllib3", "1.26.5")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if len(m.Dependencies) == 0 {
		t.Errorf("expected some dependencies for urllib3 1.26.5")
	}
}

func TestPyPIFetcher_Fetch(t *testing.T) {
	srv := newPyPITestServer(t)
	defer srv.Close()

	cache := NewCache(t.TempDir())
	f := &PyPIFetcher{BaseURL: srv.URL + "/pypi", HTTPClient: srv.Client(), Cache: cache}

	res, err := f.Fetch(context.Background(), "urllib3", "1.26.5", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.SourceUnavailable {
		t.Fatalf("unexpected SourceUnavailable")
	}
	if res.SourceDir == "" {
		t.Fatalf("empty SourceDir")
	}
	// Verify at least one .py file was unpacked.
	found := false
	filepath.WalkDir(res.SourceDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".py") {
			found = true
		}
		return nil
	})
	if !found {
		t.Errorf("no .py files found in fetched source %s", res.SourceDir)
	}
}

func TestPyPIFetcher_Ecosystem(t *testing.T) {
	f := &PyPIFetcher{}
	if f.Ecosystem() != "pypi" {
		t.Errorf("expected 'pypi'")
	}
}
```

- [ ] **Step 2: Run, verify fail**

```
go test ./pkg/vex/reachability/transitive/ -run TestPyPIFetcher -v
```

Expected: FAIL with undefined symbols (PyPIFetcher type does not exist).

- [ ] **Step 3: Implement `fetcher_pypi.go`**

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// PyPIFetcher implements Fetcher for the PyPI ecosystem.
type PyPIFetcher struct {
	// BaseURL is the PyPI JSON API base. Defaults to https://pypi.org/pypi.
	BaseURL    string
	HTTPClient *http.Client
	Cache      *Cache
}

func (f *PyPIFetcher) Ecosystem() string { return "pypi" }

func (f *PyPIFetcher) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return http.DefaultClient
}

func (f *PyPIFetcher) baseURL() string {
	if f.BaseURL != "" {
		return f.BaseURL
	}
	return "https://pypi.org/pypi"
}

// pypiMeta is the subset of the PyPI JSON schema we consume.
type pypiMeta struct {
	Info struct {
		RequiresDist []string `json:"requires_dist"`
	} `json:"info"`
	URLs []struct {
		PackageType string `json:"packagetype"`
		URL         string `json:"url"`
		Filename    string `json:"filename"`
		Digests     struct {
			SHA256 string `json:"sha256"`
		} `json:"digests"`
	} `json:"urls"`
}

// Manifest fetches and parses PyPI metadata.
func (f *PyPIFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	meta, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return PackageManifest{}, err
	}
	deps := make(map[string]string)
	for _, r := range meta.Info.RequiresDist {
		// requires_dist entries look like "urllib3 (>=1.21.1,<1.27)" possibly
		// followed by `; python_version < '3.10'` or similar markers.
		// For dep graph purposes we ignore the marker and constraint.
		name, constraint := splitRequiresDist(r)
		if name == "" {
			continue
		}
		deps[name] = constraint
	}
	return PackageManifest{Dependencies: deps}, nil
}

// Fetch downloads the sdist (or falls back to a pure-Python wheel), verifies
// its digest if expectedDigest is non-nil, and unpacks it into the cache.
func (f *PyPIFetcher) Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error) {
	meta, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}
	url, digest, kind := pickArtifact(meta)
	if url == "" {
		return FetchResult{SourceUnavailable: true}, nil
	}

	cacheKey := digest.String()
	if f.Cache != nil {
		if p, ok := f.Cache.Get(cacheKey); ok {
			return FetchResult{SourceDir: p, Digest: digest}, nil
		}
	}

	body, err := f.download(ctx, url)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonTarballFetchFailed, err)
	}
	actual := Digest{Algorithm: "sha256", Hex: hashHex(body)}
	if !actual.Equals(digest) {
		return FetchResult{}, fmt.Errorf("%s: expected %s, got %s", ReasonDigestMismatch, digest, actual)
	}
	if expectedDigest != nil && !expectedDigest.IsZero() && !expectedDigest.Equals(actual) {
		return FetchResult{}, fmt.Errorf("%s: SBOM expected %s, registry returned %s", ReasonDigestMismatch, expectedDigest, actual)
	}

	tmp, err := os.MkdirTemp("", "pypi-*")
	if err != nil {
		return FetchResult{}, err
	}
	if err := unpack(body, kind, tmp); err != nil {
		os.RemoveAll(tmp)
		return FetchResult{}, fmt.Errorf("unpack %s: %w", name, err)
	}

	srcDir := tmp
	if f.Cache != nil {
		p, err := f.Cache.Put(cacheKey, tmp)
		os.RemoveAll(tmp)
		if err != nil {
			return FetchResult{}, err
		}
		srcDir = p
	}
	return FetchResult{SourceDir: srcDir, Digest: actual}, nil
}

func (f *PyPIFetcher) fetchMeta(ctx context.Context, name, version string) (*pypiMeta, error) {
	url := fmt.Sprintf("%s/%s/%s/json", f.baseURL(), name, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pypi metadata %s: status %d", url, resp.StatusCode)
	}
	var m pypiMeta
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode pypi metadata: %w", err)
	}
	return &m, nil
}

func (f *PyPIFetcher) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pypi download %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// pickArtifact chooses the best source artifact from the available URLs.
// Preference: sdist > bdist_wheel (only for py3-none-any / pure-Python).
// Returns empty URL if neither is available (source unavailable).
func pickArtifact(m *pypiMeta) (url string, digest Digest, kind string) {
	// Prefer sdist.
	for _, u := range m.URLs {
		if u.PackageType == "sdist" && u.URL != "" {
			return u.URL, Digest{Algorithm: "sha256", Hex: u.Digests.SHA256}, "sdist"
		}
	}
	// Fall back to pure-Python wheels (py3-none-any).
	for _, u := range m.URLs {
		if u.PackageType == "bdist_wheel" && strings.HasSuffix(u.Filename, "-py3-none-any.whl") {
			return u.URL, Digest{Algorithm: "sha256", Hex: u.Digests.SHA256}, "wheel"
		}
	}
	return "", Digest{}, ""
}

// splitRequiresDist parses a requires_dist entry into (name, constraint).
// Input: "urllib3 (>=1.21.1,<1.27) ; python_version < '3.10'"
// Output: ("urllib3", ">=1.21.1,<1.27")
func splitRequiresDist(s string) (name, constraint string) {
	// Drop environment marker.
	if idx := strings.Index(s, ";"); idx >= 0 {
		s = s[:idx]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	// Split name from constraint.
	for i, r := range s {
		if r == ' ' || r == '(' || r == '>' || r == '<' || r == '=' || r == '!' || r == '~' {
			name = strings.TrimSpace(s[:i])
			rest := strings.TrimSpace(s[i:])
			rest = strings.TrimPrefix(rest, "(")
			rest = strings.TrimSuffix(rest, ")")
			return name, strings.TrimSpace(rest)
		}
	}
	return s, ""
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// unpack extracts a tar.gz or zip (wheel) into dst. kind is "sdist" or "wheel".
func unpack(data []byte, kind, dst string) error {
	if kind == "sdist" {
		return untarGz(data, dst)
	}
	// Wheels are zip files; delegate to a small zip extractor.
	return unzip(data, dst)
}

func untarGz(data []byte, dst string) error {
	gz, err := gzip.NewReader(bytesReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dst, sanitizeTarPath(hdr.Name))
		if !strings.HasPrefix(target, dst) {
			continue // path traversal guard
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		}
	}
}

func sanitizeTarPath(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(name, "/")
	parts := strings.Split(name, "/")
	out := parts[:0]
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, "/")
}

// bytesReader is a tiny helper to satisfy io.Reader from []byte without importing bytes twice.
func bytesReader(b []byte) *strings.Reader {
	return strings.NewReader(string(b))
}
```

You will also need a small zip extractor. Add it as `fetcher_zip.go` below, since npm does not use zip but pypi wheel fallback does:

Create `pkg/vex/reachability/transitive/fetcher_zip.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// unzip extracts an in-memory zip into dst.
func unzip(data []byte, dst string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		target := filepath.Join(dst, sanitizeTarPath(f.Name))
		if !strings.HasPrefix(target, dst) {
			continue
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0o755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(target)
		if err != nil {
			rc.Close()
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			rc.Close()
			out.Close()
			return err
		}
		rc.Close()
		out.Close()
	}
	return nil
}
```

Replace the `bytesReader` helper in `fetcher_pypi.go` with the standard `bytes.NewReader`:

Update the imports in `fetcher_pypi.go` to include `"bytes"` and delete the `bytesReader` function. Replace its single call site in `untarGz` with `bytes.NewReader(data)`.

- [ ] **Step 4: Run, verify pass**

```
go test ./pkg/vex/reachability/transitive/ -run TestPyPIFetcher -v
```

Expected: PASS. If the captured fixtures were not created, tests will fail at the file-open step — capture them first as shown in the pre-task instructions.

- [ ] **Step 5: Run full package tests**

```
go test ./pkg/vex/reachability/transitive/ -v
```

Expected: all transitive tests PASS.

- [ ] **Step 6: Commit**

```
git add pkg/vex/reachability/transitive/fetcher_pypi.go \
        pkg/vex/reachability/transitive/fetcher_pypi_test.go \
        pkg/vex/reachability/transitive/fetcher_zip.go \
        testdata/transitive/pypi/
git commit -m "feat(transitive): add PyPI fetcher with sdist/wheel fallback"
```

---

## Task 6: npm fetcher

**Files:**
- Create: `pkg/vex/reachability/transitive/fetcher_npm.go`
- Create: `pkg/vex/reachability/transitive/fetcher_npm_test.go`
- Create: `testdata/transitive/npm/` (captured fixtures)

**Capture fixtures:**

```
mkdir -p testdata/transitive/npm
curl -sSL -o testdata/transitive/npm/lodash_4.17.20.json \
  https://registry.npmjs.org/lodash/4.17.20
curl -sSL -o testdata/transitive/npm/lodash-4.17.20.tgz \
  "$(jq -r '.dist.tarball' testdata/transitive/npm/lodash_4.17.20.json)"
curl -sSL -o testdata/transitive/npm/express_4.17.1.json \
  https://registry.npmjs.org/express/4.17.1
curl -sSL -o testdata/transitive/npm/express-4.17.1.tgz \
  "$(jq -r '.dist.tarball' testdata/transitive/npm/express_4.17.1.json)"
```

- [ ] **Step 1: Write failing test**

Create `pkg/vex/reachability/transitive/fetcher_npm_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newNPMTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 2 {
			http.NotFound(w, r)
			return
		}
		pkg := parts[0]
		ver := parts[1]
		path := filepath.Join("..", "..", "..", "..", "testdata", "transitive", "npm", pkg+"_"+ver+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		var obj map[string]interface{}
		_ = json.Unmarshal(data, &obj)
		if dist, ok := obj["dist"].(map[string]interface{}); ok {
			dist["tarball"] = "http://" + r.Host + "/files/" + pkg + "-" + ver + ".tgz"
		}
		out, _ := json.Marshal(obj)
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	})
	mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/files/")
		path := filepath.Join("..", "..", "..", "..", "testdata", "transitive", "npm", name)
		data, err := os.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(data)
	})
	return httptest.NewServer(mux)
}

func TestNPMFetcher_Manifest(t *testing.T) {
	srv := newNPMTestServer(t)
	defer srv.Close()
	f := &NPMFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	m, err := f.Manifest(context.Background(), "express", "4.17.1")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if _, ok := m.Dependencies["body-parser"]; !ok {
		t.Errorf("expected body-parser dependency, got %v", m.Dependencies)
	}
}

func TestNPMFetcher_Fetch(t *testing.T) {
	srv := newNPMTestServer(t)
	defer srv.Close()
	cache := NewCache(t.TempDir())
	f := &NPMFetcher{BaseURL: srv.URL, HTTPClient: srv.Client(), Cache: cache}
	res, err := f.Fetch(context.Background(), "lodash", "4.17.20", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.SourceDir == "" {
		t.Fatal("empty SourceDir")
	}
	// Verify at least one .js file was extracted.
	found := false
	filepath.WalkDir(res.SourceDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".js") {
			found = true
		}
		return nil
	})
	if !found {
		t.Errorf("no .js files in %s", res.SourceDir)
	}
}

func TestNPMFetcher_Ecosystem(t *testing.T) {
	f := &NPMFetcher{}
	if f.Ecosystem() != "npm" {
		t.Errorf("expected 'npm'")
	}
}
```

- [ ] **Step 2: Run, verify fail**

```
go test ./pkg/vex/reachability/transitive/ -run TestNPMFetcher -v
```

Expected: FAIL — undefined NPMFetcher.

- [ ] **Step 3: Implement `fetcher_npm.go`**

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// NPMFetcher implements Fetcher for the npm ecosystem.
type NPMFetcher struct {
	BaseURL    string // default https://registry.npmjs.org
	HTTPClient *http.Client
	Cache      *Cache
}

func (f *NPMFetcher) Ecosystem() string { return "npm" }

func (f *NPMFetcher) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return http.DefaultClient
}

func (f *NPMFetcher) baseURL() string {
	if f.BaseURL != "" {
		return f.BaseURL
	}
	return "https://registry.npmjs.org"
}

// npmMeta is the subset of the npm registry schema we consume.
type npmMeta struct {
	Dependencies map[string]string `json:"dependencies"`
	Dist         struct {
		Tarball string `json:"tarball"`
		SHASum  string `json:"shasum"`    // sha1
		Integrity string `json:"integrity"` // "sha512-..." base64
	} `json:"dist"`
}

func (f *NPMFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	m, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return PackageManifest{}, err
	}
	deps := make(map[string]string, len(m.Dependencies))
	for k, v := range m.Dependencies {
		deps[k] = v
	}
	return PackageManifest{Dependencies: deps}, nil
}

func (f *NPMFetcher) Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error) {
	m, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}
	if m.Dist.Tarball == "" {
		return FetchResult{SourceUnavailable: true}, nil
	}

	body, err := f.download(ctx, m.Dist.Tarball)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonTarballFetchFailed, err)
	}
	actual := Digest{Algorithm: "sha256", Hex: hashHex(body)}

	if expectedDigest != nil && !expectedDigest.IsZero() && !expectedDigest.Equals(actual) {
		return FetchResult{}, fmt.Errorf("%s: SBOM expected %s, registry returned %s", ReasonDigestMismatch, expectedDigest, actual)
	}

	cacheKey := actual.String()
	if f.Cache != nil {
		if p, ok := f.Cache.Get(cacheKey); ok {
			return FetchResult{SourceDir: p, Digest: actual}, nil
		}
	}

	tmp, err := os.MkdirTemp("", "npm-*")
	if err != nil {
		return FetchResult{}, err
	}
	if err := untarGz(body, tmp); err != nil {
		os.RemoveAll(tmp)
		return FetchResult{}, fmt.Errorf("unpack npm %s: %w", name, err)
	}

	// npm tarballs unpack under a leading "package/" directory. Point at that.
	pkgDir := tmp
	if st, err := os.Stat(tmp + "/package"); err == nil && st.IsDir() {
		pkgDir = tmp + "/package"
	}

	srcDir := pkgDir
	if f.Cache != nil {
		p, err := f.Cache.Put(cacheKey, pkgDir)
		os.RemoveAll(tmp)
		if err != nil {
			return FetchResult{}, err
		}
		srcDir = p
	}
	return FetchResult{SourceDir: srcDir, Digest: actual}, nil
}

func (f *NPMFetcher) fetchMeta(ctx context.Context, name, version string) (*npmMeta, error) {
	url := fmt.Sprintf("%s/%s/%s", f.baseURL(), name, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm metadata %s: status %d", url, resp.StatusCode)
	}
	var m npmMeta
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode npm metadata: %w", err)
	}
	return &m, nil
}

func (f *NPMFetcher) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm download %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
```

- [ ] **Step 4: Run, verify pass**

```
go test ./pkg/vex/reachability/transitive/ -run TestNPMFetcher -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/fetcher_npm.go \
        pkg/vex/reachability/transitive/fetcher_npm_test.go \
        testdata/transitive/npm/
git commit -m "feat(transitive): add npm registry fetcher"
```

---

## Task 7: SBOM dependency graph builder and pruner

**Files:**
- Create: `pkg/vex/reachability/transitive/sbom_graph.go`
- Create: `pkg/vex/reachability/transitive/sbom_graph_test.go`

- [ ] **Step 1: Write the failing test**

Create `pkg/vex/reachability/transitive/sbom_graph_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"testing"
)

// fakeFetcher satisfies Fetcher for manifest-only tests by returning canned
// dependency maps.
type fakeFetcher struct {
	eco       string
	manifests map[string]map[string]string // "name@version" → deps
}

func (f *fakeFetcher) Ecosystem() string { return f.eco }
func (f *fakeFetcher) Fetch(ctx context.Context, name, version string, _ *Digest) (FetchResult, error) {
	return FetchResult{}, nil
}
func (f *fakeFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	key := name + "@" + version
	deps, ok := f.manifests[key]
	if !ok {
		return PackageManifest{}, nil
	}
	return PackageManifest{Dependencies: deps}, nil
}

func TestBuildDepGraph_PrunesToVulnerable(t *testing.T) {
	// Shape: app → flask@2 → werkzeug@2 → urllib3@1
	//          └─► requests@2 ──┘         ↑
	//                            └────────┘
	// Extra unrelated package that should NOT appear in the pruned subgraph.
	pinned := []Package{
		{Name: "flask", Version: "2.0.1"},
		{Name: "werkzeug", Version: "2.0.2"},
		{Name: "requests", Version: "2.26.0"},
		{Name: "urllib3", Version: "1.26.5"},
		{Name: "unrelated", Version: "1.0.0"},
	}
	roots := []string{"flask", "requests"}
	fetcher := &fakeFetcher{
		eco: "pypi",
		manifests: map[string]map[string]string{
			"flask@2.0.1":     {"werkzeug": ""},
			"werkzeug@2.0.2":  {"urllib3": ""},
			"requests@2.26.0": {"urllib3": ""},
			"urllib3@1.26.5":  {},
			"unrelated@1.0.0": {},
		},
	}
	g, err := BuildDepGraph(context.Background(), fetcher, pinned, roots)
	if err != nil {
		t.Fatalf("BuildDepGraph: %v", err)
	}

	paths := g.PathsTo("urllib3")
	if len(paths) != 2 {
		t.Errorf("expected 2 paths to urllib3, got %d: %v", len(paths), paths)
	}
	for _, p := range paths {
		if p[len(p)-1].Name != "urllib3" {
			t.Errorf("path does not end at urllib3: %v", p)
		}
	}

	if _, ok := g.Node("unrelated"); ok {
		// It's fine for unrelated to be in the full graph; we only prune at PathsTo.
	}
}

func TestBuildDepGraph_NoPath(t *testing.T) {
	pinned := []Package{
		{Name: "a", Version: "1"},
		{Name: "b", Version: "1"},
	}
	fetcher := &fakeFetcher{
		eco: "pypi",
		manifests: map[string]map[string]string{
			"a@1": {},
			"b@1": {},
		},
	}
	g, err := BuildDepGraph(context.Background(), fetcher, pinned, []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	if paths := g.PathsTo("b"); len(paths) != 0 {
		t.Errorf("expected 0 paths to b, got %d", len(paths))
	}
}
```

- [ ] **Step 2: Run, verify fail**

```
go test ./pkg/vex/reachability/transitive/ -run TestBuildDepGraph -v
```

Expected: FAIL — undefined symbols.

- [ ] **Step 3: Implement `sbom_graph.go`**

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"fmt"
)

// Package identifies a package by name and version.
type Package struct {
	Name    string
	Version string
}

// DepGraph is a forward dependency graph: node → its declared dependencies.
// Only packages present in the caller-supplied pinned set are included as nodes.
type DepGraph struct {
	nodes map[string]Package          // name → pinned version
	edges map[string][]string         // name → []dep name
	roots []string                    // application-root package names
}

// BuildDepGraph constructs a DepGraph by calling fetcher.Manifest for each
// pinned package and intersecting the declared dependencies with the pinned
// set. SBOM dependsOn edges are deliberately ignored — we derive structure
// from authoritative per-package manifests.
func BuildDepGraph(ctx context.Context, fetcher Fetcher, pinned []Package, roots []string) (*DepGraph, error) {
	g := &DepGraph{
		nodes: make(map[string]Package, len(pinned)),
		edges: make(map[string][]string, len(pinned)),
		roots: roots,
	}
	for _, p := range pinned {
		g.nodes[p.Name] = p
	}
	for _, p := range pinned {
		m, err := fetcher.Manifest(ctx, p.Name, p.Version)
		if err != nil {
			// Manifest fetch failures degrade the package to a leaf so the
			// walker can still traverse around it.
			continue
		}
		var deps []string
		for depName := range m.Dependencies {
			if _, ok := g.nodes[depName]; ok {
				deps = append(deps, depName)
			}
		}
		g.edges[p.Name] = deps
	}
	return g, nil
}

// Node returns the pinned Package for name if present.
func (g *DepGraph) Node(name string) (Package, bool) {
	p, ok := g.nodes[name]
	return p, ok
}

// Edges returns the direct dependencies of name in the pinned set.
func (g *DepGraph) Edges(name string) []string {
	return g.edges[name]
}

// Roots returns the application-root package names (direct dependencies of the
// top-level application component).
func (g *DepGraph) Roots() []string {
	return g.roots
}

// PathsTo returns all simple paths from any root to target. Each path starts
// with a root and ends with target. If no path exists, returns nil.
func (g *DepGraph) PathsTo(target string) [][]Package {
	if _, ok := g.nodes[target]; !ok {
		return nil
	}
	var results [][]Package
	for _, root := range g.roots {
		var path []string
		visited := make(map[string]bool)
		g.dfs(root, target, path, visited, &results)
	}
	return results
}

func (g *DepGraph) dfs(cur, target string, path []string, visited map[string]bool, results *[][]Package) {
	if visited[cur] {
		return
	}
	visited[cur] = true
	defer func() { visited[cur] = false }()

	path = append(path, cur)
	if cur == target {
		pkgs := make([]Package, len(path))
		for i, n := range path {
			pkgs[i] = g.nodes[n]
		}
		*results = append(*results, pkgs)
		return
	}
	for _, dep := range g.edges[cur] {
		g.dfs(dep, target, path, visited, results)
	}
}

// MustNode is a convenience for callers that know the node exists.
func (g *DepGraph) MustNode(name string) Package {
	if p, ok := g.nodes[name]; ok {
		return p
	}
	panic(fmt.Sprintf("dep graph: node %q missing", name))
}
```

- [ ] **Step 4: Run, verify pass**

```
go test ./pkg/vex/reachability/transitive/ -run TestBuildDepGraph -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/sbom_graph.go pkg/vex/reachability/transitive/sbom_graph_test.go
git commit -m "feat(transitive): add dependency graph builder and pruning"
```

---

## Task 8: Per-hop primitive

**Files:**
- Create: `pkg/vex/reachability/transitive/hop.go`
- Create: `pkg/vex/reachability/transitive/hop_test.go`
- Create: `testdata/transitive/hop/python-caller/` (small fixture package)

**Create the fixture first:**

```
mkdir -p testdata/transitive/hop/python-caller
cat > testdata/transitive/hop/python-caller/caller.py <<'PY'
import urllib3

def outer_func():
    return urllib3.PoolManager()

def unrelated_func():
    return "hello"
PY
```

- [ ] **Step 1: Write the failing test**

Create `pkg/vex/reachability/transitive/hop_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"path/filepath"
	"testing"
)

func TestRunHop_Python_FindsCaller(t *testing.T) {
	src, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "testdata", "transitive", "hop", "python-caller"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := RunHop(context.Background(), HopInput{
		Language:       "python",
		SourceDir:      src,
		TargetSymbols:  []string{"urllib3.PoolManager"},
		MaxTargets:     100,
	})
	if err != nil {
		t.Fatalf("RunHop: %v", err)
	}
	if len(res.ReachingSymbols) == 0 {
		t.Fatalf("expected at least one reaching symbol")
	}
	found := false
	for _, s := range res.ReachingSymbols {
		if s == "caller.outer_func" || s == "outer_func" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected outer_func in reaching symbols, got %v", res.ReachingSymbols)
	}
}

func TestRunHop_Python_NoCaller(t *testing.T) {
	src, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "testdata", "transitive", "hop", "python-caller"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := RunHop(context.Background(), HopInput{
		Language:      "python",
		SourceDir:     src,
		TargetSymbols: []string{"somepkg.does_not_exist"},
		MaxTargets:    100,
	})
	if err != nil {
		t.Fatalf("RunHop: %v", err)
	}
	if len(res.ReachingSymbols) != 0 {
		t.Errorf("expected no reaching symbols, got %v", res.ReachingSymbols)
	}
}
```

- [ ] **Step 2: Run, verify fail**

```
go test ./pkg/vex/reachability/transitive/ -run TestRunHop -v
```

Expected: FAIL — undefined symbols.

- [ ] **Step 3: Implement `hop.go`**

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarjs "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/javascript"
	grammarpython "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/python"
	grammarts "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/typescript"
	jsextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/javascript"
	pyextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/python"
)

// HopInput controls a single hop reachability check.
type HopInput struct {
	Language      string   // "python" or "javascript"
	SourceDir     string   // unpacked package source
	TargetSymbols []string // fully-qualified symbol IDs to reach
	MaxTargets    int      // bound on reaching symbol set size
}

// HopResult is the outcome of one hop.
type HopResult struct {
	ReachingSymbols []string             // subset of this package's symbols that reach any target
	Paths           []reachability.CallPath
	Degradations    []string
}

// RunHop parses the source directory with the appropriate tree-sitter
// extractor, builds an intra-package call graph with the target symbols
// injected as external nodes, and returns the set of symbols in this package
// that transitively reach any target via forward BFS.
//
// Implementation note: the existing tree-sitter extractors already create
// edges from caller symbols to external (imported) symbols by string match,
// so adding targets as virtual nodes is sufficient to connect cross-package
// edges without changes to the extractors.
func RunHop(ctx context.Context, in HopInput) (HopResult, error) {
	switch in.Language {
	case "python":
		return runHopPython(ctx, in)
	case "javascript":
		return runHopJavaScript(ctx, in)
	default:
		return HopResult{}, fmt.Errorf("unsupported language %q", in.Language)
	}
}

func collectFilesByExt(root string, exts []string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		for _, e := range exts {
			if strings.HasSuffix(path, e) {
				files = append(files, path)
				return nil
			}
		}
		return nil
	})
	return files, err
}

func runHopPython(_ context.Context, in HopInput) (HopResult, error) {
	files, err := collectFilesByExt(in.SourceDir, []string{".py"})
	if err != nil {
		return HopResult{Degradations: []string{ReasonExtractorError}}, nil
	}
	if len(files) == 0 {
		return HopResult{}, nil
	}
	parsed, _ := treesitter.ParseFiles(files, grammarpython.Language())
	defer func() {
		for _, pr := range parsed {
			pr.Tree.Close()
		}
	}()

	ext := pyextractor.New()
	graph := treesitter.NewGraph()

	// Phase 1: extract symbols and imports.
	type fi struct {
		pr      treesitter.ParseResult
		syms    []*treesitter.Symbol
		imports []treesitter.Import
	}
	infos := make([]fi, 0, len(parsed))
	for _, pr := range parsed {
		syms, err := ext.ExtractSymbols(pr.File, pr.Source, pr.Tree)
		if err != nil {
			continue
		}
		imports, err := ext.ResolveImports(pr.File, pr.Source, pr.Tree, in.SourceDir)
		if err != nil {
			continue
		}
		for _, s := range syms {
			graph.AddSymbol(s)
		}
		infos = append(infos, fi{pr: pr, syms: syms, imports: imports})
	}

	// Phase 2: inject target symbols as virtual external nodes.
	for _, t := range in.TargetSymbols {
		if graph.GetSymbol(treesitter.SymbolID(t)) == nil {
			graph.AddSymbol(&treesitter.Symbol{
				ID:         treesitter.SymbolID(t),
				Name:       t,
				IsExternal: true,
				Language:   "python",
			})
		}
	}

	// Phase 3: extract calls.
	for _, info := range infos {
		scope := treesitter.NewScope(nil)
		for _, imp := range info.imports {
			alias := imp.Alias
			if alias == "" {
				alias = imp.Module
			}
			scope.DefineImport(alias, imp.Module, imp.Symbols)
		}
		edges, err := ext.ExtractCalls(info.pr.File, info.pr.Source, info.pr.Tree, scope)
		if err != nil {
			continue
		}
		for _, e := range edges {
			graph.AddEdge(e)
		}
	}

	return forwardFromAllSymbols(graph, in)
}

func runHopJavaScript(_ context.Context, in HopInput) (HopResult, error) {
	jsFiles, err := collectFilesByExt(in.SourceDir, []string{".js", ".mjs", ".cjs", ".jsx"})
	if err != nil {
		return HopResult{Degradations: []string{ReasonExtractorError}}, nil
	}
	tsFiles, _ := collectFilesByExt(in.SourceDir, []string{".ts", ".tsx"})
	if len(jsFiles)+len(tsFiles) == 0 {
		return HopResult{}, nil
	}

	var parsed []treesitter.ParseResult
	if len(jsFiles) > 0 {
		p, _ := treesitter.ParseFiles(jsFiles, grammarjs.Language())
		parsed = append(parsed, p...)
	}
	if len(tsFiles) > 0 {
		p, _ := treesitter.ParseFiles(tsFiles, grammarts.Language())
		parsed = append(parsed, p...)
	}
	defer func() {
		for _, pr := range parsed {
			pr.Tree.Close()
		}
	}()

	ext := jsextractor.New()
	graph := treesitter.NewGraph()

	type fi struct {
		pr      treesitter.ParseResult
		syms    []*treesitter.Symbol
		imports []treesitter.Import
	}
	infos := make([]fi, 0, len(parsed))
	for _, pr := range parsed {
		syms, err := ext.ExtractSymbols(pr.File, pr.Source, pr.Tree)
		if err != nil {
			continue
		}
		imports, err := ext.ResolveImports(pr.File, pr.Source, pr.Tree, in.SourceDir)
		if err != nil {
			continue
		}
		for _, s := range syms {
			graph.AddSymbol(s)
		}
		infos = append(infos, fi{pr: pr, syms: syms, imports: imports})
	}

	for _, t := range in.TargetSymbols {
		if graph.GetSymbol(treesitter.SymbolID(t)) == nil {
			graph.AddSymbol(&treesitter.Symbol{
				ID:         treesitter.SymbolID(t),
				Name:       t,
				IsExternal: true,
				Language:   "javascript",
			})
		}
	}

	for _, info := range infos {
		scope := treesitter.NewScope(nil)
		for _, imp := range info.imports {
			alias := imp.Alias
			if alias == "" {
				alias = imp.Module
			}
			scope.DefineImport(alias, imp.Module, imp.Symbols)
		}
		edges, err := ext.ExtractCalls(info.pr.File, info.pr.Source, info.pr.Tree, scope)
		if err != nil {
			continue
		}
		for _, e := range edges {
			graph.AddEdge(e)
		}
	}

	return forwardFromAllSymbols(graph, in)
}

// forwardFromAllSymbols runs BFS from every function/method symbol to each
// target. Any symbol from which a target is reachable is returned as a
// "reaching symbol."
func forwardFromAllSymbols(graph *treesitter.Graph, in HopInput) (HopResult, error) {
	all := graph.AllSymbols()
	var starts []treesitter.SymbolID
	for _, sym := range all {
		if sym.IsExternal {
			continue
		}
		if sym.Kind == treesitter.SymbolFunction || sym.Kind == treesitter.SymbolMethod || sym.Kind == treesitter.SymbolModule {
			starts = append(starts, sym.ID)
		}
	}
	cfg := treesitter.ReachabilityConfig{MaxDepth: 20, MaxPaths: 5}
	reached := make(map[string]bool)
	var allPaths []reachability.CallPath
	for _, t := range in.TargetSymbols {
		paths := treesitter.FindReachablePaths(graph, starts, treesitter.SymbolID(t), cfg)
		for _, p := range paths {
			if len(p.Nodes) == 0 {
				continue
			}
			reached[p.Nodes[0].Symbol] = true
			allPaths = append(allPaths, p)
		}
	}
	symbols := make([]string, 0, len(reached))
	for s := range reached {
		symbols = append(symbols, s)
		if in.MaxTargets > 0 && len(symbols) >= in.MaxTargets {
			break
		}
	}
	return HopResult{
		ReachingSymbols: symbols,
		Paths:           allPaths,
	}, nil
}
```

- [ ] **Step 4: Run, verify pass**

```
go test ./pkg/vex/reachability/transitive/ -run TestRunHop -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/hop.go \
        pkg/vex/reachability/transitive/hop_test.go \
        testdata/transitive/hop/
git commit -m "feat(transitive): add per-hop reachability primitive"
```

---

## Task 9: Evidence stitching

**Files:**
- Create: `pkg/vex/reachability/transitive/evidence.go`
- Create: `pkg/vex/reachability/transitive/evidence_test.go`

- [ ] **Step 1: Write failing test**

Create `pkg/vex/reachability/transitive/evidence_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

func TestStitchCallPaths_ConcatenatesNodes(t *testing.T) {
	app := formats.CallPath{Nodes: []formats.CallNode{
		{Symbol: "app.handler", File: "app.py", Line: 10},
		{Symbol: "flask.route", File: "flask.py", Line: 100},
	}}
	mid := formats.CallPath{Nodes: []formats.CallNode{
		{Symbol: "flask.route", File: "flask.py", Line: 100},
		{Symbol: "werkzeug.Adapter.send", File: "werkzeug.py", Line: 200},
	}}
	last := formats.CallPath{Nodes: []formats.CallNode{
		{Symbol: "werkzeug.Adapter.send", File: "werkzeug.py", Line: 200},
		{Symbol: "urllib3.PoolManager", File: "urllib3.py", Line: 300},
	}}

	got := StitchCallPaths([]formats.CallPath{app, mid, last})
	if len(got.Nodes) != 4 {
		t.Errorf("expected 4 nodes, got %d", len(got.Nodes))
	}
	if got.Nodes[0].Symbol != "app.handler" {
		t.Errorf("first node: %q", got.Nodes[0].Symbol)
	}
	if got.Nodes[len(got.Nodes)-1].Symbol != "urllib3.PoolManager" {
		t.Errorf("last node: %q", got.Nodes[len(got.Nodes)-1].Symbol)
	}
}

func TestStitchCallPaths_EmptyReturnsEmpty(t *testing.T) {
	got := StitchCallPaths(nil)
	if len(got.Nodes) != 0 {
		t.Errorf("expected empty path")
	}
}

func TestStitchCallPaths_NoOverlapStillConcatenates(t *testing.T) {
	a := formats.CallPath{Nodes: []formats.CallNode{{Symbol: "x"}, {Symbol: "y"}}}
	b := formats.CallPath{Nodes: []formats.CallNode{{Symbol: "a"}, {Symbol: "b"}}}
	got := StitchCallPaths([]formats.CallPath{a, b})
	if len(got.Nodes) != 4 {
		t.Errorf("expected 4 nodes, got %d", len(got.Nodes))
	}
}
```

- [ ] **Step 2: Run, verify fail**

```
go test ./pkg/vex/reachability/transitive/ -run TestStitchCallPaths -v
```

Expected: FAIL — undefined symbol.

- [ ] **Step 3: Implement `evidence.go`**

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"github.com/ravan/cra-toolkit/pkg/formats"
)

// StitchCallPaths concatenates a sequence of per-hop call paths into a single
// continuous path. Adjacent hops are expected to share a boundary node
// (the last node of hop N equals the first node of hop N+1); if they do, the
// duplicate is elided. Non-overlapping hops are concatenated as-is.
func StitchCallPaths(parts []formats.CallPath) formats.CallPath {
	var out formats.CallPath
	for i, p := range parts {
		if len(p.Nodes) == 0 {
			continue
		}
		if i == 0 {
			out.Nodes = append(out.Nodes, p.Nodes...)
			continue
		}
		start := 0
		if len(out.Nodes) > 0 && out.Nodes[len(out.Nodes)-1].Symbol == p.Nodes[0].Symbol {
			start = 1
		}
		out.Nodes = append(out.Nodes, p.Nodes[start:]...)
	}
	return out
}
```

- [ ] **Step 4: Run, verify pass**

```
go test ./pkg/vex/reachability/transitive/ -run TestStitchCallPaths -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/evidence.go pkg/vex/reachability/transitive/evidence_test.go
git commit -m "feat(transitive): add per-hop call path stitching"
```

---

## Task 10: Walker — pairwise reverse walk with short-circuit

**Files:**
- Create: `pkg/vex/reachability/transitive/walker.go`
- Create: `pkg/vex/reachability/transitive/walker_test.go`

- [ ] **Step 1: Write failing test**

Create `pkg/vex/reachability/transitive/walker_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"testing"
)

// stubHopRunner records calls and returns canned results so the walker's
// orchestration and short-circuit logic can be exercised without real parsing.
type stubHopRunner struct {
	calls   []HopInput
	results map[string]HopResult // keyed by SourceDir (proxy for package)
}

func (s *stubHopRunner) Run(ctx context.Context, in HopInput) (HopResult, error) {
	s.calls = append(s.calls, in)
	if r, ok := s.results[in.SourceDir]; ok {
		return r, nil
	}
	return HopResult{}, nil
}

// stubFetcher returns a deterministic source dir per (name, version) without
// making any network calls.
type stubFetcher struct{}

func (stubFetcher) Ecosystem() string { return "stub" }
func (stubFetcher) Fetch(ctx context.Context, name, version string, _ *Digest) (FetchResult, error) {
	return FetchResult{SourceDir: "/pkg/" + name + "@" + version}, nil
}
func (stubFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	return PackageManifest{}, nil
}

func TestWalker_Reachable_StitchesCallPaths(t *testing.T) {
	// Path: app → D1 → D2 → V
	path := []Package{
		{Name: "D1", Version: "1"},
		{Name: "D2", Version: "1"},
		{Name: "V", Version: "1"},
	}
	hops := &stubHopRunner{
		results: map[string]HopResult{
			"/pkg/D2@1": {ReachingSymbols: []string{"D2.foo"}},
			"/pkg/D1@1": {ReachingSymbols: []string{"D1.bar"}},
		},
	}
	w := &Walker{
		Fetcher:     stubFetcher{},
		Hop:         hops.Run,
		Config:      DefaultConfig(),
		Language:    "python",
		InitialTarg: []string{"V.entry"},
	}
	res, err := w.WalkPath(context.Background(), path)
	if err != nil {
		t.Fatalf("WalkPath: %v", err)
	}
	if !res.Completed {
		t.Fatalf("expected path to complete walking to D1, res=%+v", res)
	}
	if len(res.FinalTargets) == 0 {
		t.Errorf("expected non-empty FinalTargets")
	}
	// Expect one hop per intermediate package (D2, D1) — 2 hops.
	if len(hops.calls) != 2 {
		t.Errorf("expected 2 hops, got %d", len(hops.calls))
	}
}

func TestWalker_ShortCircuit_OnBrokenLink(t *testing.T) {
	path := []Package{
		{Name: "D1", Version: "1"},
		{Name: "D2", Version: "1"},
		{Name: "V", Version: "1"},
	}
	hops := &stubHopRunner{
		results: map[string]HopResult{
			// D2 has no caller of V → broken at D2 → V link.
			"/pkg/D2@1": {ReachingSymbols: nil},
			// D1 would reach if we got there, but we should not.
			"/pkg/D1@1": {ReachingSymbols: []string{"D1.bar"}},
		},
	}
	w := &Walker{
		Fetcher:     stubFetcher{},
		Hop:         hops.Run,
		Config:      DefaultConfig(),
		Language:    "python",
		InitialTarg: []string{"V.entry"},
	}
	res, err := w.WalkPath(context.Background(), path)
	if err != nil {
		t.Fatalf("WalkPath: %v", err)
	}
	if res.Completed {
		t.Errorf("expected short-circuit, but path completed")
	}
	if res.BrokenAt != "D2" {
		t.Errorf("expected BrokenAt=D2, got %q", res.BrokenAt)
	}
	// Walker must not fetch D1 after D2 short-circuits.
	if len(hops.calls) != 1 {
		t.Errorf("expected exactly 1 hop (D2), got %d", len(hops.calls))
	}
}

func TestWalker_HopBoundExceeded(t *testing.T) {
	longPath := make([]Package, 10)
	for i := range longPath {
		longPath[i] = Package{Name: "N" + string(rune('A'+i)), Version: "1"}
	}
	hops := &stubHopRunner{results: map[string]HopResult{}}
	cfg := DefaultConfig()
	cfg.MaxHopsPerPath = 3
	w := &Walker{
		Fetcher:     stubFetcher{},
		Hop:         hops.Run,
		Config:      cfg,
		Language:    "python",
		InitialTarg: []string{"target"},
	}
	res, _ := w.WalkPath(context.Background(), longPath)
	if res.BoundExceeded != "max_hops" {
		t.Errorf("expected BoundExceeded=max_hops, got %q", res.BoundExceeded)
	}
}
```

- [ ] **Step 2: Run, verify fail**

```
go test ./pkg/vex/reachability/transitive/ -run TestWalker -v
```

Expected: FAIL — undefined symbols.

- [ ] **Step 3: Implement `walker.go`**

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"fmt"
	"time"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

// HopRunner is the per-hop primitive. walker_test uses a stub; production
// wires this to RunHop.
type HopRunner func(ctx context.Context, in HopInput) (HopResult, error)

// Walker orchestrates a pairwise reverse walk over a single SBOM dependency
// path. It does not aggregate across multiple paths — that is the Analyzer's job.
type Walker struct {
	Fetcher     Fetcher
	Hop         HopRunner
	Config      Config
	Language    string
	InitialTarg []string // target symbols at the vulnerable package
}

// WalkResult is the outcome of walking one dependency path from V backwards.
type WalkResult struct {
	// Completed is true if the walker reached the root of the path (the
	// package immediately downstream of the application) without short-
	// circuiting or hitting a bound.
	Completed bool

	// FinalTargets is the set of symbols in the path root that are tainted
	// exports — the targets the application-side forward analyzer should check.
	FinalTargets []string

	// BrokenAt names the package where the walk short-circuited because no
	// caller was found. Empty if Completed is true.
	BrokenAt string

	// BoundExceeded names the bound that was hit, if any ("max_hops").
	BoundExceeded string

	// HopPaths is the ordered list of per-hop call paths, from application
	// end toward V. Used by the Analyzer to stitch evidence.
	HopPaths []formats.CallPath

	// Degradations records structured reasons for degraded analysis.
	Degradations []string
}

// WalkPath walks a single dependency path in reverse order. The path must be
// ordered from application-side roots to the vulnerable package; the walker
// iterates it in reverse.
//
// path layout: path[0]=D1 (direct dep), path[len-1]=V (vulnerable package).
// Walker skips path[len-1] itself (the vuln package whose exports were already
// identified by the caller) and starts at path[len-2].
func (w *Walker) WalkPath(ctx context.Context, path []Package) (WalkResult, error) {
	if len(path) < 2 {
		return WalkResult{Completed: true, FinalTargets: w.InitialTarg}, nil
	}

	targetSet := w.InitialTarg
	var hopPaths []formats.CallPath
	var degradations []string

	// Iterate in reverse starting at the package immediately upstream of V
	// (path[len-2]) and ending at path[0] (the direct dep).
	hopCount := 0
	for i := len(path) - 2; i >= 0; i-- {
		if w.Config.MaxHopsPerPath > 0 && hopCount >= w.Config.MaxHopsPerPath {
			return WalkResult{
				BoundExceeded: "max_hops",
				Degradations:  append(degradations, ReasonBoundExceeded),
				HopPaths:      hopPaths,
			}, nil
		}
		hopCount++

		pkg := path[i]

		hopCtx := ctx
		if w.Config.HopTimeout > 0 {
			var cancel context.CancelFunc
			hopCtx, cancel = context.WithTimeout(ctx, w.Config.HopTimeout)
			defer cancel()
		}

		fres, err := w.Fetcher.Fetch(hopCtx, pkg.Name, pkg.Version, nil)
		if err != nil {
			degradations = append(degradations, ReasonTarballFetchFailed+":"+pkg.Name)
			continue
		}
		if fres.SourceUnavailable {
			degradations = append(degradations, ReasonSourceUnavailable+":"+pkg.Name)
			continue
		}

		res, err := w.Hop(hopCtx, HopInput{
			Language:      w.Language,
			SourceDir:     fres.SourceDir,
			TargetSymbols: targetSet,
			MaxTargets:    w.Config.MaxTargetSymbolsPerHop,
		})
		if err != nil {
			degradations = append(degradations, ReasonExtractorError+":"+pkg.Name+":"+err.Error())
			continue
		}
		degradations = append(degradations, res.Degradations...)

		if len(res.ReachingSymbols) == 0 {
			return WalkResult{
				BrokenAt:     pkg.Name,
				Degradations: append(degradations, fmt.Sprintf("%s:%s", ReasonPathBroken, pkg.Name)),
				HopPaths:     hopPaths,
			}, nil
		}
		if len(res.Paths) > 0 {
			hopPaths = append([]formats.CallPath{res.Paths[0]}, hopPaths...)
		}
		targetSet = res.ReachingSymbols
	}

	return WalkResult{
		Completed:    true,
		FinalTargets: targetSet,
		HopPaths:     hopPaths,
		Degradations: degradations,
	}, nil
}

// fundingBudgetDeadline returns a deadline relative to now based on budget.
// Exported for transitive_test use (unused directly here).
func fundingBudgetDeadline(budget time.Duration) time.Time {
	if budget <= 0 {
		return time.Time{}
	}
	return time.Now().Add(budget)
}
```

- [ ] **Step 4: Run, verify pass**

```
go test ./pkg/vex/reachability/transitive/ -run TestWalker -v
```

Expected: PASS for all three tests.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/walker.go pkg/vex/reachability/transitive/walker_test.go
git commit -m "feat(transitive): add pairwise reverse walker with short-circuit"
```

---

## Task 11: Top-level `transitive.Analyzer`

**Files:**
- Create: `pkg/vex/reachability/transitive/transitive.go`
- Create: `pkg/vex/reachability/transitive/transitive_test.go`

- [ ] **Step 1: Write failing test**

Create `pkg/vex/reachability/transitive/transitive_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

func TestAnalyzer_NotApplicable_WhenNoSBOM(t *testing.T) {
	a := &Analyzer{Config: DefaultConfig()}
	res, err := a.Analyze(context.Background(), nil, &formats.Finding{AffectedName: "urllib3"}, "/app")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.Degradations) == 0 || res.Degradations[0] != ReasonTransitiveNotApplicable {
		t.Errorf("expected transitive_not_applicable, got %v", res.Degradations)
	}
}

func TestAnalyzer_NotApplicable_WhenPackageNotInGraph(t *testing.T) {
	// Provide an SBOM and a finding for a package not present.
	sbom := &SBOMSummary{
		Packages: []Package{{Name: "flask", Version: "2.0.1"}},
		Roots:    []string{"flask"},
	}
	a := &Analyzer{
		Config: DefaultConfig(),
		Fetchers: map[string]Fetcher{"pypi": &fakeFetcher{
			eco: "pypi",
			manifests: map[string]map[string]string{"flask@2.0.1": {}},
		}},
		Language: "python",
		Ecosystem: "pypi",
	}
	res, err := a.Analyze(context.Background(), sbom, &formats.Finding{AffectedName: "unknown"}, "/app")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.Degradations) == 0 || res.Degradations[0] != ReasonTransitiveNotApplicable {
		t.Errorf("expected transitive_not_applicable, got %v", res.Degradations)
	}
}
```

- [ ] **Step 2: Run, verify fail**

```
go test ./pkg/vex/reachability/transitive/ -run TestAnalyzer -v
```

Expected: FAIL — `Analyzer`, `SBOMSummary` undefined.

- [ ] **Step 3: Implement `transitive.go`**

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
)

// SBOMSummary is the minimal SBOM projection the transitive analyzer needs:
// the version-pinned package list and the application root package names.
// vex.Run builds this from a parsed CycloneDX or SPDX SBOM before handing it
// to per-language analyzers.
type SBOMSummary struct {
	Packages []Package
	Roots    []string
}

// Analyzer is the top-level transitive reachability analyzer. One instance is
// constructed per vex.Run with the SBOM summary and ecosystem-specific fetcher
// wired in. It is safe to reuse across findings within the same run.
type Analyzer struct {
	Config    Config
	Fetchers  map[string]Fetcher // keyed by ecosystem: "pypi", "npm"
	Language  string             // "python" or "javascript"
	Ecosystem string             // matching ecosystem key for Fetchers
}

// Analyze attempts transitive reachability analysis for the given finding.
// Returns a Result with Degradations populated to indicate why transitive
// analysis could not produce a verdict (and the caller should fall back to
// the existing direct-only analyzer), or a reachable verdict with stitched
// call paths as evidence.
func (a *Analyzer) Analyze(ctx context.Context, sbom *SBOMSummary, finding *formats.Finding, sourceDir string) (reachability.Result, error) {
	if sbom == nil || len(sbom.Packages) == 0 || len(sbom.Roots) == 0 {
		return notApplicable(ReasonTransitiveNotApplicable), nil
	}
	fetcher, ok := a.Fetchers[a.Ecosystem]
	if !ok {
		return notApplicable(ReasonTransitiveNotApplicable), nil
	}

	graph, err := BuildDepGraph(ctx, fetcher, sbom.Packages, sbom.Roots)
	if err != nil {
		return reachability.Result{
			Reachable:    false,
			Confidence:   formats.ConfidenceLow,
			Degradations: []string{ReasonManifestFetchFailed},
		}, nil
	}
	if _, ok := graph.Node(finding.AffectedName); !ok {
		return notApplicable(ReasonTransitiveNotApplicable), nil
	}

	paths := graph.PathsTo(finding.AffectedName)
	if len(paths) == 0 {
		return notApplicable(ReasonTransitiveNotApplicable), nil
	}
	if a.Config.MaxPathsPerFinding > 0 && len(paths) > a.Config.MaxPathsPerFinding {
		paths = paths[:a.Config.MaxPathsPerFinding]
	}

	// Stage B: identify target symbols inside V (coarse: all exports).
	// v1 strategy: use the package's own source to collect its exported
	// symbols. For unit-test economy the Analyzer delegates this to a helper
	// that can be stubbed if needed.
	targets, targetDegradations := a.collectVulnSymbols(ctx, finding)
	if len(targets) == 0 {
		return reachability.Result{
			Reachable:    true,
			Confidence:   formats.ConfidenceLow,
			Degradations: append(targetDegradations, ReasonSourceUnavailable),
			Evidence:     "transitive: vulnerable package source unavailable; conservative reachable verdict",
		}, nil
	}

	var pathDegradations []string
	for _, p := range paths {
		w := &Walker{
			Fetcher:     fetcher,
			Hop:         RunHop,
			Config:      a.Config,
			Language:    a.Language,
			InitialTarg: targets,
		}
		res, err := w.WalkPath(ctx, p)
		if err != nil {
			pathDegradations = append(pathDegradations, err.Error())
			continue
		}
		pathDegradations = append(pathDegradations, res.Degradations...)
		if !res.Completed {
			continue
		}
		// Final app-side check: use the same RunHop against the application
		// source with the final target set from the walk.
		appRes, err := RunHop(ctx, HopInput{
			Language:      a.Language,
			SourceDir:     sourceDir,
			TargetSymbols: res.FinalTargets,
			MaxTargets:    a.Config.MaxTargetSymbolsPerHop,
		})
		if err != nil {
			continue
		}
		if len(appRes.ReachingSymbols) == 0 {
			continue
		}
		// Stitch per-hop paths and the app-side path.
		var parts []formats.CallPath
		if len(appRes.Paths) > 0 {
			parts = append(parts, appRes.Paths[0])
		}
		parts = append(parts, res.HopPaths...)
		stitched := StitchCallPaths(parts)
		return reachability.Result{
			Reachable:    true,
			Confidence:   formats.ConfidenceMedium, // coarse targets → medium, LLM narrowing will raise to high
			Evidence:     "transitive: reachable through " + joinPackages(p),
			Symbols:      appRes.ReachingSymbols,
			Paths:        []formats.CallPath{stitched},
			Degradations: pathDegradations,
		}, nil
	}

	return reachability.Result{
		Reachable:    false,
		Confidence:   formats.ConfidenceMedium,
		Evidence:     "transitive: no path from application reaches " + finding.AffectedName,
		Degradations: pathDegradations,
	}, nil
}

// collectVulnSymbols fetches the vulnerable package's source and returns its
// exported symbols as the coarse target set (Stage B of the algorithm).
func (a *Analyzer) collectVulnSymbols(ctx context.Context, finding *formats.Finding) ([]string, []string) {
	fetcher, ok := a.Fetchers[a.Ecosystem]
	if !ok {
		return nil, []string{ReasonTransitiveNotApplicable}
	}
	// Find the pinned version from the graph's node table. If not present,
	// return an empty set (the caller already verified existence).
	version := findingVersion(finding)
	if version == "" {
		return nil, []string{ReasonManifestFetchFailed}
	}
	fres, err := fetcher.Fetch(ctx, finding.AffectedName, version, nil)
	if err != nil {
		return nil, []string{ReasonTarballFetchFailed}
	}
	if fres.SourceUnavailable {
		return nil, []string{ReasonSourceUnavailable}
	}

	// Extract all exported symbols from the package source.
	symbols, degradations := extractExportedSymbols(a.Language, fres.SourceDir, finding.AffectedName)
	return symbols, degradations
}

func findingVersion(f *formats.Finding) string {
	// formats.Finding carries AffectedVersion or similar; use the simplest
	// available version field. Callers must populate at least one of these.
	return f.AffectedVersion
}

// extractExportedSymbols walks the package source and returns fully-qualified
// symbol IDs of its public API. v1: "all top-level functions and methods."
// Filtering by language conventions (leading underscore for Python private)
// is applied.
func extractExportedSymbols(language, sourceDir, packageName string) ([]string, []string) {
	// Run a HopInput with no targets just to collect symbols via the extractor.
	// We invent a throwaway target so RunHop parses the source, then read the
	// graph's symbol table via the hop result. For v1 economy, we use a small
	// local helper that runs the extractor directly.
	syms, err := listExportedSymbols(language, sourceDir, packageName)
	if err != nil {
		return nil, []string{ReasonExtractorError}
	}
	return syms, nil
}

func notApplicable(reason string) reachability.Result {
	return reachability.Result{
		Reachable:    false,
		Confidence:   formats.ConfidenceLow,
		Degradations: []string{reason},
		Evidence:     "transitive: " + reason,
	}
}

func joinPackages(p []Package) string {
	out := ""
	for i, pkg := range p {
		if i > 0 {
			out += " → "
		}
		out += pkg.Name
	}
	return out
}
```

Now add `listExportedSymbols` as a helper at the bottom of `hop.go` (or a new file `exports.go`). Create `pkg/vex/reachability/transitive/exports.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"strings"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarjs "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/javascript"
	grammarpython "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/python"
	jsextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/javascript"
	pyextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/python"
)

// listExportedSymbols extracts the public API of a package at sourceDir as
// fully-qualified symbol IDs of the form "<packageName>.<symbolName>".
func listExportedSymbols(language, sourceDir, packageName string) ([]string, error) {
	switch language {
	case "python":
		return listExportedPython(sourceDir, packageName)
	case "javascript":
		return listExportedJavaScript(sourceDir, packageName)
	}
	return nil, nil
}

func listExportedPython(sourceDir, packageName string) ([]string, error) {
	files, err := collectFilesByExt(sourceDir, []string{".py"})
	if err != nil {
		return nil, err
	}
	parsed, _ := treesitter.ParseFiles(files, grammarpython.Language())
	defer func() {
		for _, pr := range parsed {
			pr.Tree.Close()
		}
	}()
	ext := pyextractor.New()
	seen := make(map[string]struct{})
	for _, pr := range parsed {
		syms, err := ext.ExtractSymbols(pr.File, pr.Source, pr.Tree)
		if err != nil {
			continue
		}
		for _, s := range syms {
			if strings.HasPrefix(s.Name, "_") {
				continue // private
			}
			if s.Kind != treesitter.SymbolFunction && s.Kind != treesitter.SymbolMethod && s.Kind != treesitter.SymbolClass {
				continue
			}
			seen[packageName+"."+s.Name] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out, nil
}

func listExportedJavaScript(sourceDir, packageName string) ([]string, error) {
	files, err := collectFilesByExt(sourceDir, []string{".js", ".mjs", ".cjs"})
	if err != nil {
		return nil, err
	}
	parsed, _ := treesitter.ParseFiles(files, grammarjs.Language())
	defer func() {
		for _, pr := range parsed {
			pr.Tree.Close()
		}
	}()
	ext := jsextractor.New()
	seen := make(map[string]struct{})
	for _, pr := range parsed {
		syms, err := ext.ExtractSymbols(pr.File, pr.Source, pr.Tree)
		if err != nil {
			continue
		}
		for _, s := range syms {
			if s.Kind != treesitter.SymbolFunction && s.Kind != treesitter.SymbolMethod && s.Kind != treesitter.SymbolClass {
				continue
			}
			seen[packageName+"."+s.Name] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out, nil
}
```

**Also:** add `AffectedVersion` to `formats.Finding` if not already present. Check `pkg/formats/finding.go`: if the struct lacks an `AffectedVersion` field, add it. (If it already has one under a different name, update `findingVersion` accordingly.)

- [ ] **Step 4: Check the Finding struct**

```
grep -n "type Finding" pkg/formats/finding.go
grep -n "AffectedVersion\|Version" pkg/formats/finding.go
```

If `AffectedVersion` is missing, add the field:

```go
// in pkg/formats/finding.go
type Finding struct {
	...
	AffectedVersion string
	...
}
```

Ensure scanner parsers (`pkg/formats/grype/grype.go`, `pkg/formats/trivy/trivy.go`) populate it from their native fields (grype: `m.Artifact.Version`; trivy: `v.InstalledVersion`).

- [ ] **Step 5: Run tests, verify pass**

```
go test ./pkg/vex/reachability/transitive/ -v
```

Expected: all transitive tests PASS.

- [ ] **Step 6: Commit**

```
git add pkg/vex/reachability/transitive/transitive.go \
        pkg/vex/reachability/transitive/transitive_test.go \
        pkg/vex/reachability/transitive/exports.go \
        pkg/formats/finding.go \
        pkg/formats/grype/grype.go \
        pkg/formats/trivy/trivy.go
git commit -m "feat(transitive): add top-level Analyzer with stage orchestration"
```

---

## Task 12: Integrate transitive analyzer into Python analyzer

**Files:**
- Modify: `pkg/vex/reachability/python/python.go`
- Modify: `pkg/vex/reachability/python/python_test.go`

- [ ] **Step 1: Write failing test**

Append to `pkg/vex/reachability/python/python_test.go`:

```go
func TestPython_Analyzer_TransitiveShortCircuit(t *testing.T) {
	// Build a minimal Python application that imports flask and calls a
	// handler. The transitive analyzer is a stub that returns not-reachable
	// to verify fallback to direct-only behavior.
	a := &Analyzer{} // Transitive is nil → must fall back
	_, err := a.Analyze(context.Background(), t.TempDir(), &formats.Finding{
		AffectedName: "urllib3",
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
}

func TestPython_Analyzer_AcceptsTransitiveField(t *testing.T) {
	a := &Analyzer{Transitive: nil}
	_ = a // compile-time check only: struct must accept Transitive field
}
```

- [ ] **Step 2: Run, verify fail**

```
go test ./pkg/vex/reachability/python/ -run 'TestPython_Analyzer_TransitiveShortCircuit|TestPython_Analyzer_AcceptsTransitiveField' -v
```

Expected: FAIL — `Transitive` field does not exist.

- [ ] **Step 3: Add Transitive field and pre-check to python.go**

Replace the Analyzer struct definition and the `Analyze` method entry in `pkg/vex/reachability/python/python.go`:

```go
// At top of file, add import:
import (
	...
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive"
)

// Replace struct definition:
type Analyzer struct {
	// Transitive, when non-nil, is consulted before the direct-only analysis.
	// vex.Run wires this with a transitive.Analyzer constructed from the
	// parsed SBOM and product-config bounds. When Transitive produces a
	// reachable verdict, it is returned as-is; otherwise the direct-only
	// flow continues. Leaving Transitive nil preserves the prior behavior.
	Transitive *transitive.Analyzer
	// SBOMSummary carries the pinned package list and application roots
	// needed by the transitive analyzer. Populated by vex.Run.
	SBOMSummary *transitive.SBOMSummary
}
```

At the top of the existing `Analyze` method body, before `var files []string`, add:

```go
	// Pre-check: consult the transitive analyzer if configured.
	if a.Transitive != nil && a.SBOMSummary != nil {
		tres, terr := a.Transitive.Analyze(ctx, a.SBOMSummary, finding, sourceDir)
		if terr == nil && tres.Reachable {
			return tres, nil
		}
	}
```

- [ ] **Step 4: Run tests**

```
go test ./pkg/vex/reachability/python/ -v
```

Expected: all existing python tests still PASS and the new field tests PASS.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/python/python.go pkg/vex/reachability/python/python_test.go
git commit -m "feat(python): consult transitive analyzer before direct-only path"
```

---

## Task 13: Integrate transitive analyzer into JavaScript analyzer

**Files:**
- Modify: `pkg/vex/reachability/javascript/javascript.go`
- Modify: `pkg/vex/reachability/javascript/javascript_test.go`

- [ ] **Step 1: Write failing test**

Append to `pkg/vex/reachability/javascript/javascript_test.go`:

```go
func TestJavaScript_Analyzer_AcceptsTransitiveField(t *testing.T) {
	a := &Analyzer{Transitive: nil}
	_ = a
}
```

- [ ] **Step 2: Run, verify fail**

```
go test ./pkg/vex/reachability/javascript/ -run TestJavaScript_Analyzer_AcceptsTransitiveField -v
```

Expected: FAIL.

- [ ] **Step 3: Apply the same edit as Task 12 to javascript.go**

Add imports and replace struct definition:

```go
import (
	...
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive"
)

type Analyzer struct {
	Transitive  *transitive.Analyzer
	SBOMSummary *transitive.SBOMSummary
}
```

Insert the pre-check at the top of `Analyze`:

```go
	if a.Transitive != nil && a.SBOMSummary != nil {
		tres, terr := a.Transitive.Analyze(ctx, a.SBOMSummary, finding, sourceDir)
		if terr == nil && tres.Reachable {
			return tres, nil
		}
	}
```

- [ ] **Step 4: Run tests**

```
go test ./pkg/vex/reachability/javascript/ -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/javascript/javascript.go pkg/vex/reachability/javascript/javascript_test.go
git commit -m "feat(javascript): consult transitive analyzer before direct-only path"
```

---

## Task 14: Wire SBOM into vex.Run and construct transitive.Analyzer

**Files:**
- Modify: `pkg/vex/vex.go` (or wherever analyzers are constructed)
- Create: `pkg/vex/transitive_wire.go`
- Create: `pkg/vex/transitive_wire_test.go`

This task involves reading the existing vex.Run orchestration first. The engineer must:

1. Find where per-language analyzers are constructed inside the vex package.
2. Add a helper that parses the SBOM (already loaded) into a `transitive.SBOMSummary` (pinned packages list + application roots).
3. Construct a `transitive.Analyzer` once per run with the default Config.
4. Inject it into the Python and JavaScript analyzers before they run.

- [ ] **Step 1: Locate the analyzer construction site**

```
grep -rn "python.New()\|javascript.New()" pkg/vex/
```

Note the file. Expect a switch-on-language or map that creates a new analyzer per finding.

- [ ] **Step 2: Write failing test for SBOMSummary extraction**

Create `pkg/vex/transitive_wire_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

func TestBuildTransitiveSummary_CycloneDX(t *testing.T) {
	sbom := &formats.SBOM{
		Root: &formats.Component{
			Name:    "myapp",
			Version: "1.0.0",
		},
		Components: []formats.Component{
			{Name: "flask", Version: "2.0.1", PURL: "pkg:pypi/flask@2.0.1"},
			{Name: "werkzeug", Version: "2.0.2", PURL: "pkg:pypi/werkzeug@2.0.2"},
			{Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20"},
		},
		DirectDependencies: []string{"flask", "lodash"},
	}
	summary := buildTransitiveSummary(sbom, "pypi")
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if len(summary.Packages) != 2 {
		t.Errorf("expected 2 pypi packages, got %d", len(summary.Packages))
	}
	foundFlask := false
	for _, p := range summary.Packages {
		if p.Name == "flask" && p.Version == "2.0.1" {
			foundFlask = true
		}
	}
	if !foundFlask {
		t.Error("flask missing from summary")
	}
	if len(summary.Roots) != 1 || summary.Roots[0] != "flask" {
		t.Errorf("expected roots=[flask], got %v", summary.Roots)
	}
}
```

- [ ] **Step 3: Run, verify fail**

```
go test ./pkg/vex/ -run TestBuildTransitiveSummary -v
```

Expected: FAIL — `buildTransitiveSummary` undefined, or `formats.SBOM` fields missing.

- [ ] **Step 4: Inspect formats.SBOM**

```
grep -n "type SBOM\|DirectDependencies\|Components" pkg/formats/sbom.go
```

If the fields used in the test don't match the actual type, update the test to use real field names (e.g. `Root.Component`, `Components`, etc.) and adjust `buildTransitiveSummary` accordingly. The test's job is to verify extraction; the exact field path doesn't matter as long as it matches the real SBOM type.

- [ ] **Step 5: Implement `transitive_wire.go`**

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex

import (
	"strings"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive"
)

// buildTransitiveSummary extracts the minimal SBOM projection needed by the
// transitive analyzer: the set of pinned packages for the given ecosystem and
// the names of the application's direct dependencies (as roots).
//
// ecosystem: "pypi" or "npm".
func buildTransitiveSummary(sbom *formats.SBOM, ecosystem string) *transitive.SBOMSummary {
	if sbom == nil {
		return nil
	}
	prefix := "pkg:" + ecosystem + "/"
	var pkgs []transitive.Package
	knownNames := make(map[string]bool)
	for _, c := range sbom.Components {
		if !strings.HasPrefix(c.PURL, prefix) {
			continue
		}
		pkgs = append(pkgs, transitive.Package{Name: c.Name, Version: c.Version})
		knownNames[c.Name] = true
	}
	if len(pkgs) == 0 {
		return nil
	}
	var roots []string
	for _, name := range sbom.DirectDependencies {
		if knownNames[name] {
			roots = append(roots, name)
		}
	}
	if len(roots) == 0 {
		// Fall back to every package as a root (conservative).
		for _, p := range pkgs {
			roots = append(roots, p.Name)
		}
	}
	return &transitive.SBOMSummary{
		Packages: pkgs,
		Roots:    roots,
	}
}

// buildTransitiveAnalyzer constructs a per-run transitive.Analyzer for the
// given language. Returns nil when transitive analysis is disabled or the
// language is unsupported.
func buildTransitiveAnalyzer(cfg transitive.Config, language string) *transitive.Analyzer {
	if !cfg.Enabled {
		return nil
	}
	cache := transitive.NewCache(cfg.CacheDir)
	switch language {
	case "python":
		return &transitive.Analyzer{
			Config:    cfg,
			Language:  "python",
			Ecosystem: "pypi",
			Fetchers: map[string]transitive.Fetcher{
				"pypi": &transitive.PyPIFetcher{Cache: cache},
			},
		}
	case "javascript":
		return &transitive.Analyzer{
			Config:    cfg,
			Language:  "javascript",
			Ecosystem: "npm",
			Fetchers: map[string]transitive.Fetcher{
				"npm": &transitive.NPMFetcher{Cache: cache},
			},
		}
	}
	return nil
}
```

Adjust the test and implementation as needed so they match the actual `formats.SBOM`, `formats.Component` field names. If `DirectDependencies` does not exist as-is, replace with the real accessor (e.g. walking `Dependencies` edges from the root component in CycloneDX, or reading `DESCRIBES` relationships in SPDX).

- [ ] **Step 6: Wire into the per-finding analyzer lookup**

In the vex package file that constructs Python/JavaScript analyzers (found in Step 1), add the injection:

```go
pyAnalyzer := python.New()
// When vex.Options has a parsed SBOM and transitive is enabled:
if sbom != nil {
	transitiveCfg := resolveTransitiveConfig(opts) // from CLI flag + product-config
	if ta := buildTransitiveAnalyzer(transitiveCfg, "python"); ta != nil {
		pyAnalyzer.Transitive = ta
		pyAnalyzer.SBOMSummary = buildTransitiveSummary(sbom, "pypi")
	}
}
```

Analogous block for JavaScript with `npm`.

Implement `resolveTransitiveConfig` to return `transitive.DefaultConfig()` for v1; it will be extended in Task 16 to read from product-config and CLI flags.

- [ ] **Step 7: Run tests**

```
go test ./pkg/vex/... -v
```

Expected: all vex tests PASS.

- [ ] **Step 8: Commit**

```
git add pkg/vex/transitive_wire.go pkg/vex/transitive_wire_test.go pkg/vex/
git commit -m "feat(vex): wire transitive analyzer into per-language chain"
```

---

## Task 15: CLI flags `--transitive` and `--transitive-cache-dir`

**Files:**
- Modify: `internal/cli/vex.go`
- Modify: `pkg/vex/types.go` (or wherever vex.Options lives)

- [ ] **Step 1: Locate vex.Options**

```
grep -rn "type Options struct" pkg/vex/
```

Note the file.

- [ ] **Step 2: Add fields to Options**

Append to the Options struct:

```go
type Options struct {
	...
	// TransitiveEnabled, when false, disables transitive reachability
	// analysis and preserves direct-only behavior. Defaults to true.
	TransitiveEnabled bool
	// TransitiveCacheDir overrides the default cache location for fetched
	// package tarballs. Empty means use the default.
	TransitiveCacheDir string
}
```

- [ ] **Step 3: Add CLI flags**

In `internal/cli/vex.go`, inside the `newVexCmd` `Flags` slice, append:

```go
&urfave.BoolFlag{
	Name:  "transitive",
	Usage: "enable transitive dependency reachability analysis (Python, JavaScript)",
	Value: true,
},
&urfave.StringFlag{
	Name:  "transitive-cache-dir",
	Usage: "cache directory for fetched package tarballs (default ~/.cache/cra-toolkit/pkgs)",
},
```

In the `Action` closure, populate the Options:

```go
opts := &vex.Options{
	...
	TransitiveEnabled:  cmd.Bool("transitive"),
	TransitiveCacheDir: cmd.String("transitive-cache-dir"),
}
```

- [ ] **Step 4: Update `resolveTransitiveConfig` in the vex package**

Make it use the Options fields:

```go
func resolveTransitiveConfig(opts *Options) transitive.Config {
	cfg := transitive.DefaultConfig()
	cfg.Enabled = opts.TransitiveEnabled
	if opts.TransitiveCacheDir != "" {
		cfg.CacheDir = opts.TransitiveCacheDir
	}
	return cfg
}
```

- [ ] **Step 5: Manual smoke test**

```
task build
./bin/cra vex --help | grep -A1 transitive
```

Expected output includes `--transitive` and `--transitive-cache-dir` descriptions.

- [ ] **Step 6: Run full tests**

```
task test
```

Expected: PASS.

- [ ] **Step 7: Commit**

```
git add internal/cli/vex.go pkg/vex/
git commit -m "feat(cli): add --transitive and --transitive-cache-dir flags"
```

---

## Task 16: Product-config YAML bounds stanza

**Files:**
- Modify: The file that holds the ProductConfig YAML struct.
- Modify: `pkg/vex/transitive_wire.go` (extend `resolveTransitiveConfig`).

- [ ] **Step 1: Locate ProductConfig**

```
grep -rn "type ProductConfig" pkg/toolkit/ pkg/vex/
```

Likely in `pkg/toolkit/`.

- [ ] **Step 2: Add the stanza**

Inside `ProductConfig`, find or create a `Reachability` section and add a `Transitive` field:

```go
type ReachabilityConfig struct {
	Transitive transitive.Config `yaml:"transitive,omitempty"`
}

type ProductConfig struct {
	...
	Reachability ReachabilityConfig `yaml:"reachability,omitempty"`
}
```

- [ ] **Step 3: Thread ProductConfig into resolveTransitiveConfig**

Change its signature to take both Options and (optional) *ProductConfig and merge the YAML override on top of defaults:

```go
func resolveTransitiveConfig(opts *Options, pc *toolkit.ProductConfig) transitive.Config {
	cfg := transitive.DefaultConfig()
	if pc != nil {
		cfg = cfg.Merge(pc.Reachability.Transitive)
	}
	cfg.Enabled = opts.TransitiveEnabled
	if opts.TransitiveCacheDir != "" {
		cfg.CacheDir = opts.TransitiveCacheDir
	}
	return cfg
}
```

Update callers accordingly. vex.Run already has access to a ProductConfig if one is supplied via `--product-config`.

- [ ] **Step 4: Write a test**

Add to `pkg/vex/transitive_wire_test.go`:

```go
func TestResolveTransitiveConfig_YAMLOverridesDefaults(t *testing.T) {
	pc := &toolkit.ProductConfig{
		Reachability: toolkit.ReachabilityConfig{
			Transitive: transitive.Config{
				MaxHopsPerPath: 20,
			},
		},
	}
	opts := &Options{TransitiveEnabled: true}
	cfg := resolveTransitiveConfig(opts, pc)
	if cfg.MaxHopsPerPath != 20 {
		t.Errorf("expected 20, got %d", cfg.MaxHopsPerPath)
	}
	if cfg.MaxPathsPerFinding != 16 {
		t.Errorf("default MaxPathsPerFinding lost")
	}
}
```

- [ ] **Step 5: Run, verify pass**

```
go test ./pkg/vex/ -run TestResolveTransitiveConfig -v
```

Expected: PASS (after writing impl in Step 3).

- [ ] **Step 6: Commit**

```
git add pkg/toolkit/ pkg/vex/transitive_wire.go pkg/vex/transitive_wire_test.go
git commit -m "feat(config): add reachability.transitive YAML stanza"
```

---

## Task 17: Python cross-package reachable fixture

**Files:**
- Create: `testdata/integration/python-realworld-cross-package/` directory and contents

Goal: a fixture where a real Python CVE in a **transitive** dependency is actually reached by the test app through a real direct dependency's internal call chain.

- [ ] **Step 1: Pick a candidate CVE**

Research candidates (use `osv.dev`) for a CVE in a Python package whose vulnerable function is called from a commonly-used direct dependency and that is still installable from PyPI.

Good starting points:
- `CVE-2023-43804` on `urllib3@<2.0.6` (cookie leakage in cross-origin redirects) — reached by `requests` by default.
- `CVE-2020-26137` on `urllib3@<1.25.9` (CRLF injection) — reached by `requests`.

Confirm at least one real call chain from a directly-importable `requests` API (e.g. `requests.get`) into the vulnerable `urllib3` function by reading the pinned dependency source code. Pin versions to a combination where the chain is verifiable.

- [ ] **Step 2: Create source directory**

```
mkdir -p testdata/integration/python-realworld-cross-package/source
cat > testdata/integration/python-realworld-cross-package/source/app.py <<'PY'
# Minimal Flask-style application that uses requests to fetch user-supplied URLs.
# The CVE-2023-43804 vulnerability in urllib3 is reachable through requests.get()
# because requests internally constructs a urllib3 PoolManager and calls its
# request() method, which constructs Retry objects that handle redirects.

import requests

def fetch_user_url(url):
    """Fetches a URL provided by an untrusted user."""
    response = requests.get(url, allow_redirects=True)
    return response.text

if __name__ == "__main__":
    fetch_user_url("https://example.com")
PY
```

- [ ] **Step 3: Generate the SBOM**

Install the exact versions locally and run syft against the source directory:

```
cd testdata/integration/python-realworld-cross-package
python3 -m venv .sbom-venv
.sbom-venv/bin/pip install 'requests==2.31.0' 'urllib3==2.0.5'
syft .sbom-venv/lib/python3.*/site-packages -o cyclonedx-json=sbom.cdx.json
rm -rf .sbom-venv
cd -
```

Verify the SBOM contains both `requests@2.31.0` and `urllib3@2.0.5`.

- [ ] **Step 4: Create scan result and expected.json**

Create `testdata/integration/python-realworld-cross-package/trivy.json` with a single CVE entry targeting `urllib3@2.0.5` for CVE-2023-43804:

```json
{
  "SchemaVersion": 2,
  "ArtifactName": "python-realworld-cross-package",
  "ArtifactType": "filesystem",
  "Results": [
    {
      "Target": "sbom.cdx.json",
      "Class": "lang-pkgs",
      "Type": "python-pkg",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-43804",
          "PkgName": "urllib3",
          "InstalledVersion": "2.0.5",
          "FixedVersion": "2.0.6",
          "Severity": "HIGH"
        }
      ]
    }
  ]
}
```

Create `testdata/integration/python-realworld-cross-package/expected.json`:

```json
{
  "description": "Flask-style app reaching urllib3 CVE-2023-43804 transitively through requests.get(). The vulnerable redirect handling is inside urllib3's Retry class, reached through requests' internal HTTPAdapter → PoolManager chain.",
  "provenance": {
    "source_project": "urllib3/urllib3",
    "source_url": "https://github.com/urllib3/urllib3",
    "commit": "2.0.5",
    "cve": "CVE-2023-43804",
    "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-43804",
    "language": "python",
    "pattern": "cross-package-transitive",
    "ground_truth_notes": "app.fetch_user_url → requests.get → HTTPAdapter.send → PoolManager.urlopen → Retry.increment (vulnerable cookie handling)"
  },
  "findings": [
    {
      "cve": "CVE-2023-43804",
      "component_purl": "pkg:pypi/urllib3@2.0.5",
      "expected_status": "affected",
      "expected_confidence": "medium",
      "expected_resolved_by": "transitive_reachability",
      "human_justification": "requests.get is called directly in app.py; requests internally invokes urllib3.PoolManager.urlopen which constructs Retry objects that handle the vulnerable redirect flow."
    }
  ]
}
```

- [ ] **Step 5: Commit the fixture**

```
git add testdata/integration/python-realworld-cross-package/
git commit -m "test(transitive): add Python reachable cross-package fixture (CVE-2023-43804)"
```

---

## Task 18: Python cross-package not-reachable fixture

**Files:**
- Create: `testdata/integration/python-realworld-cross-package-safe/`

- [ ] **Step 1: Create source**

```
mkdir -p testdata/integration/python-realworld-cross-package-safe/source
cat > testdata/integration/python-realworld-cross-package-safe/source/app.py <<'PY'
# This app imports requests but only uses its Session object for OPTIONS probes,
# which do not invoke the redirect handling code path where CVE-2023-43804
# lives. The CVE function is not reachable from any entry point.

import requests

def check_server(url):
    session = requests.Session()
    resp = session.options(url)  # OPTIONS does not follow redirects
    return resp.headers

if __name__ == "__main__":
    check_server("https://example.com")
PY
```

- [ ] **Step 2: Copy the SBOM from the reachable fixture**

```
cp testdata/integration/python-realworld-cross-package/sbom.cdx.json testdata/integration/python-realworld-cross-package-safe/
cp testdata/integration/python-realworld-cross-package/trivy.json testdata/integration/python-realworld-cross-package-safe/
```

- [ ] **Step 3: Create expected.json**

```json
{
  "description": "Same deps as the reachable fixture but the app only uses requests.Session().options(), which does not reach CVE-2023-43804's vulnerable redirect path.",
  "provenance": {
    "source_project": "urllib3/urllib3",
    "source_url": "https://github.com/urllib3/urllib3",
    "commit": "2.0.5",
    "cve": "CVE-2023-43804",
    "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-43804",
    "language": "python",
    "pattern": "cross-package-transitive-safe",
    "ground_truth_notes": "Session.options() does not invoke redirect handling; CVE path is not reachable."
  },
  "findings": [
    {
      "cve": "CVE-2023-43804",
      "component_purl": "pkg:pypi/urllib3@2.0.5",
      "expected_status": "not_affected",
      "expected_confidence": "medium",
      "expected_resolved_by": "transitive_reachability",
      "expected_justification": "vulnerable_code_not_in_execute_path",
      "human_justification": "Session.options is the only requests API reached from entry point; options does not trigger the vulnerable redirect path."
    }
  ]
}
```

- [ ] **Step 4: Commit**

```
git add testdata/integration/python-realworld-cross-package-safe/
git commit -m "test(transitive): add Python not-reachable cross-package fixture"
```

---

## Task 19: JavaScript cross-package reachable fixture

**Files:**
- Create: `testdata/integration/javascript-realworld-cross-package/`

- [ ] **Step 1: Pick a candidate**

Research CVEs in npm packages where the vulnerable function is reached through a common direct dependency's internals. Starting points:
- CVE-2019-10744 on `lodash@<4.17.12` (prototype pollution in `defaultsDeep`) — reached by any of several tools that use lodash internally.
- CVE-2022-0155 on `follow-redirects@<1.14.7` (credential leak) — reached by `axios`.

Pick one where the call chain is real and verifiable in the pinned versions.

- [ ] **Step 2: Create source**

```
mkdir -p testdata/integration/javascript-realworld-cross-package/source
cat > testdata/integration/javascript-realworld-cross-package/source/app.js <<'JS'
// Express app that uses axios to fetch URLs. The transitive dep follow-redirects
// is invoked by axios for every redirect response, reaching CVE-2022-0155's
// credential-leak code path.

const axios = require('axios');

async function fetchWithRedirects(url) {
    const response = await axios.get(url, { maxRedirects: 5 });
    return response.data;
}

module.exports = { fetchWithRedirects };
JS
```

- [ ] **Step 3: Generate SBOM**

```
cd testdata/integration/javascript-realworld-cross-package
npm init -y
npm install axios@0.25.0 follow-redirects@1.14.0
syft node_modules -o cyclonedx-json=sbom.cdx.json
rm -rf node_modules package.json package-lock.json
cd -
```

- [ ] **Step 4: Create scan result and expected.json**

grype.json (or trivy.json) flagging `follow-redirects@1.14.0` for CVE-2022-0155.

`expected.json`:

```json
{
  "description": "Express app using axios.get reaching CVE-2022-0155 in follow-redirects through the axios → follow-redirects internal chain.",
  "provenance": {
    "source_project": "follow-redirects/follow-redirects",
    "source_url": "https://github.com/follow-redirects/follow-redirects",
    "commit": "1.14.0",
    "cve": "CVE-2022-0155",
    "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-0155",
    "language": "javascript",
    "pattern": "cross-package-transitive",
    "ground_truth_notes": "app.fetchWithRedirects → axios.get → adapter → http.request wrapped by follow-redirects → vulnerable redirect handler"
  },
  "findings": [
    {
      "cve": "CVE-2022-0155",
      "component_purl": "pkg:npm/follow-redirects@1.14.0",
      "expected_status": "affected",
      "expected_confidence": "medium",
      "expected_resolved_by": "transitive_reachability",
      "human_justification": "axios.get is invoked with maxRedirects > 0, which routes through follow-redirects' vulnerable redirect wrapper."
    }
  ]
}
```

- [ ] **Step 5: Commit**

```
git add testdata/integration/javascript-realworld-cross-package/
git commit -m "test(transitive): add JavaScript reachable cross-package fixture (CVE-2022-0155)"
```

---

## Task 20: JavaScript cross-package not-reachable fixture

**Files:**
- Create: `testdata/integration/javascript-realworld-cross-package-safe/`

- [ ] **Step 1: Create source**

```
mkdir -p testdata/integration/javascript-realworld-cross-package-safe/source
cat > testdata/integration/javascript-realworld-cross-package-safe/source/app.js <<'JS'
// This app imports axios but configures it to never follow redirects, so
// follow-redirects' vulnerable path is not reached.

const axios = require('axios');

async function fetchNoRedirects(url) {
    const response = await axios.get(url, { maxRedirects: 0 });
    return response.data;
}

module.exports = { fetchNoRedirects };
JS
```

- [ ] **Step 2: Reuse SBOM and scan from the reachable fixture**

```
cp testdata/integration/javascript-realworld-cross-package/sbom.cdx.json testdata/integration/javascript-realworld-cross-package-safe/
cp testdata/integration/javascript-realworld-cross-package/grype.json testdata/integration/javascript-realworld-cross-package-safe/ 2>/dev/null || \
cp testdata/integration/javascript-realworld-cross-package/trivy.json testdata/integration/javascript-realworld-cross-package-safe/
```

- [ ] **Step 3: Create expected.json**

```json
{
  "description": "Same deps as reachable fixture but maxRedirects=0 prevents follow-redirects from executing the vulnerable path.",
  "provenance": {
    "source_project": "follow-redirects/follow-redirects",
    "cve": "CVE-2022-0155",
    "language": "javascript",
    "pattern": "cross-package-transitive-safe",
    "ground_truth_notes": "maxRedirects: 0 short-circuits the redirect handler, so the vulnerable code is not executed."
  },
  "findings": [
    {
      "cve": "CVE-2022-0155",
      "component_purl": "pkg:npm/follow-redirects@1.14.0",
      "expected_status": "not_affected",
      "expected_confidence": "medium",
      "expected_resolved_by": "transitive_reachability",
      "expected_justification": "vulnerable_code_not_in_execute_path",
      "human_justification": "The redirect handler is never invoked when maxRedirects is 0."
    }
  ]
}
```

- [ ] **Step 4: Commit**

```
git add testdata/integration/javascript-realworld-cross-package-safe/
git commit -m "test(transitive): add JavaScript not-reachable cross-package fixture"
```

---

## Task 21: Integration test harness for cross-package fixtures

**Files:**
- Create: `pkg/vex/reachability/transitive/integration_test.go`
- Modify: `Taskfile.yml`

- [ ] **Step 1: Write the complete integration test file**

Create `pkg/vex/reachability/transitive/integration_test.go` with all four tests fully implemented. No skips, no placeholders.

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package transitive

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

// expectedFixture mirrors the structure of testdata fixture expected.json files.
type expectedFixture struct {
	Description string `json:"description"`
	Findings    []struct {
		CVE                string `json:"cve"`
		ComponentPURL      string `json:"component_purl"`
		ExpectedStatus     string `json:"expected_status"`
		ExpectedResolvedBy string `json:"expected_resolved_by"`
	} `json:"findings"`
}

func loadFixture(t *testing.T, dir string) expectedFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatalf("read expected.json: %v", err)
	}
	var f expectedFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return f
}

// cdxComponent is the minimal slice of CycloneDX JSON the integration tests
// need. Duplicated inline rather than importing pkg/vex to keep this leaf.
type cdxComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type cdxDoc struct {
	Components []cdxComponent `json:"components"`
	Metadata   struct {
		Component struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"component"`
	} `json:"metadata"`
}

// parseSBOMForTest reads a CycloneDX SBOM and returns a SBOMSummary containing
// only components matching the given ecosystem prefix (e.g. "pypi" or "npm").
// All matching components are treated as roots (conservative) because the
// fixture apps are single-entry and transitive analysis is path-driven.
func parseSBOMForTest(t *testing.T, path, ecosystem string) *SBOMSummary {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}
	var doc cdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal sbom: %v", err)
	}
	prefix := "pkg:" + ecosystem + "/"
	var pkgs []Package
	for _, c := range doc.Components {
		if !strings.HasPrefix(c.PURL, prefix) {
			continue
		}
		pkgs = append(pkgs, Package{Name: c.Name, Version: c.Version})
	}
	if len(pkgs) == 0 {
		t.Fatalf("no %s components in sbom %s", ecosystem, path)
	}
	roots := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		roots = append(roots, p.Name)
	}
	return &SBOMSummary{Packages: pkgs, Roots: roots}
}

// runIntegrationFixture executes the transitive analyzer against a fixture
// directory and asserts that Reachable matches the expected verdict.
func runIntegrationFixture(t *testing.T, fixtureDir, language, ecosystem, affectedName, affectedVersion string, wantReachable bool) {
	t.Helper()
	fx := loadFixture(t, fixtureDir)
	if len(fx.Findings) == 0 {
		t.Fatal("fixture has no findings")
	}

	summary := parseSBOMForTest(t, filepath.Join(fixtureDir, "sbom.cdx.json"), ecosystem)
	cache := NewCache(t.TempDir())

	var fetcher Fetcher
	switch ecosystem {
	case "pypi":
		fetcher = &PyPIFetcher{Cache: cache}
	case "npm":
		fetcher = &NPMFetcher{Cache: cache}
	default:
		t.Fatalf("unknown ecosystem %q", ecosystem)
	}

	analyzer := &Analyzer{
		Config:    DefaultConfig(),
		Language:  language,
		Ecosystem: ecosystem,
		Fetchers:  map[string]Fetcher{ecosystem: fetcher},
	}

	res, err := analyzer.Analyze(context.Background(), summary, &formats.Finding{
		AffectedName:    affectedName,
		AffectedVersion: affectedVersion,
	}, filepath.Join(fixtureDir, "source"))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if res.Reachable != wantReachable {
		t.Errorf("reachable: want %v, got %v\nevidence: %s\ndegradations: %v",
			wantReachable, res.Reachable, res.Evidence, res.Degradations)
	}
	if wantReachable && len(res.Paths) == 0 {
		t.Errorf("expected at least one stitched call path, got none")
	}
}

func TestIntegration_Transitive_PythonReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "python-realworld-cross-package")
	runIntegrationFixture(t, dir, "python", "pypi", "urllib3", "2.0.5", true)
}

func TestIntegration_Transitive_PythonNotReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "python-realworld-cross-package-safe")
	runIntegrationFixture(t, dir, "python", "pypi", "urllib3", "2.0.5", false)
}

func TestIntegration_Transitive_JavaScriptReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "javascript-realworld-cross-package")
	runIntegrationFixture(t, dir, "javascript", "npm", "follow-redirects", "1.14.0", true)
}

func TestIntegration_Transitive_JavaScriptNotReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "javascript-realworld-cross-package-safe")
	runIntegrationFixture(t, dir, "javascript", "npm", "follow-redirects", "1.14.0", false)
}
```

The `runIntegrationFixture` helper means every test is a single readable call. No scaffolding phase. Network access to PyPI / npm registry is required; that's why the file carries the `integration` build tag.

- [ ] **Step 2: Add the Taskfile target**

Append to `Taskfile.yml` (in the tasks: map, near the other `test:*` entries):

```yaml
  test:transitive:
    desc: Run transitive reachability integration tests (requires network for PyPI/npm)
    cmds:
      - go test -tags integration -race -count=1 -v -timeout 10m -run TestIntegration_Transitive ./pkg/vex/reachability/transitive/...
```

- [ ] **Step 3: Run the integration suite**

```
task test:transitive
```

Expected: four tests PASS. First run populates the content-addressed cache from PyPI and npm (30–60 seconds of fetching). Subsequent runs hit the cache and complete in a few seconds.

- [ ] **Step 4: Commit**

```
git add pkg/vex/reachability/transitive/integration_test.go Taskfile.yml
git commit -m "test(transitive): add cross-package integration tests with Taskfile target"
```

---

## Task 22: Update LLM judgment tests

**Files:**
- Modify: `pkg/vex/reachability/python/llm_judge_test.go`
- Modify: `pkg/vex/reachability/javascript/llm_judge_test.go`

The existing LLM judge tests iterate the realworld fixtures. They need to also cover the new cross-package fixtures so the judge sees transitive evidence.

- [ ] **Step 1: Locate judge test fixture lists**

```
grep -n "cross-package\|realworld-transitive" pkg/vex/reachability/python/llm_judge_test.go
```

If the judge test iterates a directory or a hard-coded list, add the two new Python fixture directory names (`python-realworld-cross-package`, `python-realworld-cross-package-safe`).

- [ ] **Step 2: Add fixture entries**

Inside the fixture list (exact variable name is whatever the existing file uses), add:

```go
"python-realworld-cross-package",
"python-realworld-cross-package-safe",
```

Analogous edit for `llm_judge_test.go` in javascript with the JS fixtures.

- [ ] **Step 3: Run the judge tests locally (requires gemini CLI)**

```
task test:reachability:llmjudge
```

Expected: the judge runs against the new fixtures and returns quality scores above the existing threshold. If the judge fails because the transitive analyzer is not producing enough evidence detail, add the `Degradations` field output to the evidence string emitted by the Python/JS analyzers so the judge sees it.

- [ ] **Step 4: Commit**

```
git add pkg/vex/reachability/python/llm_judge_test.go pkg/vex/reachability/javascript/llm_judge_test.go
git commit -m "test(llmjudge): extend judge coverage to transitive cross-package fixtures"
```

---

## Task 23: Documentation site update

**Files:**
- Modify: `site/docs/tools/vex.md`

- [ ] **Step 1: Add a new section**

Open `site/docs/tools/vex.md`. Add a section titled `## Transitive Reachability Analysis` near the bottom of the existing reachability discussion. Include:

```markdown
## Transitive Reachability Analysis

For Python and JavaScript projects, the VEX command can trace call chains through
transitive dependencies to determine whether a vulnerability sitting inside a
library the application does not import directly is actually reachable.

### How it works

Given an SBOM and a finding, the transitive analyzer:

1. Derives the dependency graph from registry manifests (PyPI JSON API, npm
   registry) pinned by SBOM versions.
2. Computes all paths from the application's direct dependencies to the
   vulnerable package.
3. Walks each path in reverse, one hop at a time, fetching package source from
   the registry and running a reachability check at each step.
4. Short-circuits any path where an intermediate package has no caller of its
   downstream neighbor's exports.
5. Stitches per-hop call paths into a single continuous path from the
   application through every intermediate package to the vulnerable function.

No virtualenv, `node_modules`, or build system is required — package source is
fetched directly from the registry and content-addressed in
`~/.cache/cra-toolkit/pkgs/`.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--transitive` | `true` | Enable transitive analysis. Set to `false` for direct-only behavior. |
| `--transitive-cache-dir` | `~/.cache/cra-toolkit/pkgs` | Override the package tarball cache location. |

### Bounds

Bounds are configurable through the product-config YAML:

```yaml
reachability:
  transitive:
    max_hops: 8
    max_paths: 16
    max_target_symbols_per_hop: 256
    hop_timeout: 30s
    finding_budget: 5m
```

### Degradation evidence

When analysis cannot produce a clean verdict, the VEX output records a structured
reason: `transitive_not_applicable`, `source_unavailable`, `bound_exceeded`,
`path_broken`, `digest_mismatch`, and others. See the implementation spec at
`docs/superpowers/specs/2026-04-10-transitive-reachability-design.md` for the
complete taxonomy.
```

- [ ] **Step 2: Verify mkdocs build**

```
task docs:build
```

Expected: build succeeds.

- [ ] **Step 3: Commit**

```
git add site/docs/tools/vex.md
git commit -m "docs(site): document transitive reachability analysis"
```

---

## Task 24: Showcase entry

**Files:**
- Modify: `Taskfile.yml` (add showcase task entry)
- Modify: `showcase/README.md` (if it exists, add a line)

- [ ] **Step 1: Add showcase:transitive task**

Append to `Taskfile.yml` after `showcase:reachability`:

```yaml
  showcase:transitive:
    desc: Run VEX with transitive reachability against cross-package fixtures
    deps: [build]
    cmds:
      - mkdir -p showcase/01-vex
      - ./bin/cra vex --sbom testdata/integration/python-realworld-cross-package/sbom.cdx.json --scan testdata/integration/python-realworld-cross-package/trivy.json --source-dir testdata/integration/python-realworld-cross-package/source --output-format openvex --output showcase/01-vex/transitive-python-reachable.openvex.json
      - ./bin/cra vex --sbom testdata/integration/python-realworld-cross-package-safe/sbom.cdx.json --scan testdata/integration/python-realworld-cross-package-safe/trivy.json --source-dir testdata/integration/python-realworld-cross-package-safe/source --output-format openvex --output showcase/01-vex/transitive-python-safe.openvex.json
```

Also add `- task: showcase:transitive` to the `showcase:` composite target's `cmds` list after `showcase:reachability`.

- [ ] **Step 2: Run it manually to verify**

```
task showcase:transitive
```

Expected: both output files produced. The first should report `affected` with a stitched call path; the second should report `not_affected` with a `path_broken` degradation reason.

- [ ] **Step 3: Commit**

```
git add Taskfile.yml
git commit -m "feat(showcase): add transitive reachability showcase target"
```

---

## Task 25: Final full-suite verification and plan closure

- [ ] **Step 1: Run quality gates**

```
task quality
```

Expected: all format, vet, lint, and test checks PASS.

- [ ] **Step 2: Run the integration suite**

```
task test:integration:realworld
task test:transitive
```

Expected: all tests PASS, including the four new cross-package fixtures.

- [ ] **Step 3: Verify the CLI smoke test**

```
./bin/cra vex --help | grep transitive
./bin/cra vex \
  --sbom testdata/integration/python-realworld-cross-package/sbom.cdx.json \
  --scan testdata/integration/python-realworld-cross-package/trivy.json \
  --source-dir testdata/integration/python-realworld-cross-package/source \
  --output-format openvex
```

Expected: OpenVEX output containing an `affected` statement with a `reached_by` call path that spans `app.py → requests → urllib3`.

- [ ] **Step 4: Final commit of any touched files**

```
git status
# If anything is still modified:
git add <files>
git commit -m "chore(transitive): final polish after end-to-end verification"
```

---

## Self-review checklist (engineer executes before marking plan complete)

1. All tasks' checkboxes are checked.
2. `task quality` is green.
3. `task test:transitive` is green with all four cross-package fixtures passing.
4. `cra vex --transitive=false` still works (direct-only fallback preserved).
5. Cache dir defaults to `~/.cache/cra-toolkit/pkgs/` on the engineer's OS.
6. VEX output for a transitive reach contains a stitched `reached_by` path with nodes from the app, at least one intermediate dep, and the vulnerable symbol.
7. VEX output for a short-circuited path contains a `Degradations` entry naming the broken hop (`path_broken:werkzeug` or similar).
8. None of the existing `testdata/integration/*-realworld-transitive` tests regressed.
9. Python and JavaScript LLM judge tests cover the new cross-package fixtures.
10. Documentation site has a Transitive Reachability section.
