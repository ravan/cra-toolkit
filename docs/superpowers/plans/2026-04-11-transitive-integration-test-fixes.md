# Transitive Reachability Integration Test Fixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix three compounding bugs that cause all four transitive reachability integration tests to fail, and replace the JavaScript test fixtures with a statically-analyzable package pair.

**Architecture:** Eight independent tasks executed in order: NPM layout fix → degradation constant → CycloneDX direct-deps parser → wire layer update → test helper update → JS fixture replacement → Python fixture fix → LLM judge updates. Each task is independently committable and testable.

**Tech Stack:** Go, CycloneDX BOM (cyclonedx-go library), tree-sitter, npm (body-parser@1.19.0/qs@6.7.0), PyPI (requests/urllib3)

**Spec:** `docs/superpowers/specs/2026-04-11-transitive-integration-test-fixes-design.md`

---

## File Map

| File | Change |
|------|--------|
| `pkg/vex/reachability/transitive/fetcher_npm.go` | Delete `npmPkgDir`; rename `package/`→`<name>/` in `unpackAndCache`; add `path/filepath` import |
| `pkg/vex/reachability/transitive/fetcher_npm_test.go` | Add assertion that `<pkgname>/` subdir exists in SourceDir |
| `pkg/vex/reachability/transitive/degradation.go` | Add `ReasonRootsUnknown` constant |
| `pkg/formats/cyclonedx/cyclonedx.go` | Add `ParseDirectDeps(path string) []string` and `resolveRefName` helpers; add `"os"` import |
| `pkg/formats/cyclonedx/cyclonedx_test.go` | Add `TestParseDirectDeps_*` tests |
| `pkg/vex/transitive_wire.go` | Add `directDeps []string` param to `buildTransitiveSummary`; update roots logic |
| `pkg/vex/transitive_wire_test.go` | Update all 5 call sites to pass `nil`; add `TestBuildTransitiveSummary_WithDirectDeps` |
| `pkg/vex/vex.go` | Call `cyclonedx.ParseDirectDeps` after `parseSBOM`; thread `directDeps` through `buildFilterChain` and `buildAnalyzers` |
| `pkg/vex/reachability/transitive/integration_test.go` | Extend `cdxDoc` + `parseSBOMForTest` for dependency-block root identification; add `cdxDependency` struct; update JS test targets |
| `testdata/integration/javascript-realworld-cross-package/*` | Replace: new body-parser/qs fixtures (reachable) |
| `testdata/integration/javascript-realworld-cross-package-safe/*` | Replace: new body-parser/qs fixtures (not reachable) |
| `testdata/integration/python-realworld-cross-package/sbom.cdx.json` | Add `metadata.component` application entry + app-level `dependencies` entry |
| `testdata/integration/python-realworld-cross-package-safe/sbom.cdx.json` | Same |
| `testdata/integration/python-realworld-cross-package-safe/source/app.py` | Replace `session.options()` with `Request.prepare()` |
| `testdata/integration/python-realworld-cross-package-safe/expected.json` | Update description and ground_truth_notes |
| `pkg/vex/reachability/javascript/llm_judge_test.go` | Update transitive judge test: new CVE, packages, SBOM root parsing |
| `pkg/vex/reachability/python/llm_judge_test.go` | Update not-reachable description in prompt |

---

## Task 1: Fix NPM Layout Normalization

**Files:**
- Modify: `pkg/vex/reachability/transitive/fetcher_npm.go`
- Modify: `pkg/vex/reachability/transitive/fetcher_npm_test.go`

- [ ] **Step 1: Add failing assertion to TestNPMFetcher_Fetch**

In `fetcher_npm_test.go`, after the existing walk for `.js` files (line 90), add:

```go
// Verify the package is unpacked under <pkgname>/ not package/
lodashDir := filepath.Join(res.SourceDir, "lodash")
if _, err := os.Stat(lodashDir); os.IsNotExist(err) {
    t.Errorf("expected lodash/ subdir in SourceDir %s; old package/ layout still used", res.SourceDir)
}
```

Also add `"path/filepath"` to the import block if not already present (it already imports `"path/filepath"`).

- [ ] **Step 2: Run the test to confirm it fails**

```bash
cd pkg/vex/reachability/transitive && go test -run TestNPMFetcher_Fetch -v .
```

Expected: FAIL — `expected lodash/ subdir`

- [ ] **Step 3: Fix `unpackAndCache` and delete `npmPkgDir`**

Replace the entire `unpackAndCache` function and delete `npmPkgDir` in `fetcher_npm.go`:

```go
func (f *NPMFetcher) unpackAndCache(name, cacheKey string, body []byte) (string, error) {
	tmp, err := os.MkdirTemp("", "npm-*")
	if err != nil {
		return "", err
	}
	if err := untarGz(body, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return "", fmt.Errorf("unpack npm %s: %w", name, err)
	}

	// npm tarballs always unpack to a "package/" subdirectory. Rename it to
	// "<name>/" so modulePrefix can find the package name in the file path.
	packageDir := filepath.Join(tmp, "package")
	namedDir := filepath.Join(tmp, name)
	if st, err := os.Stat(packageDir); err == nil && st.IsDir() {
		if renameErr := os.Rename(packageDir, namedDir); renameErr != nil {
			_ = os.RemoveAll(tmp)
			return "", fmt.Errorf("rename npm package dir %s → %s: %w", packageDir, namedDir, renameErr)
		}
	}

	if f.Cache == nil {
		return tmp, nil
	}
	p, putErr := f.Cache.Put(cacheKey, tmp)
	_ = os.RemoveAll(tmp)
	if putErr != nil {
		return "", putErr
	}
	return p, nil
}
```

Add `"path/filepath"` to the import block. Delete the `npmPkgDir` function entirely (lines 126–132).

- [ ] **Step 4: Run all NPM fetcher tests**

```bash
cd pkg/vex/reachability/transitive && go test -run TestNPMFetcher -v .
```

Expected: PASS for all three `TestNPMFetcher_*` tests.

- [ ] **Step 5: Run full package test suite**

```bash
task test 2>&1 | tail -20
```

Expected: no new failures.

- [ ] **Step 6: Commit**

```bash
git add pkg/vex/reachability/transitive/fetcher_npm.go \
        pkg/vex/reachability/transitive/fetcher_npm_test.go
git commit -m "fix(npm): normalize tarball layout — rename package/ to <name>/, return parent as SourceDir"
```

---

## Task 2: Add ReasonRootsUnknown Constant

**Files:**
- Modify: `pkg/vex/reachability/transitive/degradation.go`

- [ ] **Step 1: Add the constant**

In `degradation.go`, append to the `const` block:

```go
	ReasonRootsUnknown = "roots_unknown"
```

The full const block becomes:
```go
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
	ReasonRootsUnknown            = "roots_unknown"
)
```

- [ ] **Step 2: Commit**

```bash
git add pkg/vex/reachability/transitive/degradation.go
git commit -m "feat(transitive): add ReasonRootsUnknown degradation constant"
```

---

## Task 3: Add ParseDirectDeps to CycloneDX Parser

**Files:**
- Modify: `pkg/formats/cyclonedx/cyclonedx.go`
- Modify: `pkg/formats/cyclonedx/cyclonedx_test.go`

- [ ] **Step 1: Write failing tests**

Add to `cyclonedx_test.go` (inside `package cyclonedx_test`):

```go
func TestParseDirectDeps_WithDependencies(t *testing.T) {
	const sbom = `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {
			"component": {"bom-ref": "my-app", "type": "application", "name": "my-app"}
		},
		"components": [
			{"bom-ref": "pkg:npm/body-parser@1.19.0", "name": "body-parser", "version": "1.19.0", "purl": "pkg:npm/body-parser@1.19.0"},
			{"bom-ref": "pkg:npm/qs@6.7.0", "name": "qs", "version": "6.7.0", "purl": "pkg:npm/qs@6.7.0"}
		],
		"dependencies": [
			{"ref": "my-app", "dependsOn": ["pkg:npm/body-parser@1.19.0"]},
			{"ref": "pkg:npm/body-parser@1.19.0", "dependsOn": ["pkg:npm/qs@6.7.0"]}
		]
	}`
	path := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(path, []byte(sbom), 0o600); err != nil {
		t.Fatal(err)
	}
	got := cyclonedx.ParseDirectDeps(path)
	if len(got) != 1 || got[0] != "body-parser" {
		t.Errorf("ParseDirectDeps: got %v, want [body-parser]", got)
	}
}

func TestParseDirectDeps_PURLWithQualifiers(t *testing.T) {
	// Syft-generated SBOMs use PURLs with package-id qualifiers as dependency refs.
	const sbom = `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {
			"component": {"bom-ref": "my-app", "type": "application", "name": "my-app"}
		},
		"components": [
			{"bom-ref": "abc123", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0?package-id=abc123"}
		],
		"dependencies": [
			{"ref": "my-app", "dependsOn": ["pkg:pypi/requests@2.31.0?package-id=abc123"]}
		]
	}`
	path := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(path, []byte(sbom), 0o600); err != nil {
		t.Fatal(err)
	}
	got := cyclonedx.ParseDirectDeps(path)
	if len(got) != 1 || got[0] != "requests" {
		t.Errorf("ParseDirectDeps: got %v, want [requests]", got)
	}
}

func TestParseDirectDeps_NoMetadataComponent(t *testing.T) {
	const sbom = `{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}`
	path := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(path, []byte(sbom), 0o600); err != nil {
		t.Fatal(err)
	}
	got := cyclonedx.ParseDirectDeps(path)
	if len(got) != 0 {
		t.Errorf("ParseDirectDeps: got %v, want []", got)
	}
}

func TestParseDirectDeps_NoDependenciesBlock(t *testing.T) {
	const sbom = `{
		"bomFormat": "CycloneDX",
		"metadata": {"component": {"bom-ref": "my-app"}},
		"components": [{"name": "flask", "purl": "pkg:pypi/flask@2.3.0"}]
	}`
	path := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(path, []byte(sbom), 0o600); err != nil {
		t.Fatal(err)
	}
	got := cyclonedx.ParseDirectDeps(path)
	if len(got) != 0 {
		t.Errorf("ParseDirectDeps: got %v, want []", got)
	}
}
```

Add these imports to `cyclonedx_test.go`:
```go
import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats/cyclonedx"
)
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd pkg/formats/cyclonedx && go test -run TestParseDirectDeps -v .
```

Expected: FAIL — `ParseDirectDeps undefined`

- [ ] **Step 3: Implement ParseDirectDeps in cyclonedx.go**

Add `"os"` to the import block in `cyclonedx.go`. Then append these functions after `flattenCDXComponents`:

```go
// ParseDirectDeps returns the names of packages listed as direct dependencies
// of the application component in a CycloneDX SBOM's dependencies block.
// Returns nil when the file cannot be read, is not valid CycloneDX, or the
// metadata component has no dependsOn entry.
func ParseDirectDeps(path string) []string {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck

	bom := new(cdx.BOM)
	if err := cdx.NewBOMDecoder(f, cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		return nil
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return nil
	}
	appRef := bom.Metadata.Component.BOMRef
	if appRef == "" || bom.Dependencies == nil {
		return nil
	}

	// Build bom-ref → name map for components that carry a BOMRef.
	refToName := make(map[string]string)
	if bom.Components != nil {
		for _, c := range *bom.Components {
			if c.BOMRef != "" {
				refToName[c.BOMRef] = c.Name
			}
		}
	}

	for _, dep := range *bom.Dependencies {
		if dep.Ref != appRef || dep.Dependencies == nil {
			continue
		}
		var names []string
		for _, childRef := range *dep.Dependencies {
			if n := resolveRefName(childRef, refToName); n != "" {
				names = append(names, n)
			}
		}
		return names
	}
	return nil
}

// resolveRefName resolves a CycloneDX dependency ref to a package name.
// It first checks the bom-ref map, then falls back to PURL name extraction.
// Handles Syft-style qualifiers: "pkg:pypi/requests@2.31.0?package-id=xxx" → "requests".
func resolveRefName(ref string, refToName map[string]string) string {
	if n, ok := refToName[ref]; ok {
		return n
	}
	// PURL extraction: "pkg:<type>/<name>@<version>[?qualifiers]"
	if purl, err := packageurl.FromString(ref); err == nil {
		return purl.Name
	}
	return ""
}
```

- [ ] **Step 4: Run the tests**

```bash
cd pkg/formats/cyclonedx && go test -run TestParseDirectDeps -v .
```

Expected: all four `TestParseDirectDeps_*` PASS.

- [ ] **Step 5: Run full suite**

```bash
task test 2>&1 | tail -20
```

Expected: no failures.

- [ ] **Step 6: Commit**

```bash
git add pkg/formats/cyclonedx/cyclonedx.go pkg/formats/cyclonedx/cyclonedx_test.go
git commit -m "feat(cyclonedx): add ParseDirectDeps — extract direct dep names from dependencies block"
```

---

## Task 4: Update buildTransitiveSummary and Thread directDeps

**Files:**
- Modify: `pkg/vex/transitive_wire.go`
- Modify: `pkg/vex/transitive_wire_test.go`
- Modify: `pkg/vex/vex.go`

- [ ] **Step 1: Add failing test for directDeps-based root identification**

In `transitive_wire_test.go`, add after `TestBuildTransitiveSummary_Roots`:

```go
func TestBuildTransitiveSummary_WithDirectDeps(t *testing.T) {
	components := []formats.Component{
		{Name: "flask", Version: "2.3.0", PURL: "pkg:pypi/flask@2.3.0", Type: "pypi"},
		{Name: "werkzeug", Version: "2.3.0", PURL: "pkg:pypi/werkzeug@2.3.0", Type: "pypi"},
	}
	// Only flask is a direct dep; werkzeug is transitive.
	summary := buildTransitiveSummary(components, []string{"flask"}, "pypi")
	if len(summary.Roots) != 1 || summary.Roots[0] != "flask" {
		t.Errorf("roots: got %v, want [flask]", summary.Roots)
	}
}

func TestBuildTransitiveSummary_DirectDepsFilteredToEcosystem(t *testing.T) {
	// directDeps may contain names from other ecosystems; only matching ones become roots.
	summary := buildTransitiveSummary(testComponents(), []string{"flask", "express"}, "pypi")
	if len(summary.Roots) != 1 || summary.Roots[0] != "flask" {
		t.Errorf("roots: got %v, want [flask]", summary.Roots)
	}
}

func TestBuildTransitiveSummary_FallbackWhenNoDirectDeps(t *testing.T) {
	components := []formats.Component{
		{Name: "flask", Version: "2.3.0", PURL: "pkg:pypi/flask@2.3.0", Type: "pypi"},
		{Name: "werkzeug", Version: "2.3.0", PURL: "pkg:pypi/werkzeug@2.3.0", Type: "pypi"},
	}
	// nil directDeps → all packages become roots (fallback).
	summary := buildTransitiveSummary(components, nil, "pypi")
	if len(summary.Roots) != 2 {
		t.Errorf("fallback roots: got %d, want 2", len(summary.Roots))
	}
}
```

- [ ] **Step 2: Run to confirm compilation failure**

```bash
cd pkg/vex && go test -run TestBuildTransitiveSummary_WithDirectDeps -v . 2>&1 | head -20
```

Expected: compile error — `buildTransitiveSummary` called with wrong number of args.

- [ ] **Step 3: Update buildTransitiveSummary in transitive_wire.go**

Replace the function body of `buildTransitiveSummary`:

```go
// buildTransitiveSummary projects a flat []formats.Component slice into the
// minimal SBOMSummary the transitive analyzer needs. Components are filtered to
// those whose PURL starts with "pkg:<ecosystem>/" (e.g. "pkg:pypi/" or
// "pkg:npm/"). directDeps names the application's declared direct dependencies;
// only those that appear in the filtered set become roots. When directDeps is
// empty the function falls back to treating all filtered packages as roots.
func buildTransitiveSummary(components []formats.Component, directDeps []string, ecosystem string) *transitive.SBOMSummary {
	prefix := "pkg:" + ecosystem + "/"
	pkgs := make([]transitive.Package, 0, len(components))
	pkgNameSet := make(map[string]bool)

	for i := range components {
		if !strings.HasPrefix(components[i].PURL, prefix) {
			continue
		}
		pkgs = append(pkgs, transitive.Package{
			Name:    components[i].Name,
			Version: components[i].Version,
		})
		pkgNameSet[components[i].Name] = true
	}

	// Build roots from declared direct deps intersected with the ecosystem set.
	var roots []string
	for _, dep := range directDeps {
		if pkgNameSet[dep] {
			roots = append(roots, dep)
		}
	}
	// Fallback: all ecosystem packages are roots when no direct deps are known.
	if len(roots) == 0 {
		for _, p := range pkgs {
			roots = append(roots, p.Name)
		}
	}

	return &transitive.SBOMSummary{
		Packages: pkgs,
		Roots:    roots,
	}
}
```

- [ ] **Step 4: Fix all existing call sites in transitive_wire_test.go**

Update every call to pass `nil` as the second argument:

- Line 25: `buildTransitiveSummary(testComponents(), nil, "pypi")`
- Line 49: `buildTransitiveSummary(testComponents(), nil, "npm")`
- Line 59: `buildTransitiveSummary(testComponents(), nil, "cargo")`
- Line 69: `buildTransitiveSummary(nil, nil, "pypi")`
- Line 83: `buildTransitiveSummary(components, nil, "pypi")`

- [ ] **Step 5: Thread directDeps through vex.go**

In `vex.go:Run()`, after the `parseSBOM` call (around line 139), add:

```go
	directDeps := cyclonedx.ParseDirectDeps(opts.SBOMPath)
```

Then update the `buildFilterChain` call at line ~164 to pass `directDeps`:

```go
	filters := buildFilterChain(upstreamStatements, opts.SourceDir, components, directDeps, transitiveCfg, cfg.ExtraFilters, cfg.ExtraAnalyzers)
```

Update the `buildFilterChain` signature (line ~265):

```go
func buildFilterChain(upstreamStatements []formats.VEXStatement, sourceDir string, components []formats.Component, directDeps []string, transitiveCfg transitive.Config, extraFilters []Filter, extraAnalyzers map[string]reachability.Analyzer) []Filter {
```

Inside `buildFilterChain`, update the `buildAnalyzers` call (line ~283):

```go
		analyzers := buildAnalyzers(sourceDir, components, directDeps, transitiveCfg, extraAnalyzers)
```

Update the `buildAnalyzers` signature (line ~299):

```go
func buildAnalyzers(sourceDir string, components []formats.Component, directDeps []string, transitiveCfg transitive.Config, extra map[string]reachability.Analyzer) map[string]reachability.Analyzer {
```

Inside `buildAnalyzers`, update both `buildTransitiveSummary` calls (lines ~313, ~320):

```go
				a.SBOMSummary = buildTransitiveSummary(components, directDeps, "pypi")
```
```go
				a.SBOMSummary = buildTransitiveSummary(components, directDeps, "npm")
```

Ensure `cyclonedx` is imported in `vex.go`. It is already imported (used at line 212 as `cyclonedx.Parser{}`). Verify the import alias is `cyclonedx "github.com/ravan/cra-toolkit/pkg/formats/cyclonedx"`.

- [ ] **Step 6: Run the wire tests**

```bash
cd pkg/vex && go test -run TestBuildTransitiveSummary -v .
```

Expected: all `TestBuildTransitiveSummary_*` PASS including the three new ones.

- [ ] **Step 7: Run full suite**

```bash
task test 2>&1 | tail -20
```

Expected: no failures.

- [ ] **Step 8: Commit**

```bash
git add pkg/vex/transitive_wire.go pkg/vex/transitive_wire_test.go pkg/vex/vex.go
git commit -m "feat(vex): derive SBOM roots from CycloneDX dependencies block; fallback to all-packages"
```

---

## Task 5: Update parseSBOMForTest for Root Identification

**Files:**
- Modify: `pkg/vex/reachability/transitive/integration_test.go`

- [ ] **Step 1: Add cdxDependency struct and extend cdxDoc**

In `integration_test.go`, update the `cdxDoc` and `cdxComponent` structs (around lines 42–51):

```go
type cdxComponent struct {
	BOMRef  string `json:"bom-ref"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type cdxDoc struct {
	Metadata struct {
		Component struct {
			BOMRef string `json:"bom-ref"`
		} `json:"component"`
	} `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies"`
}
```

- [ ] **Step 2: Replace parseSBOMForTest body**

Replace the function body of `parseSBOMForTest` (lines 52–78):

```go
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

	// Build bom-ref → name map and collect ecosystem packages.
	refToName := make(map[string]string)
	var pkgs []Package
	pkgNameSet := make(map[string]bool)
	for _, c := range doc.Components {
		if c.BOMRef != "" {
			refToName[c.BOMRef] = c.Name
		}
		if !strings.HasPrefix(c.PURL, prefix) {
			continue
		}
		pkgs = append(pkgs, Package{Name: c.Name, Version: c.Version})
		pkgNameSet[c.Name] = true
	}
	if len(pkgs) == 0 {
		t.Fatalf("no %s components in sbom %s", ecosystem, path)
	}

	// Derive roots from the metadata application component's dependsOn.
	appRef := doc.Metadata.Component.BOMRef
	var roots []string
	if appRef != "" {
		for _, dep := range doc.Dependencies {
			if dep.Ref != appRef {
				continue
			}
			for _, childRef := range dep.DependsOn {
				name := sbomRefName(childRef, refToName)
				if pkgNameSet[name] {
					roots = append(roots, name)
				}
			}
			break
		}
	}
	if len(roots) == 0 {
		t.Logf("SBOM %s: no application-level dependsOn found — using all %s packages as roots (degraded)", path, ecosystem)
		for _, p := range pkgs {
			roots = append(roots, p.Name)
		}
	}

	return &SBOMSummary{Packages: pkgs, Roots: roots}
}

// sbomRefName resolves a CycloneDX dependency ref to a package name.
// Tries the bom-ref map first, then extracts from PURL:
// "pkg:pypi/requests@2.31.0?package-id=abc" → "requests"
func sbomRefName(ref string, refToName map[string]string) string {
	if n, ok := refToName[ref]; ok {
		return n
	}
	// PURL: "pkg:<type>/<name>@<version>[?qualifiers]"
	// Find the last "/" before "@" or "?"
	slashIdx := strings.LastIndex(ref, "/")
	if slashIdx < 0 {
		return ""
	}
	nameVer := ref[slashIdx+1:]
	if atIdx := strings.IndexByte(nameVer, '@'); atIdx >= 0 {
		return nameVer[:atIdx]
	}
	if qIdx := strings.IndexByte(nameVer, '?'); qIdx >= 0 {
		return nameVer[:qIdx]
	}
	return nameVer
}
```

- [ ] **Step 3: Verify compilation**

```bash
cd pkg/vex/reachability/transitive && go build -tags integration . 2>&1
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add pkg/vex/reachability/transitive/integration_test.go
git commit -m "test(transitive): parseSBOMForTest derives roots from CycloneDX dependencies block"
```

---

## Task 6: Replace JavaScript Fixtures

**Files:**
- Replace: `testdata/integration/javascript-realworld-cross-package/source/app.js`
- Replace: `testdata/integration/javascript-realworld-cross-package/sbom.cdx.json`
- Replace: `testdata/integration/javascript-realworld-cross-package/expected.json`
- Replace: `testdata/integration/javascript-realworld-cross-package/trivy.json`
- Replace: `testdata/integration/javascript-realworld-cross-package-safe/source/app.js`
- Replace: `testdata/integration/javascript-realworld-cross-package-safe/sbom.cdx.json`
- Replace: `testdata/integration/javascript-realworld-cross-package-safe/expected.json`
- Replace: `testdata/integration/javascript-realworld-cross-package-safe/trivy.json`
- Modify: `pkg/vex/reachability/transitive/integration_test.go`

> **Before writing files:** Verify body-parser@1.19.0 depends on qs@6.7.0:
> ```bash
> curl -s https://registry.npmjs.org/body-parser/1.19.0 | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['dependencies'].get('qs'))"
> ```
> Expected output: `6.7.0`
> If a different qs version is shown, update the fixture files and integration test to use that version.

- [ ] **Step 1: Write the reachable JavaScript app fixture**

`testdata/integration/javascript-realworld-cross-package/source/app.js`:

```javascript
// App that processes URL-encoded form bodies.
// body-parser.urlencoded({ extended: true }) internally calls qs.parse,
// reaching CVE-2022-24999 (prototype pollution in qs < 6.10.3).

const bodyParser = require('body-parser')

const parseUrlEncoded = bodyParser.urlencoded({ extended: true })

function handleFormSubmit(req, res, next) {
  parseUrlEncoded(req, res, next)
}

module.exports = { handleFormSubmit }
```

- [ ] **Step 2: Write the reachable SBOM**

`testdata/integration/javascript-realworld-cross-package/sbom.cdx.json`:

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:b1c2d3e4-f5a6-7890-bcde-f01234567891",
  "version": 1,
  "metadata": {
    "timestamp": "2026-04-11T00:00:00Z",
    "component": {
      "bom-ref": "my-app",
      "type": "application",
      "name": "my-app",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "bom-ref": "pkg:npm/body-parser@1.19.0",
      "type": "library",
      "name": "body-parser",
      "version": "1.19.0",
      "purl": "pkg:npm/body-parser@1.19.0"
    },
    {
      "bom-ref": "pkg:npm/qs@6.7.0",
      "type": "library",
      "name": "qs",
      "version": "6.7.0",
      "purl": "pkg:npm/qs@6.7.0"
    }
  ],
  "dependencies": [
    { "ref": "my-app", "dependsOn": ["pkg:npm/body-parser@1.19.0"] },
    { "ref": "pkg:npm/body-parser@1.19.0", "dependsOn": ["pkg:npm/qs@6.7.0"] }
  ]
}
```

- [ ] **Step 3: Write the reachable expected.json**

`testdata/integration/javascript-realworld-cross-package/expected.json`:

```json
{
  "description": "App using body-parser.urlencoded({ extended: true }) reaching CVE-2022-24999 in qs through body-parser's extended URL-encoding path.",
  "provenance": {
    "source_project": "expressjs/body-parser",
    "source_url": "https://github.com/expressjs/body-parser",
    "commit": "1.19.0",
    "cve": "CVE-2022-24999",
    "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-24999",
    "language": "javascript",
    "pattern": "cross-package-transitive",
    "ground_truth_notes": "handleFormSubmit → bodyParser.urlencoded (body-parser/lib/types/urlencoded.js) → qs.parse (vulnerable prototype pollution)"
  },
  "findings": [
    {
      "cve": "CVE-2022-24999",
      "component_purl": "pkg:npm/qs@6.7.0",
      "expected_status": "affected",
      "expected_confidence": "medium",
      "expected_resolved_by": "transitive_reachability",
      "human_justification": "bodyParser.urlencoded({ extended: true }) calls qs.parse via body-parser/lib/types/urlencoded.js; qs@6.7.0 is vulnerable (fixed in 6.7.3)."
    }
  ]
}
```

- [ ] **Step 4: Write the reachable trivy.json**

`testdata/integration/javascript-realworld-cross-package/trivy.json`:

```json
{
  "SchemaVersion": 2,
  "ArtifactName": "javascript-realworld-cross-package",
  "ArtifactType": "filesystem",
  "Results": [
    {
      "Target": "sbom.cdx.json",
      "Class": "lang-pkgs",
      "Type": "node-pkg",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2022-24999",
          "PkgName": "qs",
          "InstalledVersion": "6.7.0",
          "FixedVersion": "6.10.3",
          "Severity": "HIGH"
        }
      ]
    }
  ]
}
```

- [ ] **Step 5: Write the safe JavaScript app fixture**

`testdata/integration/javascript-realworld-cross-package-safe/source/app.js`:

```javascript
// App that accepts JSON bodies only.
// body-parser.json() uses JSON.parse internally — qs is never called.
// CVE-2022-24999 in qs@6.7.0 is not reachable from this code path.

const bodyParser = require('body-parser')

const parseJson = bodyParser.json()

function handleJsonPost(req, res, next) {
  parseJson(req, res, next)
}

module.exports = { handleJsonPost }
```

- [ ] **Step 6: Write the safe SBOM (identical component set)**

`testdata/integration/javascript-realworld-cross-package-safe/sbom.cdx.json`:

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:c2d3e4f5-a6b7-8901-cdef-012345678912",
  "version": 1,
  "metadata": {
    "timestamp": "2026-04-11T00:00:00Z",
    "component": {
      "bom-ref": "my-app",
      "type": "application",
      "name": "my-app",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "bom-ref": "pkg:npm/body-parser@1.19.0",
      "type": "library",
      "name": "body-parser",
      "version": "1.19.0",
      "purl": "pkg:npm/body-parser@1.19.0"
    },
    {
      "bom-ref": "pkg:npm/qs@6.7.0",
      "type": "library",
      "name": "qs",
      "version": "6.7.0",
      "purl": "pkg:npm/qs@6.7.0"
    }
  ],
  "dependencies": [
    { "ref": "my-app", "dependsOn": ["pkg:npm/body-parser@1.19.0"] },
    { "ref": "pkg:npm/body-parser@1.19.0", "dependsOn": ["pkg:npm/qs@6.7.0"] }
  ]
}
```

- [ ] **Step 7: Write the safe expected.json**

`testdata/integration/javascript-realworld-cross-package-safe/expected.json`:

```json
{
  "description": "App using body-parser.json() only — JSON parsing uses JSON.parse, never calls qs.parse. CVE-2022-24999 in qs@6.7.0 is not reachable.",
  "provenance": {
    "source_project": "expressjs/body-parser",
    "source_url": "https://github.com/expressjs/body-parser",
    "commit": "1.19.0",
    "cve": "CVE-2022-24999",
    "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-24999",
    "language": "javascript",
    "pattern": "cross-package-transitive-safe",
    "ground_truth_notes": "handleJsonPost → bodyParser.json() → JSON.parse; qs.parse is never called."
  },
  "findings": [
    {
      "cve": "CVE-2022-24999",
      "component_purl": "pkg:npm/qs@6.7.0",
      "expected_status": "not_affected",
      "expected_confidence": "medium",
      "expected_resolved_by": "transitive_reachability",
      "human_justification": "bodyParser.json() is the only body-parser API invoked; body-parser/lib/types/json.js uses JSON.parse with no qs dependency."
    }
  ]
}
```

- [ ] **Step 8: Write the safe trivy.json**

`testdata/integration/javascript-realworld-cross-package-safe/trivy.json`:

```json
{
  "SchemaVersion": 2,
  "ArtifactName": "javascript-realworld-cross-package-safe",
  "ArtifactType": "filesystem",
  "Results": [
    {
      "Target": "sbom.cdx.json",
      "Class": "lang-pkgs",
      "Type": "node-pkg",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2022-24999",
          "PkgName": "qs",
          "InstalledVersion": "6.7.0",
          "FixedVersion": "6.10.3",
          "Severity": "HIGH"
        }
      ]
    }
  ]
}
```

- [ ] **Step 9: Update integration_test.go JavaScript test targets**

In `integration_test.go`, replace lines 134–142:

```go
func TestIntegration_Transitive_JavaScriptReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "javascript-realworld-cross-package")
	runIntegrationFixture(t, dir, "javascript", "npm", "qs", "6.7.0", true)
}

func TestIntegration_Transitive_JavaScriptNotReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "javascript-realworld-cross-package-safe")
	runIntegrationFixture(t, dir, "javascript", "npm", "qs", "6.7.0", false)
}
```

- [ ] **Step 10: Verify compilation**

```bash
cd pkg/vex/reachability/transitive && go build -tags integration . 2>&1
```

Expected: no errors.

- [ ] **Step 11: Commit**

```bash
git add \
  testdata/integration/javascript-realworld-cross-package/ \
  testdata/integration/javascript-realworld-cross-package-safe/ \
  pkg/vex/reachability/transitive/integration_test.go
git commit -m "test(transitive): replace JS fixtures — body-parser/qs CVE-2022-24999 (statically provable split)"
```

---

## Task 7: Fix Python Fixtures

**Files:**
- Modify: `testdata/integration/python-realworld-cross-package/sbom.cdx.json`
- Modify: `testdata/integration/python-realworld-cross-package-safe/sbom.cdx.json`
- Replace: `testdata/integration/python-realworld-cross-package-safe/source/app.py`
- Replace: `testdata/integration/python-realworld-cross-package-safe/expected.json`

- [ ] **Step 1: Update both Python SBOMs with application component + dependency entry**

Both Python SBOMs share the same structure. Run this script from the repo root:

```bash
python3 - <<'EOF'
import json

for path in [
    "testdata/integration/python-realworld-cross-package/sbom.cdx.json",
    "testdata/integration/python-realworld-cross-package-safe/sbom.cdx.json",
]:
    with open(path) as f:
        d = json.load(f)

    # Replace file-type metadata.component with a proper application component.
    d["metadata"]["component"] = {
        "bom-ref": "my-app",
        "type": "application",
        "name": "my-app",
        "version": "1.0.0"
    }

    # Prepend the app-level dependency entry so parseSBOMForTest finds it.
    # The requests PURL includes the Syft package-id qualifier.
    app_dep = {
        "ref": "my-app",
        "dependsOn": ["pkg:pypi/requests@2.31.0?package-id=806df151b3bbaeda"]
    }
    d["dependencies"] = [app_dep] + d.get("dependencies", [])

    with open(path, "w") as f:
        json.dump(d, f, separators=(",", ":"))
    print(f"Updated {path}")
EOF
```

Verify the change took effect:
```bash
python3 -c "
import json
with open('testdata/integration/python-realworld-cross-package/sbom.cdx.json') as f:
    d = json.load(f)
print('metadata.component:', d['metadata']['component'])
print('first dep:', d['dependencies'][0])
"
```

Expected output:
```
metadata.component: {'bom-ref': 'my-app', 'type': 'application', 'name': 'my-app', 'version': '1.0.0'}
first dep: {'ref': 'my-app', 'dependsOn': ['pkg:pypi/requests@2.31.0?package-id=806df151b3bbaeda']}
```

- [ ] **Step 2: Replace the Python safe app source**

`testdata/integration/python-realworld-cross-package-safe/source/app.py`:

```python
# This app uses requests only for URL preparation (not sending).
# PreparedRequest.prepare() parses and normalises the URL using Python's
# stdlib urllib.parse — it does not open a connection or invoke urllib3.
# CVE-2023-43804 (urllib3 cookie leakage via redirect) is not reachable.

import requests


def validate_url(url):
    """Validates a URL by preparing — but not sending — a GET request."""
    req = requests.Request('GET', url)
    prepared = req.prepare()
    return prepared.url


if __name__ == "__main__":
    validate_url("https://example.com")
```

- [ ] **Step 3: Update the Python safe expected.json**

`testdata/integration/python-realworld-cross-package-safe/expected.json`:

```json
{
  "description": "App validates URLs via requests.PreparedRequest.prepare() without sending. No connection is opened; urllib3 is never invoked. CVE-2023-43804 is not reachable.",
  "provenance": {
    "source_project": "urllib3/urllib3",
    "source_url": "https://github.com/urllib3/urllib3",
    "commit": "2.0.5",
    "cve": "CVE-2023-43804",
    "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-43804",
    "language": "python",
    "pattern": "cross-package-transitive-safe",
    "ground_truth_notes": "validate_url → requests.Request.prepare() uses urllib.parse only; HTTPAdapter.send / urllib3.urlopen are never called."
  },
  "findings": [
    {
      "cve": "CVE-2023-43804",
      "component_purl": "pkg:pypi/urllib3@2.0.5",
      "expected_status": "not_affected",
      "expected_confidence": "medium",
      "expected_resolved_by": "transitive_reachability",
      "expected_justification": "vulnerable_code_not_in_execute_path",
      "human_justification": "PreparedRequest.prepare() performs URL parsing with stdlib urllib.parse; it does not open connections or invoke urllib3."
    }
  ]
}
```

- [ ] **Step 4: Verify compilation**

```bash
cd pkg/vex/reachability/transitive && go build -tags integration . 2>&1
```

- [ ] **Step 5: Commit**

```bash
git add \
  testdata/integration/python-realworld-cross-package/sbom.cdx.json \
  testdata/integration/python-realworld-cross-package-safe/sbom.cdx.json \
  testdata/integration/python-realworld-cross-package-safe/source/app.py \
  testdata/integration/python-realworld-cross-package-safe/expected.json
git commit -m "test(transitive): fix Python fixtures — PreparedRequest.prepare() safe app; add SBOM root entries"
```

---

## Task 8: Update LLM Judge Tests

**Files:**
- Modify: `pkg/vex/reachability/javascript/llm_judge_test.go`
- Modify: `pkg/vex/reachability/python/llm_judge_test.go`

- [ ] **Step 1: Update TestLLMJudge_JavaScriptTransitiveReachability**

In `pkg/vex/reachability/javascript/llm_judge_test.go`, update `TestLLMJudge_JavaScriptTransitiveReachability` (around lines 159–301):

**a) Update the finding struct** (was `follow-redirects`, now `qs`):

```go
	finding := &formats.Finding{
		AffectedName:    "qs",
		AffectedVersion: "6.7.0",
	}
```

**b) Update the SBOM parsing block** (was hardcoding all packages as roots — replace with ParseDirectDeps). Replace the manual SBOM parsing (lines ~175–197):

```go
	sbomPath := filepath.Join(reachableDir, "sbom.cdx.json")
	sbomData, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}
	var sbomDoc struct {
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(sbomData, &sbomDoc); err != nil {
		t.Fatalf("parse sbom: %v", err)
	}
	var pkgs []transitive.Package
	for _, c := range sbomDoc.Components {
		if strings.HasPrefix(c.PURL, "pkg:npm/") {
			pkgs = append(pkgs, transitive.Package{Name: c.Name, Version: c.Version})
		}
	}
	directDeps := cyclonedx.ParseDirectDeps(sbomPath)
	pkgNameSet := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		pkgNameSet[p.Name] = true
	}
	var roots []string
	for _, d := range directDeps {
		if pkgNameSet[d] {
			roots = append(roots, d)
		}
	}
	if len(roots) == 0 {
		for _, p := range pkgs {
			roots = append(roots, p.Name)
		}
	}
	summary := &transitive.SBOMSummary{Packages: pkgs, Roots: roots}
```

**c) Update the prompt** (replace the CVE description and chain):

```go
	prompt := fmt.Sprintf(`You are a security engineering judge evaluating a transitive dependency reachability analyzer for CRA compliance.

VULNERABILITY: CVE-2022-24999 — qs prototype pollution via __proto__ key in parsed query strings.
VULNERABLE PACKAGE: qs@6.7.0 (transitive dependency reached through body-parser@1.19.0)
CHAIN: app → bodyParser.urlencoded({ extended: true }) → body-parser/lib/types/urlencoded.js → qs.parse

REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%v, Confidence=%s, Degradations=%v
Call paths found: %s
Evidence: %s

NOT-REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%v, Confidence=%s, Degradations=%v
Evidence: %s

Score the transitive analyzer (1-10 each):
1. path_accuracy: Are the reported cross-package call paths real?
2. confidence_calibration: Does confidence reflect the uncertainty of transitive analysis?
3. evidence_quality: Is the stitched call path evidence sufficient for a VEX determination?
4. false_positive_rate: Is the not-reachable case (bodyParser.json) correctly identified as not-affected?
5. symbol_resolution: Are the cross-package symbols correctly resolved (urlencoded vs json)?
6. overall_quality: Would this analysis pass a CRA market surveillance authority review?

Respond ONLY with valid JSON:
{"path_accuracy": N, "confidence_calibration": N, "evidence_quality": N, "false_positive_rate": N, "symbol_resolution": N, "overall_quality": N, "reasoning": "brief explanation"}`,
		filepath.Join(reachableDir, "source"),
		reachableResult.Reachable, reachableResult.Confidence, reachableResult.Degradations,
		strings.Join(pathStrs, "; "),
		reachableResult.Evidence,
		filepath.Join(notReachableDir, "source"),
		notReachableResult.Reachable, notReachableResult.Confidence, notReachableResult.Degradations,
		notReachableResult.Evidence,
	)
```

**d) Add the cyclonedx import** at the top of the file (if not already present):
```go
	cdxformats "github.com/ravan/cra-toolkit/pkg/formats/cyclonedx"
```
And update the usage: `cyclonedx.ParseDirectDeps` → `cdxformats.ParseDirectDeps`.

- [ ] **Step 2: Update TestLLMJudge_PythonTransitiveReachability**

In `pkg/vex/reachability/python/llm_judge_test.go`, in `TestLLMJudge_PythonTransitiveReachability`:

**a) Update SBOM parsing** (same pattern as JS test above — replace all-packages-as-roots with ParseDirectDeps-based approach). Apply the same replacement as in step 1b but for `"pkg:pypi/"` instead of `"pkg:npm/"`.

**b) Update the not-reachable description in the prompt**. Find the prompt template and update the NOT-REACHABLE section to mention PreparedRequest:

Change from:
```
NOT-REACHABLE PROJECT uses Session.options() which does not invoke redirect handling
```

Change to:
```
NOT-REACHABLE PROJECT uses requests.Request.prepare() — URL preparation only, no network I/O, urllib3 never invoked
```

The exact prompt text will vary; find the not-reachable description string in the prompt and update it accordingly.

- [ ] **Step 3: Verify compilation**

```bash
cd pkg/vex/reachability/javascript && go build -tags llmjudge . 2>&1
cd pkg/vex/reachability/python && go build -tags llmjudge . 2>&1
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add \
  pkg/vex/reachability/javascript/llm_judge_test.go \
  pkg/vex/reachability/python/llm_judge_test.go
git commit -m "test(llmjudge): update transitive judge tests — body-parser/qs CVE, PreparedRequest safe app"
```

---

## Task 9: Run Integration Tests and Verify

- [ ] **Step 1: Run all four transitive integration tests**

```bash
go test -tags=integration \
  -run 'TestIntegration_Transitive' \
  ./pkg/vex/reachability/transitive/... \
  -v -timeout 15m 2>&1 | tee /tmp/integration-run.txt
```

This downloads body-parser, qs, requests, and urllib3 from the registries. Requires network access. Expected runtime: 2–8 minutes depending on cache state.

- [ ] **Step 2: Check results**

```bash
grep -E 'PASS|FAIL|reachable' /tmp/integration-run.txt
```

Expected:
```
--- PASS: TestIntegration_Transitive_PythonReachable
--- PASS: TestIntegration_Transitive_PythonNotReachable
--- PASS: TestIntegration_Transitive_JavaScriptReachable
--- PASS: TestIntegration_Transitive_JavaScriptNotReachable
```

- [ ] **Step 3: If any test fails, diagnose**

For each failing test, the error output will show `evidence:` and `degradations:`. Common failure modes:

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `reachable: want true, got false` + `source_unavailable` degradation | NPM layout fix didn't work; package dir not renamed | Check Task 1 |
| `reachable: want true, got false` + no degradation | PathsTo returns empty (wrong roots) | Check Task 4/5 SBOM parsing |
| `reachable: want false, got true` for Python | urllib3 still reachable from prepare() | Check Task 7 app.py |
| `reachable: want false, got true` for JS | bodyParser.json traces to qs somehow | Inspect body-parser source; qs.parse must not appear in json.js |

- [ ] **Step 4: Run the full non-integration test suite to ensure no regressions**

```bash
task test 2>&1 | tail -30
```

Expected: PASS.

---

## Self-Review Checklist

**Spec coverage:**
- ✓ Fix 1 (NPM layout): Task 1
- ✓ Fix 2 (ReasonRootsUnknown): Task 2
- ✓ Fix 3 (JS fixture redesign): Task 6
- ✓ Fix 4 (Python safe fixture): Task 7
- ✓ Fix 5 (Python SBOM updates): Task 7
- ✓ Fix 6 (LLM judge): Task 8
- ✓ ParseDirectDeps (required by Fix 3/4 wiring): Task 3
- ✓ buildTransitiveSummary + threading (required by Fix 3): Task 4
- ✓ parseSBOMForTest (required by Fix 3): Task 5
- ✓ Integration test verification: Task 9

**Type consistency:**
- `ParseDirectDeps(path string) []string` — used identically in Tasks 3, 4, 8
- `buildTransitiveSummary(components, directDeps, ecosystem)` — consistent across Tasks 4 and vex.go threading
- `sbomRefName` and `resolveRefName` are local helpers, not shared — no cross-task conflict
- `cdxDependency` struct defined once in integration_test.go (Task 5) and not referenced elsewhere

**No placeholders:** All code blocks are complete and compilable.
