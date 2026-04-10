# Transitive Reachability Integration Test Fixes — Design

**Date**: 2026-04-11  
**Status**: Approved

## Problem Summary

Three compounding bugs cause all four transitive reachability integration tests to fail. They mask each other: Bug 1 produces `source_unavailable` before Bugs 2 and 3 can be observed.

```
Bug 1 (npm layout) → zero exported symbols → source_unavailable verdict
  → hides Bug 2 (all packages are roots, trivial 1-element path short-circuits walk)
  → hides Bug 3 (Python safe app still routes through urllib3 → false positive)
```

A fourth structural problem exists: the JavaScript fixtures use `maxRedirects: 0` to signal "not reachable," which is a runtime-value distinction invisible to static call-graph analysis. Both JS apps would be marked `reachable` after Bugs 1–2 are fixed.

---

## Fix 1 — NPM Layout Normalization

**File**: `pkg/vex/reachability/transitive/fetcher_npm.go`

### Root cause

npm tarballs always unpack to a `package/` subdirectory. `npmPkgDir()` returns `tmp/package/` as `SourceDir`. When `modulePrefix` computes the relative path from `SourceDir` to any file, it starts *inside* `package/`, so the package name component is never present in the path. The filter skips every symbol → zero exported symbols → conservative `source_unavailable` verdict.

### Fix

After `untarGz`, rename `tmp/package` → `tmp/<pkgname>` and return `tmp` (the *parent*) as `SourceDir`. This mirrors the PyPI convention that `modulePrefix` already handles correctly.

```
Before:   SourceDir = tmp/package/        modulePrefix("tmp/package/index.js", ...) → "index"
After:    SourceDir = tmp/               modulePrefix("tmp/follow-redirects/index.js", ...) → "follow-redirects.index"
```

`unpackAndCache` performs the rename immediately after `untarGz`. `npmPkgDir` is deleted (no longer needed). Cache stores the normalized layout so the rename is done once per package version.

---

## Fix 2 — Root Identification from CycloneDX `dependencies`

**Files**: `pkg/vex/reachability/transitive/integration_test.go`, `pkg/vex/transitive_wire.go`

### Root cause

Both `parseSBOMForTest` and `buildTransitiveSummary` treat every component in the flat `components[]` list as a root. When `follow-redirects` is both listed and a root, `PathsTo("follow-redirects")` returns a trivial 1-element path `[follow-redirects]`. `WalkPath` short-circuits at `len(path) < 2` and returns all of follow-redirects's exports as `FinalTargets`. The app-side check then gates on whether the app imports follow-redirects directly — which it doesn't — yielding `not_reachable` for *both* apps.

### Fix

Parse the CycloneDX `dependencies` block to distinguish direct from transitive dependencies. Only packages listed in the *application component's* `dependsOn` become roots.

**CycloneDX structure consumed**:
```json
{
  "metadata": {
    "component": { "bom-ref": "my-app", "type": "application", "name": "my-app" }
  },
  "components": [...],
  "dependencies": [
    { "ref": "my-app", "dependsOn": ["pkg:npm/body-parser@1.19.2"] },
    { "ref": "pkg:npm/body-parser@1.19.2", "dependsOn": ["pkg:npm/qs@6.7.0"] }
  ]
}
```

**Parsing algorithm**:
1. Build `bomRef → Package` map from `components[].bom-ref`
2. Read `metadata.component.bom-ref` → application ref
3. Find `dependencies[ref == appRef].dependsOn` → direct dep refs
4. Resolve each ref to a Package name → roots list
5. **Fallback**: if `dependencies` block is absent or `dependsOn` is empty, use all packages as roots and emit a `ReasonRootsUnknown` degradation (backward-compatible, lower confidence)

**Production code (`buildTransitiveSummary`)**: Add a `directDeps []string` parameter. The caller (wherever the SBOM is read) extracts direct deps from the `dependencies` block and passes them in. If empty, falls back as above.

**Test code (`parseSBOMForTest`)**: Updated struct includes `Metadata.Component.BOMRef` and `Dependencies []cdxDependency`. Uses the same parsing algorithm.

**New degradation constant** (`degradation.go`):
```go
ReasonRootsUnknown = "roots_unknown"
```

---

## Fix 3 — JavaScript Fixture Redesign

**Directory**: `testdata/integration/javascript-realworld-cross-package{,-safe}/`

### Root cause

The current fixtures use `axios@0.25.0 → follow-redirects@1.14.0` with `maxRedirects: 0` as the "safe" signal. Two problems:
1. axios has a malicious preinstall script (excluded).
2. `maxRedirects: 0` is a runtime value — static call-graph analysis cannot distinguish `axios.get(url, { maxRedirects: 5 })` from `axios.get(url, { maxRedirects: 0 })`. Both apps would be `reachable` after Bugs 1–2 are fixed.

### New package pair

**CVE**: CVE-2022-24999 (qs prototype pollution via `__proto__`)  
**Direct dep**: `body-parser@1.19.2` (no preinstall scripts; widely trusted)  
**Vulnerable transitive dep**: `qs@6.7.0` (body-parser@1.19.2's declared dependency; CVE-2022-24999 fixed in qs 6.7.3+)

**Why this pair works statically**:

In `body-parser/lib/types/urlencoded.js`:
```javascript
var qs = require('qs')
// ...
function parseExtended (str) {
  return qs.parse(str, {allowPrototypes: true})  // explicit call
}
```

In `body-parser/lib/types/json.js` — no reference to `qs` whatsoever.

- `bodyParser.urlencoded({ extended: true })` → returns middleware that calls `parseExtended` → calls `qs.parse` directly
- `bodyParser.json()` → returns middleware that calls `JSON.parse`, never touches `qs`

This distinction is a **different function** (`urlencoded` vs `json`), not a runtime value. tree-sitter can resolve it.

### Fixture: `javascript-realworld-cross-package` (reachable)

**`source/app.js`**:
```javascript
// App that parses URL-encoded form bodies.
// body-parser.urlencoded internally calls qs.parse (CVE-2022-24999).
const bodyParser = require('body-parser')

const parseUrlEncoded = bodyParser.urlencoded({ extended: true })

function handleFormSubmit(req, res, next) {
  parseUrlEncoded(req, res, next)
}

module.exports = { handleFormSubmit }
```

**Call chain** (all explicit function calls, all statically traceable):
```
handleFormSubmit → parseUrlEncoded [bodyParser.urlencoded return value]
  → body-parser/lib/types/urlencoded.js: read() → parseExtended()
    → qs.parse()   ← CVE-2022-24999
```

### Fixture: `javascript-realworld-cross-package-safe` (not reachable)

**`source/app.js`**:
```javascript
// App that parses JSON bodies only.
// body-parser.json uses JSON.parse, never calls qs.parse.
const bodyParser = require('body-parser')

const parseJson = bodyParser.json()

function handleJsonPost(req, res, next) {
  parseJson(req, res, next)
}

module.exports = { handleJsonPost }
```

**Why not reachable**: `bodyParser.json()` is a reaching symbol whose call graph in body-parser's source never reaches `qs`. The walker finds no `FinalTargets` that the app calls → `not_reachable`.

### SBOM for both JS fixtures

Both fixtures share the same component set; only `dependsOn` on the `"my-app"` component makes body-parser the direct dep (root):

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "bom-ref": "my-app",
      "type": "application",
      "name": "my-app",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "bom-ref": "pkg:npm/body-parser@1.19.2",
      "type": "library",
      "name": "body-parser",
      "version": "1.19.2",
      "purl": "pkg:npm/body-parser@1.19.2"
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
    { "ref": "my-app", "dependsOn": ["pkg:npm/body-parser@1.19.2"] },
    { "ref": "pkg:npm/body-parser@1.19.2", "dependsOn": ["pkg:npm/qs@6.7.0"] }
  ]
}
```

### Integration test update

```go
func TestIntegration_Transitive_JavaScriptReachable(t *testing.T) {
    runIntegrationFixture(t, dir, "javascript", "npm", "qs", "6.7.0", true)
}
func TestIntegration_Transitive_JavaScriptNotReachable(t *testing.T) {
    runIntegrationFixture(t, dir, "javascript", "npm", "qs", "6.7.0", false)
}
```

---

## Fix 4 — Python Safe Fixture

**File**: `testdata/integration/python-realworld-cross-package-safe/source/app.py`

### Root cause

`session.options(url)` still opens a TCP connection through urllib3's `PoolManager`, routing through urllib3 even though it doesn't exercise the redirect path. Since ALL urllib3 exports are used as Stage B targets, the walker finds a path through urllib3's basic HTTP machinery → false positive `reachable`.

### Fix

Replace the safe app with one that calls `requests.Request.prepare()` — URL normalization and header construction only. `prepare()` performs no network I/O and makes no calls into urllib3. It uses Python's stdlib `urllib.parse` for URL parsing.

**New `source/app.py`**:
```python
# This app uses requests only for URL validation (prepare, not send).
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

**Why not reachable**: The hop for `requests` finds `HTTPAdapter.send()` and `Session.send()` as the reaching symbols (they call urllib3). `validate_url` calls only `requests.Request()` and `.prepare()` — neither is in the reaching set → `not_reachable`.

---

## Fix 5 — Python Reachable Fixture SBOM Update

**File**: `testdata/integration/python-realworld-cross-package/sbom.cdx.json`

Add `metadata.component` and `dependencies` block so `parseSBOMForTest` identifies `requests` as the only root (not `urllib3`). Without this, after Fix 2 is applied, `urllib3` would still be treated as a root (fallback path), producing a trivial 1-element path.

Same structure as the JS SBOMs:
```json
{
  "metadata": {
    "component": { "bom-ref": "my-app", "type": "application", "name": "my-app" }
  },
  "dependencies": [
    { "ref": "my-app", "dependsOn": ["pkg:pypi/requests@2.31.0"] },
    { "ref": "pkg:pypi/requests@2.31.0", "dependsOn": ["pkg:pypi/urllib3@2.0.5"] }
  ]
}
```

Both Python fixtures (reachable and safe) get this update. The Python reachable fixture already works at the source level; only the SBOM needs updating to supply correct roots.

---

## Fix 6 — LLM Judge Test Updates

**Files**: `pkg/vex/reachability/javascript/llm_judge_test.go`, `pkg/vex/reachability/python/llm_judge_test.go`

### JavaScript judge (`TestLLMJudge_JavaScriptTransitiveReachability`)

Update to reflect the new fixture pair:
- CVE: CVE-2022-24999 (was CVE-2022-0155)
- Vulnerable package: `qs@6.7.0` (was `follow-redirects@1.14.0`)
- Chain description: `app → bodyParser.urlencoded → qs.parse` (was `app → axios.get → follow-redirects`)
- SBOM parsing: use updated `parseSBOMForTest` (picks up new dependsOn-based roots)
- Prompt: updated vulnerability description and chain

### Python judge (`TestLLMJudge_PythonTransitiveReachability`)

- Update the "not reachable" description in the prompt to reflect `PreparedRequest.prepare()` instead of `session.options()`
- No structural changes; CVE and package versions unchanged

---

## Scope Boundaries

**In scope**:
- `fetcher_npm.go`: layout normalization
- `integration_test.go`: `parseSBOMForTest` struct and algorithm
- `transitive_wire.go`: `buildTransitiveSummary` signature + algorithm
- `degradation.go`: new `ReasonRootsUnknown` constant
- All 4 fixture directories: SBOMs, app source, expected.json, trivy.json
- Both LLM judge tests

**Out of scope**:
- Network cassette/VCR layer (Approach C — future work)
- Other ecosystems (Rust, Java)
- Narrowing target symbols to CVE-specific functions (future Stage C)
- Changes to `sbom_graph.go`, `walker.go`, `hop.go`, `exports.go`

---

## Verification

After all fixes, the following must pass:

```
task test -t integration   # TestIntegration_Transitive_Python{Reachable,NotReachable}
                           # TestIntegration_Transitive_JavaScript{Reachable,NotReachable}
task test -t llmjudge      # TestLLMJudge_JavaScriptTransitiveReachability
                           # TestLLMJudge_PythonTransitiveReachability
```

The integration tests download real packages from npm/PyPI; they require network access and the `integration` build tag.
