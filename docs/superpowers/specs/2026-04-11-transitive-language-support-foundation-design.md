# Transitive Reachability — Language Support Foundation

**Status:** Design
**Date:** 2026-04-11
**Scope:** Foundation refactor only. No new language implementations.

## 1. Problem

The transitive cross-package reachability analyzer at `pkg/vex/reachability/transitive/` currently supports Python and JavaScript. Language-specific behavior is wired through `switch` statements scattered across `hop.go` (`extractorForLanguage`, `buildCrossFileScope`, `resolveTarget`, `resolveSelfCall`) and `exports.go` (`listExportedSymbols`, `modulePrefix`, `listExportedPython`, `listExportedJavaScript`). The fetcher is selected via an ecosystem string carried alongside the language on the `Analyzer` struct.

Rolling the analyzer out to Ruby, PHP, and Rust under this shape means editing the same shared files for every language and fighting for merge order. Recent commit history shows a concrete instance of the problem: the ten commits following `7c8f0ec feat(transitive): add transitive reachability analysis` are almost entirely JavaScript-specific fixes (alias-only imports, assignment-expression `require()`, switch/conditional imports, flat-vs-dotted module keys). Each of those commits touched `hop.go` or `exports.go`. If Ruby, PHP, and Rust were already in the tree, every one of those commits would have been cross-language merge hazards.

This spec extracts a `LanguageSupport` interface so that each language owns its quirks in a dedicated subpackage, and the shared orchestration code in `transitive/` contains no language-specific branches.

## 2. Goals

1. Every language-specific branch in `pkg/vex/reachability/transitive/hop.go` and `pkg/vex/reachability/transitive/exports.go` is removed. Language behavior is reached only through the `LanguageSupport` interface.
2. Python and JavaScript support is ported to `LanguageSupport` implementations under `pkg/vex/reachability/transitive/languages/python/` and `pkg/vex/reachability/transitive/languages/javascript/`. All current behavior is preserved bit-for-bit: dotted module keys for Python, flat keys for JavaScript, dotted-alias resolution, `self.X` rewriting, synthetic module-level symbols, synthetic class-to-`__init__` edges.
3. `Analyzer` gains a `Language LanguageSupport` field. The existing `Ecosystem string` and `Fetchers map[string]Fetcher` fields are replaced with a single `Fetchers map[string]Fetcher` keyed by ecosystem that is looked up via `Language.Ecosystem()`. The `Ecosystem` field is deleted entirely.
4. `pkg/vex/transitive_wire.go:buildTransitiveAnalyzer` and the direct `&transitive.Analyzer{...}` construction sites in the Python and JavaScript `llm_judge_test.go` files use the new wiring.
5. `task test:transitive` (integration tests against real PyPI/npm) and `task test:reachability:transitive:llmjudge` (Python and JavaScript transitive judge tests) pass without any fixture edits and without judge-score regression beyond normal run-to-run noise.
6. Dedicated unit tests cover the registry (`LanguageFor`), the interface contract (every registered language satisfies the interface and returns non-empty values for identity methods), and each language implementation's public-API heuristics and module-path derivation on synthetic inputs.
7. Adding a new language in a future spec requires: creating one new subpackage under `transitive/languages/`, adding a three-line entry to `LanguageFor`, and nothing else in `pkg/vex/reachability/transitive/`.

## 3. Non-goals

- No new language support (Ruby, PHP, Rust, Java, C# are all out of scope).
- No changes to the per-language intra-package reachability analyzers at `pkg/vex/reachability/{python,javascript,...}/`. Those are separate from the transitive cross-package layer and are unaffected.
- No changes to tree-sitter grammars or extractors at `pkg/vex/reachability/treesitter/`.
- No changes to fetcher implementations (`fetcher_pypi.go`, `fetcher_npm.go`, `fetcher_http.go`, `fetcher_zip.go`).
- No changes to the SBOM graph, walker, cache, evidence, or config layers.
- No changes to integration test fixtures.
- No changes to the judge test prompts or scoring methodology.
- No semantic convergence between Python and JavaScript. If Python emits `urllib3.poolmanager.PoolManager` today and JavaScript emits `body-parser.urlencoded` today, they still emit those exact keys after the refactor.

## 4. Architecture

### 4.1 Package layout

```
pkg/vex/reachability/transitive/
├── analyzer.go              (unchanged logic; Analyzer struct field renamed — see 4.3)
├── cache.go                 (unchanged)
├── config.go                (unchanged)
├── degradation.go           (unchanged)
├── evidence.go              (unchanged)
├── fetcher.go               (unchanged)
├── fetcher_http.go          (unchanged)
├── fetcher_npm.go           (unchanged — referenced by languages/javascript indirectly via ecosystem key)
├── fetcher_pypi.go          (unchanged — referenced by languages/python indirectly via ecosystem key)
├── fetcher_zip.go           (unchanged)
├── hop.go                   (orchestration only; no language switches)
├── exports.go               (orchestration only; no language switches)
├── sbom_graph.go            (unchanged)
├── transitive.go            (unchanged)
├── walker.go                (unchanged)
├── language.go              (NEW — LanguageSupport interface + LanguageFor factory)
├── language_test.go         (NEW — registry and contract tests)
└── languages/
    ├── python/
    │   ├── python.go        (NEW — LanguageSupport implementation)
    │   └── python_test.go   (NEW — Python-specific unit tests)
    └── javascript/
        ├── javascript.go    (NEW — LanguageSupport implementation)
        └── javascript_test.go (NEW — JavaScript-specific unit tests)
```

Fetchers remain in the core `transitive/` package. Each language's `LanguageSupport` implementation declares which ecosystem it uses via `Ecosystem()`, and the shared fetcher map is keyed by that ecosystem name. This preserves the current model where fetchers are reusable infrastructure — for example, a hypothetical future language that also uses PyPI would reuse `fetcher_pypi.go` without duplication.

### 4.2 `LanguageSupport` interface

Defined in `pkg/vex/reachability/transitive/language.go`:

```go
package transitive

import (
    "unsafe"

    "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

// LanguageSupport is the per-language plug-in contract for transitive
// cross-package reachability analysis. Each supported language provides
// one implementation, constructed via LanguageFor.
//
// Implementations live in pkg/vex/reachability/transitive/languages/<lang>/
// and are registered in LanguageFor.
type LanguageSupport interface {
    // --- Identity ---

    // Name returns the canonical language name, e.g. "python", "javascript".
    Name() string

    // Ecosystem returns the fetcher ecosystem key, e.g. "pypi", "npm".
    // Used by Analyzer to select a Fetcher from its fetcher map.
    Ecosystem() string

    // FileExtensions returns the source file extensions this language
    // recognizes, e.g. [".py"] or [".js", ".mjs", ".cjs"].
    FileExtensions() []string

    // --- Tree-sitter plumbing ---

    // Grammar returns the tree-sitter grammar language pointer used by
    // treesitter.ParseFiles.
    Grammar() unsafe.Pointer

    // Extractor returns the language-specific tree-sitter extractor
    // that produces symbols, imports, and call edges.
    Extractor() treesitter.LanguageExtractor

    // --- Export enumeration (called by exports.go) ---

    // IsExportedSymbol reports whether a symbol is part of the package's
    // public API. Python uses the underscore convention; JavaScript uses
    // its own kind-based filter; future languages may inspect visibility
    // modifiers or export declarations.
    IsExportedSymbol(sym *treesitter.Symbol) bool

    // ModulePath derives the dotted module path for a file given the
    // source-directory root and the package name. For Python this produces
    // "urllib3.poolmanager" from "urllib3-2.0.5/src/urllib3/poolmanager.py".
    // For JavaScript the implementation may choose to always return
    // packageName (flat key scheme) regardless of file path.
    ModulePath(file, sourceDir, packageName string) string

    // SymbolKey composes a fully-qualified symbol key from a module path
    // and a symbol name. Python uses "<module>.<name>" (dotted, deep).
    // JavaScript uses "<packageName>.<name>" (flat). This is the single
    // point where the dotted-vs-flat choice is encoded.
    SymbolKey(modulePath, symbolName string) string

    // --- Scope resolution (called by hop.go) ---

    // NormalizeImports transforms the raw treesitter.Import slice emitted
    // by the extractor into the canonical form consumed by the shared
    // scope builder. This is where language-specific quirks are handled:
    // JavaScript alias-only imports (const mod = require('qs')),
    // assignment-expression requires, dotted-alias registrations, etc.
    // Python's implementation is typically the identity function.
    NormalizeImports(raw []treesitter.Import) []treesitter.Import

    // ResolveDottedTarget attempts to resolve a dotted call target whose
    // prefix is an import alias. For example, given "mod.parse" and a
    // scope where "mod" is an alias for "qs", this returns "qs.parse".
    // Returns (zero, false) when the prefix is not a known alias in scope.
    ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool)

    // ResolveSelfCall rewrites a call target of the form that references
    // the enclosing class (Python's "self.X", potentially others) into a
    // class-qualified form based on the caller's symbol ID. Languages
    // where this rewrite does not apply return `to` unchanged.
    ResolveSelfCall(to, from treesitter.SymbolID) treesitter.SymbolID
}
```

### 4.3 Factory

```go
// In pkg/vex/reachability/transitive/language.go

import (
    "fmt"
    "strings"

    "github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/javascript"
    "github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/python"
)

// LanguageFor returns the LanguageSupport implementation for the given
// language name. Returns an error for unknown languages so callers can
// surface a clear message rather than a nil dereference.
func LanguageFor(name string) (LanguageSupport, error) {
    switch strings.ToLower(name) {
    case "python":
        return python.New(), nil
    case "javascript", "js":
        return javascript.New(), nil
    }
    return nil, fmt.Errorf("unsupported language %q: only python and javascript are supported", name)
}
```

`LanguageFor` is the only registration point. Adding a language is a single `case` plus a new subpackage. Lazy construction means unused language subpackages still pay parse/compile cost but no runtime initialization cost per analysis run.

### 4.4 `Analyzer` struct changes

**Before:**

```go
type Analyzer struct {
    Config    Config
    Fetchers  map[string]Fetcher // keyed by ecosystem
    Language  string             // "python", "javascript"
    Ecosystem string             // matching ecosystem key for Fetchers
}
```

**After:**

```go
type Analyzer struct {
    Config   Config
    Fetchers map[string]Fetcher // keyed by ecosystem (e.g. "pypi", "npm")
    Language LanguageSupport    // replaces the Language and Ecosystem strings
}
```

The cache is held by each `Fetcher` implementation (`PyPIFetcher.Cache`, `NPMFetcher.Cache`) and is not a field on `Analyzer`. This is unchanged by the refactor.

The `Ecosystem` field is deleted. The `Language` field changes type from `string` to `LanguageSupport`. All internal uses of `a.Ecosystem` become `a.Language.Ecosystem()`. All internal uses of `a.Language` as a string become `a.Language.Name()` (for logging and error messages) or a direct call on `a.Language` (for operations).

### 4.5 `hop.go` orchestration after refactor

`RunHop` currently takes a `HopInput{Language string, ...}` and calls `extractorForLanguage` to resolve the language. After the refactor, `HopInput` carries `Language LanguageSupport` instead of a string, and the switch is gone.

```go
type HopInput struct {
    Language      LanguageSupport
    SourceDir     string
    TargetSymbols []string
    MaxTargets    int
}

func RunHop(_ context.Context, input HopInput) (HopResult, error) {
    ext := input.Language.Extractor()
    langPtr := input.Language.Grammar()
    fileExts := input.Language.FileExtensions()
    // ... walk files matching any of fileExts, parse, extract, and so on
}
```

The three inline helpers at the bottom of `hop.go` — `buildCrossFileScope`, `resolveTarget`, `resolveSelfCall` — each change in one of the following ways:

- `buildCrossFileScope` becomes language-agnostic. It calls `input.Language.NormalizeImports(rawImports)` at entry and then runs the existing alias-and-symbol-binding loop against the normalized import list. The body of the loop does not change.
- `resolveTarget` stays shared and language-agnostic in shape, but the dotted-prefix branch delegates to `input.Language.ResolveDottedTarget(prefix, suffix, scope)` instead of the hard-coded `scope.LookupImport` lookup. The bare-name branch (scope.Lookup + local-module qualification) is unchanged, as that behavior is already language-agnostic.
- `resolveSelfCall` is deleted from `hop.go`. The call site at phase 3 (`e.To = resolveSelfCall(e.To, e.From)`) is replaced with `e.To = input.Language.ResolveSelfCall(e.To, e.From)`.

The call site in `hop.go:176` currently reads:

```go
edges, edgeErr := ext.ExtractCalls(fi.pr.File, fi.pr.Source, fi.pr.Tree, augScope)
// ...
for _, e := range edges {
    e.To = resolveTarget(e.To, augScope, mod)
    e.To = resolveSelfCall(e.To, e.From)
    graph.AddEdge(e)
}
```

After the refactor it reads:

```go
edges, edgeErr := ext.ExtractCalls(fi.pr.File, fi.pr.Source, fi.pr.Tree, augScope)
// ...
for _, e := range edges {
    e.To = resolveTarget(e.To, augScope, mod, input.Language)
    e.To = input.Language.ResolveSelfCall(e.To, e.From)
    graph.AddEdge(e)
}
```

The synthetic module-level symbol injection (phase 2a) and the synthetic class→`__init__` edges (phase 2b) stay in `hop.go` unchanged. Both are language-agnostic in shape: phase 2a creates a module node for every parsed file, and phase 2b creates an init edge for every class symbol. Languages that emit no `SymbolClass` values produce no such edges naturally.

### 4.6 `exports.go` orchestration after refactor

`listExportedSymbols` becomes a single language-agnostic function that walks files, parses them, and uses the interface methods to enumerate exports:

```go
func listExportedSymbols(lang LanguageSupport, sourceDir, packageName string) ([]string, error) {
    files, err := collectFilesByExt(sourceDir, lang.FileExtensions())
    if err != nil {
        return nil, err
    }
    parsed, _ := treesitter.ParseFiles(files, lang.Grammar())
    defer func() {
        for _, pr := range parsed {
            pr.Tree.Close()
        }
    }()
    ext := lang.Extractor()
    seen := make(map[string]struct{})
    for _, pr := range parsed {
        mod := lang.ModulePath(pr.File, sourceDir, packageName)
        if mod != packageName && !strings.HasPrefix(mod, packageName+".") {
            continue
        }
        syms, err := ext.ExtractSymbols(pr.File, pr.Source, pr.Tree)
        if err != nil {
            continue
        }
        for _, s := range syms {
            if !lang.IsExportedSymbol(s) {
                continue
            }
            seen[lang.SymbolKey(mod, s.Name)] = struct{}{}
        }
    }
    out := make([]string, 0, len(seen))
    for k := range seen {
        out = append(out, k)
    }
    return out, nil
}
```

`listExportedPython` and `listExportedJavaScript` are deleted. `modulePrefix` and `collectFilesByExt` — `collectFilesByExt` stays in `exports.go` as a shared helper (it's already language-agnostic); `modulePrefix` moves into the Python subpackage and becomes the body of `python.ModulePath`, since its current logic is Python-specific (dotted path derivation, `__init__`/`__main__` stripping).

The JavaScript subpackage's `ModulePath` implementation is trivial: return `packageName`. This matches the current JavaScript behavior (flat keys) and eliminates the "JavaScript bypasses `modulePrefix`" asymmetry that exists today.

### 4.7 `transitive_wire.go` wiring changes

**Before:** `buildTransitiveAnalyzer` carries a switch statement mapping `language` to an ecosystem string and a fetcher constructor, then constructs `Analyzer` with the pair.

**After:**

```go
func buildTransitiveAnalyzer(cfg transitive.Config, language string) *transitive.Analyzer {
    if !cfg.Enabled {
        return nil
    }
    lang, err := transitive.LanguageFor(language)
    if err != nil {
        return nil // language not supported — transitive analysis is a no-op
    }
    var cache *transitive.Cache
    if cfg.CacheDir != "" {
        cache = transitive.NewCache(cfg.CacheDir)
    }
    fetchers := buildFetchers(cache, lang.Ecosystem())
    if fetchers == nil {
        return nil
    }
    return &transitive.Analyzer{
        Config:   cfg,
        Fetchers: fetchers,
        Language: lang,
    }
}

func buildFetchers(cache *transitive.Cache, ecosystem string) map[string]transitive.Fetcher {
    switch ecosystem {
    case "pypi":
        return map[string]transitive.Fetcher{"pypi": &transitive.PyPIFetcher{Cache: cache}}
    case "npm":
        return map[string]transitive.Fetcher{"npm": &transitive.NPMFetcher{Cache: cache}}
    }
    return nil
}
```

The fetcher construction switch is contained to `buildFetchers`, which is the ecosystem-to-fetcher mapping. This keeps the concern — fetcher selection — separate from language support, at the cost of one small switch. An alternative would be a global `Fetcher` registry in the `transitive` package; it's left out of scope because the current fetcher set is small and the present factoring is clear.

### 4.8 `llm_judge_test.go` construction sites

Both `pkg/vex/reachability/python/llm_judge_test.go` and `pkg/vex/reachability/javascript/llm_judge_test.go` construct `transitive.Analyzer` directly:

```go
// Before
ta := &transitive.Analyzer{
    Config:    transitive.DefaultConfig(),
    Language:  "python",
    Ecosystem: "pypi",
    Fetchers:  map[string]transitive.Fetcher{"pypi": fetcher},
}
```

Replaced with:

```go
// After
lang, err := transitive.LanguageFor("python")
if err != nil {
    t.Fatalf("LanguageFor: %v", err)
}
ta := &transitive.Analyzer{
    Config:   transitive.DefaultConfig(),
    Language: lang,
    Fetchers: map[string]transitive.Fetcher{"pypi": fetcher},
}
```

The JavaScript test applies the equivalent change with `"javascript"` and the npm fetcher.

## 5. Per-language implementations

### 5.1 Python

`pkg/vex/reachability/transitive/languages/python/python.go`:

- `Name()` returns `"python"`.
- `Ecosystem()` returns `"pypi"`.
- `FileExtensions()` returns `[".py"]`.
- `Grammar()` returns `grammarpython.Language()`.
- `Extractor()` returns `pyextractor.New()`.
- `IsExportedSymbol(sym)` returns `!strings.HasPrefix(sym.Name, "_") && (sym.Kind == SymbolFunction || sym.Kind == SymbolMethod || sym.Kind == SymbolClass)`. This mirrors the current `listExportedPython` body.
- `ModulePath(file, sourceDir, packageName)` contains the current `modulePrefix` body verbatim: search for the first path component equal to `packageName`, join from there, strip `.__init__` and `.__main__`, fall back to the full relative path.
- `SymbolKey(modulePath, symbolName)` returns `modulePath + "." + symbolName`. This is the current dotted-key scheme.
- `NormalizeImports(raw)` returns `raw` unchanged. Python imports as produced by the tree-sitter extractor are already in canonical form.
- `ResolveDottedTarget(prefix, suffix, scope)` calls `scope.LookupImport(prefix)` and, on hit, returns `SymbolID(module + "." + suffix)`. This is the current behavior inside `resolveTarget`.
- `ResolveSelfCall(to, from)` contains the current `resolveSelfCall` body verbatim.

### 5.2 JavaScript

`pkg/vex/reachability/transitive/languages/javascript/javascript.go`:

- `Name()` returns `"javascript"`.
- `Ecosystem()` returns `"npm"`.
- `FileExtensions()` returns `[".js", ".mjs", ".cjs"]`.
- `Grammar()` returns `grammarjs.Language()`.
- `Extractor()` returns `jsextractor.New()`.
- `IsExportedSymbol(sym)` returns `sym.Kind == SymbolFunction || sym.Kind == SymbolMethod || sym.Kind == SymbolClass`. No underscore filter; this mirrors the current `listExportedJavaScript` body.
- `ModulePath(file, sourceDir, packageName)` collapses every in-package file to `packageName` (the flat-key scheme). Implementation walks the relative path components and returns `packageName` if any component matches exactly; otherwise returns the first path component so that out-of-package neighbor files are rejected by the shared package-name prefix filter in `listExportedSymbols`. This matches the pre-refactor behavior: the old `listExportedJavaScript` used `modulePrefix` (Python-style path derivation) for the in-package filter and `packageName + "." + symbolName` for key composition; the new single `ModulePath` method folds both concerns into one return value.
- `SymbolKey(modulePath, symbolName)` returns `modulePath + "." + symbolName`. For in-package files this produces `packageName + "." + symbolName`, which is the flat-key scheme.
- `NormalizeImports(raw)` returns `raw` unchanged. The current JavaScript extractor already handles alias-only imports, assignment-expression `require()`, and dotted-alias registration at extraction time (commits `8866e2c`, `4fe41c2`, `1abac97`, `a0fcc50`). The shared `buildCrossFileScope` in `hop.go` already consumes the output correctly, and the `scope.DefineImport(imp.Alias, imp.Module, imp.Symbols)` loop already handles empty-symbol alias-only bindings. `NormalizeImports` is present on the interface as a seam for future languages, not because JavaScript needs a transformation today.
- `ResolveDottedTarget(prefix, suffix, scope)` is identical to Python's: `scope.LookupImport(prefix)` and composition. This is not a coincidence — the current `resolveTarget` in `hop.go` already treats both languages the same way for dotted-prefix resolution. The interface method exists so future languages (Ruby `Mod::func`, Rust `mod::func`) can implement different resolution rules.
- `ResolveSelfCall(to, from)` returns `to` unchanged (JavaScript has no `self.X` construct; `this.X` is handled by the extractor directly).

## 6. Testing strategy

### 6.1 Regression gate — existing suites must pass unchanged

The two test commands listed in the goals are the primary correctness signal:

- `task test:transitive` — integration tests in `pkg/vex/reachability/transitive/integration_test.go` that hit real PyPI and npm and exercise the end-to-end pipeline against the cross-package CVE fixtures.
- `task test:reachability:transitive:llmjudge` — the Python and JavaScript transitive LLM judge tests, run before and after the refactor to confirm no behavior or score regression.

No fixture edits and no prompt edits. If either suite fails after the refactor, the refactor is wrong, not the tests.

In addition, the full per-language judge suite (`task test:reachability:llmjudge`) runs in CI and must continue to pass. The intra-language analyzers are not directly affected by this refactor, but they share some types with `transitive` (e.g., `*transitive.Analyzer` is a field on the Python and JavaScript `Analyzer` structs), so they get a free second opinion.

### 6.2 New unit tests — registry and contract

`pkg/vex/reachability/transitive/language_test.go` contains:

- **Registry tests.** Table-driven test of `LanguageFor`. Cases: `"python"`, `"Python"`, `"javascript"`, `"JavaScript"`, `"js"`, `"JS"` all return non-nil implementations with the expected `Name()` and `Ecosystem()`. Case `"ruby"` returns an error whose message mentions the unsupported name. Case `""` returns an error.
- **Contract tests.** For every language returned by `LanguageFor`, assert that: `Name()` is non-empty, `Ecosystem()` is non-empty, `FileExtensions()` is non-empty and every extension starts with a dot, `Grammar()` is non-nil, `Extractor()` is non-nil, and the round trip `LanguageFor(lang.Name()).Name() == lang.Name()` holds. This catches any future language that forgets to set one of the identity fields.
- **Fetcher availability.** For each language, assert that `buildFetchers(cache, lang.Ecosystem())` returns a non-nil map with the expected ecosystem key. This lives in `transitive_wire_test.go` (not `language_test.go`) because `buildFetchers` is a wire function, not part of the `transitive` package.

### 6.3 New unit tests — per-language implementations

`pkg/vex/reachability/transitive/languages/python/python_test.go`:

- `ModulePath` covers: flat layout (`urllib3-1.26/urllib3/poolmanager.py` → `urllib3.poolmanager`), src layout (`urllib3-2.0.5/src/urllib3/util/retry.py` → `urllib3.util.retry`), `__init__.py` stripping (`urllib3-2.0/urllib3/__init__.py` → `urllib3`), `__main__.py` stripping, fallback when the package-name component is absent (`tests/test_retry.py` → `tests.test_retry`).
- `IsExportedSymbol` covers: public function, public class, public method, underscore-prefixed function (rejected), variable kind (rejected), import kind (rejected).
- `SymbolKey` covers: `("urllib3.poolmanager", "PoolManager")` → `"urllib3.poolmanager.PoolManager"`.
- `ResolveSelfCall` covers: three-component from (`adapters.HTTPAdapter.__init__`) with `self.init_poolmanager` → `adapters.HTTPAdapter.init_poolmanager`; two-component from (`api.get`) with `self.X` → unchanged; non-self prefix → unchanged.
- `ResolveDottedTarget` covers: prefix found in scope → returns composed symbol; prefix not in scope → returns `(zero, false)`.
- `NormalizeImports` covers: identity on a representative `treesitter.Import` slice.

`pkg/vex/reachability/transitive/languages/javascript/javascript_test.go`:

- `ModulePath` covers: any file → `packageName` (identity on the package-name argument).
- `IsExportedSymbol` covers: function, class, method all accepted; variable rejected; import rejected. No underscore filter.
- `SymbolKey` covers: `("body-parser", "urlencoded")` → `"body-parser.urlencoded"`.
- `ResolveSelfCall` covers: any input returns unchanged.
- `ResolveDottedTarget` covers: alias found → composed; not found → `(zero, false)`.
- `NormalizeImports` covers: identity on a representative slice.

All unit tests use only fabricated `treesitter.Symbol` and `treesitter.Import` values constructed inline. They do not invoke the tree-sitter parser and do not require fixture files. This keeps them fast and independent of the integration suite.

### 6.4 What is explicitly not tested at the unit level

- Full parse-and-resolve paths — covered by integration and judge suites.
- Scope construction across multiple files — covered by integration and judge suites.
- Call graph topology — covered by integration and judge suites.
- Fetcher HTTP interactions — existing `fetcher_pypi_test.go` and `fetcher_npm_test.go` are unchanged.

The principle is: unit tests cover pure functions of simple inputs; the judge and integration suites cover the composed behavior.

## 7. Implementation sequencing

The refactor is sequenced so that every intermediate commit keeps `task test:transitive` and `task test:reachability:transitive:llmjudge` green. This is not aspirational — it is a constraint of the spec. If any commit leaves the test suite red, that commit is wrong.

1. **Introduce the interface.** Add `language.go` with the `LanguageSupport` interface and a stub `LanguageFor` that still returns errors for every input. At this point the interface exists but is used nowhere. Tests: all existing tests still pass.
2. **Create the Python subpackage.** Add `languages/python/python.go` with the full implementation. Wire `LanguageFor("python")` to return it. The `transitive` package does not yet use it. Add `python_test.go`. Tests: all existing tests still pass; new `python_test.go` passes.
3. **Create the JavaScript subpackage.** Symmetric step. Add `languages/javascript/javascript.go`, wire `LanguageFor("javascript")` and `LanguageFor("js")`. Add `javascript_test.go`. Tests: all existing tests still pass; new `javascript_test.go` passes.
4. **Add registry and contract tests.** `language_test.go` with the `LanguageFor` table-driven tests and contract assertions. Tests pass.
5. **Port `exports.go`.** Rewrite `listExportedSymbols` as the language-agnostic orchestrator. Delete `listExportedPython`, `listExportedJavaScript`, and `modulePrefix`. Update every call site inside the `transitive` package to pass `LanguageSupport` instead of a language string. At this commit, `hop.go` still has the switch, but `exports.go` is clean. Tests: all existing tests still pass.
6. **Port `hop.go`.** Rewrite `RunHop` to take `LanguageSupport` on `HopInput`. Delete `extractorForLanguage`. Rewrite `buildCrossFileScope` to call `NormalizeImports`. Rewrite `resolveTarget` to delegate dotted resolution through `ResolveDottedTarget`. Delete `resolveSelfCall` and route through `input.Language.ResolveSelfCall`. Update every caller of `RunHop` in the same commit to pass `LanguageSupport`. Tests: all existing tests still pass.
7. **Change `Analyzer` struct.** Replace `Language string` with `Language LanguageSupport`. Delete `Ecosystem string`. Update every reader (`a.Ecosystem`, `a.Language`) in the `transitive` package. Tests: the `transitive` package still compiles but `pkg/vex/transitive_wire.go` and the two `llm_judge_test.go` files are now red.
8. **Update `transitive_wire.go`.** Replace `buildTransitiveAnalyzer` per section 4.7. Extract the fetcher switch into `buildFetchers`. Delete the now-unused ecosystem resolution code. Tests: `pkg/vex` package compiles; `transitive_wire_test.go` still passes; `llm_judge_test.go` files still red.
9. **Update `llm_judge_test.go` construction sites.** Apply the change in section 4.8 to both Python and JavaScript test files. Tests: everything green. This is the last commit before cleanup.
10. **Remove dead code.** Delete any now-unused imports, the old switch helpers, and anything flagged by `go vet` or `staticcheck`. Run `task fmt` and `task lint`. Tests: everything green.

Each step is a reviewable commit. The commits are ordered so that test breakage at any intermediate point is a bug, not expected churn.

## 8. Risks and mitigations

| Risk | Mitigation |
|---|---|
| JavaScript semantic drift — the dotted-vs-flat key scheme is load-bearing for the current judge scores. | The `SymbolKey` method is called at exactly one point in `exports.go`. The JavaScript implementation returns the same string the current code produces. The contract test for `SymbolKey` pins this explicitly, and the JavaScript judge test is the regression gate. |
| Python `__init__`/`__main__` stripping is subtle — moving it into the interface risks losing an edge case. | `ModulePath` tests cover the known cases from the current `modulePrefix` comments (flat layout, src layout, `__init__`, `__main__`, fallback). The integration test against real urllib3 is the regression gate. |
| `NormalizeImports` shape turns out to be wrong when Ruby arrives. | The foundation spec commits to `NormalizeImports` based on current needs (identity for both Python and JS). If Ruby requires a different shape, the interface is revised in the Ruby spec, not hidden behind a speculative abstraction now. |
| `ResolveDottedTarget` is a seam that both languages currently implement identically; the interface risks over-abstraction. | Both current implementations are three lines. The cost of the seam is negligible, and it pays off for the first language (Ruby) that uses `::` instead of `.` as the path separator. |
| Fetcher wiring changes break a consumer of `transitive.Analyzer`. | `Analyzer` is constructed in exactly three places across the repo: `pkg/vex/transitive_wire.go:86`, `pkg/vex/reachability/python/llm_judge_test.go:216`, and `pkg/vex/reachability/javascript/llm_judge_test.go:217`. All three are updated as part of the same commit chain (see section 7, steps 8 and 9). No out-of-tree consumers exist. |
| Judge score noise hides a real regression. | The Python judge historically scores 8/10 overall and the JavaScript judge 9/10. The refactor must reproduce scores within one point on both. Any drop of two points or more on any sub-metric is treated as a regression and investigated before merge. |

## 9. Success criteria (restatement)

1. `task test:transitive` passes without fixture edits.
2. `task test:reachability:transitive:llmjudge` passes with judge scores within one point of the pre-refactor baseline on both languages.
3. `task test:reachability:llmjudge` (the full per-language suite) passes.
4. `task quality` passes (build, test, lint, fmt).
5. Grepping the `transitive/` package for `case "python"` and `case "javascript"` returns zero matches in `hop.go` and `exports.go`.
6. `pkg/vex/reachability/transitive/languages/python/` and `pkg/vex/reachability/transitive/languages/javascript/` exist and contain the implementations described in section 5.
7. `LanguageFor` is the only place in the repo that maps language names to `LanguageSupport` implementations.
8. The Ruby, PHP, and Rust specs (future work) can be written as "create one subpackage, add one `case` to `LanguageFor`, add one fetcher if the ecosystem is new" with no other changes to `pkg/vex/reachability/transitive/`.
