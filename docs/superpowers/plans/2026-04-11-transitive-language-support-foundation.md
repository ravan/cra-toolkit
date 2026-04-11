# Transitive Language Support Foundation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor `pkg/vex/reachability/transitive/` so that language-specific behavior is reached only through a `LanguageSupport` interface, with Python and JavaScript as the first two implementations, so future languages can be added by dropping in one subpackage and one `LanguageFor` case.

**Architecture:** Introduce a `LanguageSupport` interface in the `transitive` package. Move Python and JavaScript implementations into dedicated subpackages under `transitive/languages/{python,javascript}/`. Rewrite `hop.go` and `exports.go` as language-agnostic orchestrators that call the interface. Replace `Analyzer.Language string` / `Analyzer.Ecosystem string` with `Analyzer.Language LanguageSupport`.

**Tech Stack:** Go, tree-sitter (via `pkg/vex/reachability/treesitter`), tree-sitter grammars for Python and JavaScript.

**Spec:** `docs/superpowers/specs/2026-04-11-transitive-language-support-foundation-design.md`

---

## Sequencing note

The spec's section 7 lists ten sequencing steps. The plan collapses steps 5–9 into a single atomic refactor commit (Task 5 here). Reason: spec-step 7 (change `Analyzer` struct) breaks `pkg/vex/transitive_wire.go:86` and both `llm_judge_test.go` construction sites, which violates the spec's own invariant that every intermediate commit must keep `task test:transitive` and `task test:reachability:transitive:llmjudge` green. The only way to preserve that invariant under Go's whole-package compile model is to update `Analyzer`, its internal consumers, `transitive_wire.go`, and the two judge-test files in one commit. Tasks 1–4 and 6 are each independent commits.

Every task ends with a green run of `task build`, `task test`, and (when the task touches code exercised by integration/judge suites) `task test:transitive` and `task test:reachability:transitive:llmjudge`.

---

## File structure after the refactor

**New files:**

| Path | Responsibility |
|---|---|
| `pkg/vex/reachability/transitive/language.go` | `LanguageSupport` interface definition and `LanguageFor` factory. |
| `pkg/vex/reachability/transitive/language_test.go` | Registry lookup tests and interface-contract assertions applied uniformly to every registered language. |
| `pkg/vex/reachability/transitive/languages/python/python.go` | Python `LanguageSupport` implementation. Owns all Python-specific behavior: extractor wiring, public-API rules, dotted module-path derivation with `__init__`/`__main__` stripping, `self.X` rewriting, dotted-alias resolution. |
| `pkg/vex/reachability/transitive/languages/python/python_test.go` | Unit tests for Python implementation using fabricated `treesitter.Symbol` / `treesitter.Import` / `treesitter.Scope` inputs. |
| `pkg/vex/reachability/transitive/languages/javascript/javascript.go` | JavaScript `LanguageSupport` implementation. Owns JS-specific behavior: extractor wiring, flat-package-key scheme, no-op `ResolveSelfCall`, no-op `NormalizeImports`. |
| `pkg/vex/reachability/transitive/languages/javascript/javascript_test.go` | Unit tests for JavaScript implementation, same structure as Python tests. |

**Modified files:**

| Path | Responsibility |
|---|---|
| `pkg/vex/reachability/transitive/hop.go` | Removed: `extractorForLanguage`, `resolveSelfCall`. Kept (language-agnostic): `RunHop`, `buildCrossFileScope`, `resolveTarget`, `moduleNameFrom`. `HopInput.Language` changes from `string` to `LanguageSupport`. `resolveTarget` gains a `LanguageSupport` parameter. `buildCrossFileScope` calls `lang.NormalizeImports` before the alias-binding loop. |
| `pkg/vex/reachability/transitive/exports.go` | Removed: `listExportedPython`, `listExportedJavaScript`, `modulePrefix`. `listExportedSymbols` becomes language-agnostic and takes a `LanguageSupport` instead of a language string. `collectFilesByExt` stays unchanged. |
| `pkg/vex/reachability/transitive/transitive.go` | `Analyzer.Language` changes from `string` to `LanguageSupport`. `Analyzer.Ecosystem` is deleted. `a.Fetchers[a.Ecosystem]` becomes `a.Fetchers[a.Language.Ecosystem()]`. `extractExportedSymbols` signature takes `LanguageSupport`. `HopInput{Language: a.Language, ...}` becomes `HopInput{Language: a.Language, ...}` where the field is now the interface type. |
| `pkg/vex/reachability/transitive/walker.go` | `Walker.Language` changes from `string` to `LanguageSupport`. |
| `pkg/vex/reachability/transitive/hop_test.go` | `Language: "python"` becomes `Language: python.New()`; `resolveTarget` and `buildCrossFileScope` test call sites updated to pass a `LanguageSupport`. |
| `pkg/vex/reachability/transitive/walker_test.go` | `Language: "python"` becomes `Language: python.New()`. |
| `pkg/vex/reachability/transitive/exports_test.go` | `listExportedJavaScript(tmp, "qs")` becomes `listExportedSymbols(javascript.New(), tmp, "qs")`. |
| `pkg/vex/transitive_wire.go` | `buildTransitiveAnalyzer` is rewritten to use `transitive.LanguageFor`. New `buildFetchers` helper maps ecosystem → fetcher. Removed: language→ecosystem switch, fetcher-by-ecosystem switch (now inside `buildFetchers`). |
| `pkg/vex/reachability/python/llm_judge_test.go` | Construction site at line 216 updated to use `transitive.LanguageFor`. |
| `pkg/vex/reachability/javascript/llm_judge_test.go` | Construction site at line 217 updated to use `transitive.LanguageFor`. |

**Unchanged files** (verify no drift): `analyzer.go`, `cache.go`, `config.go`, `degradation.go`, `evidence.go`, `fetcher.go`, `fetcher_http.go`, `fetcher_npm.go`, `fetcher_pypi.go`, `fetcher_zip.go`, `sbom_graph.go`.

---

## Task 1 — Introduce the `LanguageSupport` interface skeleton

**Goal:** Land `language.go` with the interface and a stub `LanguageFor` that returns errors for every input. No consumers yet. The transitive package still compiles and all existing tests still pass.

**Files:**
- Create: `pkg/vex/reachability/transitive/language.go`

- [ ] **Step 1.1: Capture baseline judge scores**

Run the two transitive judge tests once before any changes and record their final overall scores. These are the regression baseline for Task 5.

```bash
task test:reachability:transitive:llmjudge 2>&1 | grep -E "Transitive LLM Scores|overall=" | tee /tmp/transitive-judge-baseline.txt
```

Expected: two lines, one per language, each containing `path=`, `confidence=`, `evidence=`, `fp=`, `symbol=`, `overall=`. Save this output — Task 5 compares post-refactor scores against it and any sub-metric drop of two points or more is a regression.

- [ ] **Step 1.2: Create `language.go` with the interface and stub factory**

Create `pkg/vex/reachability/transitive/language.go` with exactly this content:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"fmt"
	"strings"
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

	// --- Export enumeration ---

	// IsExportedSymbol reports whether a symbol is part of the package's
	// public API.
	IsExportedSymbol(sym *treesitter.Symbol) bool

	// ModulePath derives the dotted module path for a file given the
	// source-directory root and the package name.
	ModulePath(file, sourceDir, packageName string) string

	// SymbolKey composes a fully-qualified symbol key from a module path
	// and a symbol name.
	SymbolKey(modulePath, symbolName string) string

	// --- Scope resolution ---

	// NormalizeImports transforms the raw imports emitted by the extractor
	// into the canonical form consumed by the shared scope builder.
	NormalizeImports(raw []treesitter.Import) []treesitter.Import

	// ResolveDottedTarget attempts to resolve a dotted call target whose
	// prefix is an import alias. Returns (zero, false) when the prefix is
	// not a known alias in scope.
	ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool)

	// ResolveSelfCall rewrites a self-reference call target into a
	// class-qualified form based on the caller's symbol ID. Languages
	// where this rewrite does not apply return `to` unchanged.
	ResolveSelfCall(to, from treesitter.SymbolID) treesitter.SymbolID
}

// LanguageFor returns the LanguageSupport implementation for the given
// language name. Returns an error for unknown languages so callers can
// surface a clear message rather than a nil dereference.
//
// Task 1 leaves this as a stub returning errors for every input; Tasks 2
// and 3 add the Python and JavaScript cases.
func LanguageFor(name string) (LanguageSupport, error) {
	switch strings.ToLower(name) {
	}
	return nil, fmt.Errorf("unsupported language %q", name)
}

// ensure unsafe is referenced so the import is not flagged while the stub
// has no language cases; this reference is removed implicitly once Tasks 2
// and 3 land (python.New() and javascript.New() satisfy the interface that
// uses unsafe.Pointer via Grammar).
var _ unsafe.Pointer //nolint:unused // retained until Task 2 lands Python
```

**Note:** The `_ unsafe.Pointer` declaration is a one-commit placeholder to prevent "imported and not used" build errors while `LanguageFor` is still a stub with no body. Task 2 removes the placeholder the same commit it adds the `case "python"` branch that references `python.New()` (whose `Grammar()` method returns `unsafe.Pointer`). If Go's unused-import check does not fire because the interface method `Grammar()` already consumes the `unsafe` import at declaration time, delete the `var _ unsafe.Pointer` line before committing — check by running the next step.

- [ ] **Step 1.3: Verify the transitive package compiles**

Run:

```bash
go build ./pkg/vex/reachability/transitive/...
```

Expected: exit code 0, no output. If the build fails with `imported and not used: "unsafe"`, keep the `var _ unsafe.Pointer` line. If the build succeeds without it, remove the line before committing.

- [ ] **Step 1.4: Verify all existing tests still pass**

Run:

```bash
task test
```

Expected: all tests pass. The `transitive` package has a new file with an interface and a stub factory but no consumers — nothing should have changed behaviorally.

- [ ] **Step 1.5: Verify integration and judge suites still pass**

Run:

```bash
task test:transitive
task test:reachability:transitive:llmjudge
```

Expected: both pass. Scores for the judge suite should be unchanged from the Step 1.1 baseline.

- [ ] **Step 1.6: Commit**

```bash
git add pkg/vex/reachability/transitive/language.go
git commit -m "feat(transitive): introduce LanguageSupport interface and LanguageFor stub

First step of the foundation refactor that moves language-specific
behavior out of hop.go and exports.go and into per-language subpackages.
This commit lands the interface definition and a stub factory with no
registered languages yet. Python and JavaScript implementations land in
the next two commits."
```

---

## Task 2 — Python `LanguageSupport` implementation

**Goal:** Land `pkg/vex/reachability/transitive/languages/python/python.go` as a complete `LanguageSupport` implementation, with comprehensive unit tests, and wire it into `LanguageFor`. Test-driven: all unit tests are written first and initially fail.

**Files:**
- Create: `pkg/vex/reachability/transitive/languages/python/python.go`
- Create: `pkg/vex/reachability/transitive/languages/python/python_test.go`
- Modify: `pkg/vex/reachability/transitive/language.go`

- [ ] **Step 2.1: Write the failing unit tests for the Python implementation**

Create `pkg/vex/reachability/transitive/languages/python/python_test.go` with exactly this content:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package python_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/python"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestPython_Identity(t *testing.T) {
	lang := python.New()
	if lang.Name() != "python" {
		t.Errorf("Name() = %q, want %q", lang.Name(), "python")
	}
	if lang.Ecosystem() != "pypi" {
		t.Errorf("Ecosystem() = %q, want %q", lang.Ecosystem(), "pypi")
	}
	exts := lang.FileExtensions()
	if len(exts) != 1 || exts[0] != ".py" {
		t.Errorf("FileExtensions() = %v, want [\".py\"]", exts)
	}
	if lang.Grammar() == nil {
		t.Error("Grammar() returned nil")
	}
	if lang.Extractor() == nil {
		t.Error("Extractor() returned nil")
	}
}

func TestPython_IsExportedSymbol(t *testing.T) {
	lang := python.New()
	tests := []struct {
		name string
		sym  *treesitter.Symbol
		want bool
	}{
		{"public function", &treesitter.Symbol{Name: "get", Kind: treesitter.SymbolFunction}, true},
		{"public class", &treesitter.Symbol{Name: "PoolManager", Kind: treesitter.SymbolClass}, true},
		{"public method", &treesitter.Symbol{Name: "send", Kind: treesitter.SymbolMethod}, true},
		{"underscore function is private", &treesitter.Symbol{Name: "_helper", Kind: treesitter.SymbolFunction}, false},
		{"underscore class is private", &treesitter.Symbol{Name: "_Internal", Kind: treesitter.SymbolClass}, false},
		{"dunder function is private", &treesitter.Symbol{Name: "__init__", Kind: treesitter.SymbolFunction}, false},
		{"module kind rejected", &treesitter.Symbol{Name: "adapters", Kind: treesitter.SymbolModule}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lang.IsExportedSymbol(tc.sym); got != tc.want {
				t.Errorf("IsExportedSymbol(%+v) = %v, want %v", tc.sym, got, tc.want)
			}
		})
	}
}

func TestPython_ModulePath(t *testing.T) {
	lang := python.New()
	tests := []struct {
		name        string
		file        string
		sourceDir   string
		packageName string
		want        string
	}{
		{
			name:        "flat layout",
			file:        "/tmp/urllib3-1.26/urllib3/poolmanager.py",
			sourceDir:   "/tmp",
			packageName: "urllib3",
			want:        "urllib3.poolmanager",
		},
		{
			name:        "src layout",
			file:        "/tmp/urllib3-2.0.5/src/urllib3/util/retry.py",
			sourceDir:   "/tmp",
			packageName: "urllib3",
			want:        "urllib3.util.retry",
		},
		{
			name:        "package init stripped",
			file:        "/tmp/urllib3-2.0/urllib3/__init__.py",
			sourceDir:   "/tmp",
			packageName: "urllib3",
			want:        "urllib3",
		},
		{
			name:        "package main stripped",
			file:        "/tmp/urllib3-2.0/urllib3/__main__.py",
			sourceDir:   "/tmp",
			packageName: "urllib3",
			want:        "urllib3",
		},
		{
			name:        "submodule init stripped",
			file:        "/tmp/urllib3-2.0/urllib3/util/__init__.py",
			sourceDir:   "/tmp",
			packageName: "urllib3",
			want:        "urllib3.util",
		},
		{
			name:        "fallback when package name absent",
			file:        "/tmp/urllib3-2.0/tests/test_retry.py",
			sourceDir:   "/tmp",
			packageName: "urllib3",
			want:        "urllib3-2.0.tests.test_retry",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lang.ModulePath(tc.file, tc.sourceDir, tc.packageName); got != tc.want {
				t.Errorf("ModulePath(%q, %q, %q) = %q, want %q",
					tc.file, tc.sourceDir, tc.packageName, got, tc.want)
			}
		})
	}
}

func TestPython_SymbolKey(t *testing.T) {
	lang := python.New()
	got := lang.SymbolKey("urllib3.poolmanager", "PoolManager")
	want := "urllib3.poolmanager.PoolManager"
	if got != want {
		t.Errorf("SymbolKey = %q, want %q", got, want)
	}
}

func TestPython_NormalizeImports_Identity(t *testing.T) {
	lang := python.New()
	raw := []treesitter.Import{
		{Module: "urllib3", Symbols: []string{"PoolManager"}, Alias: ""},
		{Module: "json", Alias: "j"},
	}
	got := lang.NormalizeImports(raw)
	if len(got) != len(raw) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(raw))
	}
	for i := range raw {
		if got[i] != raw[i] {
			t.Errorf("got[%d] = %+v, want %+v", i, got[i], raw[i])
		}
	}
}

func TestPython_ResolveDottedTarget(t *testing.T) {
	lang := python.New()
	scope := treesitter.NewScope(nil)
	scope.DefineImport("mod", "qs", []string{})

	t.Run("alias found", func(t *testing.T) {
		got, ok := lang.ResolveDottedTarget("mod", "parse", scope)
		if !ok {
			t.Fatalf("expected ok=true for known alias")
		}
		want := treesitter.SymbolID("qs.parse")
		if got != want {
			t.Errorf("ResolveDottedTarget = %q, want %q", got, want)
		}
	})

	t.Run("alias not found", func(t *testing.T) {
		_, ok := lang.ResolveDottedTarget("nope", "parse", scope)
		if ok {
			t.Errorf("expected ok=false for unknown alias")
		}
	})
}

func TestPython_ResolveSelfCall(t *testing.T) {
	lang := python.New()
	tests := []struct {
		name string
		to   treesitter.SymbolID
		from treesitter.SymbolID
		want treesitter.SymbolID
	}{
		{
			name: "self call inside class method",
			to:   "self.init_poolmanager",
			from: "adapters.HTTPAdapter.__init__",
			want: "adapters.HTTPAdapter.init_poolmanager",
		},
		{
			name: "free function — from has only two parts",
			to:   "self.helper",
			from: "api.get",
			want: "self.helper",
		},
		{
			name: "non-self prefix — unchanged",
			to:   "urllib3.PoolManager",
			from: "adapters.HTTPAdapter.send",
			want: "urllib3.PoolManager",
		},
		{
			name: "empty from — unchanged",
			to:   "self.helper",
			from: "",
			want: "self.helper",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := lang.ResolveSelfCall(tc.to, tc.from)
			if got != tc.want {
				t.Errorf("ResolveSelfCall(%q, %q) = %q, want %q",
					tc.to, tc.from, got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2.2: Run the tests to verify they fail**

Run:

```bash
go test ./pkg/vex/reachability/transitive/languages/python/... 2>&1 | tail -10
```

Expected: compile error `package github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/python: no Go files`. This is the expected starting state.

- [ ] **Step 2.3: Write the Python implementation**

Create `pkg/vex/reachability/transitive/languages/python/python.go` with exactly this content:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package python provides the Python LanguageSupport implementation for
// the transitive cross-package reachability analyzer. It is imported only
// by the transitive package's LanguageFor factory.
package python

import (
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarpython "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/python"
	pyextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/python"
)

// Language is the Python LanguageSupport implementation. Callers use New
// to construct a value; the zero value is not valid.
type Language struct {
	extractor treesitter.LanguageExtractor
}

// New returns a fresh Python Language. The extractor is constructed once
// per call; callers that run many analyses should cache the result.
func New() *Language {
	return &Language{extractor: pyextractor.New()}
}

func (l *Language) Name() string                         { return "python" }
func (l *Language) Ecosystem() string                    { return "pypi" }
func (l *Language) FileExtensions() []string             { return []string{".py"} }
func (l *Language) Grammar() unsafe.Pointer              { return grammarpython.Language() }
func (l *Language) Extractor() treesitter.LanguageExtractor { return l.extractor }

// IsExportedSymbol reports whether a symbol is part of the Python package's
// public API. Python convention: underscore-prefixed names are private, and
// only functions, methods, and classes are part of the callable API surface.
func (l *Language) IsExportedSymbol(sym *treesitter.Symbol) bool {
	if sym == nil {
		return false
	}
	if strings.HasPrefix(sym.Name, "_") {
		return false
	}
	switch sym.Kind {
	case treesitter.SymbolFunction, treesitter.SymbolMethod, treesitter.SymbolClass:
		return true
	}
	return false
}

// ModulePath derives the dotted module path for a Python source file
// relative to sourceDir. It searches for the first path component that
// exactly matches packageName, then uses everything from that component
// onward. This correctly handles both flat and src-layout tarballs:
//
//	Flat:       "urllib3-1.26/urllib3/poolmanager.py"    → "urllib3.poolmanager"
//	Src layout: "urllib3-2.0.5/src/urllib3/util/retry.py" → "urllib3.util.retry"
//
// __init__ and __main__ suffixes are stripped. If no component matches
// packageName, the full relative path is joined (noise paths from tests/
// or docs/ fall into this branch).
func (l *Language) ModulePath(file, sourceDir, packageName string) string {
	rel, err := filepath.Rel(sourceDir, file)
	if err != nil {
		return packageName
	}
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		if part == packageName {
			mod := strings.Join(parts[i:], ".")
			mod = strings.TrimSuffix(mod, ".__init__")
			mod = strings.TrimSuffix(mod, ".__main__")
			return mod
		}
	}
	mod := strings.Join(parts, ".")
	mod = strings.TrimSuffix(mod, ".__init__")
	mod = strings.TrimSuffix(mod, ".__main__")
	return mod
}

// SymbolKey composes a dotted symbol key: "<modulePath>.<symbolName>".
// Python uses deep dotted keys so that submodule symbols are distinguishable
// from top-level package symbols.
func (l *Language) SymbolKey(modulePath, symbolName string) string {
	return modulePath + "." + symbolName
}

// NormalizeImports is the identity function for Python. The Python extractor
// produces imports in canonical form already; no rewriting is required.
func (l *Language) NormalizeImports(raw []treesitter.Import) []treesitter.Import {
	return raw
}

// ResolveDottedTarget resolves a dotted call target whose prefix is an
// import alias. For example, given "mod" and a scope where "mod" is an
// alias for "qs", this returns "qs.parse" given suffix="parse".
func (l *Language) ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool) {
	resolved, ok := scope.LookupImport(prefix)
	if !ok {
		return "", false
	}
	return treesitter.SymbolID(resolved + "." + suffix), true
}

// ResolveSelfCall rewrites "self.X" call targets to the class-qualified
// form "Module.ClassName.X" by extracting the class context from the
// caller's symbol ID. Only applies when `from` has at least three dot-
// separated components (module.class.method). Free functions are left
// unchanged.
func (l *Language) ResolveSelfCall(to, from treesitter.SymbolID) treesitter.SymbolID {
	toStr := string(to)
	if !strings.HasPrefix(toStr, "self.") {
		return to
	}
	methodName := toStr[len("self."):]
	fromParts := strings.Split(string(from), ".")
	if len(fromParts) < 3 {
		return to
	}
	classQual := strings.Join(fromParts[:len(fromParts)-1], ".")
	return treesitter.SymbolID(classQual + "." + methodName)
}
```

- [ ] **Step 2.4: Run the Python tests to verify they pass**

Run:

```bash
go test ./pkg/vex/reachability/transitive/languages/python/... -v 2>&1 | tail -40
```

Expected: all tests pass. Every test named in Step 2.1 appears with `--- PASS`.

- [ ] **Step 2.5: Wire `LanguageFor("python")` to return `python.New()`**

Edit `pkg/vex/reachability/transitive/language.go`. Replace the empty switch body in `LanguageFor` and add the Python import.

Change the imports block from:

```go
import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)
```

to:

```go
import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/python"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)
```

Change the `LanguageFor` body from:

```go
func LanguageFor(name string) (LanguageSupport, error) {
	switch strings.ToLower(name) {
	}
	return nil, fmt.Errorf("unsupported language %q", name)
}
```

to:

```go
func LanguageFor(name string) (LanguageSupport, error) {
	switch strings.ToLower(name) {
	case "python":
		return python.New(), nil
	}
	return nil, fmt.Errorf("unsupported language %q", name)
}
```

Also delete the `var _ unsafe.Pointer` placeholder line from the end of the file if it was kept in Task 1. The `unsafe.Pointer` reference in the `Grammar()` method signature already keeps the import in use.

- [ ] **Step 2.6: Verify the transitive package builds and all existing tests pass**

Run:

```bash
go build ./pkg/vex/reachability/transitive/...
go test ./pkg/vex/reachability/transitive/...
```

Expected: build exits 0; all existing tests in `transitive` still pass. The new Python unit tests in the `python` subpackage also pass.

- [ ] **Step 2.7: Verify integration and judge suites still pass**

Run:

```bash
task test:transitive
task test:reachability:transitive:llmjudge
```

Expected: both pass. Judge scores unchanged from the Step 1.1 baseline.

- [ ] **Step 2.8: Commit**

```bash
git add pkg/vex/reachability/transitive/languages/python/python.go \
        pkg/vex/reachability/transitive/languages/python/python_test.go \
        pkg/vex/reachability/transitive/language.go
git commit -m "feat(transitive): add Python LanguageSupport implementation

Implements the LanguageSupport interface for Python in its own subpackage
with comprehensive unit tests covering public-API rules, module path
derivation across flat and src-layout tarballs, dotted symbol keys, self
call rewriting, and dotted-alias resolution. Wires LanguageFor(\"python\")
to return a new Python instance. The transitive package hop.go and
exports.go still use their internal switch statements; Task 5 removes them."
```

---

## Task 3 — JavaScript `LanguageSupport` implementation

**Goal:** Land `pkg/vex/reachability/transitive/languages/javascript/javascript.go` as a complete implementation, with unit tests, and wire both `"javascript"` and `"js"` into `LanguageFor`. Test-driven.

**Files:**
- Create: `pkg/vex/reachability/transitive/languages/javascript/javascript.go`
- Create: `pkg/vex/reachability/transitive/languages/javascript/javascript_test.go`
- Modify: `pkg/vex/reachability/transitive/language.go`

- [ ] **Step 3.1: Write the failing unit tests for the JavaScript implementation**

Create `pkg/vex/reachability/transitive/languages/javascript/javascript_test.go` with exactly this content:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package javascript_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/javascript"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestJavaScript_Identity(t *testing.T) {
	lang := javascript.New()
	if lang.Name() != "javascript" {
		t.Errorf("Name() = %q, want %q", lang.Name(), "javascript")
	}
	if lang.Ecosystem() != "npm" {
		t.Errorf("Ecosystem() = %q, want %q", lang.Ecosystem(), "npm")
	}
	exts := lang.FileExtensions()
	wantExts := map[string]bool{".js": true, ".mjs": true, ".cjs": true}
	if len(exts) != len(wantExts) {
		t.Errorf("FileExtensions() len = %d, want %d", len(exts), len(wantExts))
	}
	for _, e := range exts {
		if !wantExts[e] {
			t.Errorf("FileExtensions() contains unexpected %q", e)
		}
	}
	if lang.Grammar() == nil {
		t.Error("Grammar() returned nil")
	}
	if lang.Extractor() == nil {
		t.Error("Extractor() returned nil")
	}
}

func TestJavaScript_IsExportedSymbol(t *testing.T) {
	lang := javascript.New()
	tests := []struct {
		name string
		sym  *treesitter.Symbol
		want bool
	}{
		{"public function", &treesitter.Symbol{Name: "parse", Kind: treesitter.SymbolFunction}, true},
		{"public class", &treesitter.Symbol{Name: "BodyParser", Kind: treesitter.SymbolClass}, true},
		{"public method", &treesitter.Symbol{Name: "send", Kind: treesitter.SymbolMethod}, true},
		{"underscore function still public in JS", &treesitter.Symbol{Name: "_helper", Kind: treesitter.SymbolFunction}, true},
		{"module kind rejected", &treesitter.Symbol{Name: "index", Kind: treesitter.SymbolModule}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lang.IsExportedSymbol(tc.sym); got != tc.want {
				t.Errorf("IsExportedSymbol(%+v) = %v, want %v", tc.sym, got, tc.want)
			}
		})
	}
}

func TestJavaScript_ModulePath(t *testing.T) {
	lang := javascript.New()
	tests := []struct {
		name        string
		file        string
		sourceDir   string
		packageName string
		want        string
	}{
		{
			name:        "top-level file in package",
			file:        "/tmp/qs/index.js",
			sourceDir:   "/tmp",
			packageName: "qs",
			want:        "qs",
		},
		{
			name:        "nested file in package",
			file:        "/tmp/qs/lib/parse.js",
			sourceDir:   "/tmp",
			packageName: "qs",
			want:        "qs",
		},
		{
			name:        "deeply nested file in package",
			file:        "/tmp/body-parser/lib/types/urlencoded.js",
			sourceDir:   "/tmp",
			packageName: "body-parser",
			want:        "body-parser",
		},
		{
			// Regression: out-of-package files must not be lumped under
			// packageName. Return the first path component so that the
			// shared package-name prefix filter in listExportedSymbols
			// rejects them.
			name:        "neighbor directory not in package",
			file:        "/tmp/other-package/index.js",
			sourceDir:   "/tmp",
			packageName: "qs",
			want:        "other-package",
		},
		{
			name:        "sibling file at source root",
			file:        "/tmp/README.js",
			sourceDir:   "/tmp",
			packageName: "qs",
			want:        "README",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := lang.ModulePath(tc.file, tc.sourceDir, tc.packageName)
			if got != tc.want {
				t.Errorf("ModulePath(%q, %q, %q) = %q, want %q",
					tc.file, tc.sourceDir, tc.packageName, got, tc.want)
			}
		})
	}
}

func TestJavaScript_SymbolKey(t *testing.T) {
	lang := javascript.New()
	got := lang.SymbolKey("body-parser", "urlencoded")
	want := "body-parser.urlencoded"
	if got != want {
		t.Errorf("SymbolKey = %q, want %q", got, want)
	}
}

func TestJavaScript_NormalizeImports_Identity(t *testing.T) {
	lang := javascript.New()
	raw := []treesitter.Import{
		{Module: "qs", Alias: "mod", Symbols: []string{}},
		{Module: "express", Symbols: []string{"Router"}},
	}
	got := lang.NormalizeImports(raw)
	if len(got) != len(raw) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(raw))
	}
	for i := range raw {
		if got[i].Module != raw[i].Module || got[i].Alias != raw[i].Alias {
			t.Errorf("got[%d] = %+v, want %+v", i, got[i], raw[i])
		}
	}
}

func TestJavaScript_ResolveDottedTarget(t *testing.T) {
	lang := javascript.New()
	scope := treesitter.NewScope(nil)
	scope.DefineImport("mod", "qs", []string{})

	t.Run("alias found", func(t *testing.T) {
		got, ok := lang.ResolveDottedTarget("mod", "parse", scope)
		if !ok {
			t.Fatalf("expected ok=true for known alias")
		}
		if got != treesitter.SymbolID("qs.parse") {
			t.Errorf("ResolveDottedTarget = %q, want %q", got, "qs.parse")
		}
	})

	t.Run("alias not found", func(t *testing.T) {
		_, ok := lang.ResolveDottedTarget("nope", "parse", scope)
		if ok {
			t.Errorf("expected ok=false for unknown alias")
		}
	})
}

func TestJavaScript_ResolveSelfCall_IsIdentity(t *testing.T) {
	lang := javascript.New()
	tests := []struct {
		to   treesitter.SymbolID
		from treesitter.SymbolID
	}{
		{"self.helper", "adapters.HTTPAdapter.__init__"},
		{"this.render", "component.Foo.render"},
		{"urllib3.PoolManager", "app.main"},
	}
	for _, tc := range tests {
		t.Run(string(tc.to), func(t *testing.T) {
			got := lang.ResolveSelfCall(tc.to, tc.from)
			if got != tc.to {
				t.Errorf("ResolveSelfCall(%q, %q) = %q, want identity %q",
					tc.to, tc.from, got, tc.to)
			}
		})
	}
}
```

- [ ] **Step 3.2: Run the tests to verify they fail**

Run:

```bash
go test ./pkg/vex/reachability/transitive/languages/javascript/... 2>&1 | tail -10
```

Expected: compile error `package github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/javascript: no Go files`.

- [ ] **Step 3.3: Write the JavaScript implementation**

Create `pkg/vex/reachability/transitive/languages/javascript/javascript.go` with exactly this content:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package javascript provides the JavaScript LanguageSupport implementation
// for the transitive cross-package reachability analyzer. It is imported only
// by the transitive package's LanguageFor factory.
package javascript

import (
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarjs "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/javascript"
	jsextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/javascript"
)

// Language is the JavaScript LanguageSupport implementation. Callers use
// New to construct a value; the zero value is not valid.
type Language struct {
	extractor treesitter.LanguageExtractor
}

// New returns a fresh JavaScript Language. The extractor is constructed
// once per call; callers that run many analyses should cache the result.
func New() *Language {
	return &Language{extractor: jsextractor.New()}
}

func (l *Language) Name() string                         { return "javascript" }
func (l *Language) Ecosystem() string                    { return "npm" }
func (l *Language) FileExtensions() []string             { return []string{".js", ".mjs", ".cjs"} }
func (l *Language) Grammar() unsafe.Pointer              { return grammarjs.Language() }
func (l *Language) Extractor() treesitter.LanguageExtractor { return l.extractor }

// IsExportedSymbol reports whether a symbol is part of the JavaScript
// package's public API. Unlike Python, JS has no underscore convention for
// privacy, so any function, method, or class is considered part of the
// public surface.
func (l *Language) IsExportedSymbol(sym *treesitter.Symbol) bool {
	if sym == nil {
		return false
	}
	switch sym.Kind {
	case treesitter.SymbolFunction, treesitter.SymbolMethod, treesitter.SymbolClass:
		return true
	}
	return false
}

// ModulePath collapses every in-package file to packageName (the flat
// key scheme: callers reference npm package APIs as "pkg.symbol" rather
// than "pkg.subdir.file.symbol"). Out-of-package files return their first
// relative path component so that listExportedSymbols's shared package-
// name prefix filter rejects them, matching the pre-refactor behavior of
// listExportedJavaScript which used modulePrefix for filtering and
// packageName for key composition.
func (l *Language) ModulePath(file, sourceDir, packageName string) string {
	rel, err := filepath.Rel(sourceDir, file)
	if err != nil {
		return packageName
	}
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	parts := strings.Split(rel, string(filepath.Separator))
	for _, part := range parts {
		if part == packageName {
			return packageName
		}
	}
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// SymbolKey composes the flat key: "<modulePath>.<symbolName>". Because
// ModulePath always returns packageName, the resulting key is always
// "<packageName>.<symbolName>".
func (l *Language) SymbolKey(modulePath, symbolName string) string {
	return modulePath + "." + symbolName
}

// NormalizeImports is the identity function for JavaScript. The JavaScript
// extractor already handles alias-only imports, assignment-expression
// require(), and dotted-alias registrations at extraction time, so no
// further normalization is required.
func (l *Language) NormalizeImports(raw []treesitter.Import) []treesitter.Import {
	return raw
}

// ResolveDottedTarget resolves a dotted call target whose prefix is an
// import alias. Implementation is identical to Python's today; future
// languages with different path separators (e.g., Ruby ::, Rust ::) will
// override this.
func (l *Language) ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool) {
	resolved, ok := scope.LookupImport(prefix)
	if !ok {
		return "", false
	}
	return treesitter.SymbolID(resolved + "." + suffix), true
}

// ResolveSelfCall is the identity function for JavaScript. JS uses `this.X`
// which is already handled by the tree-sitter extractor directly; there is
// no `self.X` construct to rewrite post-hoc.
func (l *Language) ResolveSelfCall(to, from treesitter.SymbolID) treesitter.SymbolID {
	return to
}
```

- [ ] **Step 3.4: Run the JavaScript tests to verify they pass**

Run:

```bash
go test ./pkg/vex/reachability/transitive/languages/javascript/... -v 2>&1 | tail -30
```

Expected: all tests pass.

- [ ] **Step 3.5: Wire `LanguageFor("javascript")` and `LanguageFor("js")` to return `javascript.New()`**

Edit `pkg/vex/reachability/transitive/language.go`. Update the imports and add the JavaScript cases.

Change the imports block from:

```go
import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/python"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)
```

to:

```go
import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/javascript"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/python"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)
```

Change the `LanguageFor` body from:

```go
func LanguageFor(name string) (LanguageSupport, error) {
	switch strings.ToLower(name) {
	case "python":
		return python.New(), nil
	}
	return nil, fmt.Errorf("unsupported language %q", name)
}
```

to:

```go
func LanguageFor(name string) (LanguageSupport, error) {
	switch strings.ToLower(name) {
	case "python":
		return python.New(), nil
	case "javascript", "js":
		return javascript.New(), nil
	}
	return nil, fmt.Errorf("unsupported language %q", name)
}
```

- [ ] **Step 3.6: Verify the transitive package builds and all existing tests pass**

Run:

```bash
go build ./pkg/vex/reachability/transitive/...
go test ./pkg/vex/reachability/transitive/...
```

Expected: build exits 0; all transitive package tests still pass.

- [ ] **Step 3.7: Verify integration and judge suites still pass**

Run:

```bash
task test:transitive
task test:reachability:transitive:llmjudge
```

Expected: both pass. Judge scores unchanged from the Step 1.1 baseline.

- [ ] **Step 3.8: Commit**

```bash
git add pkg/vex/reachability/transitive/languages/javascript/javascript.go \
        pkg/vex/reachability/transitive/languages/javascript/javascript_test.go \
        pkg/vex/reachability/transitive/language.go
git commit -m "feat(transitive): add JavaScript LanguageSupport implementation

Implements the LanguageSupport interface for JavaScript in its own
subpackage with unit tests covering flat package-key composition (no
underscore privacy filter, no per-file module derivation), identity
NormalizeImports and ResolveSelfCall (JS uses this.X handled at extraction
time), and dotted-alias resolution. Wires LanguageFor(\"javascript\") and
LanguageFor(\"js\") to return a new JavaScript instance."
```

---

## Task 4 — Registry and contract tests

**Goal:** Land `pkg/vex/reachability/transitive/language_test.go` with registry lookup tests and an interface-contract test that applies uniformly to every registered language. This is the test tier that catches a future language forgetting to populate one of the identity fields.

**Files:**
- Create: `pkg/vex/reachability/transitive/language_test.go`

- [ ] **Step 4.1: Write the registry and contract tests**

Create `pkg/vex/reachability/transitive/language_test.go` with exactly this content:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"strings"
	"testing"
)

func TestLanguageFor_RegisteredLanguages(t *testing.T) {
	tests := []struct {
		input        string
		wantName     string
		wantEcosys   string
	}{
		{"python", "python", "pypi"},
		{"Python", "python", "pypi"},
		{"PYTHON", "python", "pypi"},
		{"javascript", "javascript", "npm"},
		{"JavaScript", "javascript", "npm"},
		{"JAVASCRIPT", "javascript", "npm"},
		{"js", "javascript", "npm"},
		{"JS", "javascript", "npm"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			lang, err := LanguageFor(tc.input)
			if err != nil {
				t.Fatalf("LanguageFor(%q) returned error: %v", tc.input, err)
			}
			if lang == nil {
				t.Fatalf("LanguageFor(%q) returned nil without error", tc.input)
			}
			if lang.Name() != tc.wantName {
				t.Errorf("Name() = %q, want %q", lang.Name(), tc.wantName)
			}
			if lang.Ecosystem() != tc.wantEcosys {
				t.Errorf("Ecosystem() = %q, want %q", lang.Ecosystem(), tc.wantEcosys)
			}
		})
	}
}

func TestLanguageFor_UnknownLanguage(t *testing.T) {
	tests := []struct {
		input string
	}{
		{""},
		{"ruby"},
		{"rust"},
		{"c++"},
		{"go"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			lang, err := LanguageFor(tc.input)
			if err == nil {
				t.Errorf("LanguageFor(%q) = %+v, nil; want error", tc.input, lang)
			}
			if lang != nil {
				t.Errorf("LanguageFor(%q) returned non-nil %+v along with error", tc.input, lang)
			}
			if !strings.Contains(err.Error(), "unsupported") {
				t.Errorf("error message %q should contain 'unsupported'", err.Error())
			}
		})
	}
}

// TestLanguageSupport_Contract verifies that every registered language
// honors the interface contract: non-empty identity fields, non-nil
// tree-sitter plumbing, and round-trippable name via LanguageFor.
func TestLanguageSupport_Contract(t *testing.T) {
	registered := []string{"python", "javascript"}
	for _, name := range registered {
		t.Run(name, func(t *testing.T) {
			lang, err := LanguageFor(name)
			if err != nil {
				t.Fatalf("LanguageFor(%q): %v", name, err)
			}
			if lang.Name() == "" {
				t.Error("Name() is empty")
			}
			if lang.Ecosystem() == "" {
				t.Error("Ecosystem() is empty")
			}
			exts := lang.FileExtensions()
			if len(exts) == 0 {
				t.Error("FileExtensions() is empty")
			}
			for _, e := range exts {
				if !strings.HasPrefix(e, ".") {
					t.Errorf("FileExtensions() contains %q without leading dot", e)
				}
			}
			if lang.Grammar() == nil {
				t.Error("Grammar() returned nil")
			}
			if lang.Extractor() == nil {
				t.Error("Extractor() returned nil")
			}
			// Round-trip: LanguageFor(lang.Name()) should return a language
			// with the same Name and Ecosystem.
			other, err := LanguageFor(lang.Name())
			if err != nil {
				t.Fatalf("round-trip LanguageFor(%q): %v", lang.Name(), err)
			}
			if other.Name() != lang.Name() {
				t.Errorf("round-trip Name: got %q, want %q", other.Name(), lang.Name())
			}
			if other.Ecosystem() != lang.Ecosystem() {
				t.Errorf("round-trip Ecosystem: got %q, want %q", other.Ecosystem(), lang.Ecosystem())
			}
		})
	}
}
```

- [ ] **Step 4.2: Run the registry tests and verify they pass**

Run:

```bash
go test -run 'TestLanguageFor|TestLanguageSupport_Contract' -v ./pkg/vex/reachability/transitive/... 2>&1 | tail -50
```

Expected: all tests pass. Python and JavaScript round-trip correctly; unknown languages return a `"unsupported..."` error.

- [ ] **Step 4.3: Verify the full transitive package test suite still passes**

Run:

```bash
go test ./pkg/vex/reachability/transitive/...
```

Expected: all tests pass (the pre-existing tests plus the new registry and contract tests).

- [ ] **Step 4.4: Verify integration and judge suites still pass**

Run:

```bash
task test:transitive
task test:reachability:transitive:llmjudge
```

Expected: both pass. Judge scores unchanged from the Step 1.1 baseline.

- [ ] **Step 4.5: Commit**

```bash
git add pkg/vex/reachability/transitive/language_test.go
git commit -m "test(transitive): add LanguageFor registry and contract tests

Table-driven tests for LanguageFor cover case-insensitive lookup of the
two registered languages and their common aliases, unknown-language error
handling, and an interface-contract test applied uniformly to every
registered language. The contract test catches a future language that
forgets to populate one of the identity fields (Name, Ecosystem,
FileExtensions, Grammar, Extractor)."
```

---

## Task 5 — Atomic refactor: port orchestration code and all callers

**Goal:** Replace all remaining language-string usage in the `transitive` package and its consumers (`vex/transitive_wire.go`, `vex/reachability/python/llm_judge_test.go`, `vex/reachability/javascript/llm_judge_test.go`) with `LanguageSupport` in a single atomic commit. This is the largest commit in the plan. After it lands, `hop.go` and `exports.go` contain no language-specific switches.

**Files:**
- Modify: `pkg/vex/reachability/transitive/hop.go`
- Modify: `pkg/vex/reachability/transitive/exports.go`
- Modify: `pkg/vex/reachability/transitive/transitive.go`
- Modify: `pkg/vex/reachability/transitive/walker.go`
- Modify: `pkg/vex/reachability/transitive/hop_test.go`
- Modify: `pkg/vex/reachability/transitive/walker_test.go`
- Modify: `pkg/vex/reachability/transitive/exports_test.go`
- Modify: `pkg/vex/transitive_wire.go`
- Modify: `pkg/vex/reachability/python/llm_judge_test.go`
- Modify: `pkg/vex/reachability/javascript/llm_judge_test.go`

**Editing order inside the single commit:** the steps below are sequenced so that after Step 5.9 the whole repo builds and tests pass. Do not run build or test between sub-steps before 5.9 — they will fail on purpose until all files are consistent.

- [ ] **Step 5.1: Rewrite `exports.go` as a language-agnostic orchestrator**

Open `pkg/vex/reachability/transitive/exports.go` and replace the entire file contents with:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

// listExportedSymbols extracts the public API of a package at sourceDir as
// fully-qualified symbol IDs. The exact key scheme is language-specific and
// decided by lang.SymbolKey; for Python this produces dotted keys like
// "urllib3.poolmanager.PoolManager" and for JavaScript this produces flat
// keys like "body-parser.urlencoded".
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
		// Skip files outside the package itself (tests, docs, examples).
		// A valid package module starts with "packageName." or equals
		// "packageName" — this filter is language-agnostic because every
		// LanguageSupport.ModulePath returns a value rooted at packageName.
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

// collectFilesByExt returns all regular files under root whose names end
// with one of the given extensions. The search is recursive.
func collectFilesByExt(root string, exts []string) ([]string, error) {
	extSet := make(map[string]struct{}, len(exts))
	for _, e := range exts {
		extSet[e] = struct{}{}
	}
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if _, ok := extSet[filepath.Ext(path)]; ok {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}
```

This deletes `listExportedPython`, `listExportedJavaScript`, `modulePrefix`, and all language-specific imports (tree-sitter grammars, extractors) from `exports.go`. The file now imports only `io/fs`, `path/filepath`, `strings`, and `treesitter`.

- [ ] **Step 5.2: Rewrite `hop.go` as a language-agnostic orchestrator**

Open `pkg/vex/reachability/transitive/hop.go` and apply these edits:

**Edit 1:** Change the imports block from:

```go
import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarjs "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/javascript"
	grammarpython "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/python"
	jsextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/javascript"
	pyextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/python"
)
```

to:

```go
import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)
```

**Edit 2:** Change the `HopInput` struct definition from:

```go
// HopInput describes a single per-hop reachability query.
type HopInput struct {
	// Language is the source language: "python" or "javascript".
	Language string
	// SourceDir is the root directory containing source files to scan.
	SourceDir string
	// TargetSymbols are the qualified symbol names to search for
	// (e.g. "urllib3.PoolManager", "lodash.merge").
	TargetSymbols []string
	// MaxTargets caps how many TargetSymbols are processed.
	MaxTargets int
}
```

to:

```go
// HopInput describes a single per-hop reachability query.
type HopInput struct {
	// Language is the LanguageSupport implementation for the source language.
	Language LanguageSupport
	// SourceDir is the root directory containing source files to scan.
	SourceDir string
	// TargetSymbols are the qualified symbol names to search for
	// (e.g. "urllib3.PoolManager", "lodash.merge").
	TargetSymbols []string
	// MaxTargets caps how many TargetSymbols are processed.
	MaxTargets int
}
```

**Edit 3:** Replace the opening of `RunHop` (the `extractorForLanguage` call) from:

```go
func RunHop(_ context.Context, input HopInput) (HopResult, error) {
	ext, langPtr, fileExt, err := extractorForLanguage(input.Language)
	if err != nil {
		return HopResult{}, err
	}

	// Collect all source files.
	var files []string
	if walkErr := filepath.WalkDir(input.SourceDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() && strings.HasSuffix(path, fileExt) {
			files = append(files, path)
		}
		return nil
	}); walkErr != nil {
		return HopResult{}, fmt.Errorf("walk %s: %w", input.SourceDir, walkErr)
	}
```

to:

```go
func RunHop(_ context.Context, input HopInput) (HopResult, error) {
	if input.Language == nil {
		return HopResult{}, fmt.Errorf("RunHop: input.Language is nil")
	}
	ext := input.Language.Extractor()
	langPtr := input.Language.Grammar()
	fileExts := input.Language.FileExtensions()

	// Collect all source files matching any of the language's extensions.
	var files []string
	if walkErr := filepath.WalkDir(input.SourceDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		for _, ext := range fileExts {
			if strings.HasSuffix(path, ext) {
				files = append(files, path)
				return nil
			}
		}
		return nil
	}); walkErr != nil {
		return HopResult{}, fmt.Errorf("walk %s: %w", input.SourceDir, walkErr)
	}
```

**Edit 4:** In Phase 2a (synthetic module-level symbols), change the `Language` field assignment from:

```go
		graph.AddSymbol(&treesitter.Symbol{
			ID:            modID,
			Name:          mod,
			QualifiedName: mod,
			Language:      input.Language,
			File:          fi.pr.File,
			Package:       mod,
			Kind:          treesitter.SymbolFunction,
		})
```

to:

```go
		graph.AddSymbol(&treesitter.Symbol{
			ID:            modID,
			Name:          mod,
			QualifiedName: mod,
			Language:      input.Language.Name(),
			File:          fi.pr.File,
			Package:       mod,
			Kind:          treesitter.SymbolFunction,
		})
```

**Edit 5:** In Phase 3 (call edge extraction), change the resolveTarget/resolveSelfCall calls from:

```go
		for _, e := range edges {
			e.To = resolveTarget(e.To, augScope, mod)
			e.To = resolveSelfCall(e.To, e.From)
			graph.AddEdge(e)
		}
```

to:

```go
		for _, e := range edges {
			e.To = resolveTarget(e.To, augScope, mod, input.Language)
			e.To = input.Language.ResolveSelfCall(e.To, e.From)
			graph.AddEdge(e)
		}
```

**Edit 6:** In Phase 4 (target injection), change the `Language` field assignment from:

```go
	for _, t := range targets {
		id := treesitter.SymbolID(t)
		targetSet[id] = struct{}{}
		if graph.GetSymbol(id) == nil {
			graph.AddSymbol(&treesitter.Symbol{
				ID:         id,
				Name:       t,
				IsExternal: true,
				Language:   input.Language,
			})
		}
	}
```

to:

```go
	for _, t := range targets {
		id := treesitter.SymbolID(t)
		targetSet[id] = struct{}{}
		if graph.GetSymbol(id) == nil {
			graph.AddSymbol(&treesitter.Symbol{
				ID:         id,
				Name:       t,
				IsExternal: true,
				Language:   input.Language.Name(),
			})
		}
	}
```

**Edit 7:** Delete the entire `extractorForLanguage` function. Locate this block in `hop.go` (starting around line 249):

```go
// extractorForLanguage returns the LanguageExtractor, grammar language pointer,
// and file extension for the given language name.
func extractorForLanguage(lang string) (ext treesitter.LanguageExtractor, langPtr unsafe.Pointer, fileExt string, err error) { //nolint:nonamedreturns // gocritic requires named returns for clarity
	switch strings.ToLower(lang) {
	case "python":
		return pyextractor.New(), grammarpython.Language(), ".py", nil
	case "javascript", "js":
		return jsextractor.New(), grammarjs.Language(), ".js", nil
	default:
		return nil, nil, "", fmt.Errorf("unsupported language %q: only python and javascript are supported", lang)
	}
}
```

Delete it entirely.

**Edit 8:** Change `buildCrossFileScope` to accept a `LanguageSupport` and normalize imports before processing. Change the function from:

```go
// buildCrossFileScope constructs a scope that resolves imported symbols to their
// fully-qualified names across module boundaries.
func buildCrossFileScope(
	imports []treesitter.Import,
	moduleSymbols map[string][]*treesitter.Symbol,
	baseScope *treesitter.Scope,
) *treesitter.Scope {
	aug := treesitter.NewScope(baseScope)
	for _, imp := range imports {
		// Register alias → module mapping even when no named symbols are listed.
		// This covers patterns like `const mod = require('qs')` where the entire
		// module is bound to an alias (Alias="mod", Symbols=[]) so that dotted
		// calls such as `mod.parse` can later be resolved to `qs.parse`.
		if imp.Alias != "" && imp.Module != "" {
			aug.DefineImport(imp.Alias, imp.Module, imp.Symbols)
		}
		for _, sym := range imp.Symbols {
			aug.Define(sym, imp.Module+"."+sym)
		}
	}
	_ = moduleSymbols // reserved for future cross-file resolution
	return aug
}
```

to:

```go
// buildCrossFileScope constructs a scope that resolves imported symbols to
// their fully-qualified names across module boundaries. It calls
// lang.NormalizeImports on the raw import slice before applying the shared
// alias-and-symbol binding loop, so that language-specific import shapes
// (alias-only require(), dotted-alias rewriting, etc.) are handled before
// the shared loop runs.
func buildCrossFileScope(
	imports []treesitter.Import,
	moduleSymbols map[string][]*treesitter.Symbol,
	baseScope *treesitter.Scope,
	lang LanguageSupport,
) *treesitter.Scope {
	normalized := lang.NormalizeImports(imports)
	aug := treesitter.NewScope(baseScope)
	for _, imp := range normalized {
		// Register alias → module mapping even when no named symbols are
		// listed. This covers patterns like `const mod = require('qs')`
		// where the entire module is bound to an alias (Alias="mod",
		// Symbols=[]) so that dotted calls such as `mod.parse` can later
		// be resolved to `qs.parse`.
		if imp.Alias != "" && imp.Module != "" {
			aug.DefineImport(imp.Alias, imp.Module, imp.Symbols)
		}
		for _, sym := range imp.Symbols {
			aug.Define(sym, imp.Module+"."+sym)
		}
	}
	_ = moduleSymbols // reserved for future cross-file resolution
	return aug
}
```

**Edit 9:** Update the caller of `buildCrossFileScope` in Phase 3 (around line 174) from:

```go
		augScope := buildCrossFileScope(fi.imports, moduleSymbols, fi.scope)
```

to:

```go
		augScope := buildCrossFileScope(fi.imports, moduleSymbols, fi.scope, input.Language)
```

**Edit 10:** Change `resolveTarget` to delegate dotted-prefix resolution through the language. Change the function from:

```go
// resolveTarget resolves a call target SymbolID using the scope for
// cross-module symbol bindings. For bare names not found in scope, it falls
// back to qualifying with localMod (the calling file's module name), which
// covers same-file function calls (e.g., call to "request" in api.py
// resolves to "api.request").
func resolveTarget(to treesitter.SymbolID, scope *treesitter.Scope, localMod string) treesitter.SymbolID {
	toStr := string(to)
	if dotIdx := strings.Index(toStr, "."); dotIdx >= 0 {
		// Dotted callee: try to resolve the prefix as an import alias.
		// e.g. "mod.parse" where scope has mod → qs  →  returns "qs.parse".
		prefix := toStr[:dotIdx]
		suffix := toStr[dotIdx+1:]
		if resolved, ok := scope.LookupImport(prefix); ok {
			return treesitter.SymbolID(resolved + "." + suffix)
		}
		return to
	}
	if qualName, ok := scope.Lookup(toStr); ok {
		return treesitter.SymbolID(qualName)
	}
	// Qualify with local module name so same-file calls are traceable.
	if localMod != "" {
		return treesitter.SymbolID(localMod + "." + toStr)
	}
	return to
}
```

to:

```go
// resolveTarget resolves a call target SymbolID using the scope for
// cross-module symbol bindings. Dotted-prefix resolution is delegated to
// lang.ResolveDottedTarget so that languages with different path separators
// (e.g., Ruby :: , Rust :: ) can provide their own logic. For bare names
// not found in scope, the function falls back to qualifying with localMod
// (the calling file's module name), which covers same-file function calls
// (e.g., call to "request" in api.py resolves to "api.request").
func resolveTarget(to treesitter.SymbolID, scope *treesitter.Scope, localMod string, lang LanguageSupport) treesitter.SymbolID {
	toStr := string(to)
	if dotIdx := strings.Index(toStr, "."); dotIdx >= 0 {
		prefix := toStr[:dotIdx]
		suffix := toStr[dotIdx+1:]
		if resolved, ok := lang.ResolveDottedTarget(prefix, suffix, scope); ok {
			return resolved
		}
		return to
	}
	if qualName, ok := scope.Lookup(toStr); ok {
		return treesitter.SymbolID(qualName)
	}
	if localMod != "" {
		return treesitter.SymbolID(localMod + "." + toStr)
	}
	return to
}
```

**Edit 11:** Delete the `resolveSelfCall` function entirely. It has been moved into each language's implementation. Locate this block at the end of `hop.go`:

```go
// resolveSelfCall rewrites call targets of the form "self.X" to their
// class-qualified form "Module.ClassName.X" by extracting the class context
// from the from symbol ID. For example, if from="adapters.HTTPAdapter.__init__"
// and to="self.init_poolmanager", this returns "adapters.HTTPAdapter.init_poolmanager".
//
// Only applies when from has at least three dot-separated components (module,
// class, method). Free functions (e.g., "api.get") are left unchanged.
func resolveSelfCall(to, from treesitter.SymbolID) treesitter.SymbolID {
	toStr := string(to)
	if !strings.HasPrefix(toStr, "self.") {
		return to
	}
	methodName := toStr[len("self."):]
	fromParts := strings.Split(string(from), ".")
	if len(fromParts) < 3 {
		// Not inside a class method — no class context available.
		return to
	}
	// classQual = everything except the last component (the method name in from).
	classQual := strings.Join(fromParts[:len(fromParts)-1], ".")
	return treesitter.SymbolID(classQual + "." + methodName)
}
```

Delete it entirely.

- [ ] **Step 5.3: Update `transitive.go` to use `LanguageSupport` on the Analyzer**

Open `pkg/vex/reachability/transitive/transitive.go` and apply these edits:

**Edit 1:** Change the `Analyzer` struct from:

```go
type Analyzer struct {
	Config    Config
	Fetchers  map[string]Fetcher // keyed by ecosystem: "pypi", "npm"
	Language  string             // "python" or "javascript"
	Ecosystem string             // matching ecosystem key for Fetchers
}
```

to:

```go
type Analyzer struct {
	Config   Config
	Fetchers map[string]Fetcher // keyed by ecosystem: "pypi", "npm"
	Language LanguageSupport    // per-language plug-in; selects fetcher via Ecosystem()
}
```

**Edit 2:** Change the fetcher lookup in `Analyze` (around line 44) from:

```go
	fetcher, ok := a.Fetchers[a.Ecosystem]
	if !ok {
		return notApplicable(ReasonTransitiveNotApplicable), nil
	}
```

to:

```go
	if a.Language == nil {
		return notApplicable(ReasonTransitiveNotApplicable), nil
	}
	fetcher, ok := a.Fetchers[a.Language.Ecosystem()]
	if !ok {
		return notApplicable(ReasonTransitiveNotApplicable), nil
	}
```

**Edit 3:** Update the `Walker` construction inside `Analyze` (around line 85) — it already uses `a.Language`, but that field is now `LanguageSupport`. No code change is needed here other than confirming `Walker.Language` is `LanguageSupport` (see Step 5.4).

**Edit 4:** Update the `RunHop` call inside `Analyze` (around line 106) from:

```go
		appRes, err := RunHop(ctx, HopInput{
			Language:      a.Language,
			SourceDir:     sourceDir,
			TargetSymbols: appTargets,
			MaxTargets:    a.Config.MaxTargetSymbolsPerHop,
		})
```

No change — `a.Language` is now `LanguageSupport` and `HopInput.Language` is now `LanguageSupport`, so the assignment type-checks directly.

**Edit 5:** Change `collectVulnSymbols` (around line 140) from:

```go
func (a *Analyzer) collectVulnSymbols(ctx context.Context, finding *formats.Finding) (symbols, degradations []string) { //nolint:nonamedreturns // gocritic requires named returns
	fetcher, ok := a.Fetchers[a.Ecosystem]
	if !ok {
		return nil, []string{ReasonTransitiveNotApplicable}
	}
```

to:

```go
func (a *Analyzer) collectVulnSymbols(ctx context.Context, finding *formats.Finding) (symbols, degradations []string) { //nolint:nonamedreturns // gocritic requires named returns
	if a.Language == nil {
		return nil, []string{ReasonTransitiveNotApplicable}
	}
	fetcher, ok := a.Fetchers[a.Language.Ecosystem()]
	if !ok {
		return nil, []string{ReasonTransitiveNotApplicable}
	}
```

**Edit 6:** Change the `extractExportedSymbols` call site inside `collectVulnSymbols` from:

```go
	// Extract all exported symbols from the package source.
	symbols, degradations = extractExportedSymbols(a.Language, fres.SourceDir, finding.AffectedName)
	return symbols, degradations
}
```

to:

```go
	// Extract all exported symbols from the package source.
	symbols, degradations = extractExportedSymbols(a.Language, fres.SourceDir, finding.AffectedName)
	return symbols, degradations
}
```

No change to the call site text — but the function signature changes in Edit 7.

**Edit 7:** Change the `extractExportedSymbols` function signature from:

```go
// extractExportedSymbols walks the package source and returns fully-qualified
// symbol IDs of its public API. v1: "all top-level functions and methods."
// Filtering by language conventions (leading underscore for Python private)
// is applied.
func extractExportedSymbols(language, sourceDir, packageName string) (symbols, degradations []string) { //nolint:nonamedreturns // gocritic requires named returns
	syms, err := listExportedSymbols(language, sourceDir, packageName)
	if err != nil {
		return nil, []string{ReasonExtractorError}
	}
	return syms, nil
}
```

to:

```go
// extractExportedSymbols walks the package source and returns fully-qualified
// symbol IDs of its public API. v1: "all top-level functions and methods."
// Filtering by language conventions (e.g., leading underscore for Python
// private) is applied by the language's IsExportedSymbol implementation.
func extractExportedSymbols(lang LanguageSupport, sourceDir, packageName string) (symbols, degradations []string) { //nolint:nonamedreturns // gocritic requires named returns
	syms, err := listExportedSymbols(lang, sourceDir, packageName)
	if err != nil {
		return nil, []string{ReasonExtractorError}
	}
	return syms, nil
}
```

- [ ] **Step 5.4: Update `walker.go` to use `LanguageSupport` on Walker**

Open `pkg/vex/reachability/transitive/walker.go` and change the `Walker` struct from:

```go
type Walker struct {
	Fetcher     Fetcher
	Hop         HopRunner
	Config      Config
	Language    string
	InitialTarg []string // target symbols at the vulnerable package
}
```

to:

```go
type Walker struct {
	Fetcher     Fetcher
	Hop         HopRunner
	Config      Config
	Language    LanguageSupport
	InitialTarg []string // target symbols at the vulnerable package
}
```

The `w.Hop(hopCtx, HopInput{Language: w.Language, ...})` call at line 78 type-checks without change — `w.Language` is now `LanguageSupport` and `HopInput.Language` is now `LanguageSupport`.

- [ ] **Step 5.5: Update `hop_test.go` to use `python.New()` and pass LanguageSupport to helpers**

Open `pkg/vex/reachability/transitive/hop_test.go` and apply these edits:

**Edit 1:** Change the imports block from:

```go
import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)
```

to:

```go
import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/python"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)
```

**Edit 2:** In `TestRunHop_Python_FindsCaller`, change:

```go
	res, err := RunHop(context.Background(), HopInput{
		Language:      "python",
		SourceDir:     src,
		TargetSymbols: []string{"urllib3.PoolManager"},
		MaxTargets:    100,
	})
```

to:

```go
	res, err := RunHop(context.Background(), HopInput{
		Language:      python.New(),
		SourceDir:     src,
		TargetSymbols: []string{"urllib3.PoolManager"},
		MaxTargets:    100,
	})
```

**Edit 3:** In `TestBuildCrossFileScope_AliasOnlyImport`, change:

```go
	augScope := buildCrossFileScope(imports, moduleSymbols, baseScope)
```

to:

```go
	augScope := buildCrossFileScope(imports, moduleSymbols, baseScope, python.New())
```

**Edit 4:** In `TestResolveTarget_DottedAliasCall`, change:

```go
	got := resolveTarget(treesitter.SymbolID("mod.parse"), scope, "urlencoded")
```

to:

```go
	got := resolveTarget(treesitter.SymbolID("mod.parse"), scope, "urlencoded", python.New())
```

**Edit 5:** In `TestRunHop_Python_NoCaller`, change:

```go
	res, err := RunHop(context.Background(), HopInput{
		Language:      "python",
		SourceDir:     src,
		TargetSymbols: []string{"somepkg.does_not_exist"},
		MaxTargets:    100,
	})
```

to:

```go
	res, err := RunHop(context.Background(), HopInput{
		Language:      python.New(),
		SourceDir:     src,
		TargetSymbols: []string{"somepkg.does_not_exist"},
		MaxTargets:    100,
	})
```

- [ ] **Step 5.6: Update `walker_test.go` to use `python.New()`**

Open `pkg/vex/reachability/transitive/walker_test.go` and apply these edits:

**Edit 1:** Add the python import. Change the imports block from:

```go
import (
	"context"
	"testing"
)
```

to:

```go
import (
	"context"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/python"
)
```

**Edit 2:** In every `Walker` literal in the test file (there are multiple — grep for `Language:` within the file), change `Language: "python"` to `Language: python.New()`. The first one is in `TestWalker_Reachable_StitchesCallPaths` at around line 56; apply the same change to every other `Walker{...}` literal in the file.

Run this to list every location that needs updating:

```bash
grep -n 'Language:.*"python"' pkg/vex/reachability/transitive/walker_test.go
```

For each line reported, replace `Language: "python"` with `Language: python.New()`.

- [ ] **Step 5.7: Update `exports_test.go` to call `listExportedSymbols` with JavaScript LanguageSupport**

Open `pkg/vex/reachability/transitive/exports_test.go`. The test file references `listExportedJavaScript` directly, which no longer exists. Replace it with calls through the new language-agnostic `listExportedSymbols`.

**Edit 1:** Add the javascript import. Change the imports block from:

```go
import (
	"os"
	"path/filepath"
	"testing"
)
```

to:

```go
import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/javascript"
)
```

**Edit 2:** Replace every call site of the form `listExportedJavaScript(tmp, "qs")` with `listExportedSymbols(javascript.New(), tmp, "qs")`. To locate every call site:

```bash
grep -n 'listExportedJavaScript' pkg/vex/reachability/transitive/exports_test.go
```

For each line reported, apply the replacement. The expected output shape (`[]string` of symbols, or `error`) is unchanged, so surrounding assertions remain valid.

**Edit 3:** If any assertion error messages still say `"listExportedJavaScript"`, update them to `"listExportedSymbols"` for clarity, e.g.:

```go
	if err != nil {
		t.Fatalf("listExportedJavaScript: %v", err)
	}
```

becomes:

```go
	if err != nil {
		t.Fatalf("listExportedSymbols: %v", err)
	}
```

- [ ] **Step 5.8: Rewrite `transitive_wire.go` to use `LanguageFor` and extract `buildFetchers`**

Open `pkg/vex/transitive_wire.go` and replace the `buildTransitiveAnalyzer` function entirely. Change this block:

```go
// buildTransitiveAnalyzer constructs a transitive.Analyzer for the given language.
// Returns nil when cfg.Enabled is false or the language is not supported
// (currently "python" and "javascript" only).
func buildTransitiveAnalyzer(cfg transitive.Config, language string) *transitive.Analyzer {
	if !cfg.Enabled {
		return nil
	}

	var ecosystem string
	switch language {
	case "python":
		ecosystem = "pypi"
	case "javascript":
		ecosystem = "npm"
	default:
		return nil
	}

	var cache *transitive.Cache
	if cfg.CacheDir != "" {
		cache = transitive.NewCache(cfg.CacheDir)
	}

	var fetcher transitive.Fetcher
	switch ecosystem {
	case "pypi":
		fetcher = &transitive.PyPIFetcher{Cache: cache}
	case "npm":
		fetcher = &transitive.NPMFetcher{Cache: cache}
	}

	return &transitive.Analyzer{
		Config:    cfg,
		Fetchers:  map[string]transitive.Fetcher{ecosystem: fetcher},
		Language:  language,
		Ecosystem: ecosystem,
	}
}
```

to:

```go
// buildTransitiveAnalyzer constructs a transitive.Analyzer for the given
// language. Returns nil when cfg.Enabled is false, the language is not
// registered in transitive.LanguageFor, or no fetcher is available for the
// language's ecosystem.
func buildTransitiveAnalyzer(cfg transitive.Config, language string) *transitive.Analyzer {
	if !cfg.Enabled {
		return nil
	}
	lang, err := transitive.LanguageFor(language)
	if err != nil {
		return nil
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

// buildFetchers returns a map containing the single fetcher required for
// the given ecosystem, or nil if the ecosystem has no registered fetcher.
// This is the one remaining ecosystem switch in the codebase; each
// language's LanguageSupport declares the ecosystem key it requires.
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

- [ ] **Step 5.9: Update `pkg/vex/reachability/python/llm_judge_test.go` construction site**

Open `pkg/vex/reachability/python/llm_judge_test.go` and find the `transitive.Analyzer` construction at around line 216. Change this block:

```go
	cache := transitive.NewCache(t.TempDir())
	fetcher := &transitive.PyPIFetcher{Cache: cache}
	ta := &transitive.Analyzer{
		Config:    transitive.DefaultConfig(),
		Language:  "python",
		Ecosystem: "pypi",
		Fetchers:  map[string]transitive.Fetcher{"pypi": fetcher},
	}
```

to:

```go
	cache := transitive.NewCache(t.TempDir())
	fetcher := &transitive.PyPIFetcher{Cache: cache}
	lang, err := transitive.LanguageFor("python")
	if err != nil {
		t.Fatalf("LanguageFor(python): %v", err)
	}
	ta := &transitive.Analyzer{
		Config:   transitive.DefaultConfig(),
		Language: lang,
		Fetchers: map[string]transitive.Fetcher{"pypi": fetcher},
	}
```

**Important:** this file declares `err` elsewhere in the same function. If the compiler flags a shadowing or redeclaration error, rename the new variable to `langErr` instead:

```go
	lang, langErr := transitive.LanguageFor("python")
	if langErr != nil {
		t.Fatalf("LanguageFor(python): %v", langErr)
	}
```

Verify which variant compiles by running `go vet ./pkg/vex/reachability/python/...` with the `llmjudge` build tag at Step 5.11 — the vet output will tell you immediately.

- [ ] **Step 5.10: Update `pkg/vex/reachability/javascript/llm_judge_test.go` construction site**

Open `pkg/vex/reachability/javascript/llm_judge_test.go` and find the `transitive.Analyzer` construction at around line 217. Change this block:

```go
	cache := transitive.NewCache(t.TempDir())
	fetcher := &transitive.NPMFetcher{Cache: cache}
	ta := &transitive.Analyzer{
		Config:    transitive.DefaultConfig(),
		Language:  "javascript",
		Ecosystem: "npm",
		Fetchers:  map[string]transitive.Fetcher{"npm": fetcher},
	}
```

to:

```go
	cache := transitive.NewCache(t.TempDir())
	fetcher := &transitive.NPMFetcher{Cache: cache}
	lang, err := transitive.LanguageFor("javascript")
	if err != nil {
		t.Fatalf("LanguageFor(javascript): %v", err)
	}
	ta := &transitive.Analyzer{
		Config:   transitive.DefaultConfig(),
		Language: lang,
		Fetchers: map[string]transitive.Fetcher{"npm": fetcher},
	}
```

Apply the same `langErr` rename if the compiler flags a shadowing error.

- [ ] **Step 5.11: Verify the whole repo builds**

Run:

```bash
go build ./...
go build -tags llmjudge ./...
```

Expected: both commands exit 0 with no output.

If the second command reports shadowed `err` in either llm_judge_test.go file, apply the `langErr` rename noted in Steps 5.9 and 5.10.

- [ ] **Step 5.12: Run the full test suite**

Run:

```bash
task test
```

Expected: all tests pass, including the new Python/JavaScript subpackage tests, the registry/contract tests from Task 4, and the pre-existing hop/walker/exports tests (which now use `python.New()` / `javascript.New()`).

- [ ] **Step 5.13: Run the transitive integration suite**

Run:

```bash
task test:transitive
```

Expected: all integration tests pass. This hits real PyPI and npm and exercises the full pipeline against the cross-package CVE fixtures. It is the strongest signal that the refactor preserves end-to-end behavior.

- [ ] **Step 5.14: Run the transitive LLM judge suite and compare scores**

Run:

```bash
task test:reachability:transitive:llmjudge 2>&1 | grep -E "Transitive LLM Scores|PASS|FAIL" | tee /tmp/transitive-judge-postrefactor.txt
```

Expected: both `TestLLMJudge_PythonTransitiveReachability` and `TestLLMJudge_JavaScriptTransitiveReachability` report PASS. The overall scores should be within one point of the baseline captured in Step 1.1.

Compare the two files:

```bash
diff /tmp/transitive-judge-baseline.txt /tmp/transitive-judge-postrefactor.txt
```

If any sub-metric (`path`, `confidence`, `evidence`, `fp`, `symbol`, `overall`) dropped by two or more points on either language, **stop and investigate before committing**. A two-point drop indicates a real regression, not noise.

- [ ] **Step 5.15: Run the full reachability judge suite**

Run:

```bash
task test:reachability:llmjudge 2>&1 | tail -30
```

Expected: all per-language judge tests pass. The intra-language analyzers were not touched by this refactor, but they share types with the `transitive` package, so this is a free second opinion.

- [ ] **Step 5.16: Run quality gates**

Run:

```bash
task quality
```

Expected: build, test, lint, and fmt all pass. If lint reports any issues in the refactored files, fix them before committing.

- [ ] **Step 5.17: Verify no language-specific switches remain in orchestration code**

Run:

```bash
grep -n 'case "python"\|case "javascript"\|case "js"' \
    pkg/vex/reachability/transitive/hop.go \
    pkg/vex/reachability/transitive/exports.go
```

Expected: no output. If any match appears, the refactor is incomplete.

- [ ] **Step 5.18: Commit**

```bash
git add pkg/vex/reachability/transitive/hop.go \
        pkg/vex/reachability/transitive/exports.go \
        pkg/vex/reachability/transitive/transitive.go \
        pkg/vex/reachability/transitive/walker.go \
        pkg/vex/reachability/transitive/hop_test.go \
        pkg/vex/reachability/transitive/walker_test.go \
        pkg/vex/reachability/transitive/exports_test.go \
        pkg/vex/transitive_wire.go \
        pkg/vex/reachability/python/llm_judge_test.go \
        pkg/vex/reachability/javascript/llm_judge_test.go
git commit -m "refactor(transitive): route language behavior through LanguageSupport

Removes every language-specific switch from hop.go and exports.go, replaces
Analyzer.Language (string) and Analyzer.Ecosystem with a single Language
field of type LanguageSupport, and threads the interface through
RunHop/HopInput, buildCrossFileScope, resolveTarget, Walker, and
extractExportedSymbols. The vex package's transitive_wire.go is updated to
call transitive.LanguageFor, and both llm_judge_test.go construction sites
are updated to use the new wiring.

After this commit, adding a new language means: create a new subpackage
under pkg/vex/reachability/transitive/languages/<lang>/, add one case to
LanguageFor in language.go, and add a fetcher case to buildFetchers in
transitive_wire.go if the ecosystem is new. Nothing else in the transitive
package is touched.

Regression gates:
- task test, task test:transitive, task test:reachability:transitive:llmjudge
  all pass
- Transitive judge scores are within one point of the pre-refactor baseline
- task quality (build, test, lint, fmt) passes"
```

---

## Task 6 — Final verification

**Goal:** Re-run all regression gates and confirm the spec's success criteria (section 9) are met. This task produces no code changes in the common case; its purpose is to catch any drift from the refactor and to document the verified state.

- [ ] **Step 6.1: Re-run the full quality gate**

Run:

```bash
task quality
```

Expected: build, test, lint, fmt all pass.

- [ ] **Step 6.2: Re-run the transitive integration suite**

Run:

```bash
task test:transitive
```

Expected: all integration tests pass.

- [ ] **Step 6.3: Re-run the transitive judge suite**

Run:

```bash
task test:reachability:transitive:llmjudge
```

Expected: both Python and JavaScript transitive judge tests pass.

- [ ] **Step 6.4: Verify spec success criteria**

Run the following checks and confirm each one matches expectations:

```bash
# Criterion: no language-specific switches in orchestration code
grep -rn 'case "python"\|case "javascript"\|case "js"' \
    pkg/vex/reachability/transitive/hop.go \
    pkg/vex/reachability/transitive/exports.go
```

Expected: no output.

```bash
# Criterion: both language subpackages exist
ls pkg/vex/reachability/transitive/languages/python/python.go
ls pkg/vex/reachability/transitive/languages/javascript/javascript.go
```

Expected: both files listed.

```bash
# Criterion: LanguageFor is the only mapping site
grep -rn 'case "python"' pkg/vex/reachability/transitive/ pkg/vex/ | grep -v _test.go
```

Expected: exactly one match in `pkg/vex/reachability/transitive/language.go` inside `LanguageFor`.

```bash
# Criterion: Analyzer has no Ecosystem field
grep -n 'Ecosystem string' pkg/vex/reachability/transitive/transitive.go
```

Expected: no output.

```bash
# Criterion: Analyzer.Language is LanguageSupport
grep -n 'Language LanguageSupport' pkg/vex/reachability/transitive/transitive.go
```

Expected: one match inside the `Analyzer` struct.

- [ ] **Step 6.5: If any cleanup is needed, apply it and commit**

If Steps 6.1–6.4 surface any stray artifact (unused imports, dead helper functions, obsolete comments), fix them and commit with:

```bash
git add <modified files>
git commit -m "chore(transitive): clean up leftovers from language support refactor"
```

If no cleanup is needed, skip this step — there is no commit in Task 6.

- [ ] **Step 6.6: Final summary**

Report the final state to the user:

- Files created: 6 (language.go, language_test.go, python/python.go, python/python_test.go, javascript/javascript.go, javascript/javascript_test.go)
- Files modified: 10 (hop.go, exports.go, transitive.go, walker.go, hop_test.go, walker_test.go, exports_test.go, transitive_wire.go, python/llm_judge_test.go, javascript/llm_judge_test.go)
- Integration and judge suites: both passing
- Judge scores: reported relative to the Task 1 baseline

---

## Self-review checklist

After drafting each task, verify against the spec:

- **Spec section 4.1 (package layout):** Covered by the File structure after the refactor table and Tasks 2, 3.
- **Spec section 4.2 (LanguageSupport interface):** Covered by Task 1, Step 1.2.
- **Spec section 4.3 (LanguageFor factory):** Covered by Task 1 (stub), Task 2 Step 2.5 (Python case), Task 3 Step 3.5 (JavaScript cases).
- **Spec section 4.4 (Analyzer struct):** Covered by Task 5 Step 5.3 Edit 1.
- **Spec section 4.5 (hop.go refactor):** Covered by Task 5 Step 5.2.
- **Spec section 4.6 (exports.go refactor):** Covered by Task 5 Step 5.1.
- **Spec section 4.7 (transitive_wire.go):** Covered by Task 5 Step 5.8.
- **Spec section 4.8 (llm_judge_test.go):** Covered by Task 5 Steps 5.9 and 5.10.
- **Spec section 5.1 (Python impl):** Covered by Task 2 Step 2.3.
- **Spec section 5.2 (JavaScript impl):** Covered by Task 3 Step 3.3.
- **Spec section 6.1 (regression gate):** Covered by Task 5 Steps 5.13, 5.14, 5.15; Task 6 Steps 6.2, 6.3.
- **Spec section 6.2 (registry tests):** Covered by Task 4 Step 4.1.
- **Spec section 6.3 (per-language unit tests):** Covered by Task 2 Step 2.1, Task 3 Step 3.1.
- **Spec section 7 (sequencing):** Covered by Tasks 1–5 in order, with spec steps 5–9 collapsed into Task 5 as explained in the Sequencing note at the top of this plan.
- **Spec section 9 (success criteria):** Covered by Task 6 Step 6.4.
