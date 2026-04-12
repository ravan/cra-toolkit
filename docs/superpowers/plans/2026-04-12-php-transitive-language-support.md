# PHP Transitive Cross-Package Reachability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add PHP to the transitive cross-package reachability analyzer with a LanguageSupport implementation, Packagist fetcher, and full test coverage.

**Architecture:** Three new components: (1) `languages/php/` subpackage implementing `LanguageSupport` with a normalizing extractor wrapper that converts PHP's `\` and `::` separators to `.`; (2) `fetcher_packagist.go` implementing `Fetcher` for the Packagist/Composer ecosystem using ZIP archives; (3) wiring in `language.go` and `transitive_wire.go`. Follows the exact pattern established by Ruby, Rust, Python, and JavaScript implementations.

**Tech Stack:** Go, tree-sitter, Packagist API (repo.packagist.org), `archive/zip`

**Spec:** `docs/superpowers/specs/2026-04-12-php-transitive-language-support-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `pkg/vex/reachability/transitive/languages/php/php.go` | Create | LanguageSupport interface + normalizedExtractor wrapper |
| `pkg/vex/reachability/transitive/languages/php/php_test.go` | Create | Unit tests for all LanguageSupport methods |
| `pkg/vex/reachability/transitive/languages/php/exports.go` | Create | ExportLister via PSR-4 composer.json autoload |
| `pkg/vex/reachability/transitive/languages/php/exports_test.go` | Create | ExportLister tests with PSR-4 and fallback |
| `pkg/vex/reachability/transitive/fetcher_packagist.go` | Create | Packagist Fetcher implementation |
| `pkg/vex/reachability/transitive/fetcher_packagist_test.go` | Create | Fetcher tests with httptest mock |
| `pkg/vex/reachability/transitive/language.go` | Modify | Add `case "php"` to LanguageFor |
| `pkg/vex/reachability/transitive/language_test.go` | Modify | Add PHP to registered languages + contract test |
| `pkg/vex/transitive_wire.go` | Modify | Add `case "packagist"` to buildFetchers |
| `testdata/integration/php-realworld-cross-package/` | Create | Positive transitive fixture |
| `testdata/integration/php-realworld-cross-package-safe/` | Create | Negative transitive fixture |
| `pkg/vex/reachability/php/llm_judge_test.go` | Modify | Add TestLLMJudge_PHPTransitiveReachability |

---

### Task 1: PHP LanguageSupport — normalizedExtractor wrapper + identity methods

**Files:**
- Create: `pkg/vex/reachability/transitive/languages/php/php.go`
- Create: `pkg/vex/reachability/transitive/languages/php/php_test.go`

- [ ] **Step 1: Write the failing identity tests**

Create `pkg/vex/reachability/transitive/languages/php/php_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package php_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/php"
)

func TestPHP_Identity(t *testing.T) {
	lang := php.New()
	if lang.Name() != "php" {
		t.Errorf("Name() = %q, want %q", lang.Name(), "php")
	}
	if lang.Ecosystem() != "packagist" {
		t.Errorf("Ecosystem() = %q, want %q", lang.Ecosystem(), "packagist")
	}
	exts := lang.FileExtensions()
	if len(exts) != 1 || exts[0] != ".php" {
		t.Errorf("FileExtensions() = %v, want [\".php\"]", exts)
	}
	if lang.Grammar() == nil {
		t.Error("Grammar() returned nil")
	}
	if lang.Extractor() == nil {
		t.Error("Extractor() returned nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/vex/reachability/transitive/languages/php/ -run TestPHP_Identity -v`
Expected: compilation error — package `php` does not exist

- [ ] **Step 3: Write php.go with identity methods and normalizedExtractor**

Create `pkg/vex/reachability/transitive/languages/php/php.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package php provides the PHP LanguageSupport implementation for the
// transitive cross-package reachability analyzer. It is imported only
// by the transitive package's LanguageFor factory.
package php

import (
	"strings"
	"unsafe"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarphp "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/php"
	phpextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/php"
)

// Language is the PHP LanguageSupport implementation. Callers use New
// to construct a value; the zero value is not valid.
type Language struct {
	extractor treesitter.LanguageExtractor
}

// New returns a fresh PHP Language. The extractor wraps the raw PHP
// extractor with separator normalization (\ and :: → .).
func New() *Language {
	return &Language{extractor: &normalizedExtractor{inner: phpextractor.New()}}
}

func (l *Language) Name() string                            { return "php" }
func (l *Language) Ecosystem() string                       { return "packagist" }
func (l *Language) FileExtensions() []string                { return []string{".php"} }
func (l *Language) Grammar() unsafe.Pointer                 { return grammarphp.Language() }
func (l *Language) Extractor() treesitter.LanguageExtractor { return l.extractor }

// normalizeSep converts PHP's \ (namespace) and :: (method dispatch)
// separators to . for the shared graph machinery.
func normalizeSep(s string) string {
	s = strings.ReplaceAll(s, `\`, ".")
	s = strings.ReplaceAll(s, "::", ".")
	return s
}

// normalizedExtractor wraps the raw PHP treesitter extractor and
// converts all \ and :: separators to . in its output. The raw
// extractor remains unchanged for single-language analysis.
type normalizedExtractor struct {
	inner treesitter.LanguageExtractor
}

func (e *normalizedExtractor) ExtractSymbols(file string, source []byte, tree *tree_sitter.Tree) ([]*treesitter.Symbol, error) {
	syms, err := e.inner.ExtractSymbols(file, source, tree)
	if err != nil {
		return nil, err
	}
	for _, s := range syms {
		s.ID = treesitter.SymbolID(normalizeSep(string(s.ID)))
		s.QualifiedName = normalizeSep(s.QualifiedName)
		s.Package = normalizeSep(s.Package)
	}
	return syms, nil
}

func (e *normalizedExtractor) ResolveImports(file string, source []byte, tree *tree_sitter.Tree, projectRoot string) ([]treesitter.Import, error) {
	imports, err := e.inner.ResolveImports(file, source, tree, projectRoot)
	if err != nil {
		return nil, err
	}
	for i := range imports {
		imports[i].Module = normalizeSep(imports[i].Module)
		imports[i].Alias = normalizeSep(imports[i].Alias)
	}
	return imports, nil
}

func (e *normalizedExtractor) ExtractCalls(file string, source []byte, tree *tree_sitter.Tree, scope *treesitter.Scope) ([]treesitter.Edge, error) {
	edges, err := e.inner.ExtractCalls(file, source, tree, scope)
	if err != nil {
		return nil, err
	}
	for i := range edges {
		edges[i].From = treesitter.SymbolID(normalizeSep(string(edges[i].From)))
		edges[i].To = treesitter.SymbolID(normalizeSep(string(edges[i].To)))
	}
	return edges, nil
}

func (e *normalizedExtractor) FindEntryPoints(symbols []*treesitter.Symbol, projectRoot string) []treesitter.SymbolID {
	eps := e.inner.FindEntryPoints(symbols, projectRoot)
	for i := range eps {
		eps[i] = treesitter.SymbolID(normalizeSep(string(eps[i])))
	}
	return eps
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/vex/reachability/transitive/languages/php/ -run TestPHP_Identity -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/transitive/languages/php/php.go pkg/vex/reachability/transitive/languages/php/php_test.go
git commit -m "feat(transitive): add PHP LanguageSupport with normalizedExtractor wrapper"
```

---

### Task 2: PHP LanguageSupport — IsExportedSymbol, ModulePath, SymbolKey

**Files:**
- Modify: `pkg/vex/reachability/transitive/languages/php/php.go`
- Modify: `pkg/vex/reachability/transitive/languages/php/php_test.go`

- [ ] **Step 1: Write failing tests for IsExportedSymbol, ModulePath, SymbolKey**

Append to `pkg/vex/reachability/transitive/languages/php/php_test.go`:

```go
import (
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestPHP_IsExportedSymbol(t *testing.T) {
	lang := php.New()
	tests := []struct {
		name string
		sym  *treesitter.Symbol
		want bool
	}{
		{"nil", nil, false},
		{"public method", &treesitter.Symbol{Name: "index", Kind: treesitter.SymbolMethod, IsPublic: true}, true},
		{"public function", &treesitter.Symbol{Name: "helper", Kind: treesitter.SymbolFunction, IsPublic: true}, true},
		{"public class", &treesitter.Symbol{Name: "UserController", Kind: treesitter.SymbolClass, IsPublic: true}, true},
		{"non-public method", &treesitter.Symbol{Name: "internal", Kind: treesitter.SymbolMethod, IsPublic: false}, false},
		{"variable kind", &treesitter.Symbol{Name: "config", Kind: treesitter.SymbolVariable, IsPublic: true}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lang.IsExportedSymbol(tc.sym); got != tc.want {
				t.Errorf("IsExportedSymbol(%+v) = %v, want %v", tc.sym, got, tc.want)
			}
		})
	}
}

func TestPHP_ModulePath(t *testing.T) {
	lang := php.New()
	tests := []struct {
		name        string
		file        string
		sourceDir   string
		packageName string
		want        string
	}{
		{
			name:        "src layout PSR-4",
			file:        "/tmp/guzzlehttp-psr7/src/Psr7/Utils.php",
			sourceDir:   "/tmp/guzzlehttp-psr7",
			packageName: "guzzlehttp/psr7",
			want:        "guzzlehttp/psr7.Psr7.Utils",
		},
		{
			name:        "lib layout",
			file:        "/tmp/monolog/lib/Logger.php",
			sourceDir:   "/tmp/monolog",
			packageName: "monolog/monolog",
			want:        "monolog/monolog.Logger",
		},
		{
			name:        "no conventional prefix",
			file:        "/tmp/pkg/Handler/RequestHandler.php",
			sourceDir:   "/tmp/pkg",
			packageName: "vendor/pkg",
			want:        "vendor/pkg.Handler.RequestHandler",
		},
		{
			name:        "root file",
			file:        "/tmp/pkg/index.php",
			sourceDir:   "/tmp/pkg",
			packageName: "vendor/pkg",
			want:        "vendor/pkg.index",
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

func TestPHP_SymbolKey(t *testing.T) {
	lang := php.New()
	got := lang.SymbolKey("guzzlehttp/psr7.Psr7.Utils", "readLine")
	want := "guzzlehttp/psr7.Psr7.Utils.readLine"
	if got != want {
		t.Errorf("SymbolKey = %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/vex/reachability/transitive/languages/php/ -run "TestPHP_IsExported|TestPHP_Module|TestPHP_Symbol" -v`
Expected: compilation error — methods not defined

- [ ] **Step 3: Implement IsExportedSymbol, ModulePath, SymbolKey**

Add to `pkg/vex/reachability/transitive/languages/php/php.go`:

```go
import (
	"path/filepath"
)

// IsExportedSymbol reports whether a symbol is part of the PHP package's
// public API. PHP has no underscore-prefix convention; visibility is
// determined by the extractor's IsPublic flag and callable symbol kinds.
func (l *Language) IsExportedSymbol(sym *treesitter.Symbol) bool {
	if sym == nil {
		return false
	}
	if !sym.IsPublic {
		return false
	}
	switch sym.Kind {
	case treesitter.SymbolFunction, treesitter.SymbolMethod, treesitter.SymbolClass:
		return true
	}
	return false
}

// ModulePath derives a dotted module path for a PHP source file relative
// to sourceDir. The conventional src/ or lib/ prefix is stripped:
//
//	src/Psr7/Utils.php  → "guzzlehttp/psr7.Psr7.Utils"
//	lib/Logger.php      → "monolog/monolog.Logger"
//	Handler/Request.php → "vendor/pkg.Handler.Request"
func (l *Language) ModulePath(file, sourceDir, packageName string) string {
	rel, err := filepath.Rel(sourceDir, file)
	if err != nil {
		return packageName
	}
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	parts := strings.Split(rel, string(filepath.Separator))
	// Strip conventional src/ or lib/ prefix.
	if len(parts) > 0 && (parts[0] == "src" || parts[0] == "lib") {
		parts = parts[1:]
	}
	if len(parts) == 0 {
		return packageName
	}
	mod := strings.Join(parts, ".")
	return packageName + "." + mod
}

// SymbolKey composes a dotted symbol key: "<modulePath>.<symbolName>".
func (l *Language) SymbolKey(modulePath, symbolName string) string {
	return modulePath + "." + symbolName
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/vex/reachability/transitive/languages/php/ -run "TestPHP_IsExported|TestPHP_Module|TestPHP_Symbol" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/transitive/languages/php/php.go pkg/vex/reachability/transitive/languages/php/php_test.go
git commit -m "feat(transitive): add PHP IsExportedSymbol, ModulePath, SymbolKey"
```

---

### Task 3: PHP LanguageSupport — NormalizeImports, ResolveDottedTarget, ResolveSelfCall

**Files:**
- Modify: `pkg/vex/reachability/transitive/languages/php/php.go`
- Modify: `pkg/vex/reachability/transitive/languages/php/php_test.go`

- [ ] **Step 1: Write failing tests**

Append to `php_test.go`:

```go
func TestPHP_NormalizeImports(t *testing.T) {
	lang := php.New()
	raw := []treesitter.Import{
		{Module: "GuzzleHttp.Psr7.Utils", Alias: "Utils"},
		{Module: "App.Models.User", Alias: "User"},
	}
	got := lang.NormalizeImports(raw)
	// Identity function — imports are already normalized by the wrapper extractor
	if got[0].Module != "GuzzleHttp.Psr7.Utils" {
		t.Errorf("Module = %q, want %q", got[0].Module, "GuzzleHttp.Psr7.Utils")
	}
	if got[0].Alias != "Utils" {
		t.Errorf("Alias = %q, want %q", got[0].Alias, "Utils")
	}
}

func TestPHP_ResolveDottedTarget(t *testing.T) {
	lang := php.New()
	scope := treesitter.NewScope(nil)
	scope.DefineImport("Utils", "GuzzleHttp.Psr7.Utils", nil)

	t.Run("alias found", func(t *testing.T) {
		got, ok := lang.ResolveDottedTarget("Utils", "readLine", scope)
		if !ok {
			t.Fatal("expected ok=true")
		}
		want := treesitter.SymbolID("GuzzleHttp.Psr7.Utils.readLine")
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("alias not found", func(t *testing.T) {
		_, ok := lang.ResolveDottedTarget("Unknown", "method", scope)
		if ok {
			t.Error("expected ok=false")
		}
	})
}

func TestPHP_ResolveSelfCall(t *testing.T) {
	lang := php.New()
	tests := []struct {
		name string
		to   treesitter.SymbolID
		from treesitter.SymbolID
		want treesitter.SymbolID
	}{
		{
			name: "self call in class method",
			to:   "self.validate",
			from: "guzzlehttp/psr7.Utils.readLine",
			want: "guzzlehttp/psr7.Utils.validate",
		},
		{
			name: "this call in class method",
			to:   "this.process",
			from: "app.Controller.UserController.index",
			want: "app.Controller.UserController.process",
		},
		{
			name: "short from — unchanged",
			to:   "self.helper",
			from: "mod.func",
			want: "self.helper",
		},
		{
			name: "non-self — unchanged",
			to:   "Utils.readLine",
			from: "app.Parser.parse",
			want: "Utils.readLine",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := lang.ResolveSelfCall(tc.to, tc.from)
			if got != tc.want {
				t.Errorf("ResolveSelfCall(%q, %q) = %q, want %q", tc.to, tc.from, got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/vex/reachability/transitive/languages/php/ -run "TestPHP_Normalize|TestPHP_Resolve" -v`
Expected: compilation error — methods not defined

- [ ] **Step 3: Implement NormalizeImports, ResolveDottedTarget, ResolveSelfCall**

Add to `php.go`:

```go
// NormalizeImports is the identity function for PHP. The normalizedExtractor
// wrapper already converts \ and :: to . in import module paths and aliases.
func (l *Language) NormalizeImports(raw []treesitter.Import) []treesitter.Import {
	return raw
}

// ResolveDottedTarget resolves a dotted call target whose prefix is an
// import alias. For example, given "Utils" and a scope where "Utils" maps
// to "GuzzleHttp.Psr7.Utils", returns "GuzzleHttp.Psr7.Utils.readLine"
// for suffix="readLine".
func (l *Language) ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool) {
	resolved, ok := scope.LookupImport(prefix)
	if !ok {
		return "", false
	}
	return treesitter.SymbolID(resolved + "." + suffix), true
}

// ResolveSelfCall rewrites "self.X" and "this.X" call targets to the
// class-qualified form "ClassName.X". The raw PHP extractor emits
// self::method and $this->method as self::method and this::method; the
// normalizedExtractor converts :: to ., producing self.X and this.X.
func (l *Language) ResolveSelfCall(to, from treesitter.SymbolID) treesitter.SymbolID {
	toStr := string(to)
	var methodName string
	switch {
	case strings.HasPrefix(toStr, "self."):
		methodName = toStr[len("self."):]
	case strings.HasPrefix(toStr, "this."):
		methodName = toStr[len("this."):]
	default:
		return to
	}
	fromParts := strings.Split(string(from), ".")
	if len(fromParts) < 3 {
		return to
	}
	classQual := strings.Join(fromParts[:len(fromParts)-1], ".")
	return treesitter.SymbolID(classQual + "." + methodName)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/vex/reachability/transitive/languages/php/ -run "TestPHP_Normalize|TestPHP_Resolve" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/transitive/languages/php/php.go pkg/vex/reachability/transitive/languages/php/php_test.go
git commit -m "feat(transitive): add PHP NormalizeImports, ResolveDottedTarget, ResolveSelfCall"
```

---

### Task 4: PHP ExportLister — PSR-4 based export enumeration

**Files:**
- Create: `pkg/vex/reachability/transitive/languages/php/exports.go`
- Create: `pkg/vex/reachability/transitive/languages/php/exports_test.go`

- [ ] **Step 1: Write failing tests**

Create `pkg/vex/reachability/transitive/languages/php/exports_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package php_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/php"
)

func writePackage(t *testing.T, name string, files map[string]string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), name)
	for path, content := range files {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func assertKeys(t *testing.T, got []string, want ...string) {
	t.Helper()
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Errorf("got %d keys %v, want %d keys %v", len(got), got, len(want), want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("key[%d]: got %q, want %q\nfull got: %v", i, got[i], want[i], got)
			return
		}
	}
}

func TestListExports_PSR4(t *testing.T) {
	root := writePackage(t, "guzzlehttp-psr7", map[string]string{
		"composer.json": `{"autoload":{"psr-4":{"GuzzleHttp\\Psr7\\":"src/"}}}`,
		"src/Utils.php": `<?php
namespace GuzzleHttp\Psr7;

class Utils {
    public static function readLine($stream) {
        return fgets($stream);
    }

    private static function internalHelper() {
        return null;
    }
}`,
	})
	lang := php.New()
	keys, err := lang.ListExports(root, "guzzlehttp/psr7")
	if err != nil {
		t.Fatal(err)
	}
	// Should include the class and public method, not private
	hasClass := false
	hasReadLine := false
	hasInternal := false
	for _, k := range keys {
		if k == "guzzlehttp/psr7.Utils.Utils" {
			hasClass = true
		}
		if k == "guzzlehttp/psr7.Utils.readLine" {
			hasReadLine = true
		}
		if k == "guzzlehttp/psr7.Utils.internalHelper" {
			hasInternal = true
		}
	}
	if !hasClass {
		t.Errorf("missing Utils class in exports: %v", keys)
	}
	if !hasReadLine {
		t.Errorf("missing readLine in exports: %v", keys)
	}
	if hasInternal {
		t.Errorf("private internalHelper should not be exported: %v", keys)
	}
}

func TestListExports_Fallback_NoComposerJSON(t *testing.T) {
	root := writePackage(t, "legacy-pkg", map[string]string{
		"src/Helper.php": `<?php
class Helper {
    public function run() {}
}`,
	})
	lang := php.New()
	keys, err := lang.ListExports(root, "vendor/legacy-pkg")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Error("fallback should find symbols from src/")
	}
}

func TestListExports_Fallback_LibDir(t *testing.T) {
	root := writePackage(t, "lib-pkg", map[string]string{
		"lib/Service.php": `<?php
class Service {
    public function handle() {}
}`,
	})
	lang := php.New()
	keys, err := lang.ListExports(root, "vendor/lib-pkg")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Error("fallback should find symbols from lib/")
	}
}

func TestListExports_SkipsTestFiles(t *testing.T) {
	root := writePackage(t, "tested-pkg", map[string]string{
		"composer.json": `{"autoload":{"psr-4":{"App\\":"src/"}}}`,
		"src/Core.php": `<?php
namespace App;
class Core { public function run() {} }`,
		"tests/CoreTest.php": `<?php
class CoreTest { public function testRun() {} }`,
	})
	lang := php.New()
	keys, err := lang.ListExports(root, "vendor/tested-pkg")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k == "vendor/tested-pkg.CoreTest.CoreTest" || k == "vendor/tested-pkg.CoreTest.testRun" {
			t.Errorf("test file leaked into exports: %q", k)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/vex/reachability/transitive/languages/php/ -run "TestListExports" -v`
Expected: compilation error — ListExports not defined

- [ ] **Step 3: Implement exports.go**

Create `pkg/vex/reachability/transitive/languages/php/exports.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package php

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarphp "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/php"
	phpextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/php"
)

// composerJSON is the subset of composer.json we consume.
type composerJSON struct {
	Autoload struct {
		PSR4 map[string]string `json:"psr-4"`
	} `json:"autoload"`
}

// ListExports enumerates the public API of a PHP package by following
// the PSR-4 autoload mapping from composer.json. Falls back to scanning
// src/, lib/, or the root directory when composer.json is absent.
//
//nolint:gocognit,gocyclo // PSR-4 walk with fallback, parse loop, and symbol filtering
func (l *Language) ListExports(sourceDir, packageName string) ([]string, error) {
	var dirs []string
	cj := readComposerJSON(sourceDir)
	if cj != nil && len(cj.Autoload.PSR4) > 0 {
		for _, dir := range cj.Autoload.PSR4 {
			absDir := filepath.Join(sourceDir, dir)
			if info, err := os.Stat(absDir); err == nil && info.IsDir() {
				dirs = append(dirs, absDir)
			}
		}
	}
	if len(dirs) == 0 {
		dirs = fallbackDirs(sourceDir)
	}
	if len(dirs) == 0 {
		return nil, nil
	}

	var files []string
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !d.IsDir() && strings.HasSuffix(path, ".php") {
				files = append(files, path)
			}
			return nil
		})
	}

	if len(files) == 0 {
		return nil, nil
	}

	parser := tree_sitter.NewParser()
	defer parser.Close()
	lang := tree_sitter.NewLanguage(grammarphp.Language())
	if err := parser.SetLanguage(lang); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	for _, file := range files {
		src, err := os.ReadFile(file) //nolint:gosec // file paths resolved within sourceDir
		if err != nil {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}

		ext := phpextractor.New()
		symbols, err := ext.ExtractSymbols(file, src, tree)
		tree.Close()
		if err != nil {
			continue
		}

		modulePath := l.ModulePath(file, sourceDir, packageName)
		for _, sym := range symbols {
			if !l.IsExportedSymbol(sym) {
				continue
			}
			key := l.SymbolKey(modulePath, sym.Name)
			seen[key] = true
		}
	}

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

// readComposerJSON reads and parses composer.json from sourceDir.
// Returns nil if the file does not exist or is invalid.
func readComposerJSON(sourceDir string) *composerJSON {
	data, err := os.ReadFile(filepath.Join(sourceDir, "composer.json")) //nolint:gosec
	if err != nil {
		return nil
	}
	var cj composerJSON
	if err := json.Unmarshal(data, &cj); err != nil {
		return nil
	}
	return &cj
}

// fallbackDirs returns directories to scan when composer.json has no
// PSR-4 mapping. Tries src/, then lib/, then the root.
func fallbackDirs(sourceDir string) []string {
	candidates := []string{
		filepath.Join(sourceDir, "src"),
		filepath.Join(sourceDir, "lib"),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return []string{c}
		}
	}
	return []string{sourceDir}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/vex/reachability/transitive/languages/php/ -run "TestListExports" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/transitive/languages/php/exports.go pkg/vex/reachability/transitive/languages/php/exports_test.go
git commit -m "feat(transitive): add PHP ExportLister with PSR-4 and fallback"
```

---

### Task 5: Packagist Fetcher

**Files:**
- Create: `pkg/vex/reachability/transitive/fetcher_packagist.go`
- Create: `pkg/vex/reachability/transitive/fetcher_packagist_test.go`

- [ ] **Step 1: Write failing tests**

Create `pkg/vex/reachability/transitive/fetcher_packagist_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackagistFetcher_Ecosystem(t *testing.T) {
	f := &PackagistFetcher{}
	if f.Ecosystem() != "packagist" {
		t.Errorf("Ecosystem() = %q, want %q", f.Ecosystem(), "packagist")
	}
}

func TestPackagistFetcher_Manifest_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/p2/guzzlehttp/psr7.json") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"packages":{"guzzlehttp/psr7":[{
				"version":"2.1.0",
				"require":{"php":">=7.2","psr/http-message":"^1.0"},
				"dist":{"url":"http://example.com/psr7.zip","type":"zip","shasum":"abc123"}
			}]}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	f := &PackagistFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	m, err := f.Manifest(context.Background(), "guzzlehttp/psr7", "2.1.0")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if _, ok := m.Dependencies["psr/http-message"]; !ok {
		t.Error("psr/http-message not in dependencies")
	}
	// Platform requirements should be filtered
	if _, ok := m.Dependencies["php"]; ok {
		t.Error("php platform requirement should have been filtered")
	}
}

func TestPackagistFetcher_Fetch_HappyPath(t *testing.T) {
	zipData := buildTestZip(t, "guzzlehttp-psr7-abc123", map[string]string{
		"src/Utils.php":  "<?php\nclass Utils {}\n",
		"composer.json":  `{"name":"guzzlehttp/psr7"}`,
	})
	digest := sha256Hex(zipData)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/p2/guzzlehttp/psr7.json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"packages":{"guzzlehttp/psr7":[{
				"version":"2.1.0",
				"require":{},
				"dist":{"url":"%s/downloads/psr7.zip","type":"zip","shasum":%q}
			}]}}`, srv.URL, digest)
		case strings.HasSuffix(r.URL.Path, "/downloads/psr7.zip"):
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(zipData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f := &PackagistFetcher{BaseURL: srv.URL, HTTPClient: srv.Client(), Cache: NewCache(t.TempDir())}
	fr, err := f.Fetch(context.Background(), "guzzlehttp/psr7", "2.1.0", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fr.SourceDir == "" {
		t.Fatal("SourceDir empty")
	}
	// Check that .php files exist
	found := false
	_ = filepath.WalkDir(fr.SourceDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(path, ".php") {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("no .php files found in unpacked source")
	}
}

func TestPackagistFetcher_Fetch_DigestMismatch(t *testing.T) {
	zipData := buildTestZip(t, "bad-pkg", map[string]string{
		"src/Bad.php": "<?php class Bad {}",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/p2/vendor/bad.json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"packages":{"vendor/bad":[{
				"version":"1.0.0",
				"require":{},
				"dist":{"url":"` + srv.URL + `/downloads/bad.zip","type":"zip","shasum":"deadbeef"}
			}]}}`))
		case strings.HasSuffix(r.URL.Path, "/downloads/bad.zip"):
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(zipData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f := &PackagistFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.Fetch(context.Background(), "vendor/bad", "1.0.0", nil)
	if err == nil || !strings.Contains(err.Error(), ReasonDigestMismatch) {
		t.Errorf("Fetch: want %q in error, got %v", ReasonDigestMismatch, err)
	}
}

func TestPackagistFetcher_Manifest_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	f := &PackagistFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.Manifest(context.Background(), "nope/nope", "0.0.1")
	if err == nil {
		t.Fatal("Manifest: expected error, got nil")
	}
}

// buildTestZip creates a zip archive with a root directory and the given files.
func buildTestZip(t *testing.T, rootDir string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		path := rootDir + "/" + name
		w, err := zw.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/vex/reachability/transitive/ -run "TestPackagistFetcher" -v`
Expected: compilation error — PackagistFetcher not defined

- [ ] **Step 3: Implement fetcher_packagist.go**

Create `pkg/vex/reachability/transitive/fetcher_packagist.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// PackagistFetcher implements Fetcher for the Packagist/Composer ecosystem.
type PackagistFetcher struct {
	// BaseURL is the Packagist API base. Defaults to https://repo.packagist.org.
	BaseURL    string
	HTTPClient *http.Client
	Cache      *Cache
}

func (f *PackagistFetcher) Ecosystem() string { return "packagist" }

func (f *PackagistFetcher) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return http.DefaultClient
}

func (f *PackagistFetcher) baseURL() string {
	if f.BaseURL != "" {
		return f.BaseURL
	}
	return "https://repo.packagist.org"
}

// packagistMeta is the subset of the Packagist p2 API response we consume.
type packagistMeta struct {
	Packages map[string][]packagistVersion `json:"packages"`
}

type packagistVersion struct {
	Version string            `json:"version"`
	Require map[string]string `json:"require"`
	Dist    struct {
		URL    string `json:"url"`
		Type   string `json:"type"`
		SHASum string `json:"shasum"`
	} `json:"dist"`
}

// fetchMeta retrieves the package metadata from the Packagist p2 API
// and finds the entry matching the requested version.
func (f *PackagistFetcher) fetchMeta(ctx context.Context, name, version string) (*packagistVersion, error) {
	url := fmt.Sprintf("%s/p2/%s.json", f.baseURL(), name)
	var meta packagistMeta
	if err := httpGetJSON(ctx, f.client(), url, &meta); err != nil {
		return nil, err
	}
	versions := meta.Packages[name]
	for i := range versions {
		if versions[i].Version == version {
			return &versions[i], nil
		}
	}
	return nil, fmt.Errorf("version %s not found for %s", version, name)
}

// Manifest fetches package metadata and returns runtime dependencies.
func (f *PackagistFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	meta, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return PackageManifest{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}
	deps := filterPlatformDeps(meta.Require)
	return PackageManifest{Dependencies: deps}, nil
}

// Fetch downloads the ZIP archive, verifies its digest, and unpacks it.
//
//nolint:gocyclo // download-verify-unpack pipeline
func (f *PackagistFetcher) Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error) {
	meta, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}

	if meta.Dist.URL == "" {
		return FetchResult{SourceUnavailable: true}, nil
	}

	registryDigest := Digest{Algorithm: "sha256", Hex: meta.Dist.SHASum}

	if f.Cache != nil && registryDigest.Hex != "" {
		if p, ok := f.Cache.Get(registryDigest.String()); ok {
			return FetchResult{SourceDir: p, Digest: registryDigest}, nil
		}
	}

	body, err := httpGetBytes(ctx, f.client(), meta.Dist.URL)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonTarballFetchFailed, err)
	}

	actual := Digest{Algorithm: "sha256", Hex: hashHex(body)}
	if registryDigest.Hex != "" && !actual.Equals(registryDigest) {
		return FetchResult{}, fmt.Errorf("%s: expected %s, got %s", ReasonDigestMismatch, registryDigest, actual)
	}
	if expectedDigest != nil && !expectedDigest.IsZero() && !expectedDigest.Equals(actual) {
		return FetchResult{}, fmt.Errorf("%s: SBOM expected %s, registry returned %s", ReasonDigestMismatch, expectedDigest, actual)
	}

	tmp, err := os.MkdirTemp("", "packagist-*")
	if err != nil {
		return FetchResult{}, err
	}

	if err := unzip(body, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return FetchResult{}, fmt.Errorf("unpack composer %s: %w", name, err)
	}

	// Composer ZIPs typically contain a single root directory. Locate it.
	srcDir := locateSourceRoot(tmp)

	if f.Cache != nil {
		p, putErr := f.Cache.Put(actual.String(), srcDir)
		_ = os.RemoveAll(tmp)
		if putErr != nil {
			return FetchResult{}, putErr
		}
		srcDir = p
	}
	return FetchResult{SourceDir: srcDir, Digest: actual}, nil
}

// locateSourceRoot finds the single subdirectory in dir (common for composer
// ZIPs), or returns dir itself if there isn't exactly one subdirectory.
func locateSourceRoot(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return dir
	}
	var dirs []os.DirEntry
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e)
		}
	}
	if len(dirs) == 1 {
		return filepath.Join(dir, dirs[0].Name())
	}
	return dir
}

// filterPlatformDeps removes PHP platform requirements (php, ext-*)
// from a dependency map since they are not fetchable packages.
func filterPlatformDeps(deps map[string]string) map[string]string {
	filtered := make(map[string]string, len(deps))
	for k, v := range deps {
		if k == "php" || strings.HasPrefix(k, "ext-") {
			continue
		}
		filtered[k] = v
	}
	return filtered
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/vex/reachability/transitive/ -run "TestPackagistFetcher" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/transitive/fetcher_packagist.go pkg/vex/reachability/transitive/fetcher_packagist_test.go
git commit -m "feat(transitive): add Packagist fetcher with ZIP unpack and digest verification"
```

---

### Task 6: Wire PHP into LanguageFor and buildFetchers

**Files:**
- Modify: `pkg/vex/reachability/transitive/language.go`
- Modify: `pkg/vex/reachability/transitive/language_test.go`
- Modify: `pkg/vex/transitive_wire.go`

- [ ] **Step 1: Write failing tests for PHP registration**

In `pkg/vex/reachability/transitive/language_test.go`, add these test cases to the `TestLanguageFor_RegisteredLanguages` table:

```go
{"php", "php", "packagist"},
{"PHP", "php", "packagist"},
```

And add `"php"` to the `registered` slice in `TestLanguageSupport_Contract`:

```go
registered := []string{"python", "javascript", "rust", "ruby", "php"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/vex/reachability/transitive/ -run "TestLanguageFor_Registered|TestLanguageSupport_Contract" -v`
Expected: FAIL — `LanguageFor("php")` returns error "unsupported language"

- [ ] **Step 3: Add PHP case to LanguageFor**

In `pkg/vex/reachability/transitive/language.go`, add the import and case:

Add import:
```go
"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/php"
```

Add case before the default return:
```go
case "php":
    return php.New(), nil
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/vex/reachability/transitive/ -run "TestLanguageFor_Registered|TestLanguageSupport_Contract" -v`
Expected: PASS

- [ ] **Step 5: Add packagist case to buildFetchers**

In `pkg/vex/transitive_wire.go`, add to the `buildFetchers` switch:

```go
case "packagist":
    return map[string]transitive.Fetcher{"packagist": &transitive.PackagistFetcher{Cache: cache}}
```

- [ ] **Step 6: Run full test suite to verify no regressions**

Run: `task test`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add pkg/vex/reachability/transitive/language.go pkg/vex/reachability/transitive/language_test.go pkg/vex/transitive_wire.go
git commit -m "feat(transitive): wire PHP language support and Packagist fetcher"
```

---

### Task 7: Cross-package test fixtures

**Files:**
- Create: `testdata/integration/php-realworld-cross-package/`
- Create: `testdata/integration/php-realworld-cross-package-safe/`

- [ ] **Step 1: Create positive fixture — app calling Utils::readLine transitively**

Create `testdata/integration/php-realworld-cross-package/source/index.php`:

```php
<?php
require 'vendor/autoload.php';
require 'parser.php';

class App {
    public function run() {
        $result = RequestParser::parse('php://stdin');
        echo $result;
    }
}
```

Create `testdata/integration/php-realworld-cross-package/source/parser.php`:

```php
<?php
use GuzzleHttp\Psr7\Utils;

class RequestParser {
    public static function parse($input) {
        $stream = fopen($input, 'r');
        return Utils::readLine($stream);
    }
}
```

Create `testdata/integration/php-realworld-cross-package/source/composer.json`:

```json
{"name":"test/app","require":{"guzzlehttp/psr7":"2.1.0"}}
```

Create `testdata/integration/php-realworld-cross-package/sbom.cdx.json`:

```json
{"$schema":"http://cyclonedx.org/schema/bom-1.6.schema.json","bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:p3000001-3333-4000-8000-000000000001","version":1,"metadata":{"timestamp":"2026-04-12T10:00:00+00:00","tools":{"components":[{"type":"application","author":"anchore","name":"syft","version":"1.42.3"}]},"component":{"bom-ref":"pkg:composer/php-realworld-cross-package@1.0.0","type":"application","name":"php-realworld-cross-package","version":"1.0.0"}},"components":[{"bom-ref":"pkg:composer/php-realworld-cross-package@1.0.0?package-id=ph100000001","type":"library","name":"php-realworld-cross-package","version":"1.0.0","purl":"pkg:composer/php-realworld-cross-package@1.0.0","properties":[{"name":"syft:package:language","value":"php"},{"name":"syft:package:type","value":"php-composer"}]},{"bom-ref":"pkg:composer/guzzlehttp/psr7@2.1.0?package-id=ph100000002","type":"library","name":"guzzlehttp/psr7","version":"2.1.0","purl":"pkg:composer/guzzlehttp/psr7@2.1.0","properties":[{"name":"syft:package:language","value":"php"},{"name":"syft:package:type","value":"php-composer"}]}]}
```

Create `testdata/integration/php-realworld-cross-package/expected.json`:

```json
{
  "description": "PHP app calling Utils::readLine() transitively through RequestParser::parse(), triggering CVE-2022-24775.",
  "provenance": {
    "source_project": "guzzle/psr7",
    "source_url": "https://github.com/guzzle/psr7",
    "commit": "2.1.0",
    "cve": "CVE-2022-24775",
    "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-24775",
    "language": "php",
    "pattern": "cross_package_reachable",
    "ground_truth_notes": "index.php calls RequestParser::parse() which calls Utils::readLine() from guzzlehttp/psr7"
  },
  "findings": [
    {
      "cve": "CVE-2022-24775",
      "aliases": ["GHSA-q7rv-6hp3-vh96"],
      "component_purl": "pkg:composer/guzzlehttp/psr7@2.1.0",
      "expected_status": "affected",
      "expected_confidence": "high",
      "expected_resolved_by": "reachability_analysis",
      "human_justification": "RequestParser::parse() calls Utils::readLine() transitively from the main script, making the vulnerability reachable."
    }
  ]
}
```

Create `testdata/integration/php-realworld-cross-package/grype.json`:

```json
{"matches":[{"vulnerability":{"id":"CVE-2022-24775","severity":"High","dataSource":"https://github.com/advisories/GHSA-q7rv-6hp3-vh96","namespace":"github:language:php"},"artifact":{"name":"guzzlehttp/psr7","version":"2.1.0","type":"php-composer","purl":"pkg:composer/guzzlehttp/psr7@2.1.0"}}]}
```

- [ ] **Step 2: Create negative fixture — app NOT calling Guzzle PSR7**

Create `testdata/integration/php-realworld-cross-package-safe/source/index.php`:

```php
<?php

class App {
    public function run() {
        $content = file_get_contents('php://stdin');
        echo $content;
    }
}
```

Create `testdata/integration/php-realworld-cross-package-safe/source/composer.json`:

```json
{"name":"test/safe-app","require":{"guzzlehttp/psr7":"2.1.0"}}
```

Use the same `sbom.cdx.json` as the positive case:

```json
{"$schema":"http://cyclonedx.org/schema/bom-1.6.schema.json","bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:p3000002-3333-4000-8000-000000000002","version":1,"metadata":{"timestamp":"2026-04-12T10:00:00+00:00","tools":{"components":[{"type":"application","author":"anchore","name":"syft","version":"1.42.3"}]},"component":{"bom-ref":"pkg:composer/php-realworld-cross-package-safe@1.0.0","type":"application","name":"php-realworld-cross-package-safe","version":"1.0.0"}},"components":[{"bom-ref":"pkg:composer/php-realworld-cross-package-safe@1.0.0?package-id=ph200000001","type":"library","name":"php-realworld-cross-package-safe","version":"1.0.0","purl":"pkg:composer/php-realworld-cross-package-safe@1.0.0","properties":[{"name":"syft:package:language","value":"php"},{"name":"syft:package:type","value":"php-composer"}]},{"bom-ref":"pkg:composer/guzzlehttp/psr7@2.1.0?package-id=ph200000002","type":"library","name":"guzzlehttp/psr7","version":"2.1.0","purl":"pkg:composer/guzzlehttp/psr7@2.1.0","properties":[{"name":"syft:package:language","value":"php"},{"name":"syft:package:type","value":"php-composer"}]}]}
```

Create `testdata/integration/php-realworld-cross-package-safe/expected.json`:

```json
{
  "description": "PHP app using file_get_contents() instead of Guzzle PSR7 — vulnerability not reachable.",
  "provenance": {
    "source_project": "guzzle/psr7",
    "source_url": "https://github.com/guzzle/psr7",
    "commit": "2.1.0",
    "cve": "CVE-2022-24775",
    "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-24775",
    "language": "php",
    "pattern": "cross_package_not_reachable",
    "ground_truth_notes": "App only uses file_get_contents() — no Guzzle PSR7 code paths are reachable"
  },
  "findings": [
    {
      "cve": "CVE-2022-24775",
      "aliases": ["GHSA-q7rv-6hp3-vh96"],
      "component_purl": "pkg:composer/guzzlehttp/psr7@2.1.0",
      "expected_status": "not_affected",
      "expected_confidence": "high",
      "expected_resolved_by": "reachability_analysis",
      "human_justification": "No code path reaches Utils::readLine() — app uses file_get_contents() instead."
    }
  ]
}
```

Create `testdata/integration/php-realworld-cross-package-safe/grype.json`:

```json
{"matches":[{"vulnerability":{"id":"CVE-2022-24775","severity":"High","dataSource":"https://github.com/advisories/GHSA-q7rv-6hp3-vh96","namespace":"github:language:php"},"artifact":{"name":"guzzlehttp/psr7","version":"2.1.0","type":"php-composer","purl":"pkg:composer/guzzlehttp/psr7@2.1.0"}}]}
```

- [ ] **Step 3: Commit**

```bash
git add testdata/integration/php-realworld-cross-package/ testdata/integration/php-realworld-cross-package-safe/
git commit -m "test(transitive): add PHP cross-package integration test fixtures"
```

---

### Task 8: PHP transitive LLM judge test

**Files:**
- Modify: `pkg/vex/reachability/php/llm_judge_test.go`

- [ ] **Step 1: Add TestLLMJudge_PHPTransitiveReachability**

Append to `pkg/vex/reachability/php/llm_judge_test.go`. The test needs these additional imports added to the existing import block: `"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive"`.

```go
func TestLLMJudge_PHPTransitiveReachability(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	reachableDir := filepath.Join(fixtureBase, "php-realworld-cross-package")
	notReachableDir := filepath.Join(fixtureBase, "php-realworld-cross-package-safe")

	summary := parseSBOMForPHPJudge(t, reachableDir)

	cache := transitive.NewCache(t.TempDir())
	fetcher := &transitive.PackagistFetcher{Cache: cache}
	lang, langErr := transitive.LanguageFor("php")
	if langErr != nil {
		t.Fatalf("LanguageFor(php): %v", langErr)
	}
	ta := &transitive.Analyzer{
		Config:   transitive.DefaultConfig(),
		Language: lang,
		Fetchers: map[string]transitive.Fetcher{"packagist": fetcher},
	}

	finding := &formats.Finding{
		AffectedName:    "guzzlehttp/psr7",
		AffectedVersion: "2.1.0",
	}

	reachableResult, err := ta.Analyze(ctx, summary, finding, filepath.Join(reachableDir, "source"))
	if err != nil {
		t.Fatalf("Analyze reachable: %v", err)
	}

	notReachableResult, err := ta.Analyze(ctx, summary, finding, filepath.Join(notReachableDir, "source"))
	if err != nil {
		t.Fatalf("Analyze not-reachable: %v", err)
	}

	var pathStrs []string
	for _, p := range reachableResult.Paths {
		pathStrs = append(pathStrs, p.String())
	}

	prompt := fmt.Sprintf(`You are a security engineering judge evaluating a transitive dependency reachability analyzer for CRA (Cyber Resilience Act) compliance. The analyzer uses tree-sitter AST parsing for PHP source code.

VULNERABILITY: CVE-2022-24775 in guzzlehttp/psr7@2.1.0.
VULNERABLE PACKAGE: guzzlehttp/psr7@2.1.0 (direct dependency)
EXPECTED REACHABLE CHAIN: RequestParser::parse() → Utils::readLine()
EXPECTED SAFE CHAIN: file_get_contents() [does NOT call Guzzle PSR7]

REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%%v, Confidence=%%s, Degradations=%%v
Call paths found: %s
Evidence: %s

NOT-REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%%v, Confidence=%%s, Degradations=%%v
Evidence: %s

Score the transitive PHP analyzer (1-10 each):
1. path_accuracy: Are the reported cross-package call paths real and correctly tracing through Utils::readLine?
2. confidence_calibration: Does the confidence level correctly reflect the certainty of transitive PHP analysis?
3. evidence_quality: Is the stitched call path evidence sufficient for a VEX determination under CRA Article 14?
4. false_positive_rate: Is the not-reachable case (file_get_contents only) correctly identified as not-affected?
5. symbol_resolution: Are the cross-package symbols correctly resolved (RequestParser::parse → Utils::readLine)?
6. overall_quality: Would this analysis pass a CRA market surveillance authority's review?

Respond ONLY with valid JSON:
{"path_accuracy": N, "confidence_calibration": N, "evidence_quality": N, "false_positive_rate": N, "symbol_resolution": N, "overall_quality": N, "reasoning": "brief explanation"}`,
		filepath.Join(reachableDir, "source"),
		strings.Join(pathStrs, "; "),
		reachableResult.Evidence,
		filepath.Join(notReachableDir, "source"),
		notReachableResult.Evidence,
	)

	prompt = fmt.Sprintf(prompt,
		reachableResult.Reachable, reachableResult.Confidence, reachableResult.Degradations,
		notReachableResult.Reachable, notReachableResult.Confidence, notReachableResult.Degradations,
	)

	cmd := exec.Command(geminiPath, "--yolo", "-p", prompt) //nolint:gosec
	var geminiOut bytes.Buffer
	cmd.Stdout = &geminiOut
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gemini CLI error: %v", err)
	}

	responseText := geminiOut.String()
	jsonStart := strings.Index(responseText, "{")
	jsonEnd := strings.LastIndex(responseText, "}")
	if jsonStart == -1 || jsonEnd == -1 {
		t.Fatalf("no JSON in gemini response: %s", responseText)
	}

	var scores reachabilityScores
	if err := json.Unmarshal([]byte(responseText[jsonStart:jsonEnd+1]), &scores); err != nil {
		t.Fatalf("parse scores: %v\nresponse: %s", err, responseText)
	}

	t.Logf("PHP Transitive LLM Scores: path=%d, confidence=%d, evidence=%d, fp=%d, symbol=%d, overall=%d",
		scores.PathAccuracy, scores.ConfidenceCalibration, scores.EvidenceQuality,
		scores.FalsePositiveRate, scores.SymbolResolution, scores.OverallQuality)
	t.Logf("Reasoning: %s", scores.Reasoning)

	threshold := 6
	dimensions := map[string]int{
		"path_accuracy":          scores.PathAccuracy,
		"confidence_calibration": scores.ConfidenceCalibration,
		"evidence_quality":       scores.EvidenceQuality,
		"false_positive_rate":    scores.FalsePositiveRate,
		"symbol_resolution":      scores.SymbolResolution,
		"overall_quality":        scores.OverallQuality,
	}
	for dim, score := range dimensions {
		if score < threshold {
			t.Errorf("%s: score %d < threshold %d", dim, score, threshold)
		}
	}
}

// parseSBOMForPHPJudge builds a minimal SBOMSummary from the fixture's SBOM file.
func parseSBOMForPHPJudge(t *testing.T, fixtureDir string) *transitive.SBOMSummary {
	t.Helper()
	sbomPath := filepath.Join(fixtureDir, "sbom.cdx.json")
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}

	var doc struct {
		Metadata struct {
			Component struct {
				BOMRef string `json:"bom-ref"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			BOMRef  string `json:"bom-ref"`
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse sbom: %v", err)
	}

	prefix := "pkg:composer/"
	var pkgs []transitive.Package
	for _, c := range doc.Components {
		if !strings.HasPrefix(c.PURL, prefix) {
			continue
		}
		pkgs = append(pkgs, transitive.Package{Name: c.Name, Version: c.Version})
	}

	// All composer packages are roots when no dependency graph is available
	var roots []string
	for _, p := range pkgs {
		roots = append(roots, p.Name)
	}

	return &transitive.SBOMSummary{Packages: pkgs, Roots: roots}
}
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./pkg/vex/reachability/php/`
Expected: compiles without errors

- [ ] **Step 3: Commit**

```bash
git add pkg/vex/reachability/php/llm_judge_test.go
git commit -m "test(transitive): add PHP transitive reachability LLM judge test"
```

---

### Task 9: Run full quality gates

**Files:** None (validation only)

- [ ] **Step 1: Run full test suite**

Run: `task test`
Expected: PASS — all existing tests still pass, new PHP tests pass

- [ ] **Step 2: Run lint**

Run: `task lint`
Expected: PASS — no new lint issues

- [ ] **Step 3: Run transitive-specific tests**

Run: `task test:transitive`
Expected: PASS

- [ ] **Step 4: Run LLM judge test (if available)**

Run: `task test:reachability:transitive:llmjudge`
Expected: PASS — existing Python/JavaScript/Ruby scores unchanged, PHP transitive scores ≥ 6
