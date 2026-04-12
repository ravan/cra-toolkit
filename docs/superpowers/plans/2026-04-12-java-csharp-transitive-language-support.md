# Java & C# Transitive Cross-Package Reachability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Java and C# to the transitive cross-package reachability analyzer with Maven/NuGet fetchers and SCM clone fallback.

**Architecture:** Each language gets a `LanguageSupport` plugin under `languages/{java,csharp}/` wrapping the existing tree-sitter extractors. Two new fetchers (`MavenFetcher`, `NuGetFetcher`) download source from their respective registries, falling back to a shared `scmClone` utility when source archives are unavailable. Java's CHA cross-file state is bridged via an extractor wrapper implementing `CrossFileStateExtractor`. Wiring adds cases to `LanguageFor` and `buildFetchers`.

**Tech Stack:** Go, tree-sitter (java/csharp grammars already vendored), Maven Central REST API, NuGet v3 API, `os/exec` for git clone

---

## File Structure

| File | Purpose |
|------|---------|
| `pkg/vex/reachability/transitive/languages/java/java.go` | Java LanguageSupport + CHA extractor wrapper |
| `pkg/vex/reachability/transitive/languages/java/java_test.go` | Java language plugin unit tests |
| `pkg/vex/reachability/transitive/languages/java/exports.go` | Java ExportLister |
| `pkg/vex/reachability/transitive/languages/java/exports_test.go` | Java export tests |
| `pkg/vex/reachability/transitive/languages/csharp/csharp.go` | C# LanguageSupport |
| `pkg/vex/reachability/transitive/languages/csharp/csharp_test.go` | C# language plugin unit tests |
| `pkg/vex/reachability/transitive/languages/csharp/exports.go` | C# ExportLister |
| `pkg/vex/reachability/transitive/languages/csharp/exports_test.go` | C# export tests |
| `pkg/vex/reachability/transitive/scm_clone.go` | Shared SCM clone utility |
| `pkg/vex/reachability/transitive/scm_clone_test.go` | SCM clone unit tests |
| `pkg/vex/reachability/transitive/fetcher_maven.go` | Maven Central fetcher |
| `pkg/vex/reachability/transitive/fetcher_maven_test.go` | Maven fetcher tests (httptest) |
| `pkg/vex/reachability/transitive/fetcher_nuget.go` | NuGet fetcher |
| `pkg/vex/reachability/transitive/fetcher_nuget_test.go` | NuGet fetcher tests (httptest) |
| `pkg/vex/reachability/transitive/language.go` | Add java/csharp to LanguageFor |
| `pkg/vex/reachability/transitive/transitive_wire.go` (in `pkg/vex/`) | Add maven/nuget to buildFetchers |
| `pkg/vex/reachability/transitive/degradation.go` | Add `ReasonSCMCloneFailed` |
| `pkg/vex/reachability/transitive/integration_test.go` | Add Java/C# integration test cases |
| `testdata/integration/java-realworld-cross-package/` | Java cross-package fixture (reachable) |
| `testdata/integration/java-realworld-cross-package-safe/` | Java cross-package fixture (not reachable) |
| `testdata/integration/csharp-realworld-cross-package/` | C# cross-package fixture (reachable) |
| `testdata/integration/csharp-realworld-cross-package-safe/` | C# cross-package fixture (not reachable) |

---

### Task 1: Java Language Plugin — LanguageSupport

**Files:**
- Create: `pkg/vex/reachability/transitive/languages/java/java.go`
- Create: `pkg/vex/reachability/transitive/languages/java/java_test.go`

- [ ] **Step 1: Write the failing test for Java identity methods**

Create `pkg/vex/reachability/transitive/languages/java/java_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package java_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/java"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestJava_Identity(t *testing.T) {
	lang := java.New()
	if lang.Name() != "java" {
		t.Errorf("Name() = %q, want %q", lang.Name(), "java")
	}
	if lang.Ecosystem() != "maven" {
		t.Errorf("Ecosystem() = %q, want %q", lang.Ecosystem(), "maven")
	}
	exts := lang.FileExtensions()
	if len(exts) != 1 || exts[0] != ".java" {
		t.Errorf("FileExtensions() = %v, want [\".java\"]", exts)
	}
	if lang.Grammar() == nil {
		t.Error("Grammar() returned nil")
	}
	if lang.Extractor() == nil {
		t.Error("Extractor() returned nil")
	}
}

func TestJava_IsExportedSymbol(t *testing.T) {
	lang := java.New()
	tests := []struct {
		name string
		sym  *treesitter.Symbol
		want bool
	}{
		{"nil", nil, false},
		{"public method", &treesitter.Symbol{Name: "fromJson", Kind: treesitter.SymbolMethod, IsPublic: true}, true},
		{"public function", &treesitter.Symbol{Name: "parse", Kind: treesitter.SymbolFunction, IsPublic: true}, true},
		{"public class", &treesitter.Symbol{Name: "Gson", Kind: treesitter.SymbolClass, IsPublic: true}, true},
		{"non-public method", &treesitter.Symbol{Name: "internal", Kind: treesitter.SymbolMethod, IsPublic: false}, false},
		{"module kind", &treesitter.Symbol{Name: "config", Kind: treesitter.SymbolModule, IsPublic: true}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lang.IsExportedSymbol(tc.sym); got != tc.want {
				t.Errorf("IsExportedSymbol(%+v) = %v, want %v", tc.sym, got, tc.want)
			}
		})
	}
}

func TestJava_ModulePath(t *testing.T) {
	lang := java.New()
	tests := []struct {
		name        string
		file        string
		sourceDir   string
		packageName string
		want        string
	}{
		{
			name:        "standard Maven src/main/java layout",
			file:        "/tmp/gson/src/main/java/com/google/gson/Gson.java",
			sourceDir:   "/tmp/gson",
			packageName: "com.google.code.gson:gson",
			want:        "com.google.code.gson:gson.com.google.gson.Gson",
		},
		{
			name:        "flat source layout",
			file:        "/tmp/lib/com/example/Service.java",
			sourceDir:   "/tmp/lib",
			packageName: "com.example:lib",
			want:        "com.example:lib.com.example.Service",
		},
		{
			name:        "file outside sourceDir",
			file:        "/tmp/other/Foo.java",
			sourceDir:   "/tmp/pkg",
			packageName: "com.example:pkg",
			want:        "com.example:pkg",
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

func TestJava_SymbolKey(t *testing.T) {
	lang := java.New()
	got := lang.SymbolKey("com.google.code.gson:gson.com.google.gson.Gson", "fromJson")
	want := "com.google.code.gson:gson.com.google.gson.Gson.fromJson"
	if got != want {
		t.Errorf("SymbolKey = %q, want %q", got, want)
	}
}

func TestJava_NormalizeImports(t *testing.T) {
	lang := java.New()
	raw := []treesitter.Import{
		{Module: "org.apache.logging.log4j.Logger", Alias: "Logger"},
		{Module: "com.google.gson.Gson", Alias: "Gson"},
	}
	got := lang.NormalizeImports(raw)
	if len(got) != 2 {
		t.Fatalf("NormalizeImports returned %d imports, want 2", len(got))
	}
	if got[0].Module != "org.apache.logging.log4j.Logger" {
		t.Errorf("got[0].Module = %q, want %q", got[0].Module, "org.apache.logging.log4j.Logger")
	}
	if got[1].Alias != "Gson" {
		t.Errorf("got[1].Alias = %q, want %q", got[1].Alias, "Gson")
	}
}

func TestJava_ResolveDottedTarget(t *testing.T) {
	lang := java.New()
	scope := treesitter.NewScope(nil)
	scope.DefineImport("Logger", "org.apache.logging.log4j.Logger", nil)

	t.Run("alias found", func(t *testing.T) {
		got, ok := lang.ResolveDottedTarget("Logger", "getLogger", scope)
		if !ok {
			t.Fatal("expected ok=true")
		}
		want := treesitter.SymbolID("org.apache.logging.log4j.Logger.getLogger")
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

func TestJava_ResolveSelfCall(t *testing.T) {
	lang := java.New()
	tests := []struct {
		name string
		to   treesitter.SymbolID
		from treesitter.SymbolID
		want treesitter.SymbolID
	}{
		{
			name: "this call in class method",
			to:   "this.validate",
			from: "com.example.Service.handle",
			want: "com.example.Service.validate",
		},
		{
			name: "short from — unchanged",
			to:   "this.helper",
			from: "mod.func",
			want: "this.helper",
		},
		{
			name: "non-this — unchanged",
			to:   "Logger.getLogger",
			from: "com.example.App.main",
			want: "Logger.getLogger",
		},
		{
			name: "minimum valid from (3 dot-parts)",
			to:   "this.run",
			from: "com.example.App.handle",
			want: "com.example.App.run",
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

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/languages/java/ -v -count=1`
Expected: FAIL — package doesn't exist yet

- [ ] **Step 3: Write the Java language plugin**

Create `pkg/vex/reachability/transitive/languages/java/java.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package java provides the Java LanguageSupport implementation for the
// transitive cross-package reachability analyzer. It is imported only
// by the transitive package's LanguageFor factory.
package java

import (
	"path/filepath"
	"strings"
	"unsafe"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarjava "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/java"
	javaextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/java"
)

// Language is the Java LanguageSupport implementation. Callers use New
// to construct a value; the zero value is not valid.
type Language struct {
	extractor *chaExtractor
}

// New returns a fresh Java Language. The extractor wraps the raw Java
// extractor with CrossFileStateExtractor delegation for CHA.
func New() *Language {
	return &Language{extractor: &chaExtractor{inner: javaextractor.New()}}
}

func (l *Language) Name() string                            { return "java" }
func (l *Language) Ecosystem() string                       { return "maven" }
func (l *Language) FileExtensions() []string                { return []string{".java"} }
func (l *Language) Grammar() unsafe.Pointer                 { return grammarjava.Language() }
func (l *Language) Extractor() treesitter.LanguageExtractor { return l.extractor }

// IsExportedSymbol reports whether a symbol is part of the Java package's
// public API. Java's visibility model is explicit — public means exported.
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

// ModulePath derives a dotted module path for a Java source file relative
// to sourceDir. Strips the conventional src/main/java/ prefix when present:
//
//	src/main/java/com/google/gson/Gson.java → "gson.com.google.gson.Gson"
//	com/example/Service.java                → "lib.com.example.Service"
func (l *Language) ModulePath(file, sourceDir, packageName string) string {
	rel, err := filepath.Rel(sourceDir, file)
	if err != nil || strings.HasPrefix(rel, "..") {
		return packageName
	}
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	parts := strings.Split(rel, string(filepath.Separator))
	// Strip conventional src/main/java/ prefix.
	if len(parts) >= 3 && parts[0] == "src" && parts[1] == "main" && parts[2] == "java" {
		parts = parts[3:]
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

// NormalizeImports is the identity function for Java. Java imports are
// already fully-qualified dotted paths. No rewriting is required.
func (l *Language) NormalizeImports(raw []treesitter.Import) []treesitter.Import {
	return raw
}

// ResolveDottedTarget resolves a dotted call target whose prefix is an
// import alias. For example, given "Logger" and a scope where "Logger"
// maps to "org.apache.logging.log4j.Logger", returns
// "org.apache.logging.log4j.Logger.getLogger" for suffix="getLogger".
func (l *Language) ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool) {
	resolved, ok := scope.LookupImport(prefix)
	if !ok {
		return "", false
	}
	return treesitter.SymbolID(resolved + "." + suffix), true
}

// ResolveSelfCall rewrites "this.X" call targets to the class-qualified
// form "ClassName.X" by extracting the class context from the caller's
// symbol ID. Only applies when `from` has at least three dot-separated
// components (package.class.method).
func (l *Language) ResolveSelfCall(to, from treesitter.SymbolID) treesitter.SymbolID {
	toStr := string(to)
	if !strings.HasPrefix(toStr, "this.") {
		return to
	}
	methodName := toStr[len("this."):]
	fromParts := strings.Split(string(from), ".")
	if len(fromParts) < 3 {
		return to
	}
	classQual := strings.Join(fromParts[:len(fromParts)-1], ".")
	return treesitter.SymbolID(classQual + "." + methodName)
}

// chaExtractor wraps the raw Java tree-sitter extractor and implements
// the CrossFileStateExtractor interface by delegating to the Java
// extractor's SnapshotCHA/RestoreCHA methods.
type chaExtractor struct {
	inner *javaextractor.Extractor
}

func (e *chaExtractor) ExtractSymbols(file string, source []byte, tree *tree_sitter.Tree) ([]*treesitter.Symbol, error) {
	return e.inner.ExtractSymbols(file, source, tree)
}

func (e *chaExtractor) ResolveImports(file string, source []byte, tree *tree_sitter.Tree, projectRoot string) ([]treesitter.Import, error) {
	return e.inner.ResolveImports(file, source, tree, projectRoot)
}

func (e *chaExtractor) ExtractCalls(file string, source []byte, tree *tree_sitter.Tree, scope *treesitter.Scope) ([]treesitter.Edge, error) {
	return e.inner.ExtractCalls(file, source, tree, scope)
}

func (e *chaExtractor) FindEntryPoints(symbols []*treesitter.Symbol, projectRoot string) []treesitter.SymbolID {
	return e.inner.FindEntryPoints(symbols, projectRoot)
}

// SnapshotState captures the CHA cross-file state for restoration.
func (e *chaExtractor) SnapshotState() any {
	return e.inner.SnapshotCHA()
}

// RestoreState merges a CHA snapshot back into the extractor.
func (e *chaExtractor) RestoreState(s any) {
	if snap, ok := s.(*javaextractor.CHASnapshot); ok {
		e.inner.RestoreCHA(snap)
	}
}
```

The `tree_sitter.Tree` type comes from `tree_sitter "github.com/tree-sitter/go-tree-sitter"` — add this to the import block alongside the existing treesitter import.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/languages/java/ -v -count=1`
Expected: PASS — all tests green

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/transitive/languages/java/java.go pkg/vex/reachability/transitive/languages/java/java_test.go
git commit -m "feat(transitive): add Java LanguageSupport plugin with CHA extractor wrapper"
```

---

### Task 2: Java ExportLister

**Files:**
- Create: `pkg/vex/reachability/transitive/languages/java/exports.go`
- Create: `pkg/vex/reachability/transitive/languages/java/exports_test.go`

- [ ] **Step 1: Write the failing test for Java exports**

Create `pkg/vex/reachability/transitive/languages/java/exports_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package java_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/java"
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

func TestListExports_MavenLayout(t *testing.T) {
	root := writePackage(t, "gson", map[string]string{
		"src/main/java/com/google/gson/Gson.java": `package com.google.gson;

public class Gson {
    public <T> T fromJson(String json, Class<T> classOfT) {
        return null;
    }

    private void internalHelper() {}
}`,
	})
	lang := java.New()
	keys, err := lang.ListExports(root, "com.google.code.gson:gson")
	if err != nil {
		t.Fatal(err)
	}
	hasClass := false
	hasFromJson := false
	hasInternal := false
	for _, k := range keys {
		if k == "com.google.gson.Gson" {
			hasClass = true
		}
		if k == "com.google.gson.Gson.fromJson" {
			hasFromJson = true
		}
		if k == "com.google.gson.Gson.internalHelper" {
			hasInternal = true
		}
	}
	if !hasClass {
		t.Errorf("missing Gson class in exports: %v", keys)
	}
	if !hasFromJson {
		t.Errorf("missing fromJson in exports: %v", keys)
	}
	if hasInternal {
		t.Errorf("private internalHelper should not be exported: %v", keys)
	}
}

func TestListExports_FlatLayout(t *testing.T) {
	root := writePackage(t, "lib", map[string]string{
		"com/example/Service.java": `package com.example;

public class Service {
    public void handle() {}
}`,
	})
	lang := java.New()
	keys, err := lang.ListExports(root, "com.example:lib")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Error("expected exported symbols from flat layout")
	}
}

func TestListExports_SkipsTestDir(t *testing.T) {
	root := writePackage(t, "tested", map[string]string{
		"src/main/java/com/example/Core.java": `package com.example;

public class Core {
    public void run() {}
}`,
		"src/test/java/com/example/CoreTest.java": `package com.example;

public class CoreTest {
    public void testRun() {}
}`,
	})
	lang := java.New()
	keys, err := lang.ListExports(root, "com.example:tested")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k == "com.example.CoreTest" || k == "com.example.CoreTest.testRun" {
			t.Errorf("test file leaked into exports: %q", k)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/languages/java/ -run TestListExports -v -count=1`
Expected: FAIL — `ListExports` method does not exist

- [ ] **Step 3: Write the Java ExportLister**

Create `pkg/vex/reachability/transitive/languages/java/exports.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package java

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	grammarjava "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/java"
	javaextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/java"
)

// skipDirs are directories excluded from export scanning.
var skipDirs = map[string]bool{
	"test": true, "tests": true, "src/test": true,
}

// ListExports enumerates the public API of a Java package by scanning
// source files. Uses src/main/java/ when present, falls back to root.
// Test directories (src/test/, test/, tests/) are excluded.
//
//nolint:gocognit,gocyclo // file walk, parse loop, and symbol filtering
func (l *Language) ListExports(sourceDir, packageName string) ([]string, error) {
	scanRoot := sourceDir
	mainJava := filepath.Join(sourceDir, "src", "main", "java")
	if info, err := os.Stat(mainJava); err == nil && info.IsDir() {
		scanRoot = mainJava
	}

	var files []string
	_ = filepath.WalkDir(scanRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			rel, relErr := filepath.Rel(sourceDir, path)
			if relErr == nil {
				for skip := range skipDirs {
					if rel == skip || strings.HasPrefix(rel, skip+string(filepath.Separator)) {
						return filepath.SkipDir
					}
				}
			}
			return nil
		}
		if strings.HasSuffix(path, ".java") {
			files = append(files, path)
		}
		return nil
	})
	if len(files) == 0 {
		return nil, nil
	}

	parser := tree_sitter.NewParser()
	defer parser.Close()
	lang := tree_sitter.NewLanguage(grammarjava.Language())
	if err := parser.SetLanguage(lang); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	for _, file := range files {
		src, err := os.ReadFile(file) //nolint:gosec // paths resolved within sourceDir
		if err != nil {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}

		ext := javaextractor.New()
		symbols, err := ext.ExtractSymbols(file, src, tree)
		tree.Close()
		if err != nil {
			continue
		}

		for _, sym := range symbols {
			if !l.IsExportedSymbol(sym) {
				continue
			}
			key := sym.QualifiedName
			if key == "" {
				continue
			}
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/languages/java/ -v -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/transitive/languages/java/exports.go pkg/vex/reachability/transitive/languages/java/exports_test.go
git commit -m "feat(transitive): add Java ExportLister with Maven layout support"
```

---

### Task 3: C# Language Plugin — LanguageSupport

**Files:**
- Create: `pkg/vex/reachability/transitive/languages/csharp/csharp.go`
- Create: `pkg/vex/reachability/transitive/languages/csharp/csharp_test.go`

- [ ] **Step 1: Write the failing test for C# identity and LanguageSupport methods**

Create `pkg/vex/reachability/transitive/languages/csharp/csharp_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csharp_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/csharp"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestCSharp_Identity(t *testing.T) {
	lang := csharp.New()
	if lang.Name() != "csharp" {
		t.Errorf("Name() = %q, want %q", lang.Name(), "csharp")
	}
	if lang.Ecosystem() != "nuget" {
		t.Errorf("Ecosystem() = %q, want %q", lang.Ecosystem(), "nuget")
	}
	exts := lang.FileExtensions()
	if len(exts) != 1 || exts[0] != ".cs" {
		t.Errorf("FileExtensions() = %v, want [\".cs\"]", exts)
	}
	if lang.Grammar() == nil {
		t.Error("Grammar() returned nil")
	}
	if lang.Extractor() == nil {
		t.Error("Extractor() returned nil")
	}
}

func TestCSharp_IsExportedSymbol(t *testing.T) {
	lang := csharp.New()
	tests := []struct {
		name string
		sym  *treesitter.Symbol
		want bool
	}{
		{"nil", nil, false},
		{"public method", &treesitter.Symbol{Name: "DeserializeObject", Kind: treesitter.SymbolMethod, IsPublic: true}, true},
		{"public function", &treesitter.Symbol{Name: "Parse", Kind: treesitter.SymbolFunction, IsPublic: true}, true},
		{"public class", &treesitter.Symbol{Name: "JsonConvert", Kind: treesitter.SymbolClass, IsPublic: true}, true},
		{"non-public method", &treesitter.Symbol{Name: "Internal", Kind: treesitter.SymbolMethod, IsPublic: false}, false},
		{"module kind", &treesitter.Symbol{Name: "Config", Kind: treesitter.SymbolModule, IsPublic: true}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lang.IsExportedSymbol(tc.sym); got != tc.want {
				t.Errorf("IsExportedSymbol(%+v) = %v, want %v", tc.sym, got, tc.want)
			}
		})
	}
}

func TestCSharp_ModulePath(t *testing.T) {
	lang := csharp.New()
	tests := []struct {
		name        string
		file        string
		sourceDir   string
		packageName string
		want        string
	}{
		{
			name:        "src layout",
			file:        "/tmp/json/src/Newtonsoft.Json/JsonConvert.cs",
			sourceDir:   "/tmp/json",
			packageName: "Newtonsoft.Json",
			want:        "Newtonsoft.Json.Newtonsoft.Json.JsonConvert",
		},
		{
			name:        "root layout",
			file:        "/tmp/lib/Service.cs",
			sourceDir:   "/tmp/lib",
			packageName: "MyLib",
			want:        "MyLib.Service",
		},
		{
			name:        "file outside sourceDir",
			file:        "/tmp/other/Foo.cs",
			sourceDir:   "/tmp/pkg",
			packageName: "MyPkg",
			want:        "MyPkg",
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

func TestCSharp_SymbolKey(t *testing.T) {
	lang := csharp.New()
	got := lang.SymbolKey("Newtonsoft.Json.Newtonsoft.Json.JsonConvert", "DeserializeObject")
	want := "Newtonsoft.Json.Newtonsoft.Json.JsonConvert.DeserializeObject"
	if got != want {
		t.Errorf("SymbolKey = %q, want %q", got, want)
	}
}

func TestCSharp_NormalizeImports(t *testing.T) {
	lang := csharp.New()
	raw := []treesitter.Import{
		{Module: "System.Text.Json", Alias: "Json"},
		{Module: "Newtonsoft.Json", Alias: "Json"},
	}
	got := lang.NormalizeImports(raw)
	if len(got) != 2 {
		t.Fatalf("NormalizeImports returned %d imports, want 2", len(got))
	}
	if got[0].Module != "System.Text.Json" {
		t.Errorf("got[0].Module = %q, want %q", got[0].Module, "System.Text.Json")
	}
}

func TestCSharp_ResolveDottedTarget(t *testing.T) {
	lang := csharp.New()
	scope := treesitter.NewScope(nil)
	scope.DefineImport("JsonConvert", "Newtonsoft.Json.JsonConvert", nil)

	t.Run("alias found", func(t *testing.T) {
		got, ok := lang.ResolveDottedTarget("JsonConvert", "DeserializeObject", scope)
		if !ok {
			t.Fatal("expected ok=true")
		}
		want := treesitter.SymbolID("Newtonsoft.Json.JsonConvert.DeserializeObject")
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

func TestCSharp_ResolveSelfCall(t *testing.T) {
	lang := csharp.New()
	tests := []struct {
		name string
		to   treesitter.SymbolID
		from treesitter.SymbolID
		want treesitter.SymbolID
	}{
		{
			name: "this call in class method",
			to:   "this.Validate",
			from: "MyApp.Controllers.UserController.Index",
			want: "MyApp.Controllers.UserController.Validate",
		},
		{
			name: "short from — unchanged",
			to:   "this.Helper",
			from: "Mod.Func",
			want: "this.Helper",
		},
		{
			name: "non-this — unchanged",
			to:   "JsonConvert.DeserializeObject",
			from: "MyApp.Service.Run",
			want: "JsonConvert.DeserializeObject",
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

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/languages/csharp/ -v -count=1`
Expected: FAIL — package doesn't exist yet

- [ ] **Step 3: Write the C# language plugin**

Create `pkg/vex/reachability/transitive/languages/csharp/csharp.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package csharp provides the C# LanguageSupport implementation for the
// transitive cross-package reachability analyzer. It is imported only
// by the transitive package's LanguageFor factory.
package csharp

import (
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarcsharp "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/csharp"
	csharpextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/csharp"
)

// Language is the C# LanguageSupport implementation. Callers use New
// to construct a value; the zero value is not valid.
type Language struct {
	extractor treesitter.LanguageExtractor
}

// New returns a fresh C# Language.
func New() *Language {
	return &Language{extractor: csharpextractor.New()}
}

func (l *Language) Name() string                            { return "csharp" }
func (l *Language) Ecosystem() string                       { return "nuget" }
func (l *Language) FileExtensions() []string                { return []string{".cs"} }
func (l *Language) Grammar() unsafe.Pointer                 { return grammarcsharp.Language() }
func (l *Language) Extractor() treesitter.LanguageExtractor { return l.extractor }

// IsExportedSymbol reports whether a symbol is part of the C# package's
// public API. C#'s public modifier is explicit.
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

// ModulePath derives a dotted module path for a C# source file relative
// to sourceDir. Strips the conventional src/ prefix when present:
//
//	src/Newtonsoft.Json/JsonConvert.cs → "Newtonsoft.Json.Newtonsoft.Json.JsonConvert"
//	Service.cs                        → "MyLib.Service"
func (l *Language) ModulePath(file, sourceDir, packageName string) string {
	rel, err := filepath.Rel(sourceDir, file)
	if err != nil || strings.HasPrefix(rel, "..") {
		return packageName
	}
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	parts := strings.Split(rel, string(filepath.Separator))
	// Strip conventional src/ prefix.
	if len(parts) > 0 && parts[0] == "src" {
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

// NormalizeImports is the identity function for C#. Using directives
// are already dotted paths. No rewriting is required.
func (l *Language) NormalizeImports(raw []treesitter.Import) []treesitter.Import {
	return raw
}

// ResolveDottedTarget resolves a dotted call target whose prefix is an
// import alias.
func (l *Language) ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool) {
	resolved, ok := scope.LookupImport(prefix)
	if !ok {
		return "", false
	}
	return treesitter.SymbolID(resolved + "." + suffix), true
}

// ResolveSelfCall rewrites "this.X" call targets to the class-qualified
// form "ClassName.X".
func (l *Language) ResolveSelfCall(to, from treesitter.SymbolID) treesitter.SymbolID {
	toStr := string(to)
	if !strings.HasPrefix(toStr, "this.") {
		return to
	}
	methodName := toStr[len("this."):]
	fromParts := strings.Split(string(from), ".")
	if len(fromParts) < 3 {
		return to
	}
	classQual := strings.Join(fromParts[:len(fromParts)-1], ".")
	return treesitter.SymbolID(classQual + "." + methodName)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/languages/csharp/ -v -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/transitive/languages/csharp/csharp.go pkg/vex/reachability/transitive/languages/csharp/csharp_test.go
git commit -m "feat(transitive): add C# LanguageSupport plugin"
```

---

### Task 4: C# ExportLister

**Files:**
- Create: `pkg/vex/reachability/transitive/languages/csharp/exports.go`
- Create: `pkg/vex/reachability/transitive/languages/csharp/exports_test.go`

- [ ] **Step 1: Write the failing test for C# exports**

Create `pkg/vex/reachability/transitive/languages/csharp/exports_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csharp_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/csharp"
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

func TestListExports_SrcLayout(t *testing.T) {
	root := writePackage(t, "json-net", map[string]string{
		"src/Newtonsoft.Json/JsonConvert.cs": `namespace Newtonsoft.Json
{
    public class JsonConvert
    {
        public static T DeserializeObject<T>(string value) { return default; }
        private static void InternalHelper() {}
    }
}`,
	})
	lang := csharp.New()
	keys, err := lang.ListExports(root, "Newtonsoft.Json")
	if err != nil {
		t.Fatal(err)
	}
	hasClass := false
	hasDeserialize := false
	hasInternal := false
	for _, k := range keys {
		if k == "Newtonsoft.Json.JsonConvert" {
			hasClass = true
		}
		if k == "Newtonsoft.Json.JsonConvert.DeserializeObject" {
			hasDeserialize = true
		}
		if k == "Newtonsoft.Json.JsonConvert.InternalHelper" {
			hasInternal = true
		}
	}
	if !hasClass {
		t.Errorf("missing JsonConvert class in exports: %v", keys)
	}
	if !hasDeserialize {
		t.Errorf("missing DeserializeObject in exports: %v", keys)
	}
	if hasInternal {
		t.Errorf("private InternalHelper should not be exported: %v", keys)
	}
}

func TestListExports_RootLayout(t *testing.T) {
	root := writePackage(t, "mylib", map[string]string{
		"Service.cs": `namespace MyLib
{
    public class Service
    {
        public void Handle() {}
    }
}`,
	})
	lang := csharp.New()
	keys, err := lang.ListExports(root, "MyLib")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Error("expected exported symbols from root layout")
	}
}

func TestListExports_SkipsTestAndBuildDirs(t *testing.T) {
	root := writePackage(t, "tested", map[string]string{
		"src/MyLib/Core.cs": `namespace MyLib
{
    public class Core { public void Run() {} }
}`,
		"test/MyLib.Tests/CoreTest.cs": `namespace MyLib.Tests
{
    public class CoreTest { public void TestRun() {} }
}`,
		"obj/Debug/Generated.cs": `namespace MyLib
{
    public class Generated { public void Auto() {} }
}`,
		"bin/Release/Output.cs": `namespace MyLib
{
    public class Output { public void Run() {} }
}`,
	})
	lang := csharp.New()
	keys, err := lang.ListExports(root, "MyLib")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k == "MyLib.Tests.CoreTest" || k == "MyLib.Tests.CoreTest.TestRun" {
			t.Errorf("test file leaked into exports: %q", k)
		}
		if k == "MyLib.Generated" || k == "MyLib.Output" {
			t.Errorf("build output leaked into exports: %q", k)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/languages/csharp/ -run TestListExports -v -count=1`
Expected: FAIL — `ListExports` method does not exist

- [ ] **Step 3: Write the C# ExportLister**

Create `pkg/vex/reachability/transitive/languages/csharp/exports.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csharp

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	grammarcsharp "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/csharp"
	csharpextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/csharp"
)

// skipDirs are directories excluded from export scanning.
var skipDirs = map[string]bool{
	"obj": true, "bin": true, "test": true, "tests": true,
}

// skipDirPatterns match directory names containing these substrings.
var skipDirPatterns = []string{"Test", "Tests", "Spec"}

// ListExports enumerates the public API of a C# package by scanning
// source files. Excludes obj/, bin/, and test directories.
//
//nolint:gocognit,gocyclo // file walk, parse loop, and symbol filtering
func (l *Language) ListExports(sourceDir, packageName string) ([]string, error) {
	var files []string
	_ = filepath.WalkDir(sourceDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if skipDirs[name] {
				return filepath.SkipDir
			}
			for _, pat := range skipDirPatterns {
				if strings.Contains(name, pat) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if strings.HasSuffix(path, ".cs") {
			files = append(files, path)
		}
		return nil
	})
	if len(files) == 0 {
		return nil, nil
	}

	parser := tree_sitter.NewParser()
	defer parser.Close()
	lang := tree_sitter.NewLanguage(grammarcsharp.Language())
	if err := parser.SetLanguage(lang); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	for _, file := range files {
		src, err := os.ReadFile(file) //nolint:gosec // paths resolved within sourceDir
		if err != nil {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}

		ext := csharpextractor.New()
		symbols, err := ext.ExtractSymbols(file, src, tree)
		tree.Close()
		if err != nil {
			continue
		}

		for _, sym := range symbols {
			if !l.IsExportedSymbol(sym) {
				continue
			}
			key := sym.QualifiedName
			if key == "" {
				continue
			}
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/languages/csharp/ -v -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/transitive/languages/csharp/exports.go pkg/vex/reachability/transitive/languages/csharp/exports_test.go
git commit -m "feat(transitive): add C# ExportLister"
```

---

### Task 5: SCM Clone Utility

**Files:**
- Create: `pkg/vex/reachability/transitive/scm_clone.go`
- Create: `pkg/vex/reachability/transitive/scm_clone_test.go`
- Modify: `pkg/vex/reachability/transitive/degradation.go`

- [ ] **Step 1: Add the new degradation reason**

Add to `pkg/vex/reachability/transitive/degradation.go`, inside the const block after `ReasonNoLibraryAPI`:

```go
	// ReasonSCMCloneFailed indicates the SCM clone fallback failed.
	// This may happen when the package has no repository URL, the repo
	// is private, or no matching version tag exists.
	ReasonSCMCloneFailed = "scm_clone_failed"
```

- [ ] **Step 2: Write the failing test for SCM clone**

Create `pkg/vex/reachability/transitive/scm_clone_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"testing"
)

func TestNormalizeRepoURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"https passthrough", "https://github.com/google/gson", "https://github.com/google/gson", false},
		{"strip .git suffix", "https://github.com/google/gson.git", "https://github.com/google/gson", false},
		{"git:// to https://", "git://github.com/google/gson.git", "https://github.com/google/gson", false},
		{"reject ssh", "git@github.com:google/gson.git", "", true},
		{"reject empty", "", "", true},
		{"http passthrough", "http://github.com/google/gson", "http://github.com/google/gson", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeRepoURL(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("normalizeRepoURL(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestVersionTags(t *testing.T) {
	tags := versionTags("1.2.3")
	expected := []string{"v1.2.3", "1.2.3", "release-1.2.3", "release/1.2.3"}
	if len(tags) != len(expected) {
		t.Fatalf("versionTags(\"1.2.3\") = %v, want %v", tags, expected)
	}
	for i, tag := range tags {
		if tag != expected[i] {
			t.Errorf("tag[%d] = %q, want %q", i, tag, expected[i])
		}
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/ -run "TestNormalizeRepoURL|TestVersionTags" -v -count=1`
Expected: FAIL — functions not defined

- [ ] **Step 4: Write the SCM clone utility**

Create `pkg/vex/reachability/transitive/scm_clone.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SCMCloneResult describes the outcome of a source clone.
type SCMCloneResult struct {
	SourceDir string
	Digest    Digest
}

// scmClone clones a Git repository at the given version into a cache
// directory. It tries multiple tag formats (v1.2.3, 1.2.3, release-1.2.3,
// release/1.2.3), falling back to the default branch if none match.
// Only https:// and http:// schemes are accepted.
//
//nolint:gocyclo // tag-matching loop with fallback
func scmClone(ctx context.Context, repoURL, version string, cache *Cache) (SCMCloneResult, error) {
	normalized, err := normalizeRepoURL(repoURL)
	if err != nil {
		return SCMCloneResult{}, err
	}

	cacheKey := "scm:" + normalized + "@" + version
	cacheDigest := Digest{Algorithm: "sha256", Hex: hashHex([]byte(cacheKey))}
	if cache != nil {
		if p, ok := cache.Get(cacheDigest.String()); ok {
			return SCMCloneResult{SourceDir: p, Digest: cacheDigest}, nil
		}
	}

	tmp, err := os.MkdirTemp("", "scm-clone-*")
	if err != nil {
		return SCMCloneResult{}, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	cloned := false
	for _, tag := range versionTags(version) {
		//nolint:gosec // repoURL validated by normalizeRepoURL; tag derived from version string
		cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--branch", tag, normalized, tmp+"/repo")
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		if err := cmd.Run(); err == nil {
			cloned = true
			break
		}
		_ = os.RemoveAll(tmp + "/repo")
	}
	if !cloned {
		// Fallback: clone default branch.
		//nolint:gosec // repoURL validated by normalizeRepoURL
		cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", normalized, tmp+"/repo")
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		if err := cmd.Run(); err != nil {
			return SCMCloneResult{}, fmt.Errorf("%s: git clone %s: %w", ReasonSCMCloneFailed, normalized, err)
		}
	}

	// Remove .git to save cache space.
	_ = os.RemoveAll(filepath.Join(tmp, "repo", ".git"))

	srcDir := filepath.Join(tmp, "repo")
	digest := Digest{Algorithm: "sha256", Hex: hashDir(srcDir)}

	if cache != nil {
		p, putErr := cache.Put(cacheDigest.String(), srcDir)
		if putErr != nil {
			return SCMCloneResult{}, putErr
		}
		return SCMCloneResult{SourceDir: p, Digest: digest}, nil
	}

	// Without cache, move to a stable temp dir the caller can use.
	stable, err := os.MkdirTemp("", "scm-result-*")
	if err != nil {
		return SCMCloneResult{}, err
	}
	if err := os.Rename(srcDir, filepath.Join(stable, "repo")); err != nil {
		_ = os.RemoveAll(stable)
		return SCMCloneResult{}, err
	}
	return SCMCloneResult{SourceDir: filepath.Join(stable, "repo"), Digest: digest}, nil
}

// normalizeRepoURL validates and normalizes a repository URL.
// Only https:// and http:// schemes are accepted. git:// is converted
// to https://. SSH URLs (git@) are rejected. The .git suffix is stripped.
func normalizeRepoURL(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("empty repository URL")
	}
	if strings.HasPrefix(raw, "git@") {
		return "", fmt.Errorf("SSH repository URLs are not supported: %s", raw)
	}
	if strings.HasPrefix(raw, "git://") {
		raw = "https://" + strings.TrimPrefix(raw, "git://")
	}
	if !strings.HasPrefix(raw, "https://") && !strings.HasPrefix(raw, "http://") {
		return "", fmt.Errorf("unsupported URL scheme: %s", raw)
	}
	raw = strings.TrimSuffix(raw, ".git")
	return raw, nil
}

// versionTags returns candidate Git tags for a semantic version string.
func versionTags(version string) []string {
	return []string{
		"v" + version,
		version,
		"release-" + version,
		"release/" + version,
	}
}

// hashDir computes a SHA-256 hash of a directory's file contents
// (names + content, lexicographically ordered).
func hashDir(dir string) string {
	h := sha256.New()
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		_, _ = h.Write([]byte(rel))
		data, err := os.ReadFile(path) //nolint:gosec // path from controlled walk
		if err == nil {
			_, _ = h.Write(data)
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/ -run "TestNormalizeRepoURL|TestVersionTags" -v -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/vex/reachability/transitive/scm_clone.go pkg/vex/reachability/transitive/scm_clone_test.go pkg/vex/reachability/transitive/degradation.go
git commit -m "feat(transitive): add shared SCM clone utility with URL validation and tag matching"
```

---

### Task 6: Maven Fetcher

**Files:**
- Create: `pkg/vex/reachability/transitive/fetcher_maven.go`
- Create: `pkg/vex/reachability/transitive/fetcher_maven_test.go`

- [ ] **Step 1: Write the failing tests for MavenFetcher**

Create `pkg/vex/reachability/transitive/fetcher_maven_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMavenFetcher_Ecosystem(t *testing.T) {
	f := &MavenFetcher{}
	if f.Ecosystem() != "maven" {
		t.Errorf("Ecosystem() = %q, want %q", f.Ecosystem(), "maven")
	}
}

func TestMavenFetcher_Manifest_HappyPath(t *testing.T) {
	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/com/google/code/gson/gson/2.10.1/gson-2.10.1.pom") {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(pom))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	f := &MavenFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	m, err := f.Manifest(context.Background(), "com.google.code.gson:gson", "2.10.1")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if _, ok := m.Dependencies["com.google.guava:guava"]; !ok {
		t.Error("guava not in dependencies")
	}
	if _, ok := m.Dependencies["junit:junit"]; ok {
		t.Error("test-scoped junit should have been filtered")
	}
}

func TestMavenFetcher_Fetch_SourcesJAR(t *testing.T) {
	zipData := buildTestZip(t, "gson-2.10.1-sources", map[string]string{
		"com/google/gson/Gson.java": `package com.google.gson;
public class Gson {}`,
	})
	digest := sha256Hex(zipData)

	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project><dependencies></dependencies></project>`

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "gson-2.10.1.pom"):
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(pom))
		case strings.HasSuffix(r.URL.Path, "gson-2.10.1-sources.jar"):
			w.Header().Set("Content-Type", "application/java-archive")
			_, _ = w.Write(zipData)
		case strings.HasSuffix(r.URL.Path, "gson-2.10.1-sources.jar.sha1"):
			// SHA-1 checksum — we use SHA-256 internally so just return empty
			// to skip SHA-1 validation in tests
			_, _ = fmt.Fprintf(w, "%s", digest[:40])
		default:
			http.NotFound(w, r)
		}
	}))
	srvURL = srv.URL
	_ = srvURL
	defer srv.Close()

	f := &MavenFetcher{BaseURL: srv.URL, HTTPClient: srv.Client(), Cache: NewCache(t.TempDir())}
	fr, err := f.Fetch(context.Background(), "com.google.code.gson:gson", "2.10.1", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fr.SourceDir == "" {
		t.Fatal("SourceDir empty")
	}
	found := false
	_ = filepath.WalkDir(fr.SourceDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(path, ".java") {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("no .java files found in unpacked source")
	}
}

func TestMavenFetcher_Manifest_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	f := &MavenFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.Manifest(context.Background(), "nope:nope", "0.0.1")
	if err == nil {
		t.Fatal("Manifest: expected error, got nil")
	}
}

func TestMavenFetcher_ParseCoordinate(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantGroup string
		wantArt   string
		wantErr   bool
	}{
		{"standard", "com.google.code.gson:gson", "com.google.code.gson", "gson", false},
		{"nested", "org.apache.logging.log4j:log4j-core", "org.apache.logging.log4j", "log4j-core", false},
		{"invalid no colon", "invalid", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, a, err := parseMavenCoordinate(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if g != tc.wantGroup || a != tc.wantArt {
				t.Errorf("got (%q, %q), want (%q, %q)", g, a, tc.wantGroup, tc.wantArt)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/ -run "TestMavenFetcher|TestMavenFetcher_ParseCoordinate" -v -count=1`
Expected: FAIL — types/functions not defined

- [ ] **Step 3: Write the Maven fetcher**

Create `pkg/vex/reachability/transitive/fetcher_maven.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// MavenFetcher implements Fetcher for the Maven Central ecosystem.
type MavenFetcher struct {
	// BaseURL is the Maven Central repository base. Defaults to https://repo1.maven.org/maven2.
	BaseURL    string
	HTTPClient *http.Client
	Cache      *Cache
}

func (f *MavenFetcher) Ecosystem() string { return "maven" }

func (f *MavenFetcher) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return http.DefaultClient
}

func (f *MavenFetcher) baseURL() string {
	if f.BaseURL != "" {
		return f.BaseURL
	}
	return "https://repo1.maven.org/maven2"
}

// pomProject is the subset of the POM XML schema we consume.
type pomProject struct {
	XMLName      xml.Name      `xml:"project"`
	Dependencies pomDeps       `xml:"dependencies"`
	SCM          pomSCM        `xml:"scm"`
}

type pomDeps struct {
	Dependency []pomDependency `xml:"dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version   string `xml:"version"`
	Scope     string `xml:"scope"`
}

type pomSCM struct {
	URL string `xml:"url"`
	Tag string `xml:"tag"`
}

// parseMavenCoordinate splits "groupId:artifactId" into its parts.
func parseMavenCoordinate(name string) (groupID, artifactID string, err error) {
	idx := strings.IndexByte(name, ':')
	if idx < 0 {
		return "", "", fmt.Errorf("invalid Maven coordinate %q: missing ':'", name)
	}
	return name[:idx], name[idx+1:], nil
}

// groupPath converts a Maven groupId to a URL path segment.
// "com.google.code.gson" → "com/google/code/gson"
func groupPath(groupID string) string {
	return strings.ReplaceAll(groupID, ".", "/")
}

// pomURL constructs the POM URL for a Maven artifact.
func (f *MavenFetcher) pomURL(groupID, artifactID, version string) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom",
		f.baseURL(), groupPath(groupID), artifactID, version, artifactID, version)
}

// sourcesJARURL constructs the sources JAR URL.
func (f *MavenFetcher) sourcesJARURL(groupID, artifactID, version string) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s-%s-sources.jar",
		f.baseURL(), groupPath(groupID), artifactID, version, artifactID, version)
}

// fetchPOM downloads and parses the POM XML.
func (f *MavenFetcher) fetchPOM(ctx context.Context, groupID, artifactID, version string) (*pomProject, error) {
	url := f.pomURL(groupID, artifactID, version)
	body, err := httpGetBytes(ctx, f.client(), url)
	if err != nil {
		return nil, err
	}
	var pom pomProject
	if err := xml.Unmarshal(body, &pom); err != nil {
		return nil, fmt.Errorf("parse POM %s: %w", url, err)
	}
	return &pom, nil
}

// Manifest fetches POM and returns runtime/compile dependencies.
func (f *MavenFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	groupID, artifactID, err := parseMavenCoordinate(name)
	if err != nil {
		return PackageManifest{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}
	pom, err := f.fetchPOM(ctx, groupID, artifactID, version)
	if err != nil {
		return PackageManifest{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}
	deps := make(map[string]string)
	for _, dep := range pom.Dependencies.Dependency {
		scope := dep.Scope
		if scope == "" {
			scope = "compile"
		}
		if scope != "compile" && scope != "runtime" {
			continue
		}
		key := dep.GroupID + ":" + dep.ArtifactID
		deps[key] = dep.Version
	}
	return PackageManifest{Dependencies: deps}, nil
}

// Fetch downloads the sources JAR for a Maven artifact. If the sources
// JAR is not available (404), it falls back to cloning from the SCM URL
// declared in the POM.
//
//nolint:gocyclo // download-verify-unpack pipeline with SCM fallback
func (f *MavenFetcher) Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error) {
	groupID, artifactID, err := parseMavenCoordinate(name)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}

	// Try sources JAR first.
	srcURL := f.sourcesJARURL(groupID, artifactID, version)
	body, srcErr := httpGetBytes(ctx, f.client(), srcURL)
	if srcErr == nil {
		return f.unpackSourcesJAR(body, name, expectedDigest)
	}

	// Sources JAR unavailable — fall back to SCM clone.
	pom, pomErr := f.fetchPOM(ctx, groupID, artifactID, version)
	if pomErr != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonTarballFetchFailed, pomErr)
	}
	if pom.SCM.URL == "" {
		return FetchResult{}, fmt.Errorf("%s: no sources JAR and no SCM URL in POM for %s", ReasonSourceUnavailable, name)
	}
	res, cloneErr := scmClone(ctx, pom.SCM.URL, version, f.Cache)
	if cloneErr != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonSourceUnavailable, cloneErr)
	}
	return FetchResult{SourceDir: res.SourceDir, Digest: res.Digest}, nil
}

// unpackSourcesJAR unpacks a sources JAR (which is a ZIP), caches and returns.
func (f *MavenFetcher) unpackSourcesJAR(body []byte, name string, expectedDigest *Digest) (FetchResult, error) {
	actual := Digest{Algorithm: "sha256", Hex: hashHex(body)}
	if expectedDigest != nil && !expectedDigest.IsZero() && !expectedDigest.Equals(actual) {
		return FetchResult{}, fmt.Errorf("%s: SBOM expected %s, got %s", ReasonDigestMismatch, expectedDigest, actual)
	}

	if f.Cache != nil {
		if p, ok := f.Cache.Get(actual.String()); ok {
			return FetchResult{SourceDir: p, Digest: actual}, nil
		}
	}

	tmp, err := os.MkdirTemp("", "maven-*")
	if err != nil {
		return FetchResult{}, err
	}
	if err := unzip(body, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return FetchResult{}, fmt.Errorf("unpack sources JAR %s: %w", name, err)
	}

	if f.Cache == nil {
		return FetchResult{SourceDir: tmp, Digest: actual}, nil
	}
	p, putErr := f.Cache.Put(actual.String(), tmp)
	_ = os.RemoveAll(tmp)
	if putErr != nil {
		return FetchResult{}, putErr
	}
	return FetchResult{SourceDir: p, Digest: actual}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/ -run "TestMavenFetcher" -v -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/transitive/fetcher_maven.go pkg/vex/reachability/transitive/fetcher_maven_test.go
git commit -m "feat(transitive): add Maven Central fetcher with sources JAR and SCM fallback"
```

---

### Task 7: NuGet Fetcher

**Files:**
- Create: `pkg/vex/reachability/transitive/fetcher_nuget.go`
- Create: `pkg/vex/reachability/transitive/fetcher_nuget_test.go`

- [ ] **Step 1: Write the failing tests for NuGetFetcher**

Create `pkg/vex/reachability/transitive/fetcher_nuget_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNuGetFetcher_Ecosystem(t *testing.T) {
	f := &NuGetFetcher{}
	if f.Ecosystem() != "nuget" {
		t.Errorf("Ecosystem() = %q, want %q", f.Ecosystem(), "nuget")
	}
}

func TestNuGetFetcher_Manifest_HappyPath(t *testing.T) {
	nuspec := `<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <dependencies>
      <group targetFramework="net6.0">
        <dependency id="Microsoft.Extensions.Logging" version="6.0.0" />
      </group>
      <group targetFramework="netstandard2.0">
        <dependency id="Newtonsoft.Json" version="13.0.1" />
      </group>
    </dependencies>
  </metadata>
</package>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/mylib.nuspec") {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(nuspec))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	f := &NuGetFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	m, err := f.Manifest(context.Background(), "MyLib", "1.0.0")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	// Union of all framework groups.
	if _, ok := m.Dependencies["Microsoft.Extensions.Logging"]; !ok {
		t.Error("Microsoft.Extensions.Logging not in dependencies")
	}
	if _, ok := m.Dependencies["Newtonsoft.Json"]; !ok {
		t.Error("Newtonsoft.Json not in dependencies")
	}
}

func TestNuGetFetcher_Fetch_WithSourceInNupkg(t *testing.T) {
	zipData := buildTestZip(t, "", map[string]string{
		"src/MyLib/Service.cs": `namespace MyLib { public class Service { public void Run() {} } }`,
		"MyLib.nuspec": `<?xml version="1.0"?><package><metadata>
		<repository type="git" url="https://github.com/example/mylib" /></metadata></package>`,
	})
	digest := sha256Hex(zipData)

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".nupkg"):
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(zipData)
		case strings.HasSuffix(r.URL.Path, ".nuspec"):
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0"?><package><metadata>
			<repository type="git" url="https://github.com/example/mylib" /></metadata></package>`))
		default:
			http.NotFound(w, r)
		}
	}))
	srvURL = srv.URL
	_ = srvURL
	_ = digest
	defer srv.Close()

	f := &NuGetFetcher{BaseURL: srv.URL, HTTPClient: srv.Client(), Cache: NewCache(t.TempDir())}
	fr, err := f.Fetch(context.Background(), "MyLib", "1.0.0", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fr.SourceDir == "" {
		t.Fatal("SourceDir empty")
	}
	found := false
	_ = filepath.WalkDir(fr.SourceDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(path, ".cs") {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("no .cs files found in unpacked source")
	}
}

func TestNuGetFetcher_Manifest_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	f := &NuGetFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.Manifest(context.Background(), "Nope", "0.0.1")
	if err == nil {
		t.Fatal("Manifest: expected error, got nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/ -run "TestNuGetFetcher" -v -count=1`
Expected: FAIL — types not defined

- [ ] **Step 3: Write the NuGet fetcher**

Create `pkg/vex/reachability/transitive/fetcher_nuget.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// NuGetFetcher implements Fetcher for the NuGet ecosystem.
type NuGetFetcher struct {
	// BaseURL is the NuGet API base. Defaults to https://api.nuget.org.
	BaseURL    string
	HTTPClient *http.Client
	Cache      *Cache
}

func (f *NuGetFetcher) Ecosystem() string { return "nuget" }

func (f *NuGetFetcher) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return http.DefaultClient
}

func (f *NuGetFetcher) baseURL() string {
	if f.BaseURL != "" {
		return f.BaseURL
	}
	return "https://api.nuget.org"
}

// nuspecPackage is the subset of the .nuspec XML schema we consume.
type nuspecPackage struct {
	XMLName  xml.Name      `xml:"package"`
	Metadata nuspecMetadata `xml:"metadata"`
}

type nuspecMetadata struct {
	Dependencies nuspecDependencies `xml:"dependencies"`
	Repository   nuspecRepository   `xml:"repository"`
}

type nuspecDependencies struct {
	Groups []nuspecGroup     `xml:"group"`
	Deps   []nuspecDep       `xml:"dependency"` // top-level (no framework group)
}

type nuspecGroup struct {
	TargetFramework string      `xml:"targetFramework,attr"`
	Deps            []nuspecDep `xml:"dependency"`
}

type nuspecDep struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

type nuspecRepository struct {
	Type   string `xml:"type,attr"`
	URL    string `xml:"url,attr"`
	Commit string `xml:"commit,attr"`
}

// nuspecURL constructs the nuspec URL for a NuGet package.
func (f *NuGetFetcher) nuspecURL(name, version string) string {
	lc := strings.ToLower(name)
	return fmt.Sprintf("%s/v3-flatcontainer/%s/%s/%s.nuspec",
		f.baseURL(), lc, version, lc)
}

// nupkgURL constructs the nupkg URL for a NuGet package.
func (f *NuGetFetcher) nupkgURL(name, version string) string {
	lc := strings.ToLower(name)
	return fmt.Sprintf("%s/v3-flatcontainer/%s/%s/%s.%s.nupkg",
		f.baseURL(), lc, version, lc, version)
}

// fetchNuspec downloads and parses the .nuspec metadata.
func (f *NuGetFetcher) fetchNuspec(ctx context.Context, name, version string) (*nuspecPackage, error) {
	url := f.nuspecURL(name, version)
	body, err := httpGetBytes(ctx, f.client(), url)
	if err != nil {
		return nil, err
	}
	var pkg nuspecPackage
	if err := xml.Unmarshal(body, &pkg); err != nil {
		return nil, fmt.Errorf("parse nuspec %s: %w", url, err)
	}
	return &pkg, nil
}

// Manifest fetches nuspec and returns dependencies (union of all framework groups).
func (f *NuGetFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	nuspec, err := f.fetchNuspec(ctx, name, version)
	if err != nil {
		return PackageManifest{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}
	deps := make(map[string]string)
	// Top-level dependencies (no framework group).
	for _, dep := range nuspec.Metadata.Dependencies.Deps {
		deps[dep.ID] = dep.Version
	}
	// Union of all framework groups.
	for _, group := range nuspec.Metadata.Dependencies.Groups {
		for _, dep := range group.Deps {
			if _, exists := deps[dep.ID]; !exists {
				deps[dep.ID] = dep.Version
			}
		}
	}
	return PackageManifest{Dependencies: deps}, nil
}

// Fetch downloads the nupkg and checks for source files. If no source
// is found, falls back to cloning from the repository URL in the nuspec.
//
//nolint:gocyclo // download-verify-unpack pipeline with SCM fallback
func (f *NuGetFetcher) Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error) {
	url := f.nupkgURL(name, version)
	body, err := httpGetBytes(ctx, f.client(), url)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonTarballFetchFailed, err)
	}

	actual := Digest{Algorithm: "sha256", Hex: hashHex(body)}
	if expectedDigest != nil && !expectedDigest.IsZero() && !expectedDigest.Equals(actual) {
		return FetchResult{}, fmt.Errorf("%s: SBOM expected %s, got %s", ReasonDigestMismatch, expectedDigest, actual)
	}

	// Unpack and check for .cs source files.
	tmp, err := os.MkdirTemp("", "nuget-*")
	if err != nil {
		return FetchResult{}, err
	}
	if err := unzip(body, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return FetchResult{}, fmt.Errorf("unpack nupkg %s: %w", name, err)
	}

	if hasSourceFiles(tmp, ".cs") {
		if f.Cache == nil {
			return FetchResult{SourceDir: tmp, Digest: actual}, nil
		}
		p, putErr := f.Cache.Put(actual.String(), tmp)
		_ = os.RemoveAll(tmp)
		if putErr != nil {
			return FetchResult{}, putErr
		}
		return FetchResult{SourceDir: p, Digest: actual}, nil
	}
	_ = os.RemoveAll(tmp)

	// No source in nupkg — fall back to SCM clone.
	nuspec, nuspecErr := f.fetchNuspec(ctx, name, version)
	if nuspecErr != nil || nuspec.Metadata.Repository.URL == "" {
		return FetchResult{}, fmt.Errorf("%s: no source in nupkg and no repository URL for %s", ReasonSourceUnavailable, name)
	}
	res, cloneErr := scmClone(ctx, nuspec.Metadata.Repository.URL, version, f.Cache)
	if cloneErr != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonSourceUnavailable, cloneErr)
	}
	return FetchResult{SourceDir: res.SourceDir, Digest: res.Digest}, nil
}

// hasSourceFiles checks if a directory contains files with the given extension,
// excluding obj/ and bin/ directories.
func hasSourceFiles(dir, ext string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "obj" || name == "bin" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ext) {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/ -run "TestNuGetFetcher" -v -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/transitive/fetcher_nuget.go pkg/vex/reachability/transitive/fetcher_nuget_test.go
git commit -m "feat(transitive): add NuGet fetcher with nupkg source detection and SCM fallback"
```

---

### Task 8: Wiring — LanguageFor, buildFetchers, buildTransitiveSummary

**Files:**
- Modify: `pkg/vex/reachability/transitive/language.go`
- Modify: `pkg/vex/transitive_wire.go`

- [ ] **Step 1: Write tests for the new LanguageFor cases**

These are lightweight tests that verify the factory returns the correct implementations. Add to the existing test file or create a new one. Since `LanguageFor` is in the `transitive` package (internal test), add inline tests:

Run the existing tests first to establish baseline:
`cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/ -run "TestLanguageFor" -v -count=1`

If no `TestLanguageFor` exists yet, verify via `LanguageFor("java")` and `LanguageFor("csharp")` calls after wiring.

- [ ] **Step 2: Add Java and C# to LanguageFor**

Modify `pkg/vex/reachability/transitive/language.go`:

Add imports:
```go
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/java"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/csharp"
```

Add cases to the switch in `LanguageFor`:
```go
	case "java":
		return java.New(), nil
	case "csharp", "c#", "cs":
		return csharp.New(), nil
```

- [ ] **Step 3: Add Maven and NuGet to buildFetchers**

Modify `pkg/vex/transitive_wire.go`:

Add cases to the switch in `buildFetchers`:
```go
	case "maven":
		return map[string]transitive.Fetcher{"maven": &transitive.MavenFetcher{Cache: cache}}
	case "nuget":
		return map[string]transitive.Fetcher{"nuget": &transitive.NuGetFetcher{Cache: cache}}
```

- [ ] **Step 4: Update buildTransitiveSummary for Maven PURL handling**

In `pkg/vex/transitive_wire.go`, modify `buildTransitiveSummary` to extract `groupId:artifactId` from Maven PURLs. The current code uses `components[i].Name` directly, but for Maven the SBOM name is just the artifactId while the fetcher needs `groupId:artifactId`.

Add a helper to extract the Maven coordinate from PURL:
```go
// mavenCoordinateFromPURL extracts "groupId:artifactId" from a Maven PURL.
// "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" → "org.apache.logging.log4j:log4j-core"
func mavenCoordinateFromPURL(purl string) string {
	// Strip "pkg:maven/" prefix and version
	trimmed := strings.TrimPrefix(purl, "pkg:maven/")
	if atIdx := strings.IndexByte(trimmed, '@'); atIdx >= 0 {
		trimmed = trimmed[:atIdx]
	}
	if qIdx := strings.IndexByte(trimmed, '?'); qIdx >= 0 {
		trimmed = trimmed[:qIdx]
	}
	// "org.apache.logging.log4j/log4j-core" → "org.apache.logging.log4j:log4j-core"
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 {
		return trimmed
	}
	return parts[0] + ":" + parts[1]
}
```

In `buildTransitiveSummary`, use Maven coordinate for Maven ecosystem:
```go
	for i := range components {
		if !strings.HasPrefix(components[i].PURL, prefix) {
			continue
		}
		name := components[i].Name
		if ecosystem == "maven" {
			name = mavenCoordinateFromPURL(components[i].PURL)
		}
		pkgs = append(pkgs, transitive.Package{
			Name:    name,
			Version: components[i].Version,
		})
		pkgNameSet[name] = true
	}
```

- [ ] **Step 5: Run full test suite to verify wiring compiles and existing tests pass**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go build ./... && go test ./pkg/vex/... -count=1`
Expected: PASS — builds clean, existing tests unaffected

- [ ] **Step 6: Commit**

```bash
git add pkg/vex/reachability/transitive/language.go pkg/vex/transitive_wire.go
git commit -m "feat(transitive): wire Java and C# into LanguageFor and buildFetchers"
```

---

### Task 9: Java Cross-Package Integration Test

**Files:**
- Create: `testdata/integration/java-realworld-cross-package/` (fixture)
- Create: `testdata/integration/java-realworld-cross-package-safe/` (fixture)
- Modify: `pkg/vex/reachability/transitive/integration_test.go`

- [ ] **Step 1: Create the Java reachable cross-package fixture**

Pick a well-known Maven package with a known vulnerability. Use `com.google.code.gson:gson` version `2.8.6` (prior to fix for CVE-2022-25647 — a deserialization vulnerability in `Gson.fromJson`).

Create `testdata/integration/java-realworld-cross-package/expected.json`:
```json
{
  "description": "Java cross-package transitive reachability: app calls Gson.fromJson through a direct dependency",
  "findings": [
    {
      "cve": "CVE-2022-25647",
      "component_purl": "pkg:maven/com.google.code.gson/gson@2.8.6",
      "expected_status": "affected",
      "expected_resolved_by": "transitive"
    }
  ]
}
```

Create `testdata/integration/java-realworld-cross-package/sbom.cdx.json`:
A minimal CycloneDX SBOM with the application component and gson as a dependency. Use the same structure as the existing Java integration test SBOMs but with a cross-package dependency chain.

Create `testdata/integration/java-realworld-cross-package/source/`:
Application Java source that imports and calls `Gson.fromJson()`:
```java
package com.example;
import com.google.gson.Gson;
public class App {
    public static void main(String[] args) {
        Gson gson = new Gson();
        String result = gson.fromJson("{}", String.class);
    }
}
```

Create `testdata/integration/java-realworld-cross-package/grype.json`:
Minimal Grype output referencing CVE-2022-25647 in gson.

- [ ] **Step 2: Create the Java NOT-reachable cross-package fixture**

Same setup but the application does NOT call any vulnerable Gson methods:

Create `testdata/integration/java-realworld-cross-package-safe/expected.json`:
```json
{
  "description": "Java cross-package transitive reachability: app imports gson but does not call vulnerable methods",
  "findings": [
    {
      "cve": "CVE-2022-25647",
      "component_purl": "pkg:maven/com.google.code.gson/gson@2.8.6",
      "expected_status": "not_affected",
      "expected_resolved_by": "transitive"
    }
  ]
}
```

Application source that imports but does not use vulnerable functions:
```java
package com.example;
public class App {
    public static void main(String[] args) {
        System.out.println("Hello, no gson used");
    }
}
```

- [ ] **Step 3: Add integration test cases**

Add to `pkg/vex/reachability/transitive/integration_test.go`:

In the `runIntegrationFixture` fetcher switch, add:
```go
	case "maven":
		fetcher = &MavenFetcher{Cache: cache}
	case "nuget":
		fetcher = &NuGetFetcher{Cache: cache}
```

Add test functions:
```go
func TestIntegration_Transitive_JavaReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "java-realworld-cross-package")
	runIntegrationFixture(t, dir, "java", "maven", "com.google.code.gson:gson", "2.8.6", true)
}

func TestIntegration_Transitive_JavaNotReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "java-realworld-cross-package-safe")
	runIntegrationFixture(t, dir, "java", "maven", "com.google.code.gson:gson", "2.8.6", false)
}
```

- [ ] **Step 4: Run integration tests**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/ -tags=integration -run "TestIntegration_Transitive_Java" -v -count=1 -timeout 120s`
Expected: PASS — downloads gson sources from Maven Central, analyzes call graph

- [ ] **Step 5: Commit**

```bash
git add testdata/integration/java-realworld-cross-package/ testdata/integration/java-realworld-cross-package-safe/ pkg/vex/reachability/transitive/integration_test.go
git commit -m "test(transitive): add Java cross-package integration tests"
```

---

### Task 10: C# Cross-Package Integration Test

**Files:**
- Create: `testdata/integration/csharp-realworld-cross-package/` (fixture)
- Create: `testdata/integration/csharp-realworld-cross-package-safe/` (fixture)
- Modify: `pkg/vex/reachability/transitive/integration_test.go`

- [ ] **Step 1: Create the C# reachable cross-package fixture**

Use `Newtonsoft.Json` version `13.0.1` (which has known vulnerabilities). The application calls `JsonConvert.DeserializeObject`.

Create fixture directories with `expected.json`, `sbom.cdx.json`, `source/`, and `grype.json` following the same pattern as the Java fixture but targeting the NuGet ecosystem.

Application source:
```csharp
using Newtonsoft.Json;
namespace MyApp
{
    public class App
    {
        public static void Main(string[] args)
        {
            var result = JsonConvert.DeserializeObject<string>("{}");
        }
    }
}
```

- [ ] **Step 2: Create the C# NOT-reachable cross-package fixture**

Application source that does not use Newtonsoft.Json:
```csharp
namespace MyApp
{
    public class App
    {
        public static void Main(string[] args)
        {
            System.Console.WriteLine("Hello, no json used");
        }
    }
}
```

- [ ] **Step 3: Add integration test functions**

Add to `integration_test.go`:
```go
func TestIntegration_Transitive_CSharpReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "csharp-realworld-cross-package")
	runIntegrationFixture(t, dir, "csharp", "nuget", "Newtonsoft.Json", "13.0.1", true)
}

func TestIntegration_Transitive_CSharpNotReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "csharp-realworld-cross-package-safe")
	runIntegrationFixture(t, dir, "csharp", "nuget", "Newtonsoft.Json", "13.0.1", false)
}
```

- [ ] **Step 4: Run integration tests**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go test ./pkg/vex/reachability/transitive/ -tags=integration -run "TestIntegration_Transitive_CSharp" -v -count=1 -timeout 120s`
Expected: PASS — clones Newtonsoft.Json from GitHub (SCM fallback), analyzes call graph

- [ ] **Step 5: Commit**

```bash
git add testdata/integration/csharp-realworld-cross-package/ testdata/integration/csharp-realworld-cross-package-safe/ pkg/vex/reachability/transitive/integration_test.go
git commit -m "test(transitive): add C# cross-package integration tests"
```

---

### Task 11: Quality Gates

**Files:** None — verification only

- [ ] **Step 1: Run full build**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && task build`
Expected: PASS — clean build

- [ ] **Step 2: Run lint**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && task lint`
Expected: PASS — fix any lint issues

- [ ] **Step 3: Run format**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && task fmt`
Expected: No changes

- [ ] **Step 4: Run full test suite**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && task test`
Expected: PASS — all existing and new tests pass

- [ ] **Step 5: Run quality gates**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && task quality`
Expected: PASS

- [ ] **Step 6: Final commit if any fixes were needed**

```bash
git add -A
git commit -m "fix(transitive): address lint and format issues for Java/C# support"
```
