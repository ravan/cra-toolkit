# Real-World Reachability Integration Test Suite — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove that the CRA toolkit's reachability analysis works consistently across all 8 languages using 48 real-world CVE fixtures, and replace the Rust placeholder with a production-grade tree-sitter analyzer.

**Architecture:** The Rust analyzer uses tree-sitter-rust for AST-based call graph construction with trait-impl dispatch resolution (analogous to Java's CHA). The 48 fixtures (6 per language) are minimal reproducers extracted from real OSS projects, each with provenance metadata. A build-tag-gated integration test runner validates all fixtures at 100% pass rate with per-language consistency reporting.

**Tech Stack:** Go, tree-sitter-rust, tree-sitter shared infrastructure (`pkg/vex/reachability/treesitter/`), CycloneDX SBOMs, Grype/Trivy scan output.

**Critical rule: Every test must pass 100%. If a test fails, fix the analyzer code — never adjust test expectations to match broken output.**

---

### Task 1: Rust Tree-Sitter Grammar Wiring

**Files:**
- Create: `pkg/vex/reachability/treesitter/grammars/rust/rust.go`
- Modify: `pkg/vex/reachability/treesitter/grammars/doc.go`
- Modify: `go.mod` (add `tree-sitter-rust` dependency)

- [ ] **Step 1: Add tree-sitter-rust grammar wrapper**

Create `pkg/vex/reachability/treesitter/grammars/rust/rust.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package rust provides the tree-sitter Rust grammar.
package rust

import (
	"unsafe"

	tree_sitter_rust "github.com/tree-sitter/tree-sitter-rust/bindings/go"
)

// Language returns the tree-sitter Rust language pointer.
func Language() unsafe.Pointer {
	return tree_sitter_rust.Language()
}
```

- [ ] **Step 2: Add Rust import to grammar anchor**

In `pkg/vex/reachability/treesitter/grammars/doc.go`, add the Rust import:

```go
import (
	_ "github.com/tree-sitter/go-tree-sitter"
	_ "github.com/tree-sitter/tree-sitter-c-sharp/bindings/go"
	_ "github.com/tree-sitter/tree-sitter-java/bindings/go"
	_ "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	_ "github.com/tree-sitter/tree-sitter-php/bindings/go"
	_ "github.com/tree-sitter/tree-sitter-python/bindings/go"
	_ "github.com/tree-sitter/tree-sitter-ruby/bindings/go"
	_ "github.com/tree-sitter/tree-sitter-rust/bindings/go"
	_ "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
)
```

- [ ] **Step 3: Add go dependency**

Run: `cd /Users/ravan/suse/repo/github/ravan/suse-cra-toolkit && go get github.com/tree-sitter/tree-sitter-rust/bindings/go && go mod tidy`

- [ ] **Step 4: Verify grammar compiles**

Run: `go build ./pkg/vex/reachability/treesitter/grammars/...`
Expected: Clean compile, no errors.

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/treesitter/grammars/rust/ pkg/vex/reachability/treesitter/grammars/doc.go go.mod go.sum
git commit -m "feat(rust): add tree-sitter-rust grammar wiring"
```

---

### Task 2: Rust Tree-Sitter Extractor — Symbol Extraction

**Files:**
- Create: `pkg/vex/reachability/treesitter/rust/extractor.go`
- Create: `pkg/vex/reachability/treesitter/rust/extractor_test.go`

This extractor implements `treesitter.LanguageExtractor` for Rust. It extracts functions, methods, structs, trait declarations, and `impl` blocks from Rust source ASTs.

- [ ] **Step 1: Write failing test for symbol extraction**

Create `pkg/vex/reachability/treesitter/rust/extractor_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust_test

import (
	"testing"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	rustgrammar "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/rust"
	rustextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/rust"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func parse(src string) (*tree_sitter.Tree, []byte) {
	source := []byte(src)
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(rustgrammar.Language())); err != nil {
		panic(err)
	}
	tree := parser.Parse(source, nil)
	return tree, source
}

func TestExtractSymbols_Functions(t *testing.T) {
	src := `
fn main() {
    println!("hello");
}

fn helper(x: i32) -> bool {
    x > 0
}
`
	tree, source := parse(src)
	defer tree.Close()

	ext := rustextractor.New()
	symbols, err := ext.ExtractSymbols("main.rs", source, tree)
	if err != nil {
		t.Fatal(err)
	}

	if len(symbols) < 2 {
		t.Fatalf("expected at least 2 symbols, got %d", len(symbols))
	}

	names := map[string]bool{}
	for _, s := range symbols {
		names[s.Name] = true
		if s.Kind != treesitter.SymbolFunction {
			t.Errorf("expected SymbolFunction for %s, got %v", s.Name, s.Kind)
		}
	}
	for _, want := range []string{"main", "helper"} {
		if !names[want] {
			t.Errorf("missing symbol %q", want)
		}
	}
}

func TestExtractSymbols_StructMethods(t *testing.T) {
	src := `
struct Server {
    port: u16,
}

impl Server {
    fn new(port: u16) -> Self {
        Server { port }
    }

    fn start(&self) {
        println!("listening on {}", self.port);
    }
}
`
	tree, source := parse(src)
	defer tree.Close()

	ext := rustextractor.New()
	symbols, err := ext.ExtractSymbols("server.rs", source, tree)
	if err != nil {
		t.Fatal(err)
	}

	names := map[string]bool{}
	for _, s := range symbols {
		names[s.Name] = true
	}
	for _, want := range []string{"Server", "new", "start"} {
		if !names[want] {
			t.Errorf("missing symbol %q", want)
		}
	}
}

func TestExtractSymbols_TraitImpl(t *testing.T) {
	src := `
trait Handler {
    fn handle(&self, req: Request) -> Response;
}

struct LogHandler;

impl Handler for LogHandler {
    fn handle(&self, req: Request) -> Response {
        println!("handling");
        Response::ok()
    }
}
`
	tree, source := parse(src)
	defer tree.Close()

	ext := rustextractor.New()
	symbols, err := ext.ExtractSymbols("handler.rs", source, tree)
	if err != nil {
		t.Fatal(err)
	}

	// Should have: Handler trait, LogHandler struct, Handler.handle (trait decl), LogHandler.handle (impl)
	names := map[string]bool{}
	for _, s := range symbols {
		names[s.QualifiedName] = true
	}
	if !names["Handler"] {
		t.Error("missing trait Handler")
	}
	if !names["LogHandler.handle"] {
		t.Error("missing LogHandler.handle")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestExtractSymbols ./pkg/vex/reachability/treesitter/rust/...`
Expected: Compile failure — `rustextractor` package does not exist yet.

- [ ] **Step 3: Implement Rust extractor — symbol extraction**

Create `pkg/vex/reachability/treesitter/rust/extractor.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package rust implements a tree-sitter-based AST extractor for Rust.
package rust

import (
	"path/filepath"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

// Extractor implements treesitter.LanguageExtractor for Rust.
type Extractor struct {
	// traitImpls maps trait name → []implementing type names.
	// Built during ExtractSymbols, used for dispatch edge resolution in ExtractCalls.
	traitImpls map[string][]string

	// methodToTypes maps method name → []types that define it.
	methodToTypes map[string][]string

	// paramTypes maps (type, method, param) → trait/type name.
	paramTypes map[paramKey]string

	// typeModule maps simple type name → module path prefix.
	typeModule map[string]string
}

type paramKey struct {
	typeName, method, param string
}

// TraitImplSnapshot holds cross-file trait dispatch state.
type TraitImplSnapshot struct {
	traitImpls map[string][]string
	paramTypes map[paramKey]string
	typeModule map[string]string
}

// New returns a new Rust extractor.
func New() *Extractor {
	return &Extractor{
		traitImpls:    make(map[string][]string),
		methodToTypes: make(map[string][]string),
		paramTypes:    make(map[paramKey]string),
		typeModule:    make(map[string]string),
	}
}

// SnapshotTraitImpls captures cross-file trait dispatch state.
func (e *Extractor) SnapshotTraitImpls() *TraitImplSnapshot {
	snap := &TraitImplSnapshot{
		traitImpls: make(map[string][]string, len(e.traitImpls)),
		paramTypes: make(map[paramKey]string, len(e.paramTypes)),
		typeModule: make(map[string]string, len(e.typeModule)),
	}
	for k, v := range e.traitImpls {
		cp := make([]string, len(v))
		copy(cp, v)
		snap.traitImpls[k] = cp
	}
	for k, v := range e.paramTypes {
		snap.paramTypes[k] = v
	}
	for k, v := range e.typeModule {
		snap.typeModule[k] = v
	}
	return snap
}

// RestoreTraitImpls merges a snapshot into the extractor's current state.
func (e *Extractor) RestoreTraitImpls(snap *TraitImplSnapshot) {
	for k, v := range snap.traitImpls {
		existing := e.traitImpls[k]
		seen := make(map[string]bool, len(existing))
		for _, s := range existing {
			seen[s] = true
		}
		for _, s := range v {
			if !seen[s] {
				e.traitImpls[k] = append(e.traitImpls[k], s)
			}
		}
	}
	for k, v := range snap.paramTypes {
		if _, ok := e.paramTypes[k]; !ok {
			e.paramTypes[k] = v
		}
	}
	for k, v := range snap.typeModule {
		if _, ok := e.typeModule[k]; !ok {
			e.typeModule[k] = v
		}
	}
}

// ExtractSymbols extracts all fn/struct/trait/impl definitions from a Rust file.
func (e *Extractor) ExtractSymbols(file string, source []byte, tree *tree_sitter.Tree) ([]*treesitter.Symbol, error) {
	e.traitImpls = make(map[string][]string)
	e.methodToTypes = make(map[string][]string)
	e.paramTypes = make(map[paramKey]string)
	e.typeModule = make(map[string]string)

	root := tree.RootNode()
	modName := moduleFromFile(file)
	var symbols []*treesitter.Symbol
	e.walkSymbols(root, source, file, modName, "", &symbols)
	return symbols, nil
}

func (e *Extractor) walkSymbols(node *tree_sitter.Node, source []byte, file, modName, currentType string, out *[]*treesitter.Symbol) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(uint(i))
		switch child.Type() {
		case "function_item":
			e.extractFunction(child, source, file, modName, currentType, out)
		case "struct_item":
			e.extractStruct(child, source, file, modName, out)
		case "trait_item":
			e.extractTrait(child, source, file, modName, out)
		case "impl_item":
			e.extractImpl(child, source, file, modName, out)
		case "enum_item":
			e.extractStruct(child, source, file, modName, out) // treat enum like struct
		case "mod_item":
			if nameNode := child.ChildByFieldName("name"); nameNode != nil {
				innerMod := modName + "::" + nodeText(nameNode, source)
				if body := child.ChildByFieldName("body"); body != nil {
					e.walkSymbols(body, source, file, innerMod, "", out)
				}
			}
		default:
			e.walkSymbols(child, source, file, modName, currentType, out)
		}
	}
}

func (e *Extractor) extractFunction(node *tree_sitter.Node, source []byte, file, modName, currentType string, out *[]*treesitter.Symbol) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	name := nodeText(nameNode, source)

	var qualName string
	kind := treesitter.SymbolFunction
	if currentType != "" {
		qualName = currentType + "." + name
		kind = treesitter.SymbolMethod
		e.methodToTypes[name] = appendUnique(e.methodToTypes[name], currentType)
	} else if modName != "" {
		qualName = modName + "." + name
	} else {
		qualName = name
	}

	sym := &treesitter.Symbol{
		ID:            treesitter.SymbolID(qualName),
		Name:          name,
		QualifiedName: qualName,
		Language:      "rust",
		File:          file,
		StartLine:     int(node.StartPosition().Row) + 1,
		EndLine:       int(node.EndPosition().Row) + 1,
		Kind:          kind,
	}
	*out = append(*out, sym)

	// Collect parameter types for trait dispatch.
	if params := node.ChildByFieldName("parameters"); params != nil {
		typeName := currentType
		if typeName == "" {
			typeName = modName
		}
		e.collectParamTypes(params, source, typeName, name)
	}
}

func (e *Extractor) extractStruct(node *tree_sitter.Node, source []byte, file, modName string, out *[]*treesitter.Symbol) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	name := nodeText(nameNode, source)
	qualName := name
	if modName != "" {
		qualName = modName + "." + name
	}

	e.typeModule[name] = modName

	sym := &treesitter.Symbol{
		ID:            treesitter.SymbolID(qualName),
		Name:          name,
		QualifiedName: qualName,
		Language:      "rust",
		File:          file,
		StartLine:     int(node.StartPosition().Row) + 1,
		EndLine:       int(node.EndPosition().Row) + 1,
		Kind:          treesitter.SymbolClass,
	}
	*out = append(*out, sym)
}

func (e *Extractor) extractTrait(node *tree_sitter.Node, source []byte, file, modName string, out *[]*treesitter.Symbol) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	name := nodeText(nameNode, source)
	qualName := name
	if modName != "" {
		qualName = modName + "." + name
	}

	e.typeModule[name] = modName

	sym := &treesitter.Symbol{
		ID:            treesitter.SymbolID(qualName),
		Name:          name,
		QualifiedName: qualName,
		Language:      "rust",
		File:          file,
		StartLine:     int(node.StartPosition().Row) + 1,
		EndLine:       int(node.EndPosition().Row) + 1,
		Kind:          treesitter.SymbolClass,
	}
	*out = append(*out, sym)

	// Extract trait method declarations (signatures).
	if body := child.ChildByFieldName("body"); body != nil {
		e.walkSymbols(body, source, file, modName, name, out)
	}
}

func (e *Extractor) extractImpl(node *tree_sitter.Node, source []byte, file, modName string, out *[]*treesitter.Symbol) {
	// impl [Trait for] Type { ... }
	typeName := ""
	traitName := ""

	// Parse the impl header to find type and optional trait.
	for i := 0; i < int(node.ChildCount()); i++ {
		c := node.Child(uint(i))
		switch c.Type() {
		case "type_identifier":
			typeName = nodeText(c, source)
		case "generic_type":
			// e.g., "Handler" in "impl Handler for LogHandler"
			if idNode := c.ChildByFieldName("type"); idNode != nil {
				typeName = nodeText(idNode, source)
			} else {
				typeName = nodeText(c, source)
			}
		case "scoped_type_identifier":
			typeName = nodeText(c, source)
		}
	}

	// Detect "impl Trait for Type" pattern.
	// In tree-sitter-rust: impl_item has optional "trait" field and "type" field.
	if traitNode := node.ChildByFieldName("trait"); traitNode != nil {
		traitName = nodeText(traitNode, source)
		if typeNode := node.ChildByFieldName("type"); typeNode != nil {
			typeName = nodeText(typeNode, source)
		}
	} else if typeNode := node.ChildByFieldName("type"); typeNode != nil {
		typeName = nodeText(typeNode, source)
	}

	if traitName != "" && typeName != "" {
		e.traitImpls[traitName] = appendUnique(e.traitImpls[traitName], typeName)
	}

	if typeName == "" {
		return
	}

	e.typeModule[typeName] = modName

	// Extract methods inside the impl block.
	if body := node.ChildByFieldName("body"); body != nil {
		e.walkSymbols(body, source, file, modName, typeName, out)
	}
}

func (e *Extractor) collectParamTypes(params *tree_sitter.Node, source []byte, typeName, methodName string) {
	for i := 0; i < int(params.ChildCount()); i++ {
		p := params.Child(uint(i))
		if p.Type() != "parameter" {
			continue
		}
		patNode := p.ChildByFieldName("pattern")
		typeNode := p.ChildByFieldName("type")
		if patNode == nil || typeNode == nil {
			continue
		}
		paramName := nodeText(patNode, source)
		paramType := nodeText(typeNode, source)
		// Strip references: &, &mut, Box<>, Arc<>, etc.
		paramType = stripRefWrappers(paramType)
		e.paramTypes[paramKey{typeName, methodName, paramName}] = paramType
	}
}

func stripRefWrappers(t string) string {
	t = strings.TrimPrefix(t, "&mut ")
	t = strings.TrimPrefix(t, "&")
	t = strings.TrimSpace(t)
	// Handle Box<T>, Arc<T>, Rc<T>
	for _, wrapper := range []string{"Box<", "Arc<", "Rc<", "Mutex<", "RwLock<"} {
		if strings.HasPrefix(t, wrapper) && strings.HasSuffix(t, ">") {
			t = t[len(wrapper) : len(t)-1]
			t = strings.TrimSpace(t)
		}
	}
	// Handle dyn Trait
	t = strings.TrimPrefix(t, "dyn ")
	t = strings.TrimSpace(t)
	return t
}

func moduleFromFile(file string) string {
	base := filepath.Base(file)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	if name == "mod" || name == "lib" || name == "main" {
		dir := filepath.Dir(file)
		if dir != "." && dir != "/" {
			return filepath.Base(dir)
		}
	}
	return name
}

func nodeText(node *tree_sitter.Node, source []byte) string {
	return string(source[node.StartByte():node.EndByte()])
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}
```

Note: The `extractTrait` function has a bug — it references `child` instead of `node`. Fix it:
```go
func (e *Extractor) extractTrait(node *tree_sitter.Node, ...) {
	// ...
	if body := node.ChildByFieldName("body"); body != nil {
		e.walkSymbols(body, source, file, modName, name, out)
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -run TestExtractSymbols ./pkg/vex/reachability/treesitter/rust/...`
Expected: All 3 tests PASS. If any tree-sitter AST node names are wrong (e.g., `function_item` vs `function_definition`), debug by printing the AST tree and fix the node type strings.

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/treesitter/rust/
git commit -m "feat(rust): implement tree-sitter symbol extraction for Rust"
```

---

### Task 3: Rust Extractor — Import Resolution

**Files:**
- Modify: `pkg/vex/reachability/treesitter/rust/extractor.go`
- Modify: `pkg/vex/reachability/treesitter/rust/extractor_test.go`

- [ ] **Step 1: Write failing test for import resolution**

Add to `extractor_test.go`:

```go
func TestResolveImports_UseStatements(t *testing.T) {
	src := `
use std::collections::HashMap;
use hyper::{Body, Request, Response};
use crate::handler::process;
use super::config;
`
	tree, source := parse(src)
	defer tree.Close()

	ext := rustextractor.New()
	imports, err := ext.ResolveImports("main.rs", source, tree, "/project")
	if err != nil {
		t.Fatal(err)
	}

	if len(imports) < 3 {
		t.Fatalf("expected at least 3 imports, got %d", len(imports))
	}

	modules := map[string]bool{}
	for _, imp := range imports {
		modules[imp.Module] = true
	}

	if !modules["std::collections::HashMap"] {
		t.Error("missing std::collections::HashMap import")
	}
	if !modules["hyper"] {
		t.Error("missing hyper import")
	}
}

func TestResolveImports_ExternCrate(t *testing.T) {
	src := `
extern crate serde;
use serde::Deserialize;
`
	tree, source := parse(src)
	defer tree.Close()

	ext := rustextractor.New()
	imports, err := ext.ResolveImports("lib.rs", source, tree, "/project")
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, imp := range imports {
		if imp.Module == "serde" || imp.Module == "serde::Deserialize" {
			found = true
		}
	}
	if !found {
		t.Error("missing serde import")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestResolveImports ./pkg/vex/reachability/treesitter/rust/...`
Expected: FAIL — `ResolveImports` returns empty or panics.

- [ ] **Step 3: Implement ResolveImports**

Add to `extractor.go`:

```go
// ResolveImports extracts use/extern crate statements from a Rust file.
func (e *Extractor) ResolveImports(file string, source []byte, tree *tree_sitter.Tree, projectRoot string) ([]treesitter.Import, error) {
	root := tree.RootNode()
	var imports []treesitter.Import

	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(uint(i))
		switch child.Type() {
		case "use_declaration":
			imps := e.extractUseDecl(child, source, file)
			imports = append(imports, imps...)
		case "extern_crate_declaration":
			if nameNode := child.ChildByFieldName("name"); nameNode != nil {
				name := nodeText(nameNode, source)
				imports = append(imports, treesitter.Import{
					Module: name,
					Alias:  name,
					File:   file,
					Line:   int(child.StartPosition().Row) + 1,
				})
			}
		}
	}

	return imports, nil
}

func (e *Extractor) extractUseDecl(node *tree_sitter.Node, source []byte, file string) []treesitter.Import {
	// use_declaration → "use" use_tree ";"
	// use_tree can be: path, path::*, path::{items}, path as alias
	var imports []treesitter.Import
	line := int(node.StartPosition().Row) + 1

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(uint(i))
		if child.Type() == "use_wildcard" || child.Type() == "use_as_clause" ||
			child.Type() == "use_list" || child.Type() == "scoped_use_list" ||
			child.Type() == "scoped_identifier" || child.Type() == "identifier" ||
			child.Type() == "use_declaration" {
			e.walkUseTree(child, source, file, line, "", &imports)
		}
	}

	// If no structured use tree found, try the argument field.
	if len(imports) == 0 {
		if arg := node.ChildByFieldName("argument"); arg != nil {
			e.walkUseTree(arg, source, file, line, "", &imports)
		}
	}

	return imports
}

func (e *Extractor) walkUseTree(node *tree_sitter.Node, source []byte, file string, line int, prefix string, out *[]treesitter.Import) {
	text := nodeText(node, source)

	switch node.Type() {
	case "identifier":
		fullPath := joinPath(prefix, text)
		*out = append(*out, treesitter.Import{
			Module:  fullPath,
			Alias:   text,
			File:    file,
			Line:    line,
		})

	case "scoped_identifier":
		fullPath := joinPath(prefix, text)
		parts := strings.Split(text, "::")
		alias := parts[len(parts)-1]
		*out = append(*out, treesitter.Import{
			Module:  fullPath,
			Alias:   alias,
			File:    file,
			Line:    line,
		})

	case "use_as_clause":
		// path as alias
		pathNode := node.ChildByFieldName("path")
		aliasNode := node.ChildByFieldName("alias")
		if pathNode != nil {
			fullPath := joinPath(prefix, nodeText(pathNode, source))
			alias := nodeText(pathNode, source)
			if aliasNode != nil {
				alias = nodeText(aliasNode, source)
			}
			parts := strings.Split(alias, "::")
			*out = append(*out, treesitter.Import{
				Module:  fullPath,
				Alias:   parts[len(parts)-1],
				File:    file,
				Line:    line,
			})
		}

	case "use_wildcard":
		// path::*
		if pathNode := node.ChildByFieldName("path"); pathNode != nil {
			*out = append(*out, treesitter.Import{
				Module:  joinPath(prefix, nodeText(pathNode, source)),
				Symbols: []string{"*"},
				File:    file,
				Line:    line,
			})
		}

	case "use_list", "scoped_use_list":
		// path::{A, B, C}
		pathPrefix := prefix
		if pathNode := node.ChildByFieldName("path"); pathNode != nil {
			pathPrefix = joinPath(prefix, nodeText(pathNode, source))
		}
		if list := node.ChildByFieldName("list"); list != nil {
			for j := 0; j < int(list.ChildCount()); j++ {
				item := list.Child(uint(j))
				if item.Type() != "," && item.Type() != "{" && item.Type() != "}" {
					e.walkUseTree(item, source, file, line, pathPrefix, out)
				}
			}
		}
		// Also handle direct children for simpler tree shapes.
		var symbols []string
		for j := 0; j < int(node.ChildCount()); j++ {
			c := node.Child(uint(j))
			if c.Type() == "identifier" || c.Type() == "scoped_identifier" {
				name := nodeText(c, source)
				symbols = append(symbols, name)
				fullPath := joinPath(pathPrefix, name)
				parts := strings.Split(name, "::")
				*out = append(*out, treesitter.Import{
					Module:  fullPath,
					Alias:   parts[len(parts)-1],
					File:    file,
					Line:    line,
				})
			} else if c.Type() == "use_as_clause" || c.Type() == "use_list" || c.Type() == "scoped_use_list" {
				e.walkUseTree(c, source, file, line, pathPrefix, out)
			}
		}
		// If we found a path and symbols in list, record as one import too.
		if len(symbols) > 0 && pathPrefix != "" {
			*out = append(*out, treesitter.Import{
				Module:  pathPrefix,
				Symbols: symbols,
				File:    file,
				Line:    line,
			})
		}

	default:
		// Recurse for unknown node types.
		for j := 0; j < int(node.ChildCount()); j++ {
			c := node.Child(uint(j))
			e.walkUseTree(c, source, file, line, prefix, out)
		}
	}
}

func joinPath(prefix, suffix string) string {
	if prefix == "" {
		return suffix
	}
	return prefix + "::" + suffix
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -run TestResolveImports ./pkg/vex/reachability/treesitter/rust/...`
Expected: PASS. Debug tree-sitter AST node names if needed — Rust use statements have complex tree structures.

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/treesitter/rust/
git commit -m "feat(rust): implement use/extern crate import resolution"
```

---

### Task 4: Rust Extractor — Call Extraction with Trait Dispatch

**Files:**
- Modify: `pkg/vex/reachability/treesitter/rust/extractor.go`
- Modify: `pkg/vex/reachability/treesitter/rust/extractor_test.go`

- [ ] **Step 1: Write failing tests for call extraction and trait dispatch**

Add to `extractor_test.go`:

```go
func TestExtractCalls_DirectCall(t *testing.T) {
	src := `
fn main() {
    helper(42);
}

fn helper(x: i32) -> bool {
    x > 0
}
`
	tree, source := parse(src)
	defer tree.Close()

	ext := rustextractor.New()
	_, _ = ext.ExtractSymbols("main.rs", source, tree)

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("main.rs", source, tree, scope)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, e := range edges {
		if strings.Contains(string(e.To), "helper") {
			found = true
			if e.Kind != treesitter.EdgeDirect {
				t.Errorf("expected EdgeDirect, got %v", e.Kind)
			}
		}
	}
	if !found {
		t.Error("missing call edge to helper()")
	}
}

func TestExtractCalls_MethodCall(t *testing.T) {
	src := `
struct Server;

impl Server {
    fn new() -> Self { Server }
    fn start(&self) {}
}

fn main() {
    let s = Server::new();
    s.start();
}
`
	tree, source := parse(src)
	defer tree.Close()

	ext := rustextractor.New()
	_, _ = ext.ExtractSymbols("main.rs", source, tree)

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("main.rs", source, tree, scope)
	if err != nil {
		t.Fatal(err)
	}

	targets := map[string]bool{}
	for _, e := range edges {
		targets[string(e.To)] = true
	}

	if !targets["Server.new"] && !targets["src.Server.new"] {
		t.Errorf("missing call edge to Server::new(), got targets: %v", targets)
	}
}

func TestExtractCalls_TraitDispatch(t *testing.T) {
	src := `
trait Handler {
    fn handle(&self);
}

struct LogHandler;

impl Handler for LogHandler {
    fn handle(&self) {
        println!("handling");
    }
}

fn run(h: &dyn Handler) {
    h.handle();
}
`
	tree, source := parse(src)
	defer tree.Close()

	ext := rustextractor.New()
	_, _ = ext.ExtractSymbols("handler.rs", source, tree)

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("handler.rs", source, tree, scope)
	if err != nil {
		t.Fatal(err)
	}

	// Should produce a dispatch edge from run → LogHandler.handle
	foundDispatch := false
	for _, e := range edges {
		if e.Kind == treesitter.EdgeDispatch && strings.Contains(string(e.To), "LogHandler.handle") {
			foundDispatch = true
		}
	}
	if !foundDispatch {
		t.Error("missing dispatch edge from run to LogHandler.handle via trait Handler")
		for _, e := range edges {
			t.Logf("  edge: %s -> %s (kind=%v)", e.From, e.To, e.Kind)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestExtractCalls ./pkg/vex/reachability/treesitter/rust/...`
Expected: FAIL — `ExtractCalls` not implemented.

- [ ] **Step 3: Implement ExtractCalls with trait dispatch**

Add to `extractor.go`:

```go
// ExtractCalls extracts all call edges from a Rust file.
func (e *Extractor) ExtractCalls(file string, source []byte, tree *tree_sitter.Tree, scope *treesitter.Scope) ([]treesitter.Edge, error) {
	root := tree.RootNode()
	var edges []treesitter.Edge
	e.collectCalls(root, source, file, "", "", scope, &edges)
	return edges, nil
}

func (e *Extractor) collectCalls(node *tree_sitter.Node, source []byte, file, currentType, currentFn string, scope *treesitter.Scope, out *[]treesitter.Edge) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(uint(i))
		switch child.Type() {
		case "function_item":
			fnName := ""
			if nameNode := child.ChildByFieldName("name"); nameNode != nil {
				fnName = nodeText(nameNode, source)
			}
			qualFn := fnName
			if currentType != "" {
				qualFn = currentType + "." + fnName
			}
			if body := child.ChildByFieldName("body"); body != nil {
				e.collectCalls(body, source, file, currentType, qualFn, scope, out)
			}

		case "impl_item":
			typeName := ""
			if typeNode := child.ChildByFieldName("type"); typeNode != nil {
				typeName = nodeText(typeNode, source)
			}
			if body := child.ChildByFieldName("body"); body != nil {
				e.collectCalls(body, source, file, typeName, currentFn, scope, out)
			}

		case "call_expression":
			e.processCallExpr(child, source, file, currentType, currentFn, scope, out)

		default:
			e.collectCalls(child, source, file, currentType, currentFn, scope, out)
		}
	}
}

func (e *Extractor) processCallExpr(node *tree_sitter.Node, source []byte, file, currentType, currentFn string, scope *treesitter.Scope, out *[]treesitter.Edge) {
	fnNode := node.ChildByFieldName("function")
	if fnNode == nil {
		return
	}

	callerID := treesitter.SymbolID(currentFn)
	if currentType != "" && !strings.Contains(currentFn, currentType) {
		callerID = treesitter.SymbolID(currentType + "." + currentFn)
	}

	line := int(node.StartPosition().Row) + 1

	switch fnNode.Type() {
	case "field_expression":
		// method call: obj.method(args)
		e.processMethodCall(fnNode, source, file, callerID, currentType, currentFn, line, scope, out)

	case "scoped_identifier":
		// Static call: Type::method(args) or module::function(args)
		text := nodeText(fnNode, source)
		parts := strings.Split(text, "::")
		methodName := parts[len(parts)-1]
		qualCallee := strings.ReplaceAll(text, "::", ".")

		*out = append(*out, treesitter.Edge{
			From:       callerID,
			To:         treesitter.SymbolID(qualCallee),
			Kind:       treesitter.EdgeDirect,
			Confidence: 1.0,
			File:       file,
			Line:       line,
		})
		_ = methodName

	case "identifier":
		// Direct function call: function(args)
		name := nodeText(fnNode, source)
		qualCallee := name
		// Try scope resolution.
		if resolved, ok := scope.Lookup(name); ok {
			qualCallee = resolved
		}

		*out = append(*out, treesitter.Edge{
			From:       callerID,
			To:         treesitter.SymbolID(qualCallee),
			Kind:       treesitter.EdgeDirect,
			Confidence: 1.0,
			File:       file,
			Line:       line,
		})

	default:
		// Fallback: use full text as callee.
		text := nodeText(fnNode, source)
		*out = append(*out, treesitter.Edge{
			From:       callerID,
			To:         treesitter.SymbolID(text),
			Kind:       treesitter.EdgeDirect,
			Confidence: 0.8,
			File:       file,
			Line:       line,
		})
	}
}

func (e *Extractor) processMethodCall(fnNode *tree_sitter.Node, source []byte, file string, callerID treesitter.SymbolID, currentType, currentFn string, line int, scope *treesitter.Scope, out *[]treesitter.Edge) {
	// field_expression: value.field
	objNode := fnNode.ChildByFieldName("value")
	fieldNode := fnNode.ChildByFieldName("field")
	if objNode == nil || fieldNode == nil {
		return
	}

	methodName := nodeText(fieldNode, source)
	objText := nodeText(objNode, source)

	// Try trait dispatch: check if the object's type is a known trait type.
	if currentType != "" && currentFn != "" {
		paramType, found := e.paramTypes[paramKey{currentType, currentFn, objText}]
		if !found {
			// Also try with qualified caller.
			baseFn := currentFn
			if idx := strings.LastIndex(currentFn, "."); idx >= 0 {
				baseFn = currentFn[idx+1:]
			}
			paramType, found = e.paramTypes[paramKey{currentType, baseFn, objText}]
		}
		if found {
			// Check if this type is a trait with known implementors.
			implementors, hasTrait := e.traitImpls[paramType]
			if hasTrait && len(implementors) > 0 {
				for _, impl := range implementors {
					*out = append(*out, treesitter.Edge{
						From:       callerID,
						To:         treesitter.SymbolID(impl + "." + methodName),
						Kind:       treesitter.EdgeDispatch,
						Confidence: 0.5,
						File:       file,
						Line:       line,
					})
				}
				return
			}
		}
	}

	// Direct method call (no trait dispatch).
	// Try to find the type of the object via scope.
	qualCallee := objText + "." + methodName
	if resolved, ok := scope.Lookup(objText); ok {
		qualCallee = resolved + "." + methodName
	}

	*out = append(*out, treesitter.Edge{
		From:       callerID,
		To:         treesitter.SymbolID(qualCallee),
		Kind:       treesitter.EdgeDirect,
		Confidence: 0.8,
		File:       file,
		Line:       line,
	})
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -run TestExtractCalls ./pkg/vex/reachability/treesitter/rust/...`
Expected: All 3 tests PASS. If trait dispatch edges aren't produced, debug the `paramTypes` population in `collectParamTypes` — ensure it recognizes `&dyn Handler` → `Handler`.

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/treesitter/rust/
git commit -m "feat(rust): implement call extraction with trait dispatch resolution"
```

---

### Task 5: Rust Extractor — Entry Point Detection

**Files:**
- Create: `pkg/vex/reachability/treesitter/rust/entrypoints.go`
- Create: `pkg/vex/reachability/treesitter/rust/entrypoints_test.go`

- [ ] **Step 1: Write failing test**

Create `pkg/vex/reachability/treesitter/rust/entrypoints_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	rustextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/rust"
)

func TestFindEntryPoints_Main(t *testing.T) {
	symbols := []*treesitter.Symbol{
		{ID: "src.main", Name: "main", Kind: treesitter.SymbolFunction, File: "src/main.rs"},
		{ID: "src.helper", Name: "helper", Kind: treesitter.SymbolFunction, File: "src/main.rs"},
	}

	ext := rustextractor.New()
	eps := ext.FindEntryPoints(symbols, "/project")
	if len(eps) != 1 {
		t.Fatalf("expected 1 entry point, got %d", len(eps))
	}
	if eps[0] != "src.main" {
		t.Errorf("expected src.main entry point, got %s", eps[0])
	}
}

func TestFindEntryPoints_TokioMain(t *testing.T) {
	// #[tokio::main] is an attribute on async fn main
	symbols := []*treesitter.Symbol{
		{ID: "src.main", Name: "main", Kind: treesitter.SymbolFunction, File: "src/main.rs"},
		{ID: "src.handler", Name: "handler", Kind: treesitter.SymbolMethod, File: "src/handler.rs"},
	}

	ext := rustextractor.New()
	eps := ext.FindEntryPoints(symbols, "/project")
	if len(eps) == 0 {
		t.Fatal("expected at least 1 entry point")
	}
}

func TestFindEntryPoints_ActixHandlers(t *testing.T) {
	symbols := []*treesitter.Symbol{
		{ID: "handlers.index", Name: "index", Kind: treesitter.SymbolFunction, File: "src/handlers.rs"},
		{ID: "handlers.submit", Name: "submit", Kind: treesitter.SymbolFunction, File: "src/handlers.rs"},
		{ID: "main.main", Name: "main", Kind: treesitter.SymbolFunction, File: "src/main.rs"},
	}

	ext := rustextractor.New()
	eps := ext.FindEntryPoints(symbols, "/project")
	// At minimum, main should be detected.
	found := false
	for _, ep := range eps {
		if ep == "main.main" {
			found = true
		}
	}
	if !found {
		t.Error("missing main entry point")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestFindEntryPoints ./pkg/vex/reachability/treesitter/rust/...`
Expected: FAIL.

- [ ] **Step 3: Implement entry point detection**

Create `pkg/vex/reachability/treesitter/rust/entrypoints.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust

import (
	"strings"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

// Rust entry point heuristics:
// - fn main() in main.rs or lib.rs
// - #[tokio::main], #[actix_web::main], #[async_std::main]
// - #[test] functions
// - Functions in files named main.rs
// - Exported lib functions (pub fn in lib.rs)

// FindEntryPoints identifies entry points in a Rust project.
func (e *Extractor) FindEntryPoints(symbols []*treesitter.Symbol, projectRoot string) []treesitter.SymbolID {
	var eps []treesitter.SymbolID
	seen := make(map[treesitter.SymbolID]bool)

	for _, sym := range symbols {
		if sym.Kind != treesitter.SymbolFunction && sym.Kind != treesitter.SymbolMethod {
			continue
		}

		isEntry := false

		// fn main()
		if sym.Name == "main" {
			isEntry = true
		}

		// Functions in main.rs or lib.rs are more likely entry points.
		if strings.HasSuffix(sym.File, "main.rs") && sym.Kind == treesitter.SymbolFunction {
			isEntry = true
		}

		// #[test] functions.
		if strings.HasPrefix(sym.Name, "test_") {
			isEntry = true
		}

		if isEntry && !seen[sym.ID] {
			eps = append(eps, sym.ID)
			seen[sym.ID] = true
		}
	}

	return eps
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -run TestFindEntryPoints ./pkg/vex/reachability/treesitter/rust/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/treesitter/rust/
git commit -m "feat(rust): implement entry point detection for Rust"
```

---

### Task 6: Rust Analyzer — Full Pipeline Integration

**Files:**
- Rewrite: `pkg/vex/reachability/rust/rust.go`
- Rewrite: `pkg/vex/reachability/rust/rust_test.go`

This task replaces the cargo-scan placeholder with the full tree-sitter pipeline, following the same 6-phase pattern as the Java analyzer.

- [ ] **Step 1: Write failing test for the full analyzer**

Rewrite `pkg/vex/reachability/rust/rust_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust_test

import (
	"context"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/rust"
)

var _ = (*rust.Analyzer)(nil) // ensure type exists

func TestAnalyzer_Language(t *testing.T) {
	a := rust.New()
	if lang := a.Language(); lang != "rust" {
		t.Fatalf("expected language 'rust', got %q", lang)
	}
}

func TestAnalyze_ReachableFixture(t *testing.T) {
	a := rust.New()

	finding := &formats.Finding{
		CVE:          "CVE-2023-26964",
		AffectedPURL: "pkg:cargo/hyper@0.14.10",
		AffectedName: "hyper",
		Language:     "rust",
		Symbols:      []string{"http2_only", "serve_connection"},
	}

	result, err := a.Analyze(context.Background(), "../../../../testdata/integration/rust-reachable/source", finding)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}

	if !result.Reachable {
		t.Errorf("expected Reachable=true, got false. Evidence: %s", result.Evidence)
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", result.Confidence)
	}
	if result.Evidence == "" {
		t.Error("expected non-empty evidence")
	}
	if len(result.Paths) == 0 {
		t.Error("expected non-empty call paths")
	}
}

func TestAnalyze_NotReachableFixture(t *testing.T) {
	a := rust.New()

	finding := &formats.Finding{
		CVE:          "CVE-2023-26964",
		AffectedPURL: "pkg:cargo/hyper@0.14.10",
		AffectedName: "hyper",
		Language:     "rust",
		Symbols:      []string{"http2_only", "serve_connection"},
	}

	result, err := a.Analyze(context.Background(), "../../../../testdata/integration/rust-not-reachable/source", finding)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}

	if result.Reachable {
		t.Errorf("expected Reachable=false, got true. Evidence: %s", result.Evidence)
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", result.Confidence)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestAnalyze ./pkg/vex/reachability/rust/...`
Expected: FAIL — the old analyzer returns low confidence placeholder results.

- [ ] **Step 3: Rewrite Rust analyzer with full tree-sitter pipeline**

Replace `pkg/vex/reachability/rust/rust.go` with:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package rust implements a tree-sitter-based reachability analyzer for Rust.
package rust

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	rustgrammar "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/rust"
	rustextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/rust"
)

// Compile-time interface conformance check.
var _ reachability.Analyzer = (*Analyzer)(nil)

// Analyzer performs Rust reachability analysis using tree-sitter AST parsing
// with trait-impl dispatch resolution.
type Analyzer struct{}

// New returns a new Rust tree-sitter reachability analyzer.
func New() *Analyzer { return &Analyzer{} }

// Language returns "rust".
func (a *Analyzer) Language() string { return "rust" }

// crateImportName maps crate names from Cargo.toml to the Rust import names
// used in source code. Only entries where the names differ are needed.
var crateImportName = map[string]string{
	"serde_json":  "serde_json",
	"serde_yaml":  "serde_yaml",
	"tokio":       "tokio",
	"actix-web":   "actix_web",
	"actix-rt":    "actix_rt",
	"async-std":   "async_std",
	"reqwest":     "reqwest",
	"hyper":       "hyper",
	"warp":        "warp",
	"axum":        "axum",
	"tower":       "tower",
	"tower-http":  "tower_http",
	"xml-rs":      "xml",
	"quick-xml":   "quick_xml",
	"rustls":      "rustls",
	"native-tls":  "native_tls",
	"openssl":     "openssl",
	"ring":        "ring",
}

// Analyze runs tree-sitter-based reachability analysis on a Rust project.
func (a *Analyzer) Analyze(ctx context.Context, sourceDir string, finding *formats.Finding) (reachability.Result, error) {
	// Phase 1: Collect all .rs files.
	var rustFiles []string
	_ = filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(path, ".rs") {
			rustFiles = append(rustFiles, path)
		}
		// Skip target/ directory.
		if d.IsDir() && d.Name() == "target" {
			return fs.SkipDir
		}
		return nil
	})

	if len(rustFiles) == 0 {
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceLow,
			Evidence:   "no .rs files found in source directory",
		}, nil
	}

	// Phase 2: Parse all files.
	parseResults, parseErrs := treesitter.ParseFiles(rustFiles, rustgrammar.Language())
	defer func() {
		for _, pr := range parseResults {
			pr.Tree.Close()
		}
	}()

	if len(parseResults) == 0 {
		errStrs := make([]string, len(parseErrs))
		for i, e := range parseErrs {
			errStrs[i] = e.Error()
		}
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceLow,
			Evidence:   fmt.Sprintf("failed to parse Rust files: %s", strings.Join(errStrs, "; ")),
		}, nil
	}

	// Phase 3: Extract symbols and imports.
	ext := rustextractor.New()

	type fileInfo struct {
		pr      treesitter.ParseResult
		symbols []*treesitter.Symbol
		imports []treesitter.Import
		scope   *treesitter.Scope
	}

	fileInfos := make([]fileInfo, 0, len(parseResults))
	for _, pr := range parseResults {
		symbols, _ := ext.ExtractSymbols(pr.File, pr.Source, pr.Tree)
		imports, _ := ext.ResolveImports(pr.File, pr.Source, pr.Tree, sourceDir)

		scope := treesitter.NewScope(nil)
		for _, imp := range imports {
			alias := imp.Alias
			if alias == "" {
				parts := strings.Split(imp.Module, "::")
				alias = parts[len(parts)-1]
			}
			scope.DefineImport(alias, imp.Module, imp.Symbols)
		}

		fileInfos = append(fileInfos, fileInfo{
			pr: pr, symbols: symbols, imports: imports, scope: scope,
		})
	}

	// Capture cross-file trait dispatch state.
	traitSnapshot := ext.SnapshotTraitImpls()

	// Phase 4: Build call graph.
	graph := treesitter.NewGraph()

	for _, fi := range fileInfos {
		for _, sym := range fi.symbols {
			graph.AddSymbol(sym)
		}
	}

	for _, fi := range fileInfos {
		// Re-extract symbols to reset per-file state.
		if _, err := ext.ExtractSymbols(fi.pr.File, fi.pr.Source, fi.pr.Tree); err != nil {
			continue
		}
		ext.RestoreTraitImpls(traitSnapshot)

		edges, _ := ext.ExtractCalls(fi.pr.File, fi.pr.Source, fi.pr.Tree, fi.scope)
		for _, e := range edges {
			graph.AddEdge(e)
		}
	}

	// Phase 5: Find entry points.
	allSymbols := graph.AllSymbols()
	entryPoints := ext.FindEntryPoints(allSymbols, sourceDir)

	if len(entryPoints) == 0 {
		// Fallback: treat all functions as entry points.
		for _, sym := range allSymbols {
			if sym.Kind == treesitter.SymbolFunction {
				entryPoints = append(entryPoints, sym.ID)
			}
		}
	}

	for _, ep := range entryPoints {
		if sym := graph.GetSymbol(ep); sym != nil {
			sym.IsEntryPoint = true
		}
	}

	// Phase 6: Build targets and run BFS.
	targets := buildTargetIDs(finding.AffectedName, finding.Symbols)

	for _, targetID := range targets {
		if graph.GetSymbol(targetID) == nil {
			graph.AddSymbol(&treesitter.Symbol{
				ID:         targetID,
				Name:       string(targetID),
				IsExternal: true,
				Language:   "rust",
			})
		}
	}

	var allPaths []reachability.CallPath
	var reachedSymbols []string

	cfg := treesitter.ReachabilityConfig{MaxDepth: 20, MaxPaths: 5}
	for _, targetID := range targets {
		paths := treesitter.FindReachablePaths(graph, entryPoints, targetID, cfg)
		if len(paths) > 0 {
			for _, p := range paths {
				allPaths = append(allPaths, reachability.CallPath(p))
			}
			reachedSymbols = append(reachedSymbols, string(targetID))
		}
	}

	if len(allPaths) == 0 {
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceHigh,
			Evidence: fmt.Sprintf("tree-sitter analysis found no call path from entry points to {%s} in %d Rust files (%d symbols, %d entry points)",
				strings.Join(finding.Symbols, ", "), len(rustFiles), graph.SymbolCount(), len(entryPoints)),
		}, nil
	}

	return reachability.Result{
		Reachable:  true,
		Confidence: formats.ConfidenceHigh,
		Evidence: fmt.Sprintf("tree-sitter call graph: %s is reachable via %d path(s): %s",
			strings.Join(reachedSymbols, ", "),
			len(allPaths),
			allPaths[0].String()),
		Symbols: reachedSymbols,
		Paths:   allPaths,
	}, nil
}

// buildTargetIDs creates target SymbolIDs from the finding's crate name and vulnerable symbols.
func buildTargetIDs(crateName string, symbols []string) []treesitter.SymbolID {
	importName := importNameForCrate(crateName)
	var targets []treesitter.SymbolID

	for _, sym := range symbols {
		// If symbol already has a qualifier (contains . or ::), use as-is.
		if strings.Contains(sym, ".") || strings.Contains(sym, "::") {
			normalized := strings.ReplaceAll(sym, "::", ".")
			targets = append(targets, treesitter.SymbolID(normalized))
			continue
		}
		// Prefix with crate import name.
		targets = append(targets, treesitter.SymbolID(importName+"."+sym))
		// Also try without prefix (in case it's a method name used directly).
		targets = append(targets, treesitter.SymbolID(sym))
	}

	return targets
}

// importNameForCrate maps a Cargo.toml crate name to its Rust import name.
func importNameForCrate(crateName string) string {
	if mapped, ok := crateImportName[crateName]; ok {
		return mapped
	}
	// Default: replace hyphens with underscores.
	return strings.ReplaceAll(crateName, "-", "_")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v ./pkg/vex/reachability/rust/...`
Expected: All tests PASS including `TestAnalyze_ReachableFixture` and `TestAnalyze_NotReachableFixture`. If any fail, debug by examining the call graph — add logging to see symbols, edges, and entry points. Fix the extractor code until both fixtures pass at high confidence.

- [ ] **Step 5: Run all existing tests to check for regressions**

Run: `go test -race -count=1 ./...`
Expected: No regressions. The only changes are additive (new Rust grammar + extractor + analyzer rewrite).

- [ ] **Step 6: Commit**

```bash
git add pkg/vex/reachability/rust/
git commit -m "feat(rust): replace cargo-scan placeholder with full tree-sitter analyzer

Implements production-grade Rust reachability analysis with:
- AST-based symbol extraction (functions, methods, structs, traits)
- Trait-impl dispatch resolution (analogous to Java CHA)
- Use statement / extern crate import resolution
- Entry point detection (main, tokio::main, test functions)
- Full call graph BFS from entry points to vulnerable symbols"
```

---

### Task 7: Rust Analyzer — Unsafe Scope and Feature Flag Tracking

**Files:**
- Create: `pkg/vex/reachability/treesitter/rust/unsafe_scope.go`
- Create: `pkg/vex/reachability/treesitter/rust/cargo.go`
- Modify: `pkg/vex/reachability/treesitter/rust/extractor.go`
- Modify: `pkg/vex/reachability/treesitter/rust/extractor_test.go`

- [ ] **Step 1: Write failing test for unsafe scope tracking**

Add to `extractor_test.go`:

```go
func TestExtractSymbols_UnsafeBlock(t *testing.T) {
	src := `
fn safe_wrapper() {
    let x = 42;
    unsafe {
        dangerous_call(x);
    }
}

unsafe fn dangerous_call(x: i32) {}
`
	tree, source := parse(src)
	defer tree.Close()

	ext := rustextractor.New()
	symbols, err := ext.ExtractSymbols("main.rs", source, tree)
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range symbols {
		if s.Name == "dangerous_call" {
			// The function itself is unsafe — should still be extractable.
			if s.Kind != treesitter.SymbolFunction {
				t.Errorf("expected SymbolFunction for dangerous_call")
			}
		}
	}
}
```

- [ ] **Step 2: Write failing test for cfg feature detection**

Add to `extractor_test.go`:

```go
func TestExtractSymbols_CfgFeatureGated(t *testing.T) {
	src := `
#[cfg(feature = "xml")]
fn parse_xml(data: &str) {
    xml::parse(data);
}

fn always_available() {}
`
	tree, source := parse(src)
	defer tree.Close()

	ext := rustextractor.New()
	symbols, err := ext.ExtractSymbols("main.rs", source, tree)
	if err != nil {
		t.Fatal(err)
	}

	// Both functions should be extracted — cfg filtering happens at the analyzer level.
	names := map[string]bool{}
	for _, s := range symbols {
		names[s.Name] = true
	}
	if !names["parse_xml"] {
		t.Error("missing cfg-gated function parse_xml")
	}
	if !names["always_available"] {
		t.Error("missing always_available")
	}
}
```

- [ ] **Step 3: Implement cargo.go for Cargo.toml feature parsing**

Create `pkg/vex/reachability/treesitter/rust/cargo.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// CargoMetadata holds parsed Cargo.toml data relevant to reachability.
type CargoMetadata struct {
	Features       map[string][]string // feature → dependencies
	DefaultFeatures []string           // features enabled by default
	Dependencies   map[string]CargoDep // dependency → config
}

// CargoDep holds a Cargo dependency entry.
type CargoDep struct {
	Version  string   `toml:"version"`
	Features []string `toml:"features"`
	Optional bool     `toml:"optional"`
}

type cargoToml struct {
	Features     map[string][]string    `toml:"features"`
	Dependencies map[string]interface{} `toml:"dependencies"`
}

// ParseCargoToml reads and parses a Cargo.toml file for feature information.
func ParseCargoToml(sourceDir string) (*CargoMetadata, error) {
	path := filepath.Join(sourceDir, "Cargo.toml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ct cargoToml
	if err := toml.Unmarshal(data, &ct); err != nil {
		return nil, err
	}

	meta := &CargoMetadata{
		Features:     ct.Features,
		Dependencies: make(map[string]CargoDep),
	}

	if defaults, ok := ct.Features["default"]; ok {
		meta.DefaultFeatures = defaults
	}

	for name, val := range ct.Dependencies {
		switch v := val.(type) {
		case string:
			meta.Dependencies[name] = CargoDep{Version: v}
		case map[string]interface{}:
			dep := CargoDep{}
			if ver, ok := v["version"].(string); ok {
				dep.Version = ver
			}
			if opt, ok := v["optional"].(bool); ok {
				dep.Optional = opt
			}
			if feats, ok := v["features"].([]interface{}); ok {
				for _, f := range feats {
					if fs, ok := f.(string); ok {
						dep.Features = append(dep.Features, fs)
					}
				}
			}
			meta.Dependencies[name] = dep
		}
	}

	return meta, nil
}

// IsFeatureEnabled checks if a feature is enabled (in default features list).
func (m *CargoMetadata) IsFeatureEnabled(feature string) bool {
	for _, f := range m.DefaultFeatures {
		if f == feature {
			return true
		}
	}
	return false
}

// IsDependencyEnabled checks if a dependency is included (not optional, or
// optional but enabled via a default feature).
func (m *CargoMetadata) IsDependencyEnabled(name string) bool {
	dep, ok := m.Dependencies[name]
	if !ok {
		return false
	}
	if !dep.Optional {
		return true
	}
	// Optional dep — check if enabled via features.
	normalized := strings.ReplaceAll(name, "-", "_")
	return m.IsFeatureEnabled(name) || m.IsFeatureEnabled(normalized)
}
```

Note: This requires adding `github.com/BurntSushi/toml` to go.mod. Run: `go get github.com/BurntSushi/toml`

- [ ] **Step 4: Run all tests**

Run: `go test -v ./pkg/vex/reachability/treesitter/rust/... && go test -v ./pkg/vex/reachability/rust/...`
Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/treesitter/rust/ go.mod go.sum
git commit -m "feat(rust): add unsafe scope tracking and Cargo.toml feature parsing"
```

---

### Task 8: Wire Rust Analyzer into analyzerMethod

**Files:**
- Modify: `pkg/vex/reachability_filter.go`

The `analyzerMethod` function currently returns `"tree_sitter"` for all non-Go non-generic analyzers, which is correct for Rust. But verify the Rust analyzer is properly wired in `vex.go` (it already is — `case "rust": analyzers["rust"] = rust.New()`). This task ensures the analyzer method string is correct.

- [ ] **Step 1: Verify analyzerMethod returns "tree_sitter" for Rust**

Read `pkg/vex/reachability_filter.go:98-107`. The default case returns `"tree_sitter"` which covers Rust. No change needed.

- [ ] **Step 2: Run full test suite**

Run: `go test -race -count=1 ./...`
Expected: All PASS, no regressions.

- [ ] **Step 3: Commit (only if changes were needed)**

No commit needed if no changes. Move on.

---

### Task 9: Create Go Real-World Fixtures

**Files:**
- Create: `testdata/integration/go-realworld-direct-call/` (expected.json, sbom.cdx.json, grype.json, source/)
- Create: `testdata/integration/go-realworld-transitive/`
- Create: `testdata/integration/go-realworld-dispatch/`
- Create: `testdata/integration/go-realworld-imported-unused/`
- Create: `testdata/integration/go-realworld-guarded-path/`
- Create: `testdata/integration/go-realworld-dev-only/`

Each fixture follows the exact same JSON structure as existing fixtures in `testdata/integration/`. The source code is a minimal reproducer extracted from a real OSS project at the vulnerable commit.

**Important:** For Go fixtures, the existing test infrastructure uses `govulncheck`. Since govulncheck requires building the Go module, the `source/` directory must contain a valid `go.mod` and `go.sum`. However, `govulncheck` may not be available in CI, so the Go real-world fixtures should use the generic fallback pattern (grype scan + source code grep via `rg`) rather than relying on govulncheck. Actually, looking at the existing Go integration tests — they use govulncheck. For consistency, do the same.

For all 6 fixtures, the `expected.json` must include the `provenance` block as specified in the design spec.

- [ ] **Step 1: Create go-realworld-direct-call fixture**

This fixture tests CVE-2022-32149 in `golang.org/x/text` — direct call to `language.Parse()`.

Create `testdata/integration/go-realworld-direct-call/expected.json`:
```json
{
  "description": "CLI tool directly calling language.Parse() from golang.org/x/text v0.3.7, the vulnerable function for CVE-2022-32149 (ReDoS via Accept-Language header parsing).",
  "provenance": {
    "source_project": "golang/text",
    "source_url": "https://github.com/golang/text",
    "commit": "v0.3.7",
    "cve": "CVE-2022-32149",
    "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-32149",
    "language": "go",
    "pattern": "direct_call",
    "ground_truth_notes": "main.go directly calls language.Parse() which is the vulnerable function for this CVE."
  },
  "findings": [
    {
      "cve": "CVE-2022-32149",
      "component_purl": "pkg:golang/golang.org/x/text@v0.3.7",
      "expected_status": "affected"
    }
  ]
}
```

Create `testdata/integration/go-realworld-direct-call/source/go.mod`:
```
module github.com/example/go-realworld-direct-call

go 1.21

require golang.org/x/text v0.3.7
```

Create `testdata/integration/go-realworld-direct-call/source/main.go`:
```go
package main

import (
	"fmt"
	"os"

	"golang.org/x/text/language"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: tool <accept-language>")
		os.Exit(1)
	}
	// Direct call to the vulnerable function.
	tag, err := language.Parse(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Parsed language:", tag)
}
```

Generate `go.sum` by running: `cd testdata/integration/go-realworld-direct-call/source && go mod tidy`

Create `testdata/integration/go-realworld-direct-call/sbom.cdx.json` — CycloneDX SBOM with golang.org/x/text@v0.3.7 as a component. Follow exact format from existing `go-reachable/sbom.cdx.json`.

Create `testdata/integration/go-realworld-direct-call/grype.json` — Grype scan reporting CVE-2022-32149 for golang.org/x/text@v0.3.7 with `vulnerableFunctions: ["Parse"]`. Follow exact format from existing `go-reachable/grype.json`.

- [ ] **Step 2: Create go-realworld-transitive fixture**

CVE-2022-41723 — `golang.org/x/net/http2` HPACK decoder. App creates HTTP server that transitively uses the vulnerable HPACK decoder through `net/http` → `http2` → `hpack`.

Create source with an HTTP server that uses `http.ListenAndServeTLS()`, which enables HTTP/2 and exposes the vulnerable HPACK decoder path.

- [ ] **Step 3: Create go-realworld-dispatch fixture**

CVE-2024-24790 — `net/netip` `Addr.Is4In6()` called through `net.Conn` interface. Source calls `conn.RemoteAddr()` and uses the result through `netip.Addr` interface method.

- [ ] **Step 4: Create go-realworld-imported-unused fixture**

CVE-2023-39325 — `golang.org/x/net/http2` imported in go.mod but only gRPC is used (through `google.golang.org/grpc`), never the HTTP/2 server handler directly.

- [ ] **Step 5: Create go-realworld-guarded-path fixture**

CVE-2022-27664 — `golang.org/x/net/http2` behind `//go:build integration` build tag that's not active in production builds.

- [ ] **Step 6: Create go-realworld-dev-only fixture**

CVE-2023-44487 — `golang.org/x/net` only used in `_test.go` file, not in any production code.

- [ ] **Step 7: Validate all fixtures have valid JSON**

Run: `for f in testdata/integration/go-realworld-*/expected.json; do python3 -c "import json; json.load(open('$f'))" && echo "$f OK"; done`
Expected: All 6 print OK.

- [ ] **Step 8: Commit**

```bash
git add testdata/integration/go-realworld-*/
git commit -m "test: add 6 real-world Go CVE fixtures for reachability integration tests"
```

---

### Task 10: Create Python Real-World Fixtures

**Files:**
- Create: `testdata/integration/python-realworld-direct-call/` through `python-realworld-dev-only/`

Same structure as Task 9 but for Python. Use `trivy.json` for scans (consistent with existing Python fixtures).

CVEs:
1. **direct-call**: CVE-2020-1747 — PyYAML `yaml.load()` without SafeLoader
2. **transitive**: CVE-2019-19844 — Django password reset via view → form → model chain
3. **dispatch**: CVE-2021-32052 — Django URLValidator via form field validation chain
4. **imported-unused**: CVE-2022-42969 — `py` library imported but never called
5. **guarded-path**: CVE-2021-23336 — `urllib.parse` behind LEGACY_QUERY_PARSING=False flag
6. **dev-only**: CVE-2023-43804 — `urllib3` only in test HTTP client

- [ ] **Step 1: Create all 6 Python fixtures**

For each fixture, create:
- `expected.json` with provenance block
- `sbom.cdx.json` with the vulnerable PyPI component
- `trivy.json` with the CVE finding and `vulnerableFunctions` list
- `source/` with `requirements.txt` and minimal Python files

Follow the exact structure from `testdata/integration/python-treesitter-reachable/`.

- [ ] **Step 2: Validate JSON**

Run: `for f in testdata/integration/python-realworld-*/expected.json; do python3 -c "import json; json.load(open('$f'))" && echo "$f OK"; done`

- [ ] **Step 3: Commit**

```bash
git add testdata/integration/python-realworld-*/
git commit -m "test: add 6 real-world Python CVE fixtures for reachability integration tests"
```

---

### Task 11: Create JavaScript Real-World Fixtures

**Files:**
- Create: `testdata/integration/javascript-realworld-direct-call/` through `javascript-realworld-dev-only/`

CVEs:
1. **direct-call**: CVE-2021-23337 — lodash `template()` in SSR renderer
2. **transitive**: CVE-2022-46175 — `json5` prototype pollution through config loader
3. **dispatch**: CVE-2019-10744 — lodash `defaultsDeep` via middleware callback chain
4. **imported-unused**: CVE-2021-3807 — `ansi-regex` in package.json, only chalk uses it
5. **guarded-path**: CVE-2022-25883 — `semver` behind `ENABLE_VERSION_CHECK` env var
6. **dev-only**: CVE-2023-26136 — `tough-cookie` only in test suite

- [ ] **Step 1: Create all 6 JavaScript fixtures**
- [ ] **Step 2: Validate JSON**
- [ ] **Step 3: Commit**

```bash
git add testdata/integration/javascript-realworld-*/
git commit -m "test: add 6 real-world JavaScript CVE fixtures for reachability integration tests"
```

---

### Task 12: Create Java Real-World Fixtures

**Files:**
- Create: `testdata/integration/java-realworld-direct-call/` through `java-realworld-dev-only/`

CVEs:
1. **direct-call**: CVE-2022-1471 — SnakeYAML `Yaml.load()` in config reader
2. **transitive**: CVE-2021-44228 — Log4Shell via logger → appender → JNDI lookup
3. **dispatch**: CVE-2022-22965 — Spring4Shell via WebDataBinder → BeanWrapper interface
4. **imported-unused**: CVE-2023-20861 — Spring Expression Language, SpEL never invoked
5. **guarded-path**: CVE-2022-22976 — Spring Security behind security.enabled=false
6. **dev-only**: CVE-2023-34034 — Spring Security only in integration test config

- [ ] **Step 1: Create all 6 Java fixtures**
- [ ] **Step 2: Validate JSON**
- [ ] **Step 3: Commit**

```bash
git add testdata/integration/java-realworld-*/
git commit -m "test: add 6 real-world Java CVE fixtures for reachability integration tests"
```

---

### Task 13: Create C# Real-World Fixtures

**Files:**
- Create: `testdata/integration/csharp-realworld-direct-call/` through `csharp-realworld-dev-only/`

CVEs:
1. **direct-call**: CVE-2023-29331 — .NET X509Certificate2 private key extraction
2. **transitive**: CVE-2023-33170 — ASP.NET Core auth bypass via middleware pipeline
3. **dispatch**: CVE-2022-34716 — .NET SignedXml via virtual XmlResolver override
4. **imported-unused**: CVE-2023-36049 — .NET Uri imported but never called
5. **guarded-path**: CVE-2023-36799 — .NET X509Chain behind #if DEBUG
6. **dev-only**: CVE-2023-38178 — .NET Kestrel HTTP/2 only in load test project

- [ ] **Step 1: Create all 6 C# fixtures**
- [ ] **Step 2: Validate JSON**
- [ ] **Step 3: Commit**

```bash
git add testdata/integration/csharp-realworld-*/
git commit -m "test: add 6 real-world C# CVE fixtures for reachability integration tests"
```

---

### Task 14: Create PHP Real-World Fixtures

**Files:**
- Create: `testdata/integration/php-realworld-direct-call/` through `php-realworld-dev-only/`

CVEs:
1. **direct-call**: CVE-2021-43608 — Symfony Serializer code execution
2. **transitive**: CVE-2022-24894 — Symfony HTTP cache via kernel → cache → response
3. **dispatch**: CVE-2023-46734 — Twig XSS via late static binding filter chain
4. **imported-unused**: CVE-2022-31091 — Guzzle imported but file_get_contents used
5. **guarded-path**: CVE-2023-43655 — Composer behind APP_ENV=production
6. **dev-only**: CVE-2022-24775 — guzzlehttp/psr7 only in PHPUnit

- [ ] **Step 1: Create all 6 PHP fixtures**
- [ ] **Step 2: Validate JSON**
- [ ] **Step 3: Commit**

```bash
git add testdata/integration/php-realworld-*/
git commit -m "test: add 6 real-world PHP CVE fixtures for reachability integration tests"
```

---

### Task 15: Create Ruby Real-World Fixtures

**Files:**
- Create: `testdata/integration/ruby-realworld-direct-call/` through `ruby-realworld-dev-only/`

CVEs:
1. **direct-call**: CVE-2022-23633 — Action Pack response body leak in streaming
2. **transitive**: CVE-2022-32224 — ActiveRecord via model → serializer → YAML
3. **dispatch**: CVE-2023-22795 — Action Dispatch via method_missing through middleware
4. **imported-unused**: CVE-2022-44570 — Rack in Gemfile but custom server used
5. **guarded-path**: CVE-2023-22796 — Active Support behind config.use_legacy_time_parsing
6. **dev-only**: CVE-2023-28362 — Action Text only in RSpec feature tests

- [ ] **Step 1: Create all 6 Ruby fixtures**
- [ ] **Step 2: Validate JSON**
- [ ] **Step 3: Commit**

```bash
git add testdata/integration/ruby-realworld-*/
git commit -m "test: add 6 real-world Ruby CVE fixtures for reachability integration tests"
```

---

### Task 16: Create Rust Real-World Fixtures

**Files:**
- Create: `testdata/integration/rust-realworld-direct-call/` through `rust-realworld-dev-only/`

CVEs:
1. **direct-call**: CVE-2024-24576 — `std::process::Command` arg injection in CLI wrapper
2. **transitive**: CVE-2023-38497 — Cargo build script → download → extract chain
3. **dispatch**: CVE-2022-36114 — Cargo tar extraction via Read trait impl on decompressor
4. **imported-unused**: CVE-2024-32650 — `rustls` in Cargo.toml but native-tls used
5. **guarded-path**: CVE-2023-34411 — `xml-rs` behind `#[cfg(feature = "xml")]` not enabled
6. **dev-only**: CVE-2022-46176 — Cargo SSH only in `[dev-dependencies]`

- [ ] **Step 1: Create all 6 Rust fixtures**

Each fixture needs:
- `expected.json` with provenance
- `sbom.cdx.json` with cargo component
- `grype.json` with the CVE finding
- `source/` with `Cargo.toml` and Rust source files (no Cargo.lock needed for tree-sitter analysis)

- [ ] **Step 2: Validate JSON**
- [ ] **Step 3: Commit**

```bash
git add testdata/integration/rust-realworld-*/
git commit -m "test: add 6 real-world Rust CVE fixtures for reachability integration tests"
```

---

### Task 17: Build-Tag-Gated Integration Test Runner

**Files:**
- Create: `pkg/vex/realworld_integration_test.go`

This is the core test runner that validates all 48 fixtures with consistency reporting.

- [ ] **Step 1: Write the test runner**

Create `pkg/vex/realworld_integration_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package vex_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex"
)

// realworldExpectedJSON extends expectedJSON with provenance and richer expectations.
type realworldExpectedJSON struct {
	Description string `json:"description"`
	Provenance  struct {
		SourceProject    string `json:"source_project"`
		SourceURL        string `json:"source_url"`
		Commit           string `json:"commit"`
		CVE              string `json:"cve"`
		CVEURL           string `json:"cve_url"`
		Language         string `json:"language"`
		Pattern          string `json:"pattern"`
		GroundTruthNotes string `json:"ground_truth_notes"`
	} `json:"provenance"`
	Findings []struct {
		CVE                 string   `json:"cve"`
		ComponentPURL       string   `json:"component_purl"`
		ExpectedStatus      string   `json:"expected_status"`
		ExpectedJustification string `json:"expected_justification,omitempty"`
		ExpectedResolvedBy  string   `json:"expected_resolved_by"`
		ExpectedCallDepthMin int     `json:"expected_call_depth_min,omitempty"`
		ExpectedSymbols     []string `json:"expected_symbols,omitempty"`
	} `json:"findings"`
}

// languageStats tracks pass/fail counts per language.
type languageStats struct {
	total        int
	pass         int
	fail         int
	reachableOK  int
	reachableExp int
	notReachOK   int
	notReachExp  int
}

func TestIntegration_RealWorldReachability(t *testing.T) {
	base := filepath.Join(fixtureBase)

	// Discover all realworld fixtures.
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("failed to read fixture directory: %v", err)
	}

	type fixture struct {
		name     string
		dir      string
		language string
		pattern  string
	}

	var fixtures []fixture
	for _, e := range entries {
		if !e.IsDir() || !strings.Contains(e.Name(), "-realworld-") {
			continue
		}
		parts := strings.SplitN(e.Name(), "-realworld-", 2)
		if len(parts) != 2 {
			continue
		}
		fixtures = append(fixtures, fixture{
			name:     e.Name(),
			dir:      filepath.Join(base, e.Name()),
			language: parts[0],
			pattern:  parts[1],
		})
	}

	if len(fixtures) == 0 {
		t.Fatal("no realworld fixtures found")
	}

	// Group by language.
	byLang := map[string][]fixture{}
	for _, fx := range fixtures {
		byLang[fx.language] = append(byLang[fx.language], fx)
	}

	stats := map[string]*languageStats{}

	langs := make([]string, 0, len(byLang))
	for lang := range byLang {
		langs = append(langs, lang)
	}
	sort.Strings(langs)

	for _, lang := range langs {
		langFixtures := byLang[lang]
		stats[lang] = &languageStats{}

		t.Run(lang, func(t *testing.T) {
			for _, fx := range langFixtures {
				t.Run(fx.pattern, func(t *testing.T) {
					stats[lang].total++

					// Load and validate expected.json.
					expected := loadRealworldExpected(t, fx.dir)
					requireProvenance(t, expected)

					// Determine scan file.
					scanFile := detectScanFile(t, fx.dir)

					opts := &vex.Options{
						SBOMPath:     filepath.Join(fx.dir, "sbom.cdx.json"),
						ScanPaths:    []string{filepath.Join(fx.dir, scanFile)},
						SourceDir:    filepath.Join(fx.dir, "source"),
						OutputFormat: "openvex",
					}

					doc := runPipeline(t, opts)

					allPassed := true
					for _, ef := range expected.Findings {
						stmt := findStatement(t, doc, ef.CVE)

						if stmt.Status != ef.ExpectedStatus {
							t.Errorf("CVE %s: expected status %q, got %q", ef.CVE, ef.ExpectedStatus, stmt.Status)
							allPassed = false
						}

						if stmt.ImpactStatement == "" {
							t.Errorf("CVE %s: impact_statement is empty; expected non-empty evidence", ef.CVE)
							allPassed = false
						}

						// Track reachable vs not_reachable stats.
						if ef.ExpectedStatus == "affected" {
							stats[lang].reachableExp++
							if stmt.Status == "affected" {
								stats[lang].reachableOK++
							}
						} else if ef.ExpectedStatus == "not_affected" {
							stats[lang].notReachExp++
							if stmt.Status == "not_affected" {
								stats[lang].notReachOK++
							}
						}
					}

					if allPassed {
						stats[lang].pass++
					} else {
						stats[lang].fail++
					}
				})
			}
		})
	}

	// Print consistency report.
	t.Log("\n=== Real-World Reachability Consistency Report ===")
	t.Logf("%-12s | %5s | %4s | %4s | %12s | %13s |",
		"Language", "Total", "Pass", "Fail", "Reachable", "NotReachable")
	t.Log(strings.Repeat("-", 70))

	totalAll, passAll, failAll := 0, 0, 0
	reachOKAll, reachExpAll, notReachOKAll, notReachExpAll := 0, 0, 0, 0

	for _, lang := range langs {
		s := stats[lang]
		t.Logf("%-12s | %5d | %4d | %4d | %10s | %11s |",
			lang, s.total, s.pass, s.fail,
			fmt.Sprintf("%d/%d", s.reachableOK, s.reachableExp),
			fmt.Sprintf("%d/%d", s.notReachOK, s.notReachExp))
		totalAll += s.total
		passAll += s.pass
		failAll += s.fail
		reachOKAll += s.reachableOK
		reachExpAll += s.reachableExp
		notReachOKAll += s.notReachOK
		notReachExpAll += s.notReachExp
	}

	t.Log(strings.Repeat("-", 70))
	t.Logf("%-12s | %5d | %4d | %4d | %10s | %11s |",
		"TOTAL", totalAll, passAll, failAll,
		fmt.Sprintf("%d/%d", reachOKAll, reachExpAll),
		fmt.Sprintf("%d/%d", notReachOKAll, notReachExpAll))

	// Fail if any fixture failed.
	if failAll > 0 {
		t.Errorf("FAIL: %d/%d fixtures failed — 100%% pass rate required", failAll, totalAll)
	}
}

func loadRealworldExpected(t *testing.T, dir string) realworldExpectedJSON {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "expected.json")) //nolint:gosec
	if err != nil {
		t.Fatalf("failed to read expected.json: %v", err)
	}
	var expected realworldExpectedJSON
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatalf("failed to parse expected.json: %v", err)
	}
	return expected
}

func requireProvenance(t *testing.T, expected realworldExpectedJSON) {
	t.Helper()
	if expected.Provenance.SourceProject == "" {
		t.Error("provenance.source_project is required")
	}
	if expected.Provenance.CVE == "" {
		t.Error("provenance.cve is required")
	}
	if expected.Provenance.Language == "" {
		t.Error("provenance.language is required")
	}
	if expected.Provenance.Pattern == "" {
		t.Error("provenance.pattern is required")
	}
	if expected.Provenance.GroundTruthNotes == "" {
		t.Error("provenance.ground_truth_notes is required")
	}
}

func detectScanFile(t *testing.T, dir string) string {
	t.Helper()
	for _, name := range []string{"grype.json", "trivy.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return name
		}
	}
	t.Fatalf("no scan file (grype.json or trivy.json) found in %s", dir)
	return ""
}
```

- [ ] **Step 2: Verify it compiles**

Run: `go build -tags integration ./pkg/vex/...`
Expected: Clean compile.

- [ ] **Step 3: Commit**

```bash
git add pkg/vex/realworld_integration_test.go
git commit -m "test: add build-tag-gated real-world reachability integration test runner"
```

---

### Task 18: Taskfile Integration

**Files:**
- Modify: `Taskfile.yml`

- [ ] **Step 1: Add test:integration:realworld task**

Add to `Taskfile.yml` after the existing `test:integration:` entry:

```yaml
  test:integration:realworld:
    desc: Run real-world reachability integration tests (48 CVE fixtures)
    cmds:
      - go test -tags integration -race -count=1 -v -timeout 10m -run TestIntegration_RealWorldReachability ./pkg/vex/...
```

- [ ] **Step 2: Commit**

```bash
git add Taskfile.yml
git commit -m "ci: add task test:integration:realworld for real-world CVE fixtures"
```

---

### Task 19: Run All Fixtures and Fix Failures

**This is the critical task. Every test must pass 100%. Fix analyzer bugs, not test expectations.**

- [ ] **Step 1: Run the integration suite**

Run: `task test:integration:realworld`
Expected: The consistency report shows 48/48 pass. If not, proceed to debug.

- [ ] **Step 2: For each failing fixture, debug systematically**

For each failure:
1. Read the test output to understand which CVE/status failed
2. Run the specific fixture in verbose mode: `go test -tags integration -v -run 'TestIntegration_RealWorldReachability/{language}/{pattern}' ./pkg/vex/...`
3. If `expected status "affected" but got "not_affected"`:
   - The analyzer isn't finding a call path to the vulnerable symbol
   - Check: Are the target symbol names correct in `grype.json`'s `vulnerableFunctions`?
   - Check: Is the source code actually calling the vulnerable function?
   - Check: Are import aliases being resolved correctly?
   - Fix the analyzer's extractor or add missing symbol mappings
4. If `expected status "not_affected" but got "affected"`:
   - The analyzer is finding a false positive path
   - Check: Is the source code actually NOT calling the function?
   - Fix the analyzer's scoping/resolution to avoid false edges
5. If `expected status but got "under_investigation"`:
   - The reachability filter didn't run at all
   - Check: Is the source/ directory present? Is the language detected? Is the SBOM component matching?

- [ ] **Step 3: Fix and re-run until 100% pass**

Iterate: fix → test → fix → test until all 48 pass.

- [ ] **Step 4: Run full test suite for regressions**

Run: `go test -race -count=1 ./...`
Expected: All existing tests still pass.

- [ ] **Step 5: Commit all fixes**

```bash
git add -A
git commit -m "fix: resolve all real-world integration test failures

All 48 real-world CVE fixtures now pass at 100% across 8 languages.
Fixed [describe specific issues found and fixed]."
```

---

### Task 20: Final Validation

- [ ] **Step 1: Run quality gates**

Run: `task quality`
Expected: All pass (fmt, vet, lint, test).

- [ ] **Step 2: Run real-world integration suite one final time**

Run: `task test:integration:realworld`
Expected: 48/48 pass, consistency report shows 100%.

- [ ] **Step 3: Verify the consistency report output**

The test output should show:
```
=== Real-World Reachability Consistency Report ===
Language     | Total | Pass | Fail |   Reachable |  NotReachable |
----------------------------------------------------------------------
csharp       |     6 |    6 |    0 |         3/3 |           3/3 |
go           |     6 |    6 |    0 |         3/3 |           3/3 |
java         |     6 |    6 |    0 |         3/3 |           3/3 |
javascript   |     6 |    6 |    0 |         3/3 |           3/3 |
php          |     6 |    6 |    0 |         3/3 |           3/3 |
python       |     6 |    6 |    0 |         3/3 |           3/3 |
ruby         |     6 |    6 |    0 |         3/3 |           3/3 |
rust         |     6 |    6 |    0 |         3/3 |           3/3 |
----------------------------------------------------------------------
TOTAL        |    48 |   48 |    0 |       24/24 |         24/24 |
```

- [ ] **Step 4: Commit any final adjustments**

Only if needed. Then this task is complete.
