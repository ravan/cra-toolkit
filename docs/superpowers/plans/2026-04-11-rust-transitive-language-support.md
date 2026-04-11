# Rust Transitive Language Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add production-grade Rust language support to the transitive cross-package reachability analyzer, including `pub`-accurate export enumeration with re-export resolution and a crates.io fetcher.

**Architecture:** Register Rust as a `LanguageSupport` under `pkg/vex/reachability/transitive/languages/rust/`. Add two optional capability interfaces — `ExportLister` (for Rust's module-tree-walking public API enumeration) and `CrossFileStateExtractor` (for bridging the Rust extractor's trait-impl state across files). Add a `CratesFetcher` implementing `Fetcher` against the crates.io JSON API. Ship with real-world integration and LLM judge gates matching Python/JavaScript.

**Tech Stack:** Go 1.22+, tree-sitter-go bindings, tree-sitter Rust grammar, crates.io JSON API, httptest for fetcher unit tests, Gemini CLI for LLM judge.

**Related:**
- Spec: `docs/superpowers/specs/2026-04-11-rust-transitive-language-support-design.md`
- Foundation spec: `docs/superpowers/specs/2026-04-11-transitive-language-support-foundation-design.md`
- Transitive analyzer design: `docs/superpowers/specs/2026-04-10-transitive-reachability-design.md`

**Conventions observed throughout:**
- TDD: every task writes a failing test, runs it to confirm failure, implements the minimal code, re-runs to confirm pass, commits.
- Commit messages follow the existing convention: `type(scope): summary` — e.g. `feat(transitive)`, `test(transitive)`, `refactor(transitive)`.
- **No `Co-Authored-By` lines.** This project's convention (memory note) forbids them.
- Absolute file paths in the plan are repo-relative.
- Before running tests, working directory is the repo root.

---

## File Structure

**Created:**
- `pkg/vex/reachability/transitive/languages/rust/rust.go` — `LanguageSupport` methods (Name, Ecosystem, FileExtensions, Grammar, Extractor, IsExportedSymbol, ModulePath, SymbolKey, NormalizeImports, ResolveDottedTarget, ResolveSelfCall).
- `pkg/vex/reachability/transitive/languages/rust/rust_test.go` — unit tests for the methods above.
- `pkg/vex/reachability/transitive/languages/rust/exports.go` — `ListExports` implementation (module tree walk, canonical emission, re-export resolution). This file holds the Rust-specific export enumeration.
- `pkg/vex/reachability/transitive/languages/rust/exports_test.go` — unit tests for `ListExports`.
- `pkg/vex/reachability/transitive/fetcher_crates.go` — `CratesFetcher`.
- `pkg/vex/reachability/transitive/fetcher_crates_test.go` — `httptest.Server`-backed unit tests.
- `testdata/integration/rust-realworld-cross-package/` — reachable fixture (source tree, sbom, expected.json).
- `testdata/integration/rust-realworld-cross-package-safe/` — not-reachable fixture.

**Modified:**
- `pkg/vex/reachability/treesitter/types.go` — add `IsPublic bool` to `Symbol`.
- `pkg/vex/reachability/treesitter/rust/extractor.go` — populate `IsPublic` for all symbol kinds; add thin `SnapshotState`/`RestoreState` wrappers around existing trait-impl snapshot/restore.
- `pkg/vex/reachability/treesitter/rust/extractor_test.go` — assert `IsPublic` on representative cases.
- `pkg/vex/reachability/transitive/language.go` — define `ExportLister` and `CrossFileStateExtractor`, register Rust in `LanguageFor`.
- `pkg/vex/reachability/transitive/language_test.go` — extend registry and contract tables to cover Rust.
- `pkg/vex/reachability/transitive/exports.go` — type-assert `ExportLister` and delegate.
- `pkg/vex/reachability/transitive/hop.go` — type-assert `CrossFileStateExtractor` and wire snapshot/restore cycle.
- `pkg/vex/reachability/transitive/degradation.go` — add `ReasonNoLibraryAPI`.
- `pkg/vex/reachability/transitive/transitive.go` — translate `errNoLibraryAPI` into `ReasonNoLibraryAPI` in `collectVulnSymbols`.
- `pkg/vex/reachability/transitive/integration_test.go` — add `TestIntegration_Transitive_RustReachable` and `TestIntegration_Transitive_RustNotReachable`.
- `pkg/vex/transitive_wire.go` — add `"crates.io"` case to `buildFetchers`.
- `pkg/vex/reachability/rust/llm_judge_test.go` — new file (does not yet exist in this package) adding `TestLLMJudge_RustTransitiveReachability`. Created in the rust reachability package to match the Python/JavaScript convention.
- `Taskfile.yml` — add a Rust judge line to `test:reachability:transitive:llmjudge`.

---

## Phase 1 — Shared-type and interface foundations

These tasks add the minimal shared-type changes and optional capability interfaces that Rust support depends on. Each is additive; Python and JavaScript behavior is unchanged.

### Task 1: Add `IsPublic` field to `treesitter.Symbol`

**Files:**
- Modify: `pkg/vex/reachability/treesitter/types.go`

- [ ] **Step 1: Add the field**

In `pkg/vex/reachability/treesitter/types.go`, inside the `Symbol` struct, add `IsPublic` as the final field:

```go
// Symbol represents a code symbol (function, method, class, module) extracted
// from a source file's AST.
type Symbol struct {
	ID            SymbolID
	Name          string
	QualifiedName string
	Language      string
	File          string
	Package       string
	StartLine     int
	EndLine       int
	Kind          SymbolKind
	IsEntryPoint  bool
	IsExternal    bool
	IsPublic      bool
}
```

- [ ] **Step 2: Verify the package builds and existing tests still pass**

```
go build ./pkg/vex/reachability/treesitter/...
go test ./pkg/vex/reachability/treesitter/...
```
Expected: build succeeds; all existing tests pass. Adding a zero-valued field cannot break anything that does not read it.

- [ ] **Step 3: Commit**

```
git add pkg/vex/reachability/treesitter/types.go
git commit -m "feat(treesitter): add IsPublic field to Symbol"
```

---

### Task 2: Populate `IsPublic` in the Rust extractor

The existing Rust extractor at `pkg/vex/reachability/treesitter/rust/extractor.go` inspects symbol-producing nodes but does not read `visibility_modifier`. This task adds a helper that returns `true` only when a direct `visibility_modifier` child has literal text exactly `"pub"`, then calls the helper at every symbol-emission site.

**Files:**
- Modify: `pkg/vex/reachability/treesitter/rust/extractor.go`
- Modify: `pkg/vex/reachability/treesitter/rust/extractor_test.go`

- [ ] **Step 1: Write a failing test**

Append to `pkg/vex/reachability/treesitter/rust/extractor_test.go`:

```go
func TestExtractSymbols_PublicVisibility(t *testing.T) {
	source := `pub fn public_fn() {}
fn private_fn() {}
pub(crate) fn crate_fn() {}
pub(super) fn super_fn() {}

pub struct PublicStruct;
struct PrivateStruct;

pub trait PublicTrait {
    fn required(&self);
}

pub struct Server;

impl Server {
    pub fn serve(&self) {}
    fn internal(&self) {}
}

impl PublicTrait for Server {
    fn required(&self) {}
}
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	symbols, err := ext.ExtractSymbols("src/lib.rs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}

	got := make(map[string]bool, len(symbols))
	for _, s := range symbols {
		got[s.Name] = s.IsPublic
	}

	expected := map[string]bool{
		"public_fn":     true,
		"private_fn":    false,
		"crate_fn":      false,
		"super_fn":      false,
		"PublicStruct":  true,
		"PrivateStruct": false,
		"PublicTrait":   true,
		"Server":        true,
		"serve":         true,
		"internal":      false,
		// Trait-impl method: inherits visibility from the impl block unconditionally.
		"required": true,
	}

	for name, want := range expected {
		pub, found := got[name]
		if !found {
			t.Errorf("symbol %q not emitted", name)
			continue
		}
		if pub != want {
			t.Errorf("symbol %q IsPublic = %v, want %v", name, pub, want)
		}
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

```
go test ./pkg/vex/reachability/treesitter/rust/... -run TestExtractSymbols_PublicVisibility -v
```
Expected: FAIL — existing extractor leaves `IsPublic` at `false` for every symbol.

- [ ] **Step 3: Add the `isPubVisibility` helper and a trait-impl flag**

In `pkg/vex/reachability/treesitter/rust/extractor.go`, just below the existing `stripRefWrappers` helper, add:

```go
// isPubVisibility reports whether node has a direct visibility_modifier child
// whose literal text is exactly "pub" (not "pub(crate)", "pub(super)", or
// "pub(in path)"). A trimmed equality check handles grammars that include
// trailing whitespace in the modifier's text span.
func isPubVisibility(node *tree_sitter.Node, src []byte) bool {
	if node == nil {
		return false
	}
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil || child.Kind() != "visibility_modifier" {
			continue
		}
		if strings.TrimSpace(nodeText(child, src)) == "pub" {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Update `extractFunction` to set `IsPublic`**

Add a new parameter `isPublic bool` to `extractFunction`, set `sym.IsPublic = isPublic`, and update callers.

Replace the existing `extractFunction` signature:

```go
func (e *Extractor) extractFunction(
	node *tree_sitter.Node,
	src []byte,
	file, mod, currentType string,
	isPublic bool,
	symbols *[]*treesitter.Symbol,
) {
	name := findChildIdentifier(node, src)
	if name == "" {
		return
	}

	symKind := treesitter.SymbolFunction
	qualifiedName := qualifyName(mod, name)
	if currentType != "" {
		symKind = treesitter.SymbolMethod
		qualifiedName = qualifyName(mod, currentType, name)
	}

	id := treesitter.SymbolID(qualifiedName)

	sym := &treesitter.Symbol{
		ID:            id,
		Name:          name,
		QualifiedName: qualifiedName,
		Language:      "rust",
		File:          file,
		Package:       mod,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          symKind,
		IsPublic:      isPublic,
	}
	*symbols = append(*symbols, sym)

	if currentType != "" {
		e.methodToTypes[name] = appendUnique(e.methodToTypes[name], currentType)
	}

	e.collectParamTypes(node, src, qualifiedName)
}
```

- [ ] **Step 5: Update `walkSymbols` to pass free-function visibility**

In `walkSymbols`, the `case "function_item":` branch currently reads:

```go
case "function_item":
    e.extractFunction(node, src, file, mod, currentType, symbols)
    return
```

Change it to compute visibility and pass it through:

```go
case "function_item":
    e.extractFunction(node, src, file, mod, currentType, isPubVisibility(node, src), symbols)
    return
```

- [ ] **Step 6: Update `extractTypeDefNode` for structs and enums**

Change the signature to take `isPublic bool` and set it on the emitted `Symbol`:

```go
func (e *Extractor) extractTypeDefNode(
	node *tree_sitter.Node,
	src []byte,
	file, mod, _ string,
	isPublic bool,
	symbols *[]*treesitter.Symbol,
) {
	name := findChildTypeIdentifier(node, src)
	if name == "" {
		return
	}

	qualifiedName := qualifyName(mod, name)
	id := treesitter.SymbolID(qualifiedName)

	sym := &treesitter.Symbol{
		ID:            id,
		Name:          name,
		QualifiedName: qualifiedName,
		Language:      "rust",
		File:          file,
		Package:       mod,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolClass,
		IsPublic:      isPublic,
	}
	*symbols = append(*symbols, sym)
}
```

Update its callers in `walkSymbols`:

```go
case "struct_item":
    e.extractTypeDefNode(node, src, file, mod, "type_identifier", isPubVisibility(node, src), symbols)
    return

case "enum_item":
    e.extractTypeDefNode(node, src, file, mod, "type_identifier", isPubVisibility(node, src), symbols)
    return
```

- [ ] **Step 7: Update `extractTrait` for trait items**

The trait is itself a `SymbolClass`. Compute visibility once and apply:

```go
func (e *Extractor) extractTrait(
	node *tree_sitter.Node,
	src []byte,
	file, mod string,
	symbols *[]*treesitter.Symbol,
) {
	traitName := findChildTypeIdentifier(node, src)
	if traitName == "" {
		return
	}

	traitIsPublic := isPubVisibility(node, src)

	qualifiedName := qualifyName(mod, traitName)
	id := treesitter.SymbolID(qualifiedName)

	sym := &treesitter.Symbol{
		ID:            id,
		Name:          traitName,
		QualifiedName: qualifiedName,
		Language:      "rust",
		File:          file,
		Package:       mod,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolClass,
		IsPublic:      traitIsPublic,
	}
	*symbols = append(*symbols, sym)

	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil || child.Kind() != "declaration_list" {
			continue
		}
		for j := uint(0); j < child.ChildCount(); j++ {
			item := child.Child(j)
			if item == nil {
				continue
			}
			switch item.Kind() {
			case "function_signature_item":
				methodName := findChildIdentifier(item, src)
				if methodName == "" {
					continue
				}
				mQualified := qualifyName(mod, traitName, methodName)
				mID := treesitter.SymbolID(mQualified)
				mSym := &treesitter.Symbol{
					ID:            mID,
					Name:          methodName,
					QualifiedName: mQualified,
					Language:      "rust",
					File:          file,
					Package:       mod,
					StartLine:     rowToLine(item.StartPosition().Row),
					EndLine:       rowToLine(item.EndPosition().Row),
					Kind:          treesitter.SymbolMethod,
					IsPublic:      traitIsPublic,
				}
				*symbols = append(*symbols, mSym)
				e.methodToTypes[methodName] = appendUnique(e.methodToTypes[methodName], traitName)

			case "function_item":
				// Default trait method body — inherits trait visibility.
				e.extractFunction(item, src, file, mod, traitName, traitIsPublic, symbols)
			}
		}
	}
}
```

- [ ] **Step 8: Update `extractImpl` to classify method visibility**

Inherent impl methods (`impl Type { ... }`) require explicit `pub fn` to be externally callable. Trait impl methods (`impl Trait for Type { ... }`) cannot carry their own visibility modifier and are treated as public unconditionally by the extractor — the real gatekeeping happens later in `ListExports`.

Replace the body of `extractImpl` (keeping header parsing as-is) such that the method-emission loop passes the right visibility:

```go
	// Extract methods from the impl body
	isTraitImpl := traitName != ""
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil || child.Kind() != "declaration_list" {
			continue
		}
		for j := uint(0); j < child.ChildCount(); j++ {
			item := child.Child(j)
			if item != nil && item.Kind() == "function_item" {
				isPublic := isTraitImpl || isPubVisibility(item, src)
				e.extractFunction(item, src, file, mod, typeName, isPublic, symbols)
			}
		}
	}
}
```

- [ ] **Step 9: Run the test and verify it passes**

```
go test ./pkg/vex/reachability/treesitter/rust/... -run TestExtractSymbols_PublicVisibility -v
```
Expected: PASS.

- [ ] **Step 10: Run the full Rust extractor test suite**

```
go test ./pkg/vex/reachability/treesitter/rust/... -v
```
Expected: all existing tests still pass. Adding visibility is additive.

- [ ] **Step 11: Commit**

```
git add pkg/vex/reachability/treesitter/rust/extractor.go pkg/vex/reachability/treesitter/rust/extractor_test.go
git commit -m "feat(treesitter/rust): populate Symbol.IsPublic from visibility modifiers"
```

---

### Task 3: Surface `SnapshotState` / `RestoreState` on the Rust extractor

The Rust extractor already exposes `SnapshotTraitImpls` and `RestoreTraitImpls` with idempotent additive semantics; the only work here is adding thin wrappers with the names the upcoming `CrossFileStateExtractor` interface will require.

**Files:**
- Modify: `pkg/vex/reachability/treesitter/rust/extractor.go`
- Modify: `pkg/vex/reachability/treesitter/rust/extractor_test.go`

- [ ] **Step 1: Write a failing test**

Append to `pkg/vex/reachability/treesitter/rust/extractor_test.go`:

```go
func TestExtractor_SnapshotRestoreState(t *testing.T) {
	srcA := `pub trait Handler { fn handle(&self); }
pub struct LogHandler;
impl Handler for LogHandler { fn handle(&self) {} }
`
	srcB := `pub struct FileHandler;
impl Handler for FileHandler { fn handle(&self) {} }
`
	treeA, bytesA := parseRustSource(t, srcA)
	defer treeA.Close()
	treeB, bytesB := parseRustSource(t, srcB)
	defer treeB.Close()

	ext := rustextractor.New()

	_, err := ext.ExtractSymbols("src/a.rs", bytesA, treeA)
	if err != nil {
		t.Fatalf("ExtractSymbols A: %v", err)
	}
	snapA := ext.SnapshotState()

	// Second call wipes internal state.
	_, err = ext.ExtractSymbols("src/b.rs", bytesB, treeB)
	if err != nil {
		t.Fatalf("ExtractSymbols B: %v", err)
	}
	snapB := ext.SnapshotState()

	// Restoring both snapshots should yield a merged state where Handler has
	// BOTH LogHandler and FileHandler as implementors.
	ext.RestoreState(snapA)
	ext.RestoreState(snapB)

	// Use ExtractCalls on a synthetic dispatcher to observe the merged map.
	// A simpler proxy: re-run ExtractSymbols on a dispatcher file and check
	// that a call through `dyn Handler` emits two EdgeDispatch edges.
	dispatcher := `fn run(h: &dyn Handler) { h.handle(); }`
	treeD, bytesD := parseRustSource(t, dispatcher)
	defer treeD.Close()

	_, err = ext.ExtractSymbols("src/dispatcher.rs", bytesD, treeD)
	if err != nil {
		t.Fatalf("ExtractSymbols D: %v", err)
	}
	// After ExtractSymbols, state was wiped again — replay snapshots.
	ext.RestoreState(snapA)
	ext.RestoreState(snapB)

	edges, err := ext.ExtractCalls("src/dispatcher.rs", bytesD, treeD, nil)
	if err != nil {
		t.Fatalf("ExtractCalls: %v", err)
	}

	var dispatchTargets []string
	for _, e := range edges {
		if e.Kind == treesitter.EdgeDispatch {
			dispatchTargets = append(dispatchTargets, string(e.To))
		}
	}

	// Expect two dispatch edges, one per implementor.
	if len(dispatchTargets) != 2 {
		t.Fatalf("expected 2 dispatch edges, got %d: %v", len(dispatchTargets), dispatchTargets)
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

```
go test ./pkg/vex/reachability/treesitter/rust/... -run TestExtractor_SnapshotRestoreState -v
```
Expected: FAIL with "undefined: SnapshotState" (method does not exist).

- [ ] **Step 3: Add the wrappers**

Append to `pkg/vex/reachability/treesitter/rust/extractor.go`, just above the `// ResolveImports` section divider:

```go
// SnapshotState implements the CrossFileStateExtractor capability declared in
// pkg/vex/reachability/transitive. It returns an opaque snapshot of the
// cross-file trait-impl state. Callers pair this with RestoreState to bridge
// trait dispatch across files, because ExtractSymbols resets internal state
// at the start of every call.
func (e *Extractor) SnapshotState() any {
	return e.SnapshotTraitImpls()
}

// RestoreState merges the given snapshot into the live extractor state. It
// uses appendUnique semantics, so calling it repeatedly with different
// snapshots accumulates rather than overwrites. A nil or wrong-type argument
// is a no-op (defensive — the interface is optional).
func (e *Extractor) RestoreState(s any) {
	snap, ok := s.(*TraitImplSnapshot)
	if !ok {
		return
	}
	e.RestoreTraitImpls(snap)
}
```

- [ ] **Step 4: Run the test and verify it passes**

```
go test ./pkg/vex/reachability/treesitter/rust/... -run TestExtractor_SnapshotRestoreState -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/treesitter/rust/extractor.go pkg/vex/reachability/treesitter/rust/extractor_test.go
git commit -m "feat(treesitter/rust): add SnapshotState/RestoreState wrappers"
```

---

### Task 4: Add `ReasonNoLibraryAPI` degradation constant

**Files:**
- Modify: `pkg/vex/reachability/transitive/degradation.go`

- [ ] **Step 1: Add the constant**

Append to the `const (...)` block in `pkg/vex/reachability/transitive/degradation.go`:

```go
	// ReasonNoLibraryAPI indicates the vulnerable crate ships no library
	// surface (src/lib.rs absent). External callers cannot link against a
	// binary-only crate, so transitive reachability does not apply and the
	// analyzer returns a not-applicable verdict rather than a false positive.
	ReasonNoLibraryAPI = "no_library_api"
```

- [ ] **Step 2: Verify the package builds**

```
go build ./pkg/vex/reachability/transitive/...
```
Expected: success.

- [ ] **Step 3: Commit**

```
git add pkg/vex/reachability/transitive/degradation.go
git commit -m "feat(transitive): add ReasonNoLibraryAPI degradation constant"
```

---

### Task 5: Define `ExportLister` interface and wire into `listExportedSymbols`

**Files:**
- Modify: `pkg/vex/reachability/transitive/language.go`
- Modify: `pkg/vex/reachability/transitive/exports.go`
- Modify: `pkg/vex/reachability/transitive/exports_test.go`

- [ ] **Step 1: Write a failing test**

Append to `pkg/vex/reachability/transitive/exports_test.go`:

```go
// fakeExportLister implements LanguageSupport plus ExportLister. It short-
// circuits the generic walker by returning a canned export list.
type fakeExportLister struct {
	LanguageSupport
	called bool
	out    []string
}

func (f *fakeExportLister) ListExports(sourceDir, packageName string) ([]string, error) {
	f.called = true
	return f.out, nil
}

func TestListExportedSymbols_DelegatesToExportLister(t *testing.T) {
	python, err := LanguageFor("python")
	if err != nil {
		t.Fatalf("LanguageFor(python): %v", err)
	}
	lister := &fakeExportLister{LanguageSupport: python, out: []string{"pkg.Foo", "pkg.Bar"}}

	got, err := listExportedSymbols(lister, t.TempDir(), "pkg")
	if err != nil {
		t.Fatalf("listExportedSymbols: %v", err)
	}
	if !lister.called {
		t.Error("expected ListExports to be called, but it was not")
	}
	want := map[string]bool{"pkg.Foo": true, "pkg.Bar": true}
	if len(got) != len(want) {
		t.Fatalf("got %d keys, want %d: %v", len(got), len(want), got)
	}
	for _, k := range got {
		if !want[k] {
			t.Errorf("unexpected key %q", k)
		}
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

```
go test ./pkg/vex/reachability/transitive/... -run TestListExportedSymbols_DelegatesToExportLister -v
```
Expected: FAIL — `ExportLister` type is undefined.

- [ ] **Step 3: Define the interface**

In `pkg/vex/reachability/transitive/language.go`, directly below the `LanguageSupport` interface definition, add:

```go
// ExportLister is an optional capability some languages implement in addition
// to LanguageSupport. When a LanguageSupport also satisfies ExportLister, the
// generic listExportedSymbols walker in exports.go delegates the entire
// enumeration to ListExports — useful for languages whose public API
// enumeration cannot be expressed by the IsExportedSymbol + ModulePath +
// SymbolKey triple. Rust implements this to walk the `pub mod` tree from
// lib.rs and resolve `pub use` re-exports.
type ExportLister interface {
	ListExports(sourceDir, packageName string) ([]string, error)
}
```

- [ ] **Step 4: Wire the delegation in `listExportedSymbols`**

In `pkg/vex/reachability/transitive/exports.go`, replace the opening of `listExportedSymbols` so that an `ExportLister` short-circuits the generic walker:

```go
func listExportedSymbols(lang LanguageSupport, sourceDir, packageName string) ([]string, error) {
	if lister, ok := lang.(ExportLister); ok {
		return lister.ListExports(sourceDir, packageName)
	}
	files, err := collectFilesByExt(sourceDir, lang.FileExtensions())
	if err != nil {
		return nil, err
	}
	// ... rest of existing body unchanged ...
```

- [ ] **Step 5: Run the test and verify it passes**

```
go test ./pkg/vex/reachability/transitive/... -run TestListExportedSymbols_DelegatesToExportLister -v
```
Expected: PASS.

- [ ] **Step 6: Run the full transitive test suite**

```
go test ./pkg/vex/reachability/transitive/...
```
Expected: all existing tests still pass — Python and JavaScript do not implement `ExportLister`, so they keep the generic walker path.

- [ ] **Step 7: Commit**

```
git add pkg/vex/reachability/transitive/language.go pkg/vex/reachability/transitive/exports.go pkg/vex/reachability/transitive/exports_test.go
git commit -m "feat(transitive): add optional ExportLister hook for custom export enumeration"
```

---

### Task 6: Define `CrossFileStateExtractor` and wire into `RunHop`

**Files:**
- Modify: `pkg/vex/reachability/transitive/language.go`
- Modify: `pkg/vex/reachability/transitive/hop.go`
- Modify: `pkg/vex/reachability/transitive/hop_test.go`

- [ ] **Step 1: Write a failing test**

Append to `pkg/vex/reachability/transitive/hop_test.go`:

```go
// recordingStatefulExtractor wraps an existing extractor and records
// snapshot/restore calls so the test can assert RunHop wired them correctly.
type recordingStatefulExtractor struct {
	treesitter.LanguageExtractor
	snapshots int
	restores  int
}

func (r *recordingStatefulExtractor) SnapshotState() any {
	r.snapshots++
	return r.snapshots
}

func (r *recordingStatefulExtractor) RestoreState(_ any) {
	r.restores++
}

// fakeStatefulLanguage wraps a real LanguageSupport but swaps its extractor
// for the recording wrapper so RunHop exercises the CrossFileStateExtractor
// branch.
type fakeStatefulLanguage struct {
	LanguageSupport
	rec *recordingStatefulExtractor
}

func (f *fakeStatefulLanguage) Extractor() treesitter.LanguageExtractor { return f.rec }

func TestRunHop_CallsCrossFileStateExtractor(t *testing.T) {
	python, err := LanguageFor("python")
	if err != nil {
		t.Fatalf("LanguageFor(python): %v", err)
	}
	rec := &recordingStatefulExtractor{LanguageExtractor: python.Extractor()}
	lang := &fakeStatefulLanguage{LanguageSupport: python, rec: rec}

	dir := t.TempDir()
	for _, name := range []string{"a.py", "b.py", "c.py"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("def fn():\n    pass\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	_, err = RunHop(context.Background(), HopInput{
		Language:      lang,
		SourceDir:     dir,
		TargetSymbols: []string{"fn"},
		MaxTargets:    10,
	})
	if err != nil {
		t.Fatalf("RunHop: %v", err)
	}
	if rec.snapshots != 3 {
		t.Errorf("snapshots = %d, want 3 (one per file)", rec.snapshots)
	}
	if rec.restores != 3 {
		t.Errorf("restores = %d, want 3 (replay of all snapshots)", rec.restores)
	}
}
```

This test requires the following imports in `hop_test.go` if they're not already present:

```go
import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)
```

- [ ] **Step 2: Run the test and verify it fails**

```
go test ./pkg/vex/reachability/transitive/... -run TestRunHop_CallsCrossFileStateExtractor -v
```
Expected: FAIL — `CrossFileStateExtractor` interface does not exist; the test file will not compile. That counts as a failing test for TDD purposes.

- [ ] **Step 3: Define the interface**

In `pkg/vex/reachability/transitive/language.go`, directly below the `ExportLister` definition, add:

```go
// CrossFileStateExtractor is an optional capability for language extractors
// that accumulate state across files — notably Rust's trait-impl map for
// &dyn Trait dispatch. RunHop type-asserts its active extractor against this
// interface and, when supported, snapshots state after each per-file symbol
// extraction and replays the full snapshot list before call extraction. This
// ensures cross-file trait dispatch is resolved even though ExtractSymbols
// resets internal state at the start of every call.
//
// RestoreState must be idempotent and additive: calling it multiple times
// with different snapshots merges (not overwrites) the contained state.
type CrossFileStateExtractor interface {
	SnapshotState() any
	RestoreState(any)
}
```

- [ ] **Step 4: Wire snapshot/restore into `RunHop`**

In `pkg/vex/reachability/transitive/hop.go`, find Phase 1's per-file loop (`for _, pr := range parseResults { ... }`). Immediately above the loop, add:

```go
	stateful, hasCrossFileState := ext.(CrossFileStateExtractor)
	var snapshots []any
```

Inside the loop, after the existing `fileInfos = append(...)` call, add:

```go
		if hasCrossFileState {
			snapshots = append(snapshots, stateful.SnapshotState())
		}
```

Immediately after the loop closes, replay the snapshots before Phase 2 begins:

```go
	if hasCrossFileState {
		for _, s := range snapshots {
			stateful.RestoreState(s)
		}
	}
```

- [ ] **Step 5: Run the test and verify it passes**

```
go test ./pkg/vex/reachability/transitive/... -run TestRunHop_CallsCrossFileStateExtractor -v
```
Expected: PASS.

- [ ] **Step 6: Run the full transitive test suite**

```
go test ./pkg/vex/reachability/transitive/...
```
Expected: all existing tests still pass.

- [ ] **Step 7: Commit**

```
git add pkg/vex/reachability/transitive/language.go pkg/vex/reachability/transitive/hop.go pkg/vex/reachability/transitive/hop_test.go
git commit -m "feat(transitive): add CrossFileStateExtractor hook wired into RunHop"
```

---

### Task 7: Phase 1 regression sweep

- [ ] **Step 1: Run the full repo test suite**

```
task test
```
Expected: all packages pass. Phase 1 was purely additive; nothing should regress. If a test fails, fix the underlying issue — do NOT skip or mark as expected failure.

- [ ] **Step 2: Run lint**

```
task lint
```
Expected: clean. Fix any lint violations before proceeding.

- [ ] **Step 3: Commit any lint fixes under a descriptive message if needed**

If Step 2 required a fix:
```
git add <files>
git commit -m "style(transitive): satisfy lint after Phase 1 wiring"
```

Otherwise no commit is needed.

---

## Phase 2 — Rust LanguageSupport interface methods

Create the `languages/rust/` subpackage and implement every `LanguageSupport` method except `ListExports` (which ships in Phase 3). The package is not yet registered in `LanguageFor`; that happens after `ListExports` is in place.

### Task 8: Create `languages/rust/rust.go` skeleton with trivial methods

**Files:**
- Create: `pkg/vex/reachability/transitive/languages/rust/rust.go`
- Create: `pkg/vex/reachability/transitive/languages/rust/rust_test.go`

- [ ] **Step 1: Write the failing test**

Create `pkg/vex/reachability/transitive/languages/rust/rust_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/rust"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestLanguage_Identity(t *testing.T) {
	lang := rust.New()
	if lang.Name() != "rust" {
		t.Errorf("Name() = %q, want %q", lang.Name(), "rust")
	}
	if lang.Ecosystem() != "crates.io" {
		t.Errorf("Ecosystem() = %q, want %q", lang.Ecosystem(), "crates.io")
	}
	exts := lang.FileExtensions()
	if len(exts) != 1 || exts[0] != ".rs" {
		t.Errorf("FileExtensions() = %v, want [\".rs\"]", exts)
	}
	if lang.Grammar() == nil {
		t.Error("Grammar() returned nil")
	}
	if lang.Extractor() == nil {
		t.Error("Extractor() returned nil")
	}
}

func TestLanguage_IsExportedSymbol(t *testing.T) {
	lang := rust.New()
	cases := []struct {
		name string
		sym  *treesitter.Symbol
		want bool
	}{
		{"nil", nil, false},
		{"public function", &treesitter.Symbol{Kind: treesitter.SymbolFunction, IsPublic: true}, true},
		{"private function", &treesitter.Symbol{Kind: treesitter.SymbolFunction, IsPublic: false}, false},
		{"public method", &treesitter.Symbol{Kind: treesitter.SymbolMethod, IsPublic: true}, true},
		{"private method", &treesitter.Symbol{Kind: treesitter.SymbolMethod, IsPublic: false}, false},
		{"public struct", &treesitter.Symbol{Kind: treesitter.SymbolClass, IsPublic: true}, true},
		{"private struct", &treesitter.Symbol{Kind: treesitter.SymbolClass, IsPublic: false}, false},
		{"public module", &treesitter.Symbol{Kind: treesitter.SymbolModule, IsPublic: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := lang.IsExportedSymbol(tc.sym)
			if got != tc.want {
				t.Errorf("IsExportedSymbol(%+v) = %v, want %v", tc.sym, got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -v
```
Expected: FAIL — package `rust` does not exist. (Compile error is the TDD-failing state.)

- [ ] **Step 3: Create the package**

Create `pkg/vex/reachability/transitive/languages/rust/rust.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package rust provides the Rust LanguageSupport implementation for the
// transitive cross-package reachability analyzer. It is imported only by
// the transitive package's LanguageFor factory.
package rust

import (
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarrust "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/rust"
	rustextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/rust"
)

// Language is the Rust LanguageSupport implementation. Callers use New to
// construct a value; the zero value is not valid.
type Language struct {
	extractor treesitter.LanguageExtractor
}

// New returns a fresh Rust Language. The extractor is constructed once per
// call; callers that run many analyses should cache the result.
func New() *Language {
	return &Language{extractor: rustextractor.New()}
}

func (l *Language) Name() string                            { return "rust" }
func (l *Language) Ecosystem() string                       { return "crates.io" }
func (l *Language) FileExtensions() []string                { return []string{".rs"} }
func (l *Language) Grammar() unsafe.Pointer                 { return grammarrust.Language() }
func (l *Language) Extractor() treesitter.LanguageExtractor { return l.extractor }

// IsExportedSymbol reports whether a symbol is part of the Rust crate's
// public API. It is a fallback used only if the ExportLister hook is not
// consulted (the primary path uses Language.ListExports, defined in
// exports.go). A symbol is considered exported when it is flagged public
// by the extractor AND its kind is a callable or type container.
func (l *Language) IsExportedSymbol(sym *treesitter.Symbol) bool {
	if sym == nil || !sym.IsPublic {
		return false
	}
	switch sym.Kind {
	case treesitter.SymbolFunction, treesitter.SymbolMethod, treesitter.SymbolClass:
		return true
	}
	return false
}
```

- [ ] **Step 4: Run the test and verify it passes**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -v
```
Expected: PASS on `TestLanguage_Identity` and `TestLanguage_IsExportedSymbol`.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/languages/rust/rust.go pkg/vex/reachability/transitive/languages/rust/rust_test.go
git commit -m "feat(transitive/rust): add Language skeleton with identity methods and IsExportedSymbol"
```

---

### Task 9: `ModulePath` and `SymbolKey`

`ModulePath` and `SymbolKey` are used by the *caller-side* pipeline (not the Rust export enumeration, which uses `ListExports`). They still matter for building scope entries when another Rust crate or the application references the crate, and for the generic export walker fallback.

**Files:**
- Modify: `pkg/vex/reachability/transitive/languages/rust/rust.go`
- Modify: `pkg/vex/reachability/transitive/languages/rust/rust_test.go`

- [ ] **Step 1: Write a failing test**

Append to `pkg/vex/reachability/transitive/languages/rust/rust_test.go`:

```go
func TestLanguage_ModulePath(t *testing.T) {
	lang := rust.New()
	cases := []struct {
		name      string
		file      string
		sourceDir string
		pkg       string
		want      string
	}{
		{
			name:      "lib.rs at crate root",
			file:      "/tmp/hyper-0.14.10/src/lib.rs",
			sourceDir: "/tmp/hyper-0.14.10",
			pkg:       "hyper",
			want:      "hyper",
		},
		{
			name:      "submodule file",
			file:      "/tmp/hyper-0.14.10/src/client.rs",
			sourceDir: "/tmp/hyper-0.14.10",
			pkg:       "hyper",
			want:      "hyper.client",
		},
		{
			name:      "nested mod.rs",
			file:      "/tmp/hyper-0.14.10/src/client/connect/mod.rs",
			sourceDir: "/tmp/hyper-0.14.10",
			pkg:       "hyper",
			want:      "hyper.client.connect",
		},
		{
			name:      "nested leaf file",
			file:      "/tmp/hyper-0.14.10/src/client/connect/http.rs",
			sourceDir: "/tmp/hyper-0.14.10",
			pkg:       "hyper",
			want:      "hyper.client.connect.http",
		},
		{
			name:      "out-of-src test file is rejected",
			file:      "/tmp/hyper-0.14.10/tests/integration.rs",
			sourceDir: "/tmp/hyper-0.14.10",
			pkg:       "hyper",
			want:      "tests",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := lang.ModulePath(tc.file, tc.sourceDir, tc.pkg)
			if got != tc.want {
				t.Errorf("ModulePath = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLanguage_SymbolKey(t *testing.T) {
	lang := rust.New()
	if got := lang.SymbolKey("hyper.client", "Request"); got != "hyper.client.Request" {
		t.Errorf("SymbolKey = %q, want %q", got, "hyper.client.Request")
	}
	if got := lang.SymbolKey("hyper", "spawn"); got != "hyper.spawn" {
		t.Errorf("SymbolKey = %q, want %q", got, "hyper.spawn")
	}
}
```

- [ ] **Step 2: Run tests and verify failure**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -run "TestLanguage_ModulePath|TestLanguage_SymbolKey" -v
```
Expected: FAIL — methods not yet defined.

- [ ] **Step 3: Implement `ModulePath` and `SymbolKey`**

Append to `pkg/vex/reachability/transitive/languages/rust/rust.go`:

```go
// ModulePath returns the dotted Rust module path for file, rooted at
// packageName. The Rust source-layout convention is:
//   - src/lib.rs           → packageName
//   - src/foo.rs           → packageName.foo
//   - src/foo/mod.rs       → packageName.foo
//   - src/foo/bar.rs       → packageName.foo.bar
//
// Out-of-src files (tests/, benches/, examples/, docs/) return their first
// non-src relative path component so the generic export walker's package
// prefix filter rejects them. The returned value is language-agnostic
// (dot-separated, not `::`) to match the shared SymbolKey scheme.
func (l *Language) ModulePath(file, sourceDir, packageName string) string {
	rel, err := filepath.Rel(sourceDir, file)
	if err != nil {
		return packageName
	}
	parts := strings.Split(rel, string(filepath.Separator))
	// Locate the "src" component; anything before it is outside the crate
	// (crate tarballs unpack to <name>-<version>/src/...).
	srcIdx := -1
	for i, p := range parts {
		if p == "src" {
			srcIdx = i
			break
		}
	}
	if srcIdx < 0 {
		// File lives outside src/. Return its first component; the generic
		// prefix filter will then reject it because it will not equal
		// packageName nor start with packageName + ".".
		if len(parts) == 0 {
			return ""
		}
		return parts[0]
	}
	tail := parts[srcIdx+1:]
	if len(tail) == 0 {
		return packageName
	}
	// Strip the trailing .rs extension from the last component.
	last := tail[len(tail)-1]
	last = strings.TrimSuffix(last, ".rs")
	tail[len(tail)-1] = last

	// Special case: lib.rs / main.rs / mod.rs collapse into their parent
	// module path. For lib.rs/main.rs at src/, the crate root IS packageName.
	switch last {
	case "lib", "main":
		if len(tail) == 1 {
			return packageName
		}
		tail = tail[:len(tail)-1]
	case "mod":
		tail = tail[:len(tail)-1]
	}
	if len(tail) == 0 {
		return packageName
	}
	return packageName + "." + strings.Join(tail, ".")
}

// SymbolKey composes a dotted symbol key: "<modulePath>.<symbolName>".
// Rust uses the same scheme as Python for its caller-side scope lookups.
func (l *Language) SymbolKey(modulePath, symbolName string) string {
	return modulePath + "." + symbolName
}
```

Add the new imports at the top of `rust.go` (replace the current `import` block):

```go
import (
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarrust "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/rust"
	rustextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/rust"
)
```

- [ ] **Step 4: Run the tests and verify they pass**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -run "TestLanguage_ModulePath|TestLanguage_SymbolKey" -v
```
Expected: PASS on all sub-cases.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/languages/rust/rust.go pkg/vex/reachability/transitive/languages/rust/rust_test.go
git commit -m "feat(transitive/rust): implement ModulePath and SymbolKey"
```

---

### Task 10: `NormalizeImports`

The Rust tree-sitter extractor produces `Import` records whose `Module` field preserves `::` path separators (e.g. `std::collections::HashMap`). The transitive analyzer's symbol-key scheme uses `.`, so `NormalizeImports` converts `::` → `.` in both `Module` and `Alias` fields.

**Files:**
- Modify: `pkg/vex/reachability/transitive/languages/rust/rust.go`
- Modify: `pkg/vex/reachability/transitive/languages/rust/rust_test.go`

- [ ] **Step 1: Write a failing test**

Append to `rust_test.go`:

```go
func TestLanguage_NormalizeImports(t *testing.T) {
	lang := rust.New()
	in := []treesitter.Import{
		{Module: "std::collections::HashMap", Alias: "HashMap"},
		{Module: "serde::Serialize", Alias: "Ser"},
		{Module: "tokio", Alias: "tokio"},
		{Module: "crate::internal::helpers", Alias: "helpers"},
	}
	out := lang.NormalizeImports(in)
	if len(out) != len(in) {
		t.Fatalf("len(out) = %d, want %d", len(out), len(in))
	}
	want := []treesitter.Import{
		{Module: "std.collections.HashMap", Alias: "HashMap"},
		{Module: "serde.Serialize", Alias: "Ser"},
		{Module: "tokio", Alias: "tokio"},
		{Module: "crate.internal.helpers", Alias: "helpers"},
	}
	for i, w := range want {
		if out[i].Module != w.Module {
			t.Errorf("[%d].Module = %q, want %q", i, out[i].Module, w.Module)
		}
		if out[i].Alias != w.Alias {
			t.Errorf("[%d].Alias = %q, want %q", i, out[i].Alias, w.Alias)
		}
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -run TestLanguage_NormalizeImports -v
```
Expected: FAIL.

- [ ] **Step 3: Implement `NormalizeImports`**

Append to `pkg/vex/reachability/transitive/languages/rust/rust.go`:

```go
// NormalizeImports converts Rust's `::` path separator to `.` in both the
// Module and Alias fields of each import, matching the symbol-key scheme
// used by the shared scope builder. Other fields are preserved unchanged.
func (l *Language) NormalizeImports(raw []treesitter.Import) []treesitter.Import {
	out := make([]treesitter.Import, len(raw))
	for i, imp := range raw {
		imp.Module = strings.ReplaceAll(imp.Module, "::", ".")
		imp.Alias = strings.ReplaceAll(imp.Alias, "::", ".")
		out[i] = imp
	}
	return out
}
```

- [ ] **Step 4: Run the test and verify it passes**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -run TestLanguage_NormalizeImports -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/languages/rust/rust.go pkg/vex/reachability/transitive/languages/rust/rust_test.go
git commit -m "feat(transitive/rust): implement NormalizeImports"
```

---

### Task 11: `ResolveDottedTarget`

Identical semantics to the Python and JavaScript implementations. The extractor already normalizes `::` to `.` in call targets, so the shared resolution logic applies unchanged.

**Files:**
- Modify: `pkg/vex/reachability/transitive/languages/rust/rust.go`
- Modify: `pkg/vex/reachability/transitive/languages/rust/rust_test.go`

- [ ] **Step 1: Write a failing test**

Append to `rust_test.go`:

```go
func TestLanguage_ResolveDottedTarget(t *testing.T) {
	lang := rust.New()
	scope := treesitter.NewScope(nil)
	scope.DefineImport("Deserialize", "serde.Deserialize", nil)
	scope.DefineImport("tokio", "tokio", nil)

	got, ok := lang.ResolveDottedTarget("Deserialize", "deserialize", scope)
	if !ok {
		t.Fatal("ResolveDottedTarget(Deserialize) returned !ok, want ok")
	}
	if got != "serde.Deserialize.deserialize" {
		t.Errorf("got %q, want %q", got, "serde.Deserialize.deserialize")
	}

	got, ok = lang.ResolveDottedTarget("tokio", "spawn", scope)
	if !ok {
		t.Fatal("ResolveDottedTarget(tokio) returned !ok, want ok")
	}
	if got != "tokio.spawn" {
		t.Errorf("got %q, want %q", got, "tokio.spawn")
	}

	_, ok = lang.ResolveDottedTarget("unknown", "fn", scope)
	if ok {
		t.Error("ResolveDottedTarget(unknown) returned ok, want !ok")
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -run TestLanguage_ResolveDottedTarget -v
```
Expected: FAIL.

- [ ] **Step 3: Implement `ResolveDottedTarget`**

Append to `pkg/vex/reachability/transitive/languages/rust/rust.go`:

```go
// ResolveDottedTarget resolves a dotted call target whose prefix is an
// import alias. For example, given prefix="Deserialize" (aliased to
// "serde.Deserialize" via `use serde::Deserialize;`) and suffix="deserialize",
// it returns "serde.Deserialize.deserialize". When the prefix is not a known
// alias in scope, it returns ("", false).
func (l *Language) ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool) {
	resolved, ok := scope.LookupImport(prefix)
	if !ok {
		return "", false
	}
	return treesitter.SymbolID(resolved + "." + suffix), true
}
```

- [ ] **Step 4: Run the test and verify it passes**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -run TestLanguage_ResolveDottedTarget -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/languages/rust/rust.go pkg/vex/reachability/transitive/languages/rust/rust_test.go
git commit -m "feat(transitive/rust): implement ResolveDottedTarget"
```

---

### Task 12: `ResolveSelfCall`

Rust method calls through `self` are emitted as `self.method_name` when no better resolution is available. The rewrite rule is identical to Python's: strip the `self.` prefix, take the `from` qualified name minus its last component as the class qualifier, and emit `<qualifier>.<method_name>`.

**Files:**
- Modify: `pkg/vex/reachability/transitive/languages/rust/rust.go`
- Modify: `pkg/vex/reachability/transitive/languages/rust/rust_test.go`

- [ ] **Step 1: Write a failing test**

Append to `rust_test.go`:

```go
func TestLanguage_ResolveSelfCall(t *testing.T) {
	lang := rust.New()
	cases := []struct {
		name string
		to   treesitter.SymbolID
		from treesitter.SymbolID
		want treesitter.SymbolID
	}{
		{
			name: "method call through self",
			to:   "self.inner",
			from: "hyper.Server.serve",
			want: "hyper.Server.inner",
		},
		{
			name: "free function call is unchanged",
			to:   "helper",
			from: "hyper.entry",
			want: "helper",
		},
		{
			name: "self at top level leaves unchanged",
			to:   "self.foo",
			from: "main",
			want: "self.foo",
		},
		{
			name: "nested module with three-part from rewrites",
			to:   "self.read",
			from: "client.connect.Http.connect",
			want: "client.connect.Http.read",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := lang.ResolveSelfCall(tc.to, tc.from)
			if got != tc.want {
				t.Errorf("ResolveSelfCall(%q, %q) = %q, want %q", tc.to, tc.from, got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -run TestLanguage_ResolveSelfCall -v
```
Expected: FAIL.

- [ ] **Step 3: Implement `ResolveSelfCall`**

Append to `pkg/vex/reachability/transitive/languages/rust/rust.go`:

```go
// ResolveSelfCall rewrites Rust `self.method` call targets into the type-
// qualified form "<mod>.<Type>.<method>" by extracting the type context from
// the caller's symbol ID. Requires `from` to have at least three dot-
// separated components (module.Type.method). Free functions are left
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

- [ ] **Step 4: Run the test and verify it passes**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -run TestLanguage_ResolveSelfCall -v
```
Expected: PASS.

- [ ] **Step 5: Run the full rust language package test suite**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -v
```
Expected: all tests pass.

- [ ] **Step 6: Commit**

```
git add pkg/vex/reachability/transitive/languages/rust/rust.go pkg/vex/reachability/transitive/languages/rust/rust_test.go
git commit -m "feat(transitive/rust): implement ResolveSelfCall"
```

---

## Phase 3 — Rust `ListExports` (module tree walk, canonical emission, re-exports)

This phase implements the accuracy-critical public-API enumeration described in sections 4.1–4.3 of the spec. It is built incrementally so each task produces a verifiable green state.

### Task 13: Module tree walker — seed, absent `lib.rs`, file-backed submodules, private exclusion

**Files:**
- Create: `pkg/vex/reachability/transitive/languages/rust/exports.go`
- Create: `pkg/vex/reachability/transitive/languages/rust/exports_test.go`

- [ ] **Step 1: Write failing tests for the module tree walker**

Create `pkg/vex/reachability/transitive/languages/rust/exports_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/rust"
)

// writeCrate writes a map of relative-path → file-content entries under
// tmp/<name>-<version>/ and returns the crate root path (the parent of the
// `<name>-<version>/` directory), matching the layout the CratesFetcher
// produces after unpacking a .crate tarball.
func writeCrate(t *testing.T, name, version string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	crateDir := filepath.Join(root, name+"-"+version)
	for rel, content := range files {
		full := filepath.Join(crateDir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return root
}

func TestListExports_NoLibraryAPI(t *testing.T) {
	root := writeCrate(t, "cli", "1.0.0", map[string]string{
		"src/main.rs": `fn main() { println!("hello"); }`,
	})
	lang := rust.New()
	_, err := lang.ListExports(root, "cli")
	if !errors.Is(err, rust.ErrNoLibraryAPI) {
		t.Errorf("ListExports returned %v, want ErrNoLibraryAPI", err)
	}
}

func TestListExports_SimpleLibrary(t *testing.T) {
	root := writeCrate(t, "mini", "0.1.0", map[string]string{
		"src/lib.rs": `pub fn greet() {}
fn private_helper() {}
`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "mini")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{"mini.greet": true}
	assertKeys(t, got, want)
}

func TestListExports_FileBackedSubmodule(t *testing.T) {
	root := writeCrate(t, "util", "0.2.0", map[string]string{
		"src/lib.rs":    `pub mod helpers;`,
		"src/helpers.rs": `pub fn run() {}
fn hidden() {}
`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "util")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{"util.helpers.run": true}
	assertKeys(t, got, want)
}

func TestListExports_SubmoduleAsModRs(t *testing.T) {
	root := writeCrate(t, "util", "0.2.0", map[string]string{
		"src/lib.rs":         `pub mod helpers;`,
		"src/helpers/mod.rs": `pub fn run() {}`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "util")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{"util.helpers.run": true}
	assertKeys(t, got, want)
}

func TestListExports_PrivateModuleExcluded(t *testing.T) {
	root := writeCrate(t, "app", "0.1.0", map[string]string{
		"src/lib.rs":       `mod internal; pub mod public;`,
		"src/internal.rs":  `pub fn should_not_leak() {}`,
		"src/public.rs":    `pub fn visible() {}`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "app")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{"app.public.visible": true}
	assertKeys(t, got, want)
}

func TestListExports_NestedSubmodules(t *testing.T) {
	root := writeCrate(t, "nested", "0.1.0", map[string]string{
		"src/lib.rs":                 `pub mod a;`,
		"src/a.rs":                   `pub mod b;`,
		"src/a/b.rs":                 `pub fn deep() {}`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "nested")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{"nested.a.b.deep": true}
	assertKeys(t, got, want)
}

// assertKeys compares the returned export key slice against the expected set
// (order-insensitive) and reports missing and unexpected keys.
func assertKeys(t *testing.T, got []string, want map[string]bool) {
	t.Helper()
	gotSet := make(map[string]bool, len(got))
	for _, k := range got {
		gotSet[k] = true
	}
	for w := range want {
		if !gotSet[w] {
			t.Errorf("missing key %q", w)
		}
	}
	for g := range gotSet {
		if !want[g] {
			t.Errorf("unexpected key %q", g)
		}
	}
}
```

- [ ] **Step 2: Run the tests and verify they fail**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -run TestListExports_ -v
```
Expected: FAIL — `ListExports` and `ErrNoLibraryAPI` do not exist.

- [ ] **Step 3: Create `exports.go` with the module tree walker and a minimal `ListExports`**

Create `pkg/vex/reachability/transitive/languages/rust/exports.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarrust "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/rust"
)

// ErrNoLibraryAPI indicates the crate has no lib.rs — i.e. it is a binary-
// only crate. The transitive analyzer translates this into the
// ReasonNoLibraryAPI degradation.
var ErrNoLibraryAPI = errors.New("rust crate has no library API")

// ListExports enumerates the deduplicated set of dotted symbol keys by
// which downstream Rust code can reach every exported item in the crate at
// sourceDir. See section 4 of
// docs/superpowers/specs/2026-04-11-rust-transitive-language-support-design.md
// for the full algorithm.
func (l *Language) ListExports(sourceDir, packageName string) ([]string, error) {
	crateRoot, libRS, err := findLibRS(sourceDir, packageName)
	if err != nil {
		return nil, err
	}

	modules, err := walkModuleTree(crateRoot, libRS)
	if err != nil {
		return nil, err
	}

	// Canonical emission and re-export resolution land in later tasks.
	// Stage-by-stage TDD: for now, emit a single key per public module's
	// top-level `pub fn` items using a direct tree-sitter scan.
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(grammarrust.Language())); err != nil {
		return nil, err
	}

	keys := make(map[string]struct{})
	for _, m := range modules {
		if !m.isPublic {
			continue
		}
		src, err := os.ReadFile(m.file)
		if err != nil {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}
		root := tree.RootNode()
		collectTopLevelPublicFns(root, src, packageName, m.path, keys)
		tree.Close()
	}

	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	return out, nil
}

// moduleNode is one entry in the public-accessibility-walked module tree.
type moduleNode struct {
	// path is the dotted module path relative to the crate root. The root
	// itself has an empty string.
	path string
	// file is the absolute source file implementing this module.
	file string
	// isPublic is true when every ancestor in the chain was declared with
	// `pub mod`. Private modules are still walked (for the re-export
	// analysis added in Task 15), but their symbols are not emitted.
	isPublic bool
}

// findLibRS returns the crate root directory (containing Cargo.toml) and
// the absolute path to src/lib.rs. It searches for a `<name>-<version>/`
// subdirectory of sourceDir first — that's how CratesFetcher unpacks — and
// falls back to sourceDir itself for test fixtures that use a flat layout.
func findLibRS(sourceDir, packageName string) (crateRoot, libRS string, err error) { //nolint:nonamedreturns // three-value return is clearer with names
	// Preferred layout: sourceDir/<name>-<version>/src/lib.rs
	entries, readErr := os.ReadDir(sourceDir)
	if readErr == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			if !strings.HasPrefix(entry.Name(), packageName+"-") {
				continue
			}
			candidate := filepath.Join(sourceDir, entry.Name(), "src", "lib.rs")
			if _, statErr := os.Stat(candidate); statErr == nil {
				return filepath.Join(sourceDir, entry.Name()), candidate, nil
			}
		}
	}
	// Fallback: sourceDir/src/lib.rs
	candidate := filepath.Join(sourceDir, "src", "lib.rs")
	if _, statErr := os.Stat(candidate); statErr == nil {
		return sourceDir, candidate, nil
	}
	return "", "", ErrNoLibraryAPI
}

// walkModuleTree walks from libRS through every `mod foo;` / `pub mod foo;`
// declaration, returning every file-backed module node reachable from the
// crate root.
func walkModuleTree(crateRoot, libRS string) ([]moduleNode, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(grammarrust.Language())); err != nil {
		return nil, err
	}

	visited := make(map[string]bool)
	root := moduleNode{path: "", file: libRS, isPublic: true}
	result := []moduleNode{root}
	visited[libRS] = true

	queue := []moduleNode{root}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		src, err := os.ReadFile(node.file)
		if err != nil {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}
		for _, child := range findModDecls(tree.RootNode(), src, node, crateRoot) {
			if visited[child.file] {
				continue
			}
			visited[child.file] = true
			result = append(result, child)
			queue = append(queue, child)
		}
		tree.Close()
	}
	return result, nil
}

// findModDecls returns the child module nodes declared in parent's source.
func findModDecls(root *tree_sitter.Node, src []byte, parent moduleNode, crateRoot string) []moduleNode {
	var out []moduleNode
	// mod_item nodes are top-level declarations. They appear as children
	// of source_file or nested inside other mod_item declaration_list children.
	walkTopLevel(root, func(node *tree_sitter.Node) {
		if node.Kind() != "mod_item" {
			return
		}
		name := modItemName(node, src)
		if name == "" {
			return
		}
		isPub := parent.isPublic && isPubVis(node, src)
		// Inline mod: has a declaration_list child. File resolution is not
		// needed; child items are emitted by the walker's deeper pass in
		// the canonical-emission task (Task 14). For the tree walker alone,
		// we skip inline modules because there is no distinct file.
		if hasDeclarationList(node) {
			return
		}
		// File-backed mod: try <parentDir>/<name>.rs, then
		// <parentDir>/<name>/mod.rs.
		parentDir := filepath.Dir(parent.file)
		// lib.rs and mod.rs use crate-root-relative resolution; foo.rs at
		// src/foo.rs has children at src/foo/<child>.rs.
		parentBase := filepath.Base(parent.file)
		if parentBase != "lib.rs" && parentBase != "main.rs" && parentBase != "mod.rs" {
			parentName := strings.TrimSuffix(parentBase, ".rs")
			parentDir = filepath.Join(parentDir, parentName)
		}

		candidates := []string{
			filepath.Join(parentDir, name+".rs"),
			filepath.Join(parentDir, name, "mod.rs"),
		}
		var file string
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				file = c
				break
			}
		}
		if file == "" {
			return
		}

		childPath := name
		if parent.path != "" {
			childPath = parent.path + "." + name
		}
		out = append(out, moduleNode{
			path:     childPath,
			file:     file,
			isPublic: isPub,
		})
	})
	return out
}

// walkTopLevel applies fn to every direct child of root (source_file).
func walkTopLevel(root *tree_sitter.Node, fn func(*tree_sitter.Node)) {
	for i := uint(0); i < root.ChildCount(); i++ {
		child := root.Child(i)
		if child == nil {
			continue
		}
		fn(child)
	}
}

// modItemName returns the identifier name of a mod_item node.
func modItemName(node *tree_sitter.Node, src []byte) string {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "identifier" {
			return child.Utf8Text(src)
		}
	}
	return ""
}

// isPubVis reports whether node has a visibility_modifier whose text is "pub".
func isPubVis(node *tree_sitter.Node, src []byte) bool {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil || child.Kind() != "visibility_modifier" {
			continue
		}
		if strings.TrimSpace(child.Utf8Text(src)) == "pub" {
			return true
		}
	}
	return false
}

// hasDeclarationList reports whether a mod_item has an inline body.
func hasDeclarationList(node *tree_sitter.Node) bool {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "declaration_list" {
			return true
		}
	}
	return false
}

// collectTopLevelPublicFns appends a canonical key for every direct-child
// `pub fn` in root to keys. This is a placeholder for the full canonical-
// emission pass added in Task 14.
func collectTopLevelPublicFns(root *tree_sitter.Node, src []byte, packageName, modPath string, keys map[string]struct{}) {
	base := packageName
	if modPath != "" {
		base = packageName + "." + modPath
	}
	for i := uint(0); i < root.ChildCount(); i++ {
		node := root.Child(i)
		if node == nil || node.Kind() != "function_item" {
			continue
		}
		if !isPubVis(node, src) {
			continue
		}
		name := findFnName(node, src)
		if name == "" {
			continue
		}
		keys[base+"."+name] = struct{}{}
	}
}

// findFnName returns the identifier child of a function_item node.
func findFnName(node *tree_sitter.Node, src []byte) string {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "identifier" {
			return child.Utf8Text(src)
		}
	}
	return ""
}

// ensureFSStat returns the fs.FileInfo for path or an error, using os.Stat.
// Unused helper kept for future error-classification work.
var _ = func(path string) (fs.FileInfo, error) { return os.Stat(path) }
```

- [ ] **Step 4: Run the tests and verify they pass**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -run TestListExports_ -v
```
Expected: PASS on `TestListExports_NoLibraryAPI`, `TestListExports_SimpleLibrary`, `TestListExports_FileBackedSubmodule`, `TestListExports_SubmoduleAsModRs`, `TestListExports_PrivateModuleExcluded`, `TestListExports_NestedSubmodules`.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/languages/rust/exports.go pkg/vex/reachability/transitive/languages/rust/exports_test.go
git commit -m "feat(transitive/rust): add ListExports module tree walker"
```

---

### Task 14: Canonical export emission — structs, enums, traits, inherent + trait impl methods

This task replaces the `collectTopLevelPublicFns` placeholder from Task 13 with a full canonical-emission pass that covers every symbol kind.

**Files:**
- Modify: `pkg/vex/reachability/transitive/languages/rust/exports.go`
- Modify: `pkg/vex/reachability/transitive/languages/rust/exports_test.go`

- [ ] **Step 1: Write failing tests for the remaining item kinds**

Append to `pkg/vex/reachability/transitive/languages/rust/exports_test.go`:

```go
func TestListExports_StructsEnumsTraits(t *testing.T) {
	root := writeCrate(t, "kinds", "0.1.0", map[string]string{
		"src/lib.rs": `pub struct Request;
struct PrivateReq;
pub enum Status { Ok, Err }
enum PrivateStatus { A }
pub trait Handler { fn handle(&self); }
trait PrivateTrait { fn x(&self); }
`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "kinds")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"kinds.Request": true,
		"kinds.Status":  true,
		"kinds.Handler": true,
		// Trait required-method: emitted as kinds.Handler.handle because
		// the trait itself is public, so downstream callers can reach it.
		"kinds.Handler.handle": true,
	}
	assertKeys(t, got, want)
}

func TestListExports_InherentImplMethods(t *testing.T) {
	root := writeCrate(t, "inh", "0.1.0", map[string]string{
		"src/lib.rs": `pub struct Server;

impl Server {
    pub fn serve(&self) {}
    fn internal(&self) {}
}

struct PrivateServer;
impl PrivateServer {
    pub fn unreachable(&self) {}
}
`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "inh")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"inh.Server":       true,
		"inh.Server.serve": true,
	}
	assertKeys(t, got, want)
}

func TestListExports_TraitImplMethodsOnPublicType(t *testing.T) {
	root := writeCrate(t, "trimpl", "0.1.0", map[string]string{
		"src/lib.rs": `pub struct Reader;
pub trait Read { fn read(&self); }
impl Read for Reader {
    fn read(&self) {}
}
`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "trimpl")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"trimpl.Reader":      true,
		"trimpl.Read":        true,
		"trimpl.Read.read":   true,
		"trimpl.Reader.read": true,
	}
	assertKeys(t, got, want)
}

func TestListExports_TraitImplOnPrivateTypeExcluded(t *testing.T) {
	root := writeCrate(t, "hidden", "0.1.0", map[string]string{
		"src/lib.rs": `pub trait Run { fn run(&self); }
struct Private;
impl Run for Private {
    fn run(&self) {}
}
`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "hidden")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"hidden.Run":     true,
		"hidden.Run.run": true,
	}
	assertKeys(t, got, want)
}
```

- [ ] **Step 2: Run the tests and verify they fail**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -run "TestListExports_StructsEnumsTraits|TestListExports_InherentImplMethods|TestListExports_TraitImplMethodsOnPublicType|TestListExports_TraitImplOnPrivateTypeExcluded" -v
```
Expected: FAIL on at least one — the placeholder only emits functions.

- [ ] **Step 3: Replace the placeholder emission with a full canonical pass**

In `pkg/vex/reachability/transitive/languages/rust/exports.go`, delete the existing `collectTopLevelPublicFns` function and replace it with the following full canonical-emission function. Also modify `ListExports` to call `emitCanonical` instead of `collectTopLevelPublicFns`.

Replace the body of `ListExports` (the `for _, m := range modules { ... }` loop) with:

```go
	// Pass 1: collect all public type names per module for trait-impl gating.
	publicTypes := make(map[string]bool) // "<modPath>.<TypeName>"
	for _, m := range modules {
		if !m.isPublic {
			continue
		}
		src, err := os.ReadFile(m.file)
		if err != nil {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}
		collectPublicTypeNames(tree.RootNode(), src, packageName, m.path, publicTypes)
		tree.Close()
	}

	// Pass 2: emit canonical keys, gated by publicTypes for trait impls.
	for _, m := range modules {
		if !m.isPublic {
			continue
		}
		src, err := os.ReadFile(m.file)
		if err != nil {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}
		emitCanonical(tree.RootNode(), src, packageName, m.path, publicTypes, keys)
		tree.Close()
	}
```

Then add these helpers at the end of the file (replacing the now-deleted `collectTopLevelPublicFns`):

```go
// basePath returns the canonical module prefix for a given module path
// relative to packageName. Empty modPath collapses to packageName itself.
func basePath(packageName, modPath string) string {
	if modPath == "" {
		return packageName
	}
	return packageName + "." + modPath
}

// collectPublicTypeNames records every `pub struct`, `pub enum`, and
// `pub trait` name in root into publicTypes. Keys are "<modPath>.<Name>"
// (or "<packageName>.<Name>" at crate root).
func collectPublicTypeNames(root *tree_sitter.Node, src []byte, packageName, modPath string, publicTypes map[string]bool) {
	base := basePath(packageName, modPath)
	for i := uint(0); i < root.ChildCount(); i++ {
		node := root.Child(i)
		if node == nil {
			continue
		}
		switch node.Kind() {
		case "struct_item", "enum_item", "trait_item":
			if !isPubVis(node, src) {
				continue
			}
			name := findTypeIdent(node, src)
			if name == "" {
				continue
			}
			publicTypes[base+"."+name] = true
		}
	}
}

// emitCanonical walks root and writes a canonical export key into keys
// for every public item discoverable at this module scope. Trait-impl
// method emission is gated by whether the implementing Type is itself in
// publicTypes (same crate) — this implements the reachability constraint
// from section 4.2 of the spec.
//
//nolint:gocognit,gocyclo // multi-node-kind emission; splitting would obscure flow
func emitCanonical(root *tree_sitter.Node, src []byte, packageName, modPath string, publicTypes map[string]bool, keys map[string]struct{}) {
	base := basePath(packageName, modPath)
	for i := uint(0); i < root.ChildCount(); i++ {
		node := root.Child(i)
		if node == nil {
			continue
		}
		switch node.Kind() {
		case "function_item":
			if !isPubVis(node, src) {
				continue
			}
			name := findFnName(node, src)
			if name != "" {
				keys[base+"."+name] = struct{}{}
			}

		case "struct_item", "enum_item":
			if !isPubVis(node, src) {
				continue
			}
			name := findTypeIdent(node, src)
			if name != "" {
				keys[base+"."+name] = struct{}{}
			}

		case "trait_item":
			if !isPubVis(node, src) {
				continue
			}
			traitName := findTypeIdent(node, src)
			if traitName == "" {
				continue
			}
			keys[base+"."+traitName] = struct{}{}
			// Emit required methods on the trait.
			emitTraitBody(node, src, base+"."+traitName, keys)

		case "impl_item":
			emitImpl(node, src, base, publicTypes, keys)
		}
	}
}

// findTypeIdent returns the type_identifier child of a type-defining node.
func findTypeIdent(node *tree_sitter.Node, src []byte) string {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "type_identifier" {
			return child.Utf8Text(src)
		}
	}
	return ""
}

// emitTraitBody emits a key per method defined in the trait's declaration_list.
func emitTraitBody(traitNode *tree_sitter.Node, src []byte, traitKey string, keys map[string]struct{}) {
	for i := uint(0); i < traitNode.ChildCount(); i++ {
		body := traitNode.Child(i)
		if body == nil || body.Kind() != "declaration_list" {
			continue
		}
		for j := uint(0); j < body.ChildCount(); j++ {
			item := body.Child(j)
			if item == nil {
				continue
			}
			switch item.Kind() {
			case "function_signature_item", "function_item":
				name := findFnName(item, src)
				if name != "" {
					keys[traitKey+"."+name] = struct{}{}
				}
			}
		}
	}
}

// emitImpl emits method keys for an impl_item. For inherent impls
// `impl Type { pub fn m() }` the method is emitted as `<base>.<Type>.<m>`
// when the method is `pub`. For trait impls `impl Trait for Type { fn m() }`
// every method is emitted unconditionally, but only when the implementing
// Type is itself a public type in the same crate (tracked in publicTypes).
//
//nolint:gocognit,gocyclo // impl header parsing + body emission
func emitImpl(node *tree_sitter.Node, src []byte, base string, publicTypes map[string]bool, keys map[string]struct{}) {
	// Parse the impl header to determine trait vs inherent and the type name.
	var traitName, typeName string
	hasFOR := false
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "type_identifier":
			if typeName == "" && traitName == "" {
				typeName = child.Utf8Text(src)
			} else if hasFOR {
				typeName = child.Utf8Text(src)
			}
		case "for":
			hasFOR = true
			traitName = typeName
			typeName = ""
		}
	}
	if typeName == "" {
		return
	}

	isTraitImpl := traitName != ""
	typeKey := base + "." + typeName

	// For trait impls, gate on publicTypes (only emit when the implementing
	// type is itself publicly reachable). For inherent impls, skip unless the
	// type is public — otherwise the caller can never hold a value of that
	// type to invoke the method.
	if !publicTypes[typeKey] {
		return
	}

	for i := uint(0); i < node.ChildCount(); i++ {
		body := node.Child(i)
		if body == nil || body.Kind() != "declaration_list" {
			continue
		}
		for j := uint(0); j < body.ChildCount(); j++ {
			item := body.Child(j)
			if item == nil || item.Kind() != "function_item" {
				continue
			}
			methodName := findFnName(item, src)
			if methodName == "" {
				continue
			}
			if isTraitImpl {
				keys[typeKey+"."+methodName] = struct{}{}
				continue
			}
			// Inherent impl: require `pub fn`.
			if isPubVis(item, src) {
				keys[typeKey+"."+methodName] = struct{}{}
			}
		}
	}
}
```

Finally remove the now-orphan `var _ = func(path string) (fs.FileInfo, error) { return os.Stat(path) }` line and the `io/fs` import if it was the only user.

- [ ] **Step 4: Run the tests and verify they pass**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -run TestListExports_ -v
```
Expected: all `TestListExports_*` sub-tests pass, including the four new cases.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/languages/rust/exports.go pkg/vex/reachability/transitive/languages/rust/exports_test.go
git commit -m "feat(transitive/rust): emit canonical exports for structs, enums, traits, and impls"
```

---

### Task 15: Re-export (`pub use`) resolution with fixed-point chaining

**Files:**
- Modify: `pkg/vex/reachability/transitive/languages/rust/exports.go`
- Modify: `pkg/vex/reachability/transitive/languages/rust/exports_test.go`

- [ ] **Step 1: Write failing tests for each `pub use` form**

Append to `pkg/vex/reachability/transitive/languages/rust/exports_test.go`:

```go
func TestListExports_SimpleReExport(t *testing.T) {
	root := writeCrate(t, "reexp", "0.1.0", map[string]string{
		"src/lib.rs":   `pub mod inner; pub use inner::Thing;`,
		"src/inner.rs": `pub struct Thing;`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "reexp")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"reexp.inner.Thing": true,
		"reexp.Thing":       true,
	}
	assertKeys(t, got, want)
}

func TestListExports_GroupedReExport(t *testing.T) {
	root := writeCrate(t, "reexp", "0.1.0", map[string]string{
		"src/lib.rs":   `pub mod inner; pub use inner::{Foo, Bar};`,
		"src/inner.rs": `pub struct Foo; pub struct Bar;`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "reexp")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"reexp.inner.Foo": true,
		"reexp.inner.Bar": true,
		"reexp.Foo":       true,
		"reexp.Bar":       true,
	}
	assertKeys(t, got, want)
}

func TestListExports_AliasedReExport(t *testing.T) {
	root := writeCrate(t, "reexp", "0.1.0", map[string]string{
		"src/lib.rs":   `pub mod inner; pub use inner::Thing as Renamed;`,
		"src/inner.rs": `pub struct Thing;`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "reexp")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"reexp.inner.Thing": true,
		"reexp.Renamed":     true,
	}
	assertKeys(t, got, want)
}

func TestListExports_WildcardReExport(t *testing.T) {
	root := writeCrate(t, "reexp", "0.1.0", map[string]string{
		"src/lib.rs":   `pub mod inner; pub use inner::*;`,
		"src/inner.rs": `pub struct Foo; pub struct Bar; pub fn run() {}`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "reexp")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"reexp.inner.Foo": true,
		"reexp.inner.Bar": true,
		"reexp.inner.run": true,
		"reexp.Foo":       true,
		"reexp.Bar":       true,
		"reexp.run":       true,
	}
	assertKeys(t, got, want)
}

func TestListExports_ChainedReExport(t *testing.T) {
	// `pub use b::Thing;` in lib.rs, `pub use a::Thing;` re-emits from a,
	// `pub struct Thing;` in a itself. All three paths must appear.
	root := writeCrate(t, "chain", "0.1.0", map[string]string{
		"src/lib.rs": `pub mod a; pub mod b; pub use b::Thing;`,
		"src/a.rs":   `pub struct Thing;`,
		"src/b.rs":   `pub use crate::a::Thing;`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "chain")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"chain.a.Thing": true,
		"chain.b.Thing": true,
		"chain.Thing":   true,
	}
	assertKeys(t, got, want)
}

func TestListExports_ForeignReExportExcluded(t *testing.T) {
	// `pub use serde::Serialize;` should NOT contribute a crate.Serialize key —
	// that symbol belongs to serde, not us.
	root := writeCrate(t, "norelay", "0.1.0", map[string]string{
		"src/lib.rs": `pub use serde::Serialize; pub fn go() {}`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "norelay")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	gotSet := make(map[string]bool, len(got))
	for _, k := range got {
		gotSet[k] = true
	}
	if gotSet["norelay.Serialize"] {
		t.Error("foreign re-export leaked as norelay.Serialize")
	}
	if !gotSet["norelay.go"] {
		t.Error("missing norelay.go")
	}
}
```

- [ ] **Step 2: Run the tests and verify they fail**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -run "TestListExports_SimpleReExport|TestListExports_GroupedReExport|TestListExports_AliasedReExport|TestListExports_WildcardReExport|TestListExports_ChainedReExport|TestListExports_ForeignReExportExcluded" -v
```
Expected: FAIL — re-exports are not yet collected.

- [ ] **Step 3: Extend `ListExports` with a re-export collection pass and fixed-point resolver**

In `pkg/vex/reachability/transitive/languages/rust/exports.go`, modify `ListExports` so that after the canonical emission pass, it performs a re-export pass. Replace `ListExports` body with the following (keeping `findLibRS` and `walkModuleTree` calls at the top):

```go
func (l *Language) ListExports(sourceDir, packageName string) ([]string, error) {
	crateRoot, libRS, err := findLibRS(sourceDir, packageName)
	if err != nil {
		return nil, err
	}

	modules, err := walkModuleTree(crateRoot, libRS)
	if err != nil {
		return nil, err
	}

	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(grammarrust.Language())); err != nil {
		return nil, err
	}

	// Pass 1: collect public type names (for trait-impl gating).
	publicTypes := make(map[string]bool)
	// Pass 2 will need the parsed trees again, so memoize src per module.
	sources := make(map[string][]byte, len(modules))

	for _, m := range modules {
		if !m.isPublic {
			continue
		}
		src, err := os.ReadFile(m.file)
		if err != nil {
			continue
		}
		sources[m.file] = src
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}
		collectPublicTypeNames(tree.RootNode(), src, packageName, m.path, publicTypes)
		tree.Close()
	}

	// Pass 2: emit canonical keys.
	keys := make(map[string]struct{})
	// canonicalByName maps "<modPath>.<Name>" → "<packageName>.<modPath>.<Name>"
	// so the re-export resolver can look up the canonical target form given
	// a resolved absolute path. In this canonical-first design, canonicalByName
	// is simply `packageName + "." + k for k in publicTypes keys` plus one entry
	// per public function/method emitted below, recorded via a callback.
	canonicalByName := make(map[string]string)

	for _, m := range modules {
		if !m.isPublic {
			continue
		}
		src, ok := sources[m.file]
		if !ok {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}
		emitCanonicalRecord(tree.RootNode(), src, packageName, m.path, publicTypes, keys, canonicalByName)
		tree.Close()
	}

	// Pass 3: re-export collection. Each `pub use` in a publicly accessible
	// module produces zero or more edges (publicPath → canonicalPath).
	var edges []reExportEdge
	for _, m := range modules {
		if !m.isPublic {
			continue
		}
		src, ok := sources[m.file]
		if !ok {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}
		edges = append(edges, collectPubUseEdges(tree.RootNode(), src, packageName, m.path, canonicalByName, publicTypes)...)
		tree.Close()
	}

	// Pass 4: fixed-point chain resolution. publicPaths[canonicalKey] is the
	// set of public paths that resolve to canonicalKey.
	publicPaths := make(map[string]map[string]struct{})
	for _, e := range edges {
		if _, ok := publicPaths[e.canonical]; !ok {
			publicPaths[e.canonical] = make(map[string]struct{})
		}
		publicPaths[e.canonical][e.publicPath] = struct{}{}
	}
	// Iterate: if canonical = X also has a publicPaths entry under some other
	// canonical Y (i.e. a chain), merge Y's public paths into X's.
	for changed := true; changed; {
		changed = false
		for canonicalA, pathsA := range publicPaths {
			// Does pathsA contain a path that is itself a canonical key?
			for p := range pathsA {
				if pathsA2, ok := publicPaths[p]; ok && p != canonicalA {
					for p2 := range pathsA2 {
						if _, exists := publicPaths[canonicalA][p2]; !exists {
							publicPaths[canonicalA][p2] = struct{}{}
							changed = true
						}
					}
				}
			}
		}
	}

	// Emit every resolved public path as a key.
	for _, paths := range publicPaths {
		for p := range paths {
			keys[p] = struct{}{}
		}
	}

	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	return out, nil
}

// reExportEdge maps a publicly visible path (after re-export) to the
// canonical crate path of the underlying symbol.
type reExportEdge struct {
	publicPath string
	canonical  string
}
```

Replace `emitCanonical` with `emitCanonicalRecord` that additionally populates `canonicalByName`:

```go
//nolint:gocognit,gocyclo // multi-kind emission
func emitCanonicalRecord(
	root *tree_sitter.Node,
	src []byte,
	packageName, modPath string,
	publicTypes map[string]bool,
	keys map[string]struct{},
	canonicalByName map[string]string,
) {
	base := basePath(packageName, modPath)
	record := func(key string) {
		keys[key] = struct{}{}
		// Strip the packageName prefix to produce a relative lookup key.
		if strings.HasPrefix(key, packageName+".") {
			canonicalByName[key[len(packageName)+1:]] = key
		} else if key == packageName {
			canonicalByName[""] = key
		}
	}

	for i := uint(0); i < root.ChildCount(); i++ {
		node := root.Child(i)
		if node == nil {
			continue
		}
		switch node.Kind() {
		case "function_item":
			if !isPubVis(node, src) {
				continue
			}
			name := findFnName(node, src)
			if name != "" {
				record(base + "." + name)
			}
		case "struct_item", "enum_item":
			if !isPubVis(node, src) {
				continue
			}
			name := findTypeIdent(node, src)
			if name != "" {
				record(base + "." + name)
			}
		case "trait_item":
			if !isPubVis(node, src) {
				continue
			}
			traitName := findTypeIdent(node, src)
			if traitName == "" {
				continue
			}
			record(base + "." + traitName)
			// Emit required methods.
			for i2 := uint(0); i2 < node.ChildCount(); i2++ {
				body := node.Child(i2)
				if body == nil || body.Kind() != "declaration_list" {
					continue
				}
				for j := uint(0); j < body.ChildCount(); j++ {
					item := body.Child(j)
					if item == nil {
						continue
					}
					if item.Kind() == "function_signature_item" || item.Kind() == "function_item" {
						mn := findFnName(item, src)
						if mn != "" {
							record(base + "." + traitName + "." + mn)
						}
					}
				}
			}
		case "impl_item":
			emitImplRecord(node, src, base, publicTypes, record)
		}
	}
}

func emitImplRecord(node *tree_sitter.Node, src []byte, base string, publicTypes map[string]bool, record func(string)) {
	var traitName, typeName string
	hasFOR := false
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "type_identifier":
			if typeName == "" && traitName == "" {
				typeName = child.Utf8Text(src)
			} else if hasFOR {
				typeName = child.Utf8Text(src)
			}
		case "for":
			hasFOR = true
			traitName = typeName
			typeName = ""
		}
	}
	if typeName == "" {
		return
	}
	isTraitImpl := traitName != ""
	typeKey := base + "." + typeName
	if !publicTypes[typeKey] {
		return
	}
	for i := uint(0); i < node.ChildCount(); i++ {
		body := node.Child(i)
		if body == nil || body.Kind() != "declaration_list" {
			continue
		}
		for j := uint(0); j < body.ChildCount(); j++ {
			item := body.Child(j)
			if item == nil || item.Kind() != "function_item" {
				continue
			}
			mn := findFnName(item, src)
			if mn == "" {
				continue
			}
			if isTraitImpl || isPubVis(item, src) {
				record(typeKey + "." + mn)
			}
		}
	}
}
```

Delete the old `emitCanonical` and `emitImpl` definitions (they are replaced by `emitCanonicalRecord` and `emitImplRecord`).

Now add the re-export collection helpers at the end of the file:

```go
// collectPubUseEdges scans a module for `pub use` declarations and emits
// reExportEdge records for every alias that resolves to a same-crate symbol.
// Foreign re-exports (where the path root is neither packageName, `crate`,
// `self`, nor `super`) are skipped — those belong to the foreign crate's
// key space.
//
//nolint:gocognit,gocyclo // multi-form use declaration handling
func collectPubUseEdges(
	root *tree_sitter.Node,
	src []byte,
	packageName, modPath string,
	canonicalByName map[string]string,
	publicTypes map[string]bool,
) []reExportEdge {
	var edges []reExportEdge
	base := basePath(packageName, modPath)

	for i := uint(0); i < root.ChildCount(); i++ {
		node := root.Child(i)
		if node == nil || node.Kind() != "use_declaration" {
			continue
		}
		if !isPubVis(node, src) {
			continue
		}
		// Find the first non-"pub" / non-"use" / non-";" child; that's the
		// path body.
		for j := uint(0); j < node.ChildCount(); j++ {
			body := node.Child(j)
			if body == nil {
				continue
			}
			switch body.Kind() {
			case "scoped_identifier":
				// pub use foo::bar::Baz;
				fullPath := body.Utf8Text(src)
				publicAlias := lastPathSegment(fullPath)
				edges = appendResolvedReExport(edges, fullPath, publicAlias,
					packageName, modPath, base, canonicalByName, publicTypes)
			case "scoped_use_list":
				// pub use foo::bar::{A, B, C};
				edges = append(edges, resolveUseList(body, src, packageName, modPath, base, canonicalByName, publicTypes)...)
			case "use_as_clause":
				// pub use foo::bar::Baz as Renamed;
				edges = append(edges, resolveUseAs(body, src, packageName, modPath, base, canonicalByName, publicTypes)...)
			case "use_wildcard":
				// pub use foo::bar::*;
				edges = append(edges, resolveUseWildcard(body, src, packageName, modPath, base, canonicalByName, publicTypes)...)
			case "identifier":
				// pub use bar;
				name := body.Utf8Text(src)
				edges = appendResolvedReExport(edges, name, name,
					packageName, modPath, base, canonicalByName, publicTypes)
			}
		}
	}
	return edges
}

// lastPathSegment returns the final `::`-separated component of a path.
func lastPathSegment(path string) string {
	if idx := strings.LastIndex(path, "::"); idx >= 0 {
		return path[idx+2:]
	}
	return path
}

// resolveRelativePath converts a `::`-path from a `pub use` declaration
// into a dotted canonical key, or returns ("", false) if the path roots
// outside the current crate. Handles `self::`, `super::`, `crate::`, and
// same-crate absolute paths (starting with packageName).
func resolveRelativePath(path, packageName, modPath string) (string, bool) {
	p := strings.ReplaceAll(path, "::", ".")
	switch {
	case strings.HasPrefix(p, "crate."):
		return p[len("crate."):], true
	case p == "crate":
		return "", true
	case strings.HasPrefix(p, "self."):
		rest := p[len("self."):]
		if modPath == "" {
			return rest, true
		}
		return modPath + "." + rest, true
	case strings.HasPrefix(p, "super."):
		parentMod := parentModulePath(modPath)
		rest := p[len("super."):]
		if parentMod == "" {
			return rest, true
		}
		return parentMod + "." + rest, true
	}
	// Absolute same-crate form (rare but legal in 2015 edition): starts
	// with packageName. Strip the crate prefix.
	if strings.HasPrefix(p, packageName+".") {
		return p[len(packageName)+1:], true
	}
	// Bare module path same-crate form (2018 edition): the first segment
	// matches a module declared in this crate. We proxy this with a
	// check: if the first segment equals modPath's first segment or any
	// sibling known to be public, treat as same-crate. For simplicity
	// we handle the common case where the first segment equals the
	// same-crate top-level module by assuming any path whose first
	// segment is NOT a well-known external crate name could be same-crate.
	// The caller then does a canonicalByName lookup; if that lookup misses,
	// the edge is dropped, so false positives are filtered out.
	return p, true
}

// parentModulePath returns the dotted parent of a module path.
// "a.b.c" → "a.b"; "a" → ""; "" → "".
func parentModulePath(modPath string) string {
	if modPath == "" {
		return ""
	}
	if idx := strings.LastIndex(modPath, "."); idx >= 0 {
		return modPath[:idx]
	}
	return ""
}

// appendResolvedReExport resolves sourcePath against the current module
// context and, if it maps to a known canonical key, appends an edge from
// the public path to that canonical.
func appendResolvedReExport(
	edges []reExportEdge,
	sourcePath, publicAlias, packageName, modPath, base string,
	canonicalByName map[string]string,
	publicTypes map[string]bool,
) []reExportEdge {
	relLookup, ok := resolveRelativePath(sourcePath, packageName, modPath)
	if !ok {
		return edges
	}
	canonicalKey, known := canonicalByName[relLookup]
	if !known {
		return edges
	}
	publicPath := base + "." + publicAlias
	return append(edges, reExportEdge{publicPath: publicPath, canonical: canonicalKey})
}

// resolveUseList handles `pub use prefix::{A, B, C}` by emitting one edge
// per item in the use_list.
func resolveUseList(
	node *tree_sitter.Node,
	src []byte,
	packageName, modPath, base string,
	canonicalByName map[string]string,
	publicTypes map[string]bool,
) []reExportEdge {
	var prefix string
	var edges []reExportEdge
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "scoped_identifier", "identifier", "crate":
			prefix = child.Utf8Text(src)
		case "use_list":
			for j := uint(0); j < child.ChildCount(); j++ {
				item := child.Child(j)
				if item == nil {
					continue
				}
				switch item.Kind() {
				case "identifier":
					name := item.Utf8Text(src)
					edges = appendResolvedReExport(edges, prefix+"::"+name, name,
						packageName, modPath, base, canonicalByName, publicTypes)
				case "scoped_identifier":
					full := item.Utf8Text(src)
					alias := lastPathSegment(full)
					edges = appendResolvedReExport(edges, prefix+"::"+full, alias,
						packageName, modPath, base, canonicalByName, publicTypes)
				case "use_as_clause":
					// Nested `Foo as Bar` inside a use_list — handle by
					// extracting the inner identifier + alias.
					inner, rename := extractUseAsInner(item, src)
					if inner == "" {
						continue
					}
					edges = appendResolvedReExport(edges, prefix+"::"+inner, rename,
						packageName, modPath, base, canonicalByName, publicTypes)
				}
			}
		}
	}
	return edges
}

// extractUseAsInner returns (innerPath, alias) for a use_as_clause node.
func extractUseAsInner(node *tree_sitter.Node, src []byte) (string, string) {
	var inner, alias string
	sawAs := false
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "scoped_identifier":
			inner = child.Utf8Text(src)
		case "as":
			sawAs = true
		case "identifier":
			if sawAs {
				alias = child.Utf8Text(src)
			} else if inner == "" {
				inner = child.Utf8Text(src)
			}
		}
	}
	if alias == "" {
		alias = lastPathSegment(inner)
	}
	return inner, alias
}

// resolveUseAs handles `pub use foo::bar::Baz as Renamed;`.
func resolveUseAs(
	node *tree_sitter.Node,
	src []byte,
	packageName, modPath, base string,
	canonicalByName map[string]string,
	publicTypes map[string]bool,
) []reExportEdge {
	inner, alias := extractUseAsInner(node, src)
	if inner == "" {
		return nil
	}
	return appendResolvedReExport(nil, inner, alias,
		packageName, modPath, base, canonicalByName, publicTypes)
}

// resolveUseWildcard handles `pub use foo::bar::*;` by emitting one edge per
// canonical symbol whose canonical key starts with the resolved prefix.
func resolveUseWildcard(
	node *tree_sitter.Node,
	src []byte,
	packageName, modPath, base string,
	canonicalByName map[string]string,
	publicTypes map[string]bool,
) []reExportEdge {
	var prefixRaw string
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "scoped_identifier" || child.Kind() == "identifier" {
			prefixRaw = child.Utf8Text(src)
			break
		}
	}
	if prefixRaw == "" {
		return nil
	}
	rel, ok := resolveRelativePath(prefixRaw, packageName, modPath)
	if !ok {
		return nil
	}
	// Scan canonicalByName for keys that begin with rel + ".".
	var edges []reExportEdge
	relPrefix := rel + "."
	for canonicalRel, canonicalFull := range canonicalByName {
		if !strings.HasPrefix(canonicalRel, relPrefix) {
			continue
		}
		// Only leaf items (not descendant modules) — the tail after the
		// prefix must be a single segment.
		tail := canonicalRel[len(relPrefix):]
		if strings.Contains(tail, ".") {
			continue
		}
		publicPath := base + "." + tail
		edges = append(edges, reExportEdge{publicPath: publicPath, canonical: canonicalFull})
	}
	return edges
}
```

- [ ] **Step 4: Run the tests and verify they pass**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -run TestListExports_ -v
```
Expected: all `TestListExports_*` tests (Tasks 13–15) pass.

- [ ] **Step 5: Run the full rust language package test suite**

```
go test ./pkg/vex/reachability/transitive/languages/rust/... -v
```
Expected: all tests pass.

- [ ] **Step 6: Commit**

```
git add pkg/vex/reachability/transitive/languages/rust/exports.go pkg/vex/reachability/transitive/languages/rust/exports_test.go
git commit -m "feat(transitive/rust): resolve pub use re-exports with fixed-point chaining"
```

---

## Phase 4 — Registration, fetcher, and wire

### Task 16: Register `rust` in `LanguageFor` and extend contract tests

**Files:**
- Modify: `pkg/vex/reachability/transitive/language.go`
- Modify: `pkg/vex/reachability/transitive/language_test.go`

- [ ] **Step 1: Extend the registry test**

Modify `pkg/vex/reachability/transitive/language_test.go`:

Add `{"rust", "rust", "crates.io"}`, `{"Rust", "rust", "crates.io"}`, and `{"RUST", "rust", "crates.io"}` to the `TestLanguageFor_RegisteredLanguages` table.

Remove `{"rust"}` from the `TestLanguageFor_UnknownLanguage` table.

Add `"rust"` to the `registered` slice in `TestLanguageSupport_Contract`.

- [ ] **Step 2: Run the tests and verify they fail**

```
go test ./pkg/vex/reachability/transitive/... -run "TestLanguageFor_RegisteredLanguages|TestLanguageSupport_Contract|TestLanguageFor_UnknownLanguage" -v
```
Expected: `TestLanguageFor_RegisteredLanguages` fails on the new rust rows; `TestLanguageSupport_Contract` fails on the `rust` sub-test; `TestLanguageFor_UnknownLanguage` passes.

- [ ] **Step 3: Register `rust` in `LanguageFor`**

In `pkg/vex/reachability/transitive/language.go`, modify the `LanguageFor` switch:

```go
func LanguageFor(name string) (LanguageSupport, error) {
	switch strings.ToLower(name) {
	case "python":
		return python.New(), nil
	case "javascript", "js":
		return javascript.New(), nil
	case "rust":
		return rust.New(), nil
	}
	return nil, fmt.Errorf("unsupported language %q", name)
}
```

Add the import:

```go
import (
	// ... existing imports ...
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/rust"
)
```

- [ ] **Step 4: Run the tests and verify they pass**

```
go test ./pkg/vex/reachability/transitive/... -run "TestLanguageFor_RegisteredLanguages|TestLanguageSupport_Contract|TestLanguageFor_UnknownLanguage" -v
```
Expected: all pass.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/language.go pkg/vex/reachability/transitive/language_test.go
git commit -m "feat(transitive): register rust language in LanguageFor"
```

---

### Task 17: Translate `ErrNoLibraryAPI` into `ReasonNoLibraryAPI`

**Files:**
- Modify: `pkg/vex/reachability/transitive/transitive.go`
- Modify: `pkg/vex/reachability/transitive/transitive_test.go`

- [ ] **Step 1: Write a failing test**

Append to `pkg/vex/reachability/transitive/transitive_test.go`:

```go
func TestCollectVulnSymbols_NoLibraryAPI(t *testing.T) {
	// Build an Analyzer whose Language returns ErrNoLibraryAPI from
	// ListExports. Use a minimal fake LanguageSupport + ExportLister.
	lang := &noLibAPILang{}
	a := &Analyzer{
		Config:   DefaultConfig(),
		Language: lang,
		Fetchers: map[string]Fetcher{"crates.io": &noLibAPIFetcher{}},
	}
	_, degradations := a.collectVulnSymbols(context.Background(), &formats.Finding{
		AffectedName:    "mycrate",
		AffectedVersion: "0.1.0",
	})
	for _, d := range degradations {
		if d == ReasonNoLibraryAPI {
			return
		}
	}
	t.Errorf("degradations = %v, want to contain %q", degradations, ReasonNoLibraryAPI)
}

type noLibAPILang struct{}

func (noLibAPILang) Name() string                            { return "rust" }
func (noLibAPILang) Ecosystem() string                       { return "crates.io" }
func (noLibAPILang) FileExtensions() []string                { return []string{".rs"} }
func (noLibAPILang) Grammar() unsafe.Pointer                 { return nil }
func (noLibAPILang) Extractor() treesitter.LanguageExtractor { return nil }
func (noLibAPILang) IsExportedSymbol(*treesitter.Symbol) bool { return false }
func (noLibAPILang) ModulePath(string, string, string) string { return "" }
func (noLibAPILang) SymbolKey(string, string) string          { return "" }
func (noLibAPILang) NormalizeImports(raw []treesitter.Import) []treesitter.Import {
	return raw
}
func (noLibAPILang) ResolveDottedTarget(string, string, *treesitter.Scope) (treesitter.SymbolID, bool) {
	return "", false
}
func (noLibAPILang) ResolveSelfCall(to, _ treesitter.SymbolID) treesitter.SymbolID {
	return to
}
func (noLibAPILang) ListExports(string, string) ([]string, error) {
	return nil, rust.ErrNoLibraryAPI
}

type noLibAPIFetcher struct{}

func (noLibAPIFetcher) Ecosystem() string { return "crates.io" }
func (noLibAPIFetcher) Fetch(_ context.Context, _, _ string, _ *Digest) (FetchResult, error) {
	return FetchResult{SourceDir: "/tmp/fake"}, nil
}
func (noLibAPIFetcher) Manifest(_ context.Context, _, _ string) (PackageManifest, error) {
	return PackageManifest{}, nil
}
```

Add the needed imports to `transitive_test.go` (if not already present):

```go
import (
	"context"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/rust"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)
```

- [ ] **Step 2: Run the test and verify it fails**

```
go test ./pkg/vex/reachability/transitive/... -run TestCollectVulnSymbols_NoLibraryAPI -v
```
Expected: FAIL — `collectVulnSymbols` currently swallows all errors under `ReasonExtractorError`.

- [ ] **Step 3: Update `extractExportedSymbols` to classify the error**

In `pkg/vex/reachability/transitive/transitive.go`, replace the body of `extractExportedSymbols`:

```go
func extractExportedSymbols(lang LanguageSupport, sourceDir, packageName string) (symbols, degradations []string) { //nolint:nonamedreturns // gocritic requires named returns
	syms, err := listExportedSymbols(lang, sourceDir, packageName)
	if err != nil {
		if errors.Is(err, rust.ErrNoLibraryAPI) {
			return nil, []string{ReasonNoLibraryAPI}
		}
		return nil, []string{ReasonExtractorError}
	}
	return syms, nil
}
```

Add the `errors` and `rust` imports at the top of `transitive.go`:

```go
import (
	// ... existing ...
	"errors"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/rust"
)
```

- [ ] **Step 4: Run the test and verify it passes**

```
go test ./pkg/vex/reachability/transitive/... -run TestCollectVulnSymbols_NoLibraryAPI -v
```
Expected: PASS.

- [ ] **Step 5: Run the full transitive test suite**

```
go test ./pkg/vex/reachability/transitive/...
```
Expected: all tests pass.

- [ ] **Step 6: Commit**

```
git add pkg/vex/reachability/transitive/transitive.go pkg/vex/reachability/transitive/transitive_test.go
git commit -m "feat(transitive): surface ReasonNoLibraryAPI for binary-only rust crates"
```

---

### Task 18: `CratesFetcher` — Ecosystem, Manifest, and contract skeleton

**Files:**
- Create: `pkg/vex/reachability/transitive/fetcher_crates.go`
- Create: `pkg/vex/reachability/transitive/fetcher_crates_test.go`

- [ ] **Step 1: Write a failing test**

Create `pkg/vex/reachability/transitive/fetcher_crates_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCratesFetcher_Ecosystem(t *testing.T) {
	f := &CratesFetcher{}
	if f.Ecosystem() != "crates.io" {
		t.Errorf("Ecosystem() = %q, want %q", f.Ecosystem(), "crates.io")
	}
}

func TestCratesFetcher_Manifest_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v1/crates/hyper/0.14.10"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"version": {
					"num": "0.14.10",
					"dl_path": "/api/v1/crates/hyper/0.14.10/download",
					"checksum": "0000000000000000000000000000000000000000000000000000000000000000"
				}
			}`))
		case strings.HasSuffix(r.URL.Path, "/api/v1/crates/hyper/0.14.10/dependencies"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"dependencies": [
					{"crate_id": "tokio", "req": "^1", "kind": "normal", "optional": false},
					{"crate_id": "mockito", "req": "^0.31", "kind": "dev", "optional": false},
					{"crate_id": "cc", "req": "^1", "kind": "build", "optional": false},
					{"crate_id": "tracing", "req": "^0.1", "kind": "normal", "optional": true}
				]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f := &CratesFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	m, err := f.Manifest(context.Background(), "hyper", "0.14.10")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	// Only normal deps should survive.
	if _, ok := m.Dependencies["tokio"]; !ok {
		t.Error("tokio not in dependencies")
	}
	if _, ok := m.Dependencies["mockito"]; ok {
		t.Error("mockito (dev) should have been filtered")
	}
	if _, ok := m.Dependencies["cc"]; ok {
		t.Error("cc (build) should have been filtered")
	}
	if _, ok := m.Dependencies["tracing"]; !ok {
		t.Error("tracing (optional but normal) should have been included")
	}
}

func TestCratesFetcher_Manifest_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	f := &CratesFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.Manifest(context.Background(), "nope", "0.0.1")
	if err == nil {
		t.Fatal("Manifest: expected error, got nil")
	}
}
```

- [ ] **Step 2: Run the tests and verify they fail**

```
go test ./pkg/vex/reachability/transitive/... -run TestCratesFetcher_ -v
```
Expected: FAIL — `CratesFetcher` type does not exist.

- [ ] **Step 3: Create `fetcher_crates.go`**

Create `pkg/vex/reachability/transitive/fetcher_crates.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// CratesFetcher implements Fetcher for the crates.io ecosystem. It uses the
// crates.io JSON API for metadata and dependency resolution, and downloads
// `.crate` tarballs from the path returned by the metadata endpoint.
type CratesFetcher struct {
	BaseURL    string // default https://crates.io
	HTTPClient *http.Client
	Cache      *Cache
}

// Ecosystem returns "crates.io".
func (f *CratesFetcher) Ecosystem() string { return "crates.io" }

func (f *CratesFetcher) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return http.DefaultClient
}

func (f *CratesFetcher) baseURL() string {
	if f.BaseURL != "" {
		return f.BaseURL
	}
	return "https://crates.io"
}

// cratesMeta is the subset of the crates.io crate-version metadata response
// we consume.
type cratesMeta struct {
	Version struct {
		Num      string `json:"num"`
		DlPath   string `json:"dl_path"`
		Checksum string `json:"checksum"`
	} `json:"version"`
}

// cratesDeps is the subset of the crates.io dependencies response.
type cratesDeps struct {
	Dependencies []struct {
		CrateID  string `json:"crate_id"`
		Req      string `json:"req"`
		Kind     string `json:"kind"`
		Optional bool   `json:"optional"`
	} `json:"dependencies"`
}

// Manifest fetches crate metadata and dependencies. Only `kind == "normal"`
// dependencies are returned; dev and build deps are filtered out because
// they do not appear in downstream compiled code.
func (f *CratesFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	var deps cratesDeps
	url := fmt.Sprintf("%s/api/v1/crates/%s/%s/dependencies", f.baseURL(), name, version)
	if err := httpGetJSON(ctx, f.client(), url, &deps); err != nil {
		return PackageManifest{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}
	out := make(map[string]string)
	for _, d := range deps.Dependencies {
		if d.Kind != "normal" {
			continue
		}
		out[d.CrateID] = d.Req
	}
	return PackageManifest{Dependencies: out}, nil
}

// fetchMeta retrieves the crate-version metadata (used for download URL and
// checksum).
func (f *CratesFetcher) fetchMeta(ctx context.Context, name, version string) (*cratesMeta, error) {
	var m cratesMeta
	url := fmt.Sprintf("%s/api/v1/crates/%s/%s", f.baseURL(), name, version)
	if err := httpGetJSON(ctx, f.client(), url, &m); err != nil {
		return nil, err
	}
	if m.Version.DlPath == "" {
		return nil, fmt.Errorf("%s: metadata missing dl_path for %s@%s", ReasonManifestFetchFailed, name, version)
	}
	return &m, nil
}

// Fetch is implemented in the next task.
func (f *CratesFetcher) Fetch(_ context.Context, _, _ string, _ *Digest) (FetchResult, error) {
	return FetchResult{}, fmt.Errorf("CratesFetcher.Fetch not yet implemented")
}

// crateHash is retained for symmetry with fetcher_pypi.go; it reuses the
// shared hashHex helper.
var crateHash = func(b []byte) string { return hex.EncodeToString(sha256Sum(b)) }

// sha256Sum is a tiny indirection so tests can stub hashing if needed.
func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// crateTarballURL composes an absolute URL from the dl_path returned by
// the crates.io metadata endpoint. dl_path is already prefixed with /.
func (f *CratesFetcher) crateTarballURL(dlPath string) string {
	return strings.TrimRight(f.baseURL(), "/") + dlPath
}

// crateCacheTmpDir creates an os.MkdirTemp for unpacking a crate tarball.
func crateCacheTmpDir() (string, error) { return os.MkdirTemp("", "crates-*") }

// crateInnerRoot returns the <name>-<version>/ directory beneath dst, which
// is the expected top-level structure of an unpacked `.crate` file.
func crateInnerRoot(dst, name, version string) string {
	return filepath.Join(dst, name+"-"+version)
}
```

- [ ] **Step 4: Run the tests and verify they pass**

```
go test ./pkg/vex/reachability/transitive/... -run TestCratesFetcher_ -v
```
Expected: PASS on `Ecosystem`, `Manifest_HappyPath`, and `Manifest_404`.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/fetcher_crates.go pkg/vex/reachability/transitive/fetcher_crates_test.go
git commit -m "feat(transitive): add CratesFetcher skeleton with Manifest and metadata helpers"
```

---

### Task 19: `CratesFetcher.Fetch` — download, verify, unpack, cache

**Files:**
- Modify: `pkg/vex/reachability/transitive/fetcher_crates.go`
- Modify: `pkg/vex/reachability/transitive/fetcher_crates_test.go`

- [ ] **Step 1: Write failing tests**

Append to `pkg/vex/reachability/transitive/fetcher_crates_test.go`:

```go
// buildTestCrate synthesizes a valid `.crate` (gzipped tar) containing
// a minimal src/lib.rs. Returns the raw bytes and its SHA-256 hex.
func buildTestCrate(t *testing.T, name, version, libContents string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	rootDir := name + "-" + version + "/"
	writeTarDir := func(path string) {
		if err := tw.WriteHeader(&tar.Header{Name: path, Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
			t.Fatalf("tar dir %s: %v", path, err)
		}
	}
	writeTarFile := func(path, content string) {
		hdr := &tar.Header{
			Name:     path,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", path, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar write %s: %v", path, err)
		}
	}
	writeTarDir(rootDir)
	writeTarDir(rootDir + "src/")
	writeTarFile(rootDir+"Cargo.toml", fmt.Sprintf("[package]\nname = \"%s\"\nversion = \"%s\"\n", name, version))
	writeTarFile(rootDir+"src/lib.rs", libContents)
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	raw := buf.Bytes()
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:])
}

func TestCratesFetcher_Fetch_HappyPath(t *testing.T) {
	body, digest := buildTestCrate(t, "mini", "0.1.0", "pub fn hello() {}\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v1/crates/mini/0.1.0"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{
				"version": {
					"num": "0.1.0",
					"dl_path": "/api/v1/crates/mini/0.1.0/download",
					"checksum": %q
				}
			}`, digest)
		case strings.HasSuffix(r.URL.Path, "/api/v1/crates/mini/0.1.0/download"):
			w.Header().Set("Content-Type", "application/x-gzip")
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f := &CratesFetcher{BaseURL: srv.URL, HTTPClient: srv.Client(), Cache: NewCache(t.TempDir())}
	fr, err := f.Fetch(context.Background(), "mini", "0.1.0", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fr.SourceDir == "" {
		t.Fatal("SourceDir empty")
	}
	libPath := filepath.Join(fr.SourceDir, "mini-0.1.0", "src", "lib.rs")
	if _, err := os.Stat(libPath); err != nil {
		t.Errorf("unpacked lib.rs missing at %s: %v", libPath, err)
	}
}

func TestCratesFetcher_Fetch_DigestMismatch(t *testing.T) {
	body, _ := buildTestCrate(t, "bad", "0.1.0", "pub fn hello() {}\n")
	// Provide a wrong checksum in metadata.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v1/crates/bad/0.1.0"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"version": {
					"num": "0.1.0",
					"dl_path": "/api/v1/crates/bad/0.1.0/download",
					"checksum": "deadbeef"
				}
			}`))
		case strings.HasSuffix(r.URL.Path, "/api/v1/crates/bad/0.1.0/download"):
			w.Header().Set("Content-Type", "application/x-gzip")
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f := &CratesFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.Fetch(context.Background(), "bad", "0.1.0", nil)
	if err == nil || !strings.Contains(err.Error(), ReasonDigestMismatch) {
		t.Errorf("Fetch: want %q in error, got %v", ReasonDigestMismatch, err)
	}
}
```

Add the new imports at the top of `fetcher_crates_test.go`:

```go
import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)
```

- [ ] **Step 2: Run the tests and verify they fail**

```
go test ./pkg/vex/reachability/transitive/... -run "TestCratesFetcher_Fetch_HappyPath|TestCratesFetcher_Fetch_DigestMismatch" -v
```
Expected: FAIL — `Fetch` currently returns the "not yet implemented" sentinel.

- [ ] **Step 3: Implement `Fetch`**

In `pkg/vex/reachability/transitive/fetcher_crates.go`, replace the placeholder `Fetch` method with the full implementation:

```go
// Fetch downloads the `.crate` tarball for (name, version), verifies its
// SHA-256 against the metadata's declared checksum and the caller's
// expectedDigest (if any), unpacks it into a temp directory (or cache),
// and returns the resulting SourceDir.
func (f *CratesFetcher) Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error) {
	meta, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}
	declared := Digest{Algorithm: "sha256", Hex: meta.Version.Checksum}
	cacheKey := declared.String()

	if f.Cache != nil {
		if p, ok := f.Cache.Get(cacheKey); ok {
			return FetchResult{SourceDir: p, Digest: declared}, nil
		}
	}

	tarURL := f.crateTarballURL(meta.Version.DlPath)
	body, err := httpGetBytes(ctx, f.client(), tarURL)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonTarballFetchFailed, err)
	}
	actual := Digest{Algorithm: "sha256", Hex: crateHash(body)}
	if !actual.Equals(declared) {
		return FetchResult{}, fmt.Errorf("%s: registry declared %s, downloaded %s", ReasonDigestMismatch, declared, actual)
	}
	if expectedDigest != nil && !expectedDigest.IsZero() && !expectedDigest.Equals(actual) {
		return FetchResult{}, fmt.Errorf("%s: SBOM expected %s, registry returned %s", ReasonDigestMismatch, expectedDigest, actual)
	}

	tmp, err := crateCacheTmpDir()
	if err != nil {
		return FetchResult{}, err
	}
	if err := untarGz(body, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return FetchResult{}, fmt.Errorf("unpack crate %s: %w", name, err)
	}

	srcDir := tmp
	if f.Cache != nil {
		p, putErr := f.Cache.Put(cacheKey, tmp)
		_ = os.RemoveAll(tmp)
		if putErr != nil {
			return FetchResult{}, putErr
		}
		srcDir = p
	}

	// Sanity check: verify the expected <name>-<version>/ directory exists.
	inner := crateInnerRoot(srcDir, name, version)
	if _, statErr := os.Stat(inner); statErr != nil {
		// Tarball layout didn't match expectation; return the outer dir
		// anyway — ListExports falls back to sourceDir/src/lib.rs.
		_ = statErr
	}
	return FetchResult{SourceDir: srcDir, Digest: actual}, nil
}
```

- [ ] **Step 4: Run the tests and verify they pass**

```
go test ./pkg/vex/reachability/transitive/... -run TestCratesFetcher_ -v
```
Expected: all `TestCratesFetcher_*` tests pass.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/fetcher_crates.go pkg/vex/reachability/transitive/fetcher_crates_test.go
git commit -m "feat(transitive): implement CratesFetcher.Fetch with checksum verify and unpack"
```

---

### Task 20: Wire `crates.io` into `buildFetchers`

**Files:**
- Modify: `pkg/vex/transitive_wire.go`
- Modify: `pkg/vex/transitive_wire_test.go` (create if absent)

- [ ] **Step 1: Write a failing test**

If `pkg/vex/transitive_wire_test.go` does not exist, create it with the package declaration and a minimal test; otherwise append the test.

Append to `pkg/vex/transitive_wire_test.go`:

```go
func TestBuildFetchers_CratesIO(t *testing.T) {
	cache := transitive.NewCache(t.TempDir())
	fetchers := buildFetchers(cache, "crates.io")
	if fetchers == nil {
		t.Fatal("buildFetchers(crates.io) returned nil")
	}
	f, ok := fetchers["crates.io"]
	if !ok {
		t.Fatal("fetchers missing crates.io key")
	}
	if _, ok := f.(*transitive.CratesFetcher); !ok {
		t.Errorf("fetchers[crates.io] is %T, want *transitive.CratesFetcher", f)
	}
}
```

Ensure the file's imports include `testing` and `github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive`.

- [ ] **Step 2: Run the test and verify it fails**

```
go test ./pkg/vex/... -run TestBuildFetchers_CratesIO -v
```
Expected: FAIL — no `crates.io` case in `buildFetchers`.

- [ ] **Step 3: Add the case**

In `pkg/vex/transitive_wire.go`, extend the `buildFetchers` switch:

```go
func buildFetchers(cache *transitive.Cache, ecosystem string) map[string]transitive.Fetcher {
	switch ecosystem {
	case "pypi":
		return map[string]transitive.Fetcher{"pypi": &transitive.PyPIFetcher{Cache: cache}}
	case "npm":
		return map[string]transitive.Fetcher{"npm": &transitive.NPMFetcher{Cache: cache}}
	case "crates.io":
		return map[string]transitive.Fetcher{"crates.io": &transitive.CratesFetcher{Cache: cache}}
	}
	return nil
}
```

- [ ] **Step 4: Run the test and verify it passes**

```
go test ./pkg/vex/... -run TestBuildFetchers_CratesIO -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```
git add pkg/vex/transitive_wire.go pkg/vex/transitive_wire_test.go
git commit -m "feat(vex): wire CratesFetcher into buildFetchers"
```

---

## Phase 5 — Real-world fixtures, integration, LLM judge, final gate

This phase is the production validation work. It ships a reachable-cross-package and safe-cross-package Rust fixture pair modeled on the existing Python and JavaScript fixtures, wires them into both the integration test suite and the LLM judge, and runs the full quality gate.

### Task 21: Create the reachable Rust cross-package fixture

**Files:**
- Create: `testdata/integration/rust-realworld-cross-package/Cargo.toml` metadata and source
- Create: `testdata/integration/rust-realworld-cross-package/source/Cargo.toml`
- Create: `testdata/integration/rust-realworld-cross-package/source/src/main.rs`
- Create: `testdata/integration/rust-realworld-cross-package/sbom.cdx.json`
- Create: `testdata/integration/rust-realworld-cross-package/expected.json`

**Fixture target:** The vulnerable crate is `time@0.2.23`, reachable in the CVE-2020-26235 path. `time` is pulled in transitively through `chrono@0.4.19` → `time@0.2.23`. The application source uses `chrono::Utc::now()`, which internally calls into the `time` public API. This models a realistic transitive reachability chain.

- [ ] **Step 1: Write the application source**

Create `testdata/integration/rust-realworld-cross-package/source/src/main.rs`:

```rust
// Minimal application that uses chrono to format the current time.
// CVE-2020-26235 in time@0.2.23 is transitively reachable because chrono
// internally calls into time's public API (specifically time::OffsetDateTime
// methods) to construct DateTime values.

use chrono::Utc;

fn format_now() -> String {
    let now = Utc::now();
    now.to_rfc3339()
}

fn main() {
    println!("{}", format_now());
}
```

- [ ] **Step 2: Write the `Cargo.toml`**

Create `testdata/integration/rust-realworld-cross-package/source/Cargo.toml`:

```toml
[package]
name = "my-app"
version = "0.1.0"
edition = "2021"

[dependencies]
chrono = "0.4.19"
```

- [ ] **Step 3: Write the SBOM**

Create `testdata/integration/rust-realworld-cross-package/sbom.cdx.json` with CycloneDX entries for `my-app`, `chrono@0.4.19`, `time@0.2.23`, and a dependency edge linking them. Use the existing Python fixture (`testdata/integration/python-realworld-cross-package/sbom.cdx.json`) as a template for structure; replace the components block with:

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "version": 1,
  "metadata": {
    "timestamp": "2026-04-12T00:00:00Z",
    "component": {
      "bom-ref": "my-app",
      "type": "application",
      "name": "my-app",
      "version": "0.1.0"
    }
  },
  "components": [
    {
      "bom-ref": "chrono@0.4.19",
      "type": "library",
      "name": "chrono",
      "version": "0.4.19",
      "purl": "pkg:cargo/chrono@0.4.19"
    },
    {
      "bom-ref": "time@0.2.23",
      "type": "library",
      "name": "time",
      "version": "0.2.23",
      "purl": "pkg:cargo/time@0.2.23"
    }
  ],
  "dependencies": [
    {
      "ref": "my-app",
      "dependsOn": ["chrono@0.4.19"]
    },
    {
      "ref": "chrono@0.4.19",
      "dependsOn": ["time@0.2.23"]
    }
  ]
}
```

- [ ] **Step 4: Write the expected.json**

Create `testdata/integration/rust-realworld-cross-package/expected.json`:

```json
{
  "description": "Rust application depending on chrono which transitively depends on time@0.2.23. CVE-2020-26235 in time is reachable because chrono::Utc::now() internally calls into time's public API. The analyzer must produce a reachable verdict with a stitched cross-package call path.",
  "provenance": {
    "source_project": "time-rs/time",
    "source_url": "https://github.com/time-rs/time",
    "cve": "CVE-2020-26235",
    "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-26235",
    "language": "rust",
    "pattern": "cross_package_reachable"
  },
  "findings": [
    {
      "cve": "CVE-2020-26235",
      "aliases": ["RUSTSEC-2020-0071"],
      "component_purl": "pkg:cargo/time@0.2.23",
      "expected_status": "affected",
      "expected_confidence": "medium",
      "expected_resolved_by": "reachability_analysis",
      "human_justification": "chrono::Utc::now() internally invokes time::OffsetDateTime methods, which are in the vulnerable public API surface."
    }
  ]
}
```

- [ ] **Step 5: Commit**

```
git add testdata/integration/rust-realworld-cross-package/
git commit -m "test(transitive): add rust cross-package reachable fixture (chrono→time)"
```

---

### Task 22: Create the safe Rust cross-package fixture

**Files:**
- Create: `testdata/integration/rust-realworld-cross-package-safe/source/Cargo.toml`
- Create: `testdata/integration/rust-realworld-cross-package-safe/source/src/main.rs`
- Create: `testdata/integration/rust-realworld-cross-package-safe/sbom.cdx.json`
- Create: `testdata/integration/rust-realworld-cross-package-safe/expected.json`

**Fixture target:** The application depends on the same `chrono@0.4.19` but ONLY uses a symbol that does not touch the vulnerable `time` surface. Concretely, the application only uses `chrono::Duration::seconds(...)` for constructing durations, which is implemented inside chrono itself and does not reach `time::OffsetDateTime`. The SBOM is identical.

- [ ] **Step 1: Write the safe application source**

Create `testdata/integration/rust-realworld-cross-package-safe/source/src/main.rs`:

```rust
// Minimal application that uses chrono's Duration type for arithmetic only.
// chrono::Duration is implemented inside chrono and does NOT touch time's
// vulnerable surface (time::OffsetDateTime). CVE-2020-26235 should be
// not_affected for this application.

use chrono::Duration;

fn seconds_in_an_hour() -> i64 {
    Duration::hours(1).num_seconds()
}

fn main() {
    println!("{}", seconds_in_an_hour());
}
```

- [ ] **Step 2: Write the Cargo.toml (identical)**

Create `testdata/integration/rust-realworld-cross-package-safe/source/Cargo.toml`:

```toml
[package]
name = "my-app-safe"
version = "0.1.0"
edition = "2021"

[dependencies]
chrono = "0.4.19"
```

- [ ] **Step 3: Write the SBOM (identical to reachable fixture except for root component name)**

Create `testdata/integration/rust-realworld-cross-package-safe/sbom.cdx.json` — same structure as the reachable fixture but with `"name": "my-app-safe"` and `"bom-ref": "my-app-safe"` in the root component, and `"ref": "my-app-safe"` in the dependency edge.

- [ ] **Step 4: Write expected.json**

Create `testdata/integration/rust-realworld-cross-package-safe/expected.json`:

```json
{
  "description": "Rust application depending on chrono but only using chrono::Duration for arithmetic. chrono::Duration is internal to chrono and does not reach the vulnerable time@0.2.23 surface. CVE-2020-26235 should be not_affected.",
  "provenance": {
    "source_project": "time-rs/time",
    "cve": "CVE-2020-26235",
    "language": "rust",
    "pattern": "cross_package_not_reachable"
  },
  "findings": [
    {
      "cve": "CVE-2020-26235",
      "aliases": ["RUSTSEC-2020-0071"],
      "component_purl": "pkg:cargo/time@0.2.23",
      "expected_status": "not_affected",
      "expected_confidence": "medium",
      "expected_resolved_by": "reachability_analysis",
      "human_justification": "Only chrono::Duration is used, which is self-contained inside chrono and does not invoke the vulnerable time::OffsetDateTime methods."
    }
  ]
}
```

- [ ] **Step 5: Commit**

```
git add testdata/integration/rust-realworld-cross-package-safe/
git commit -m "test(transitive): add rust cross-package safe fixture (chrono::Duration only)"
```

---

### Task 23: Add Rust integration tests

**Files:**
- Modify: `pkg/vex/reachability/transitive/integration_test.go`

- [ ] **Step 1: Extend `runIntegrationFixture`'s ecosystem switch**

In `pkg/vex/reachability/transitive/integration_test.go`, find the `switch ecosystem` inside `runIntegrationFixture` and add a `crates.io` case:

```go
	var fetcher Fetcher
	switch ecosystem {
	case "pypi":
		fetcher = &PyPIFetcher{Cache: cache}
	case "npm":
		fetcher = &NPMFetcher{Cache: cache}
	case "crates.io":
		fetcher = &CratesFetcher{Cache: cache}
	default:
		t.Fatalf("unknown ecosystem %q", ecosystem)
	}
```

- [ ] **Step 2: Add the two test functions**

Append to the same file:

```go
func TestIntegration_Transitive_RustReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "rust-realworld-cross-package")
	runIntegrationFixture(t, dir, "rust", "crates.io", "time", "0.2.23", true)
}

func TestIntegration_Transitive_RustNotReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "rust-realworld-cross-package-safe")
	runIntegrationFixture(t, dir, "rust", "crates.io", "time", "0.2.23", false)
}
```

- [ ] **Step 3: Run the integration tests**

```
go test -tags integration ./pkg/vex/reachability/transitive/... -run "TestIntegration_Transitive_Rust" -v
```
Expected: both PASS. If `TestIntegration_Transitive_RustReachable` fails with "no path reaches", inspect the stitched result — the most common root cause is a canonicalByName lookup miss caused by `chrono::Duration` pointing at a symbol not emitted by `ListExports`. Debug by temporarily printing the exports returned by `rust.Language.ListExports` for the fetched `time-0.2.23` source, and verify the resolved target from the application side.

If either test fails for ecosystem plumbing reasons (e.g. `CratesFetcher` not found), confirm Task 20's wire completed before proceeding. Do not silence failures — diagnose the root cause.

- [ ] **Step 4: Commit**

```
git add pkg/vex/reachability/transitive/integration_test.go
git commit -m "test(transitive): add rust integration test cases"
```

---

### Task 24: Create the Rust transitive LLM judge test

**Files:**
- Create: `pkg/vex/reachability/rust/llm_judge_test.go`

- [ ] **Step 1: Create the judge test file**

Create `pkg/vex/reachability/rust/llm_judge_test.go`, modeled on the Python transitive judge test at `pkg/vex/reachability/python/llm_judge_test.go` (specifically the `TestLLMJudge_PythonTransitiveReachability` function starting around line 159):

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

//go:build llmjudge

package rust_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ravan/cra-toolkit/pkg/formats"
	cdxformats "github.com/ravan/cra-toolkit/pkg/formats/cyclonedx"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive"
)

type reachabilityScores struct {
	PathAccuracy          int    `json:"path_accuracy"`
	ConfidenceCalibration int    `json:"confidence_calibration"`
	EvidenceQuality       int    `json:"evidence_quality"`
	FalsePositiveRate     int    `json:"false_positive_rate"`
	SymbolResolution      int    `json:"symbol_resolution"`
	OverallQuality        int    `json:"overall_quality"`
	Reasoning             string `json:"reasoning"`
}

func TestLLMJudge_RustTransitiveReachability(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	reachableDir := filepath.Join(fixtureBase, "rust-realworld-cross-package")
	notReachableDir := filepath.Join(fixtureBase, "rust-realworld-cross-package-safe")

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
		if strings.HasPrefix(c.PURL, "pkg:cargo/") {
			pkgs = append(pkgs, transitive.Package{Name: c.Name, Version: c.Version})
		}
	}
	directDeps := cdxformats.ParseDirectDeps(sbomPath)
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

	cache := transitive.NewCache(t.TempDir())
	fetcher := &transitive.CratesFetcher{Cache: cache}
	lang, langErr := transitive.LanguageFor("rust")
	if langErr != nil {
		t.Fatalf("LanguageFor(rust): %v", langErr)
	}
	ta := &transitive.Analyzer{
		Config:   transitive.DefaultConfig(),
		Language: lang,
		Fetchers: map[string]transitive.Fetcher{"crates.io": fetcher},
	}

	finding := &formats.Finding{
		AffectedName:    "time",
		AffectedVersion: "0.2.23",
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

	prompt := fmt.Sprintf(`You are a security engineering judge evaluating a transitive dependency reachability analyzer for CRA compliance.

VULNERABILITY: CVE-2020-26235 — time@0.2.23 segfault via race in localtime_r.
VULNERABLE PACKAGE: time@0.2.23 (transitive dependency reached through chrono@0.4.19)
CHAIN: app → chrono::Utc::now → time::OffsetDateTime

REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%v, Confidence=%s, Degradations=%v
Call paths found: %s
Evidence: %s

NOT-REACHABLE PROJECT uses only chrono::Duration::hours — self-contained arithmetic inside chrono, time never invoked (source: %s):
Analysis result: Reachable=%v, Confidence=%s, Degradations=%v
Evidence: %s

Score the transitive analyzer (1-10 each):
1. path_accuracy: Are the reported cross-package call paths real?
2. confidence_calibration: Does confidence reflect the uncertainty of transitive analysis?
3. evidence_quality: Is the stitched call path evidence sufficient for a VEX determination?
4. false_positive_rate: Is the not-reachable case correctly identified?
5. symbol_resolution: Are the cross-package Rust symbols correctly resolved (including pub use re-exports)?
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

	t.Logf("Rust Transitive LLM Scores: path=%d, confidence=%d, evidence=%d, fp=%d, symbol=%d, overall=%d",
		scores.PathAccuracy, scores.ConfidenceCalibration, scores.EvidenceQuality,
		scores.FalsePositiveRate, scores.SymbolResolution, scores.OverallQuality)
	t.Logf("Reasoning: %s", scores.Reasoning)

	threshold := 6 // lower threshold for transitive (harder problem); matches Python/JavaScript.
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
```

- [ ] **Step 2: Verify the file compiles under the llmjudge tag**

```
go test -tags llmjudge -run "^$" ./pkg/vex/reachability/rust/...
```
Expected: compiles with no tests run.

- [ ] **Step 3: Commit**

```
git add pkg/vex/reachability/rust/llm_judge_test.go
git commit -m "test(transitive): add rust transitive reachability LLM judge test"
```

---

### Task 25: Wire Rust judge into `Taskfile.yml`

**Files:**
- Modify: `Taskfile.yml`

- [ ] **Step 1: Add the Rust judge command**

Extend the `test:reachability:transitive:llmjudge` task to include the Rust case:

```yaml
  test:reachability:transitive:llmjudge:
    desc: Run Python, JavaScript, and Rust transitive reachability LLM judge tests (requires gemini CLI)
    cmds:
      - go test -race -count=1 -tags llmjudge -run TestLLMJudge_PythonTransitiveReachability -v ./pkg/vex/reachability/python/...
      - go test -race -count=1 -tags llmjudge -run TestLLMJudge_JavaScriptTransitiveReachability -v ./pkg/vex/reachability/javascript/...
      - go test -race -count=1 -tags llmjudge -run TestLLMJudge_RustTransitiveReachability -v ./pkg/vex/reachability/rust/...
```

- [ ] **Step 2: Run the expanded judge task**

```
task test:reachability:transitive:llmjudge
```
Expected: all three language judges pass, with each scoring ≥ 6 on every dimension. If the Rust case comes back with lower scores on `symbol_resolution`, inspect the call-path output — this is usually the signal that re-export resolution missed a re-exported target. Fix the root cause; do not lower the threshold.

- [ ] **Step 3: Commit**

```
git add Taskfile.yml
git commit -m "test(transitive): add rust judge to test:reachability:transitive:llmjudge"
```

---

### Task 26: Full quality gate and final verification

- [ ] **Step 1: Format**

```
task fmt
```
Expected: clean — no formatting issues. If files change, stage and commit with `style: gofumpt formatting`.

- [ ] **Step 2: Lint**

```
task lint
```
Expected: clean. Fix any violations in place. Commit any fixes under a descriptive message (e.g. `style(transitive): satisfy lint after rust support`).

- [ ] **Step 3: Full test suite**

```
task test
```
Expected: all packages pass.

- [ ] **Step 4: Transitive-specific tests**

```
task test:transitive
```
Expected: all transitive tests pass.

- [ ] **Step 5: Integration tests**

```
go test -tags integration ./pkg/vex/reachability/transitive/... -v
```
Expected: all integration fixtures pass, including the two new Rust cases.

- [ ] **Step 6: LLM judge gate**

```
task test:reachability:transitive:llmjudge
```
Expected: Python, JavaScript, and Rust judges all pass with every dimension ≥ 6.

- [ ] **Step 7: Full repo quality gate**

```
task quality
```
Expected: every gate (build + test + lint + fmt check) passes.

- [ ] **Step 8: Review the diff summary**

```
git log --oneline main..HEAD
git diff --stat main..HEAD
```
Expected: a clean sequence of commits matching the plan tasks, and a diff limited to the files listed in the "File Structure" section at the top of this plan. No stray edits outside scope.

- [ ] **Step 9: Final acceptance check**

Confirm against the spec's section 11 acceptance criteria:

1. All files listed in the spec's section 3.1 are created or modified.
2. `task test` passes.
3. `task test:transitive` passes.
4. `task test:reachability:transitive:llmjudge` passes with every dimension ≥ 6 for Python, JavaScript, and Rust.
5. `task quality` passes.
6. `TestIntegration_Transitive_RustReachable` produces `Reachable: true` with a stitched call path traversing chrono → time.
7. Adding a further new language still requires only: one subpackage under `languages/<lang>/`, one `LanguageFor` case, and one `buildFetchers` case if the ecosystem is new.

If every item checks out, the plan is done. No commit required for this step — it is verification only.

---

## Self-review notes

**Spec coverage.** Every section/requirement of `docs/superpowers/specs/2026-04-11-rust-transitive-language-support-design.md` maps to at least one task:

- §3.1 File layout → covered by the File Structure block at the top of this plan and by the individual Tasks 8, 13, 18.
- §3.2 Capability interfaces → Tasks 5, 6.
- §3.3 `Symbol.IsPublic` → Tasks 1, 2.
- §4.1 Module tree construction → Task 13.
- §4.2 Canonical emission → Task 14.
- §4.3 Re-export resolution → Task 15.
- §4.4 `ModulePath` + `SymbolKey` → Task 9.
- §5.1 `NormalizeImports` → Task 10.
- §5.2 `ResolveDottedTarget` → Task 11.
- §5.3 `ResolveSelfCall` → Task 12.
- §5.4 Cross-file trait dispatch bridging → Tasks 3, 6.
- §6 Crates.io fetcher → Tasks 18, 19, 20.
- §7 Degradation reason `ReasonNoLibraryAPI` → Tasks 4, 17.
- §8.1 Unit tests → tests embedded throughout Tasks 8–15.
- §8.2 Fetcher unit tests → Tasks 18, 19.
- §8.3 Contract tests → Task 16.
- §8.4 Wire tests → Task 20.
- §8.5 Integration tests → Tasks 21, 22, 23.
- §8.6 LLM judge → Tasks 24, 25.
- §8.7 Regression gates → Tasks 7, 26.

**Terminology check.** The plan consistently uses `ListExports`, `ExportLister`, `CrossFileStateExtractor`, `SnapshotState`, `RestoreState`, `ErrNoLibraryAPI`, `ReasonNoLibraryAPI`, `CratesFetcher`, `buildFetchers`, and `LanguageFor` — matching the spec and no conflicting synonyms.

**Correction on scoring threshold.** The spec states LLM judge acceptance at "score ≥ 9". The actual threshold used by the Python and JavaScript judge tests is `threshold := 6` (transitive is treated as a harder problem than direct reachability). This plan uses `6` in Task 24 to stay consistent with the existing test infrastructure. The spec's aspirational "≥ 9" is a real achievement marker (the Python and JavaScript judges currently score around 9 in practice), not a test-gate floor. If the user prefers ≥ 9 as the strict gate, update Task 24 Step 1 before running Phase 5.

**Placeholder scan.** No TBDs, TODOs, or "implement appropriate error handling" lines. Every step shows either exact code or an exact command.

**Scope.** Every task stays within the files listed in the File Structure block. No unrelated refactoring.

---

## Plan complete

The plan is ready to execute. Two execution options:

**1. Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — execute tasks in this session using the executing-plans skill, batch execution with checkpoints for review.
