# Ruby Transitive Language Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add production-grade Ruby language support to the transitive cross-package reachability analyzer, including four extractor accuracy improvements (nested scope, mixins, attr_*, scope-aware resolution), ExportLister via require-chain walk, CrossFileStateExtractor for mixin/hierarchy, and a RubyGems fetcher with double-unpack.

**Architecture:** Improve the existing tree-sitter Ruby extractor at `pkg/vex/reachability/treesitter/ruby/` with nested scope tracking, mixin detection, attr_* synthesis, and scope-aware call resolution. Register Ruby as a `LanguageSupport` under `pkg/vex/reachability/transitive/languages/ruby/`, implementing both `ExportLister` (require-chain walk from gem entry file) and `CrossFileStateExtractor` (mixin registry + class hierarchy). Add a `RubyGemsFetcher` implementing `Fetcher` against the rubygems.org API with `.gem` double-unpack. Ship with real-world integration and LLM judge gates matching Python/JavaScript/Rust.

**Tech Stack:** Go 1.22+, tree-sitter-go bindings, tree-sitter Ruby grammar (`github.com/tree-sitter/tree-sitter-ruby/bindings/go`), rubygems.org API, httptest for fetcher unit tests, Gemini CLI for LLM judge.

**Related:**
- Spec: `docs/superpowers/specs/2026-04-12-ruby-transitive-language-support-design.md`
- Foundation spec: `docs/superpowers/specs/2026-04-11-transitive-language-support-foundation-design.md`
- Rust spec (pattern reference): `docs/superpowers/specs/2026-04-11-rust-transitive-language-support-design.md`

**Conventions observed throughout:**
- TDD: every task writes a failing test, runs it to confirm failure, implements the minimal code, re-runs to confirm pass, commits.
- Commit messages follow the existing convention: `type(scope): summary` — e.g. `feat(transitive)`, `test(transitive)`, `fix(ruby)`.
- **No `Co-Authored-By` lines.** This project's convention (memory note) forbids them.
- File paths are repo-relative. Working directory for commands is the repo root.
- Use real OSS project data for tests, no mocking/stubbing of analysis results.

---

## File Structure

**Created:**
- `pkg/vex/reachability/transitive/languages/ruby/ruby.go` — Ruby `LanguageSupport` (11 required methods + `ExportLister` + `CrossFileStateExtractor`).
- `pkg/vex/reachability/transitive/languages/ruby/ruby_test.go` — unit tests for the 11 `LanguageSupport` methods.
- `pkg/vex/reachability/transitive/languages/ruby/exports.go` — `ListExports` implementation (entry file discovery, require-chain walk, export enumeration).
- `pkg/vex/reachability/transitive/languages/ruby/exports_test.go` — unit tests for `ListExports`.
- `pkg/vex/reachability/transitive/fetcher_rubygems.go` — `RubyGemsFetcher`.
- `pkg/vex/reachability/transitive/fetcher_rubygems_test.go` — `httptest.Server`-backed unit tests.
- `testdata/integration/ruby-realworld-cross-package/` — reachable fixture (source tree, sbom, expected.json).
- `testdata/integration/ruby-realworld-cross-package-safe/` — not-reachable fixture.

**Modified:**
- `pkg/vex/reachability/treesitter/ruby/extractor.go` — nested scope tracking, visibility tracking, mixin detection, attr_* synthesis, scope-aware call resolution, CrossFileState snapshots.
- `pkg/vex/reachability/treesitter/ruby/extractor_test.go` — tests for all extractor improvements.
- `pkg/vex/reachability/transitive/language.go` — register Ruby in `LanguageFor`.
- `pkg/vex/reachability/transitive/language_test.go` — extend registry and contract tables.
- `pkg/vex/reachability/transitive/integration_test.go` — add Ruby integration cases.
- `pkg/vex/transitive_wire.go` — add `"rubygems"` case to `buildFetchers`.
- `pkg/vex/reachability/ruby/llm_judge_test.go` — add `TestLLMJudge_RubyTransitiveReachability`.
- `Taskfile.yml` — add Ruby judge line to `test:reachability:transitive:llmjudge`.

---

## Phase 1 — Extractor improvements

These tasks improve the existing Ruby tree-sitter extractor. Each is independently testable and committed. The standalone Ruby analyzer benefits from every change.

### Task 1: Add nested class/module scope tracking

The current extractor flattens qualified names — `module Admin; class UsersController; def create` produces `UsersController::create` instead of `Admin::UsersController::create`. This task threads a scope stack through `walkProgram` and all its callees.

**Files:**
- Modify: `pkg/vex/reachability/treesitter/ruby/extractor.go`
- Modify: `pkg/vex/reachability/treesitter/ruby/extractor_test.go`

- [ ] **Step 1: Write failing tests**

Append to `pkg/vex/reachability/treesitter/ruby/extractor_test.go`:

```go
func TestExtractSymbols_NestedModule(t *testing.T) {
	source := `module Admin
  class UsersController
    def create
      "ok"
    end
  end
end`
	ext := New()
	tree := parseRuby(t, source)
	symbols, err := ext.ExtractSymbols("app.rb", []byte(source), tree)
	if err != nil {
		t.Fatal(err)
	}

	wantIDs := map[string]bool{
		"Admin":                            true,
		"Admin::UsersController":           true,
		"Admin::UsersController::create":   true,
	}
	gotIDs := make(map[string]bool)
	for _, s := range symbols {
		gotIDs[string(s.ID)] = true
	}
	for id := range wantIDs {
		if !gotIDs[id] {
			t.Errorf("missing symbol %q; got %v", id, keys(gotIDs))
		}
	}
}

func TestExtractSymbols_DeeplyNested(t *testing.T) {
	source := `module A
  module B
    class C
      def d
        "deep"
      end
    end
  end
end`
	ext := New()
	tree := parseRuby(t, source)
	symbols, err := ext.ExtractSymbols("deep.rb", []byte(source), tree)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, s := range symbols {
		if string(s.ID) == "A::B::C::d" {
			found = true
			break
		}
	}
	if !found {
		var ids []string
		for _, s := range symbols {
			ids = append(ids, string(s.ID))
		}
		t.Errorf("expected A::B::C::d, got %v", ids)
	}
}

func TestExtractSymbols_CompoundClassName(t *testing.T) {
	source := `class Admin::UsersController
  def index
    "ok"
  end
end`
	ext := New()
	tree := parseRuby(t, source)
	symbols, err := ext.ExtractSymbols("app.rb", []byte(source), tree)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, s := range symbols {
		if string(s.ID) == "Admin::UsersController::index" {
			found = true
			break
		}
	}
	if !found {
		var ids []string
		for _, s := range symbols {
			ids = append(ids, string(s.ID))
		}
		t.Errorf("expected Admin::UsersController::index, got %v", ids)
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
```

If `parseRuby` doesn't already exist in the test file, add it:

```go
func parseRuby(t *testing.T, source string) *tree_sitter.Tree {
	t.Helper()
	parser := tree_sitter.NewParser()
	defer parser.Close()
	lang := tree_sitter.NewLanguage(grammarruby.Language())
	if err := parser.SetLanguage(lang); err != nil {
		t.Fatal(err)
	}
	tree := parser.Parse([]byte(source), nil)
	if tree == nil {
		t.Fatal("parse returned nil tree")
	}
	return tree
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
go test -run 'TestExtractSymbols_NestedModule|TestExtractSymbols_DeeplyNested|TestExtractSymbols_CompoundClassName' -v ./pkg/vex/reachability/treesitter/ruby/...
```
Expected: FAIL — symbols have flat names like `UsersController::create` instead of `Admin::UsersController::create`.

- [ ] **Step 3: Implement nested scope tracking**

In `pkg/vex/reachability/treesitter/ruby/extractor.go`:

1. Replace the `walkProgram` function signature to accept a scope stack instead of no class context:

```go
func walkProgram(
	node *tree_sitter.Node,
	src []byte,
	file string,
	scopeStack []string,
	symbols *[]*treesitter.Symbol,
)
```

2. Update `ExtractSymbols` to call `walkProgram(root, src, file, nil, &symbols)`.

3. In `walkProgram`, when encountering a `"class"` or `"module"` node:
   - Extract the name via `classOrModuleName(node, src)`.
   - If the name contains `::` (compound name like `Admin::UsersController`), split on `::` and push all segments.
   - Otherwise push the single name.
   - Build the fully-qualified name: `strings.Join(append(scopeStack, nameParts...), "::")`.
   - Create the symbol with this qualified name as both `ID` and `QualifiedName`.
   - Walk the body with the extended scope stack: `append(scopeStack, nameParts...)`.

4. Update `extractContainerNode` to accept and propagate `scopeStack`:

```go
func extractContainerNode(
	node *tree_sitter.Node,
	src []byte,
	file string,
	kind treesitter.SymbolKind,
	scopeStack []string,
	symbols *[]*treesitter.Symbol,
) {
	name := classOrModuleName(node, src)
	if name == "" {
		return
	}
	var nameParts []string
	if strings.Contains(name, "::") {
		nameParts = strings.Split(name, "::")
	} else {
		nameParts = []string{name}
	}
	newStack := append(append([]string{}, scopeStack...), nameParts...)
	qualifiedName := strings.Join(newStack, "::")

	*symbols = append(*symbols, &treesitter.Symbol{
		ID:            treesitter.SymbolID(qualifiedName),
		Name:          name,
		QualifiedName: qualifiedName,
		Language:      "ruby",
		File:          file,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          kind,
	})

	body := node.ChildByFieldName("body")
	if body == nil {
		return
	}
	extractMethodsFromBody(body, src, file, newStack, symbols)
}
```

5. Update `extractMethodsFromBody` to accept `scopeStack []string` instead of `className string`:

```go
func extractMethodsFromBody(
	body *tree_sitter.Node,
	src []byte,
	file string,
	scopeStack []string,
	symbols *[]*treesitter.Symbol,
)
```

In its dispatching: pass `scopeStack` to nested `extractContainerNode` calls and to `extractMethodNode`/`extractSingletonMethodNode`.

6. Update `extractMethodNode` and `extractSingletonMethodNode` to accept `scopeStack []string`:

```go
func extractMethodNode(node *tree_sitter.Node, src []byte, file string, scopeStack []string, symbols *[]*treesitter.Symbol)
```

7. Update `appendMethodSymbol` to use `scopeStack`:

```go
func appendMethodSymbol(
	file string,
	scopeStack []string,
	methodName string,
	node *tree_sitter.Node,
	symbols *[]*treesitter.Symbol,
) {
	className := strings.Join(scopeStack, "::")
	qualifiedName := className + "::" + methodName
	*symbols = append(*symbols, &treesitter.Symbol{
		ID:            treesitter.SymbolID(qualifiedName),
		Name:          methodName,
		QualifiedName: qualifiedName,
		Language:      "ruby",
		File:          file,
		Package:       className,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolMethod,
	})
}
```

8. Similarly update `collectCalls` to thread `scopeStack` instead of flat `currentClass`:

```go
func collectCalls(
	node *tree_sitter.Node,
	src []byte,
	file string,
	scopeStack []string,
	currentMethod string,
	edges *[]treesitter.Edge,
)
```

When entering a class/module node, push onto `scopeStack`. When building `from` in `buildFrom`, join `scopeStack` with `"::"`.

9. Update `ExtractCalls` to pass `nil` scopeStack and `""` currentMethod.

10. Update `buildFrom` to accept `scopeStack []string` and join them:

```go
func buildFrom(scopeStack []string, currentMethod, file string) treesitter.SymbolID {
	className := strings.Join(scopeStack, "::")
	if className != "" && currentMethod != "" {
		return treesitter.SymbolID(className + "::" + currentMethod)
	}
	if className != "" {
		return treesitter.SymbolID(className)
	}
	if currentMethod != "" {
		return treesitter.SymbolID(currentMethod)
	}
	return treesitter.SymbolID(file)
}
```

- [ ] **Step 4: Run tests to verify they pass**

```
go test -v ./pkg/vex/reachability/treesitter/ruby/...
```
Expected: all tests pass, including the new nested scope tests and all existing tests.

- [ ] **Step 5: Run standalone Ruby analyzer tests**

```
go test -v ./pkg/vex/reachability/ruby/...
```
Expected: all existing tests pass. The standalone analyzer calls the same extractor.

- [ ] **Step 6: Commit**

```
git add pkg/vex/reachability/treesitter/ruby/extractor.go pkg/vex/reachability/treesitter/ruby/extractor_test.go
git commit -m "fix(ruby): add nested class/module scope tracking to extractor"
```

---

### Task 2: Add visibility tracking (private/protected/public)

Track Ruby's `private`/`protected`/`public` visibility modifiers and set `IsPublic` on extracted symbols.

**Files:**
- Modify: `pkg/vex/reachability/treesitter/ruby/extractor.go`
- Modify: `pkg/vex/reachability/treesitter/ruby/extractor_test.go`

- [ ] **Step 1: Write failing tests**

Append to `pkg/vex/reachability/treesitter/ruby/extractor_test.go`:

```go
func TestExtractSymbols_PrivateMethod(t *testing.T) {
	source := `class Foo
  def public_method
    "hi"
  end

  private

  def private_method
    "secret"
  end
end`
	ext := New()
	tree := parseRuby(t, source)
	symbols, err := ext.ExtractSymbols("foo.rb", []byte(source), tree)
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range symbols {
		switch s.Name {
		case "public_method":
			if !s.IsPublic {
				t.Errorf("public_method should have IsPublic=true")
			}
		case "private_method":
			if s.IsPublic {
				t.Errorf("private_method should have IsPublic=false")
			}
		}
	}
}

func TestExtractSymbols_ProtectedMethod(t *testing.T) {
	source := `class Foo
  def open_method
    "open"
  end

  protected

  def guarded_method
    "guarded"
  end
end`
	ext := New()
	tree := parseRuby(t, source)
	symbols, err := ext.ExtractSymbols("foo.rb", []byte(source), tree)
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range symbols {
		switch s.Name {
		case "open_method":
			if !s.IsPublic {
				t.Errorf("open_method should have IsPublic=true")
			}
		case "guarded_method":
			if s.IsPublic {
				t.Errorf("guarded_method should have IsPublic=false")
			}
		}
	}
}

func TestExtractSymbols_ExplicitPrivate(t *testing.T) {
	source := `class Foo
  def alpha
    "a"
  end

  def beta
    "b"
  end

  private :beta
end`
	ext := New()
	tree := parseRuby(t, source)
	symbols, err := ext.ExtractSymbols("foo.rb", []byte(source), tree)
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range symbols {
		switch s.Name {
		case "alpha":
			if !s.IsPublic {
				t.Errorf("alpha should have IsPublic=true")
			}
		case "beta":
			if s.IsPublic {
				t.Errorf("beta should have IsPublic=false after private :beta")
			}
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
go test -run 'TestExtractSymbols_PrivateMethod|TestExtractSymbols_ProtectedMethod|TestExtractSymbols_ExplicitPrivate' -v ./pkg/vex/reachability/treesitter/ruby/...
```
Expected: FAIL — `IsPublic` is never set.

- [ ] **Step 3: Implement visibility tracking**

In `pkg/vex/reachability/treesitter/ruby/extractor.go`:

1. Add a `visibility` type and constants:

```go
type visibility int

const (
	visPublic    visibility = iota
	visProtected
	visPrivate
)
```

2. Thread `vis visibility` through `extractMethodsFromBody`. Default is `visPublic`. When a call node with method name `"private"`, `"protected"`, or `"public"` is encountered in the body:
   - If it has no arguments (bare `private` call): update the visibility state for subsequent methods.
   - If it has symbol arguments (e.g., `private :beta`): track those method names in a `privateOverrides map[string]bool`.

3. In `appendMethodSymbol`, accept a `vis visibility` parameter and set `IsPublic: vis == visPublic`.

4. After all symbols are extracted, do a second pass to apply `privateOverrides`: for any symbol whose name matches a key in `privateOverrides`, set `IsPublic = false`.

5. For classes and modules themselves, always set `IsPublic = true` (Ruby has no private class/module mechanism in normal usage).

The implementation needs to detect standalone `private`/`protected`/`public` calls in the body. In the tree-sitter AST, these appear as `call` nodes (or `identifier` nodes acting as method calls) where the method name is one of the three visibility keywords. Check:
- If the node is a `call` with first child text `"private"`, `"protected"`, or `"public"`:
  - Check if it has arguments (via `ChildByFieldName("arguments")`).
  - If no arguments: this is a visibility toggle — update `vis`.
  - If arguments are symbol literals (`:method_name`): collect them for the override pass.

- [ ] **Step 4: Run tests to verify they pass**

```
go test -v ./pkg/vex/reachability/treesitter/ruby/...
```
Expected: all pass.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/treesitter/ruby/extractor.go pkg/vex/reachability/treesitter/ruby/extractor_test.go
git commit -m "feat(ruby): add private/protected/public visibility tracking to extractor"
```

---

### Task 3: Add attr_accessor/attr_reader/attr_writer synthesis

Detect `attr_*` declarations and synthesize getter/setter method symbols.

**Files:**
- Modify: `pkg/vex/reachability/treesitter/ruby/extractor.go`
- Modify: `pkg/vex/reachability/treesitter/ruby/extractor_test.go`

- [ ] **Step 1: Write failing tests**

Append to `pkg/vex/reachability/treesitter/ruby/extractor_test.go`:

```go
func TestExtractSymbols_AttrAccessor(t *testing.T) {
	source := `class Config
  attr_accessor :host, :port
end`
	ext := New()
	tree := parseRuby(t, source)
	symbols, err := ext.ExtractSymbols("config.rb", []byte(source), tree)
	if err != nil {
		t.Fatal(err)
	}

	wantMethods := map[string]bool{
		"Config::host":  true,
		"Config::host=": true,
		"Config::port":  true,
		"Config::port=": true,
	}
	for _, s := range symbols {
		delete(wantMethods, string(s.ID))
	}
	for missing := range wantMethods {
		t.Errorf("missing synthesized method %q", missing)
	}
}

func TestExtractSymbols_AttrReader(t *testing.T) {
	source := `class User
  attr_reader :id
end`
	ext := New()
	tree := parseRuby(t, source)
	symbols, err := ext.ExtractSymbols("user.rb", []byte(source), tree)
	if err != nil {
		t.Fatal(err)
	}

	foundGetter := false
	foundSetter := false
	for _, s := range symbols {
		if string(s.ID) == "User::id" {
			foundGetter = true
		}
		if string(s.ID) == "User::id=" {
			foundSetter = true
		}
	}
	if !foundGetter {
		t.Error("missing getter User::id")
	}
	if foundSetter {
		t.Error("attr_reader should not generate setter User::id=")
	}
}

func TestExtractSymbols_AttrWriter(t *testing.T) {
	source := `class User
  attr_writer :password
end`
	ext := New()
	tree := parseRuby(t, source)
	symbols, err := ext.ExtractSymbols("user.rb", []byte(source), tree)
	if err != nil {
		t.Fatal(err)
	}

	foundGetter := false
	foundSetter := false
	for _, s := range symbols {
		if string(s.ID) == "User::password" {
			foundGetter = true
		}
		if string(s.ID) == "User::password=" {
			foundSetter = true
		}
	}
	if foundGetter {
		t.Error("attr_writer should not generate getter User::password")
	}
	if !foundSetter {
		t.Error("missing setter User::password=")
	}
}

func TestExtractSymbols_AttrWithPrivate(t *testing.T) {
	source := `class Foo
  attr_accessor :public_name

  private

  attr_accessor :secret_name
end`
	ext := New()
	tree := parseRuby(t, source)
	symbols, err := ext.ExtractSymbols("foo.rb", []byte(source), tree)
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range symbols {
		switch s.Name {
		case "public_name":
			if !s.IsPublic {
				t.Errorf("public_name should have IsPublic=true")
			}
		case "secret_name":
			if s.IsPublic {
				t.Errorf("secret_name should have IsPublic=false (after private)")
			}
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
go test -run 'TestExtractSymbols_Attr' -v ./pkg/vex/reachability/treesitter/ruby/...
```
Expected: FAIL — no synthesized accessor methods found.

- [ ] **Step 3: Implement attr_* synthesis**

In `extractMethodsFromBody`, when a `call` or `command_call` node has first child text `"attr_accessor"`, `"attr_reader"`, or `"attr_writer"`:

1. Extract all symbol literal arguments (children with Kind `"simple_symbol"`, strip leading `:`).
2. For each attribute name:
   - `attr_reader`: synthesize one getter method symbol `ClassName::name`.
   - `attr_writer`: synthesize one setter method symbol `ClassName::name=`.
   - `attr_accessor`: synthesize both.
3. Set `IsPublic` based on the current visibility state.
4. Set `Kind = treesitter.SymbolMethod`, `File`, `StartLine`/`EndLine` from the attr_* call node.

```go
func extractAttrMethods(
	node *tree_sitter.Node,
	src []byte,
	file string,
	scopeStack []string,
	vis visibility,
	symbols *[]*treesitter.Symbol,
) {
	methodText := nodeText(node.Child(0), src)
	args := node.ChildByFieldName("arguments")
	if args == nil {
		return
	}
	className := strings.Join(scopeStack, "::")
	for i := 0; i < int(args.ChildCount()); i++ {
		child := args.Child(uint(i))
		if child.Kind() != "simple_symbol" {
			continue
		}
		attrName := strings.TrimPrefix(nodeText(child, src), ":")

		makeMethod := func(name string) {
			qualifiedName := className + "::" + name
			*symbols = append(*symbols, &treesitter.Symbol{
				ID:            treesitter.SymbolID(qualifiedName),
				Name:          name,
				QualifiedName: qualifiedName,
				Language:      "ruby",
				File:          file,
				Package:       className,
				StartLine:     rowToLine(node.StartPosition().Row),
				EndLine:       rowToLine(node.EndPosition().Row),
				Kind:          treesitter.SymbolMethod,
				IsPublic:      vis == visPublic,
			})
		}

		switch methodText {
		case "attr_reader":
			makeMethod(attrName)
		case "attr_writer":
			makeMethod(attrName + "=")
		case "attr_accessor":
			makeMethod(attrName)
			makeMethod(attrName + "=")
		}
	}
}
```

Call this from `extractMethodsFromBody` when the call's method name matches `attr_*`.

- [ ] **Step 4: Run tests to verify they pass**

```
go test -v ./pkg/vex/reachability/treesitter/ruby/...
```
Expected: all pass.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/treesitter/ruby/extractor.go pkg/vex/reachability/treesitter/ruby/extractor_test.go
git commit -m "feat(ruby): synthesize attr_accessor/reader/writer method symbols"
```

---

### Task 4: Add mixin detection (include/extend/prepend)

Detect `include`, `extend`, and `prepend` statements and record them in cross-file state.

**Files:**
- Modify: `pkg/vex/reachability/treesitter/ruby/extractor.go`
- Modify: `pkg/vex/reachability/treesitter/ruby/extractor_test.go`

- [ ] **Step 1: Add CrossFileState types to the extractor**

In `pkg/vex/reachability/treesitter/ruby/extractor.go`, add the state structures:

```go
type MixinEntry struct {
	Module string
	Kind   string // "include", "extend", "prepend"
}

type CrossFileState struct {
	Mixins        map[string][]MixinEntry // class → mixins
	Hierarchy     map[string]string       // class → superclass
	ModuleMethods map[string][]string     // module → methods
}

func newCrossFileState() *CrossFileState {
	return &CrossFileState{
		Mixins:        make(map[string][]MixinEntry),
		Hierarchy:     make(map[string]string),
		ModuleMethods: make(map[string][]string),
	}
}
```

Update the `Extractor` struct to hold the state:

```go
type Extractor struct {
	routes []routeAction
	state  *CrossFileState
}

func New() *Extractor {
	return &Extractor{state: newCrossFileState()}
}
```

- [ ] **Step 2: Write failing tests for mixin detection**

Append to `pkg/vex/reachability/treesitter/ruby/extractor_test.go`:

```go
func TestExtractSymbols_IncludeModule(t *testing.T) {
	source := `class Foo
  include Cacheable
  include Admin::Helpers
end`
	ext := New()
	tree := parseRuby(t, source)
	_, err := ext.ExtractSymbols("foo.rb", []byte(source), tree)
	if err != nil {
		t.Fatal(err)
	}

	mixins := ext.State().Mixins["Foo"]
	if len(mixins) != 2 {
		t.Fatalf("expected 2 mixins for Foo, got %d: %+v", len(mixins), mixins)
	}
	if mixins[0].Module != "Cacheable" || mixins[0].Kind != "include" {
		t.Errorf("mixin[0] = %+v, want {Cacheable, include}", mixins[0])
	}
	if mixins[1].Module != "Admin::Helpers" || mixins[1].Kind != "include" {
		t.Errorf("mixin[1] = %+v, want {Admin::Helpers, include}", mixins[1])
	}
}

func TestExtractSymbols_ExtendAndPrepend(t *testing.T) {
	source := `class Bar
  extend ClassMethods
  prepend Auditable
end`
	ext := New()
	tree := parseRuby(t, source)
	_, err := ext.ExtractSymbols("bar.rb", []byte(source), tree)
	if err != nil {
		t.Fatal(err)
	}

	mixins := ext.State().Mixins["Bar"]
	if len(mixins) != 2 {
		t.Fatalf("expected 2 mixins for Bar, got %d", len(mixins))
	}
	kinds := make(map[string]bool)
	for _, m := range mixins {
		kinds[m.Kind] = true
	}
	if !kinds["extend"] {
		t.Error("missing extend mixin")
	}
	if !kinds["prepend"] {
		t.Error("missing prepend mixin")
	}
}

func TestExtractSymbols_ClassHierarchy(t *testing.T) {
	source := `class Child < Base
  def hello
    "hi"
  end
end`
	ext := New()
	tree := parseRuby(t, source)
	_, err := ext.ExtractSymbols("child.rb", []byte(source), tree)
	if err != nil {
		t.Fatal(err)
	}

	parent, ok := ext.State().Hierarchy["Child"]
	if !ok || parent != "Base" {
		t.Errorf("Hierarchy[Child] = %q, want %q", parent, "Base")
	}
}

func TestExtractSymbols_ModuleMethods(t *testing.T) {
	source := `module Cacheable
  def cache_key
    "key"
  end

  def expire_cache
    "expired"
  end
end`
	ext := New()
	tree := parseRuby(t, source)
	_, err := ext.ExtractSymbols("cacheable.rb", []byte(source), tree)
	if err != nil {
		t.Fatal(err)
	}

	methods := ext.State().ModuleMethods["Cacheable"]
	if len(methods) != 2 {
		t.Fatalf("expected 2 methods for Cacheable, got %d: %v", len(methods), methods)
	}
}
```

Add a public accessor method to the extractor:

```go
func (e *Extractor) State() *CrossFileState {
	return e.state
}
```

- [ ] **Step 3: Run tests to verify they fail**

```
go test -run 'TestExtractSymbols_IncludeModule|TestExtractSymbols_ExtendAndPrepend|TestExtractSymbols_ClassHierarchy|TestExtractSymbols_ModuleMethods' -v ./pkg/vex/reachability/treesitter/ruby/...
```
Expected: FAIL — state is empty, State() method may not exist yet.

- [ ] **Step 4: Implement mixin/hierarchy/module-method detection**

In `extractContainerNode`, when processing a `class` node:

1. Check for a superclass: look for a `superclass` field child (`node.ChildByFieldName("superclass")`). If present, extract the constant name and record in `state.Hierarchy[qualifiedName] = superclassName`.

2. In `extractMethodsFromBody`, when encountering a `call` node with first child text `"include"`, `"extend"`, or `"prepend"`:
   - Extract the constant argument (first argument, which may be a `constant` or `scope_resolution` node).
   - For `scope_resolution` nodes (e.g., `Admin::Helpers`), recursively build the full constant name.
   - Record in `state.Mixins[className]`.

3. After extracting method symbols from a module body, record the method names in `state.ModuleMethods[qualifiedModuleName]`. Only record methods (not classes or nested modules).

For extracting constant names from arguments, add:

```go
func extractConstantName(node *tree_sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	switch node.Kind() {
	case "constant":
		return nodeText(node, src)
	case "scope_resolution":
		var parts []string
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(uint(i))
			if child.Kind() == "constant" {
				parts = append(parts, nodeText(child, src))
			} else if child.Kind() == "scope_resolution" {
				parts = append(parts, extractConstantName(child, src))
			}
		}
		return strings.Join(parts, "::")
	}
	return nodeText(node, src)
}
```

- [ ] **Step 5: Run tests to verify they pass**

```
go test -v ./pkg/vex/reachability/treesitter/ruby/...
```
Expected: all pass.

- [ ] **Step 6: Commit**

```
git add pkg/vex/reachability/treesitter/ruby/extractor.go pkg/vex/reachability/treesitter/ruby/extractor_test.go
git commit -m "feat(ruby): detect include/extend/prepend mixins and class hierarchy"
```

---

### Task 5: Add scope-aware call resolution

Make `ExtractCalls` consult the `Scope` parameter to resolve calls through imports.

**Files:**
- Modify: `pkg/vex/reachability/treesitter/ruby/extractor.go`
- Modify: `pkg/vex/reachability/treesitter/ruby/extractor_test.go`

- [ ] **Step 1: Write failing test**

Append to `pkg/vex/reachability/treesitter/ruby/extractor_test.go`:

```go
func TestExtractCalls_ScopeAwareResolution(t *testing.T) {
	source := `class Parser
  def parse(content)
    Nokogiri::HTML(content)
  end
end`
	ext := New()
	tree := parseRuby(t, source)

	scope := treesitter.NewScope(nil)
	scope.DefineImport("Nokogiri", "nokogiri.Nokogiri", nil)

	edges, err := ext.ExtractCalls("parser.rb", []byte(source), tree, scope)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, e := range edges {
		toStr := string(e.To)
		if toStr == "nokogiri.Nokogiri.HTML" || strings.HasPrefix(toStr, "nokogiri.Nokogiri") {
			found = true
			break
		}
	}
	if !found {
		var tos []string
		for _, e := range edges {
			tos = append(tos, string(e.To))
		}
		t.Errorf("expected scope-resolved target containing 'nokogiri.Nokogiri', got %v", tos)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```
go test -run 'TestExtractCalls_ScopeAwareResolution' -v ./pkg/vex/reachability/treesitter/ruby/...
```
Expected: FAIL — call target is `Nokogiri::HTML` (literal), not `nokogiri.Nokogiri.HTML` (resolved).

- [ ] **Step 3: Implement scope-aware resolution**

In `ExtractCalls`, pass the `scope` parameter through to `collectCalls` and `processCall`:

1. Update `collectCalls` signature to accept `scope *treesitter.Scope`.
2. Update `processCall` signature to accept `scope *treesitter.Scope`.
3. In `processCall`, after constructing the target from the AST, attempt scope resolution:

```go
func resolveTarget(target string, scope *treesitter.Scope) string {
	if scope == nil {
		return target
	}
	// Split on :: to get prefix and suffix
	parts := strings.SplitN(target, "::", 2)
	if len(parts) != 2 {
		// Try dot separator too
		parts = strings.SplitN(target, ".", 2)
		if len(parts) != 2 {
			return target
		}
	}
	resolved, ok := scope.LookupImport(parts[0])
	if !ok {
		return target
	}
	return resolved + "." + parts[1]
}
```

Apply this after building the target string in `processCall`, for both scope-resolution calls (`Nokogiri::HTML`) and method calls (`receiver.method`).

- [ ] **Step 4: Run tests to verify they pass**

```
go test -v ./pkg/vex/reachability/treesitter/ruby/...
```
Expected: all pass.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/treesitter/ruby/extractor.go pkg/vex/reachability/treesitter/ruby/extractor_test.go
git commit -m "feat(ruby): add scope-aware call resolution to ExtractCalls"
```

---

### Task 6: Add CrossFileStateExtractor support (SnapshotState/RestoreState)

Implement `SnapshotState` and `RestoreState` on the Ruby extractor so `RunHop` can accumulate mixin/hierarchy state across files.

**Files:**
- Modify: `pkg/vex/reachability/treesitter/ruby/extractor.go`
- Modify: `pkg/vex/reachability/treesitter/ruby/extractor_test.go`

- [ ] **Step 1: Write failing tests**

Append to `pkg/vex/reachability/treesitter/ruby/extractor_test.go`:

```go
func TestExtractor_SnapshotRestore(t *testing.T) {
	ext := New()

	// File 1: define a module with methods
	source1 := `module Cacheable
  def cache_key
    "key"
  end
end`
	tree1 := parseRuby(t, source1)
	_, err := ext.ExtractSymbols("cacheable.rb", []byte(source1), tree1)
	if err != nil {
		t.Fatal(err)
	}
	snap1 := ext.SnapshotState()

	// File 2: class includes the module
	source2 := `class User
  include Cacheable
end`
	tree2 := parseRuby(t, source2)
	_, err = ext.ExtractSymbols("user.rb", []byte(source2), tree2)
	if err != nil {
		t.Fatal(err)
	}
	snap2 := ext.SnapshotState()

	// Create a fresh extractor and restore both snapshots
	ext2 := New()
	ext2.RestoreState(snap1)
	ext2.RestoreState(snap2)

	state := ext2.State()
	if len(state.ModuleMethods["Cacheable"]) == 0 {
		t.Error("ModuleMethods[Cacheable] empty after restore")
	}
	if len(state.Mixins["User"]) == 0 {
		t.Error("Mixins[User] empty after restore")
	}
}

func TestExtractor_RestoreState_AppendUnique(t *testing.T) {
	ext := New()

	// Simulate duplicate snapshots
	ext.State().ModuleMethods["Foo"] = []string{"bar"}
	snap := ext.SnapshotState()

	ext.RestoreState(snap)
	ext.RestoreState(snap)

	methods := ext.State().ModuleMethods["Foo"]
	if len(methods) != 1 {
		t.Errorf("expected 1 method after duplicate restore, got %d: %v", len(methods), methods)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
go test -run 'TestExtractor_Snapshot' -v ./pkg/vex/reachability/treesitter/ruby/...
```
Expected: FAIL — `SnapshotState` and `RestoreState` methods don't exist.

- [ ] **Step 3: Implement SnapshotState and RestoreState**

Add to `pkg/vex/reachability/treesitter/ruby/extractor.go`:

```go
func (e *Extractor) SnapshotState() any {
	// Deep copy the state
	snap := newCrossFileState()
	for k, v := range e.state.Mixins {
		entries := make([]MixinEntry, len(v))
		copy(entries, v)
		snap.Mixins[k] = entries
	}
	for k, v := range e.state.Hierarchy {
		snap.Hierarchy[k] = v
	}
	for k, v := range e.state.ModuleMethods {
		methods := make([]string, len(v))
		copy(methods, v)
		snap.ModuleMethods[k] = methods
	}
	return snap
}

func (e *Extractor) RestoreState(s any) {
	snap, ok := s.(*CrossFileState)
	if !ok {
		return
	}
	// Merge with append-unique semantics
	for k, entries := range snap.Mixins {
		for _, entry := range entries {
			if !containsMixin(e.state.Mixins[k], entry) {
				e.state.Mixins[k] = append(e.state.Mixins[k], entry)
			}
		}
	}
	for k, v := range snap.Hierarchy {
		if _, exists := e.state.Hierarchy[k]; !exists {
			e.state.Hierarchy[k] = v
		}
	}
	for k, methods := range snap.ModuleMethods {
		for _, m := range methods {
			if !containsString(e.state.ModuleMethods[k], m) {
				e.state.ModuleMethods[k] = append(e.state.ModuleMethods[k], m)
			}
		}
	}
}

func containsMixin(entries []MixinEntry, entry MixinEntry) bool {
	for _, e := range entries {
		if e.Module == entry.Module && e.Kind == entry.Kind {
			return true
		}
	}
	return false
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

```
go test -v ./pkg/vex/reachability/treesitter/ruby/...
```
Expected: all pass.

- [ ] **Step 5: Run full test suite to check for regressions**

```
go test ./pkg/vex/reachability/ruby/... ./pkg/vex/reachability/treesitter/ruby/...
```
Expected: all pass.

- [ ] **Step 6: Commit**

```
git add pkg/vex/reachability/treesitter/ruby/extractor.go pkg/vex/reachability/treesitter/ruby/extractor_test.go
git commit -m "feat(ruby): add SnapshotState/RestoreState for cross-file mixin tracking"
```

---

## Phase 2 — Ruby LanguageSupport implementation

### Task 7: Create Ruby LanguageSupport (11 required methods)

**Files:**
- Create: `pkg/vex/reachability/transitive/languages/ruby/ruby.go`
- Create: `pkg/vex/reachability/transitive/languages/ruby/ruby_test.go`

- [ ] **Step 1: Write failing tests**

Create `pkg/vex/reachability/transitive/languages/ruby/ruby_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package ruby_test

import (
	"reflect"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/ruby"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestRuby_Identity(t *testing.T) {
	lang := ruby.New()
	if lang.Name() != "ruby" {
		t.Errorf("Name() = %q, want %q", lang.Name(), "ruby")
	}
	if lang.Ecosystem() != "rubygems" {
		t.Errorf("Ecosystem() = %q, want %q", lang.Ecosystem(), "rubygems")
	}
	exts := lang.FileExtensions()
	if len(exts) != 1 || exts[0] != ".rb" {
		t.Errorf("FileExtensions() = %v, want [\".rb\"]", exts)
	}
	if lang.Grammar() == nil {
		t.Error("Grammar() returned nil")
	}
	if lang.Extractor() == nil {
		t.Error("Extractor() returned nil")
	}
}

func TestRuby_IsExportedSymbol(t *testing.T) {
	lang := ruby.New()
	tests := []struct {
		name string
		sym  *treesitter.Symbol
		want bool
	}{
		{"nil", nil, false},
		{"public method", &treesitter.Symbol{Name: "create", Kind: treesitter.SymbolMethod, IsPublic: true}, true},
		{"public function", &treesitter.Symbol{Name: "run", Kind: treesitter.SymbolFunction, IsPublic: true}, true},
		{"public class", &treesitter.Symbol{Name: "User", Kind: treesitter.SymbolClass, IsPublic: true}, true},
		{"public module", &treesitter.Symbol{Name: "Admin", Kind: treesitter.SymbolModule, IsPublic: true}, true},
		{"private method", &treesitter.Symbol{Name: "secret", Kind: treesitter.SymbolMethod, IsPublic: false}, false},
		{"underscore method", &treesitter.Symbol{Name: "_internal", Kind: treesitter.SymbolMethod, IsPublic: true}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lang.IsExportedSymbol(tc.sym); got != tc.want {
				t.Errorf("IsExportedSymbol(%+v) = %v, want %v", tc.sym, got, tc.want)
			}
		})
	}
}

func TestRuby_ModulePath(t *testing.T) {
	lang := ruby.New()
	tests := []struct {
		name        string
		file        string
		sourceDir   string
		packageName string
		want        string
	}{
		{
			name:        "lib entry file",
			file:        "/tmp/nokogiri-1.15.0/lib/nokogiri.rb",
			sourceDir:   "/tmp/nokogiri-1.15.0",
			packageName: "nokogiri",
			want:        "nokogiri.nokogiri",
		},
		{
			name:        "nested lib file",
			file:        "/tmp/nokogiri-1.15.0/lib/nokogiri/html/document.rb",
			sourceDir:   "/tmp/nokogiri-1.15.0",
			packageName: "nokogiri",
			want:        "nokogiri.nokogiri.html.document",
		},
		{
			name:        "spec file excluded",
			file:        "/tmp/nokogiri-1.15.0/spec/html_spec.rb",
			sourceDir:   "/tmp/nokogiri-1.15.0",
			packageName: "nokogiri",
			want:        "nokogiri.spec.html_spec",
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

func TestRuby_SymbolKey(t *testing.T) {
	lang := ruby.New()
	got := lang.SymbolKey("nokogiri.nokogiri.html", "Document")
	want := "nokogiri.nokogiri.html.Document"
	if got != want {
		t.Errorf("SymbolKey = %q, want %q", got, want)
	}
}

func TestRuby_NormalizeImports(t *testing.T) {
	lang := ruby.New()
	raw := []treesitter.Import{
		{Module: "nokogiri", Alias: "nokogiri"},
		{Module: "active_support", Alias: "active_support"},
	}
	got := lang.NormalizeImports(raw)

	// nokogiri should get CamelCase alias from gem map
	if got[0].Alias != "Nokogiri" {
		t.Errorf("nokogiri alias = %q, want %q", got[0].Alias, "Nokogiri")
	}
	// active_support should get heuristic CamelCase alias
	if got[1].Alias != "ActiveSupport" {
		t.Errorf("active_support alias = %q, want %q", got[1].Alias, "ActiveSupport")
	}
}

func TestRuby_NormalizeImports_ReplacesColons(t *testing.T) {
	lang := ruby.New()
	raw := []treesitter.Import{
		{Module: "Foo::Bar", Alias: "Foo::Bar"},
	}
	got := lang.NormalizeImports(raw)
	if got[0].Module != "Foo.Bar" {
		t.Errorf("Module = %q, want %q", got[0].Module, "Foo.Bar")
	}
	if got[0].Alias != "Foo.Bar" {
		t.Errorf("Alias = %q, want %q", got[0].Alias, "Foo.Bar")
	}
}

func TestRuby_ResolveDottedTarget(t *testing.T) {
	lang := ruby.New()
	scope := treesitter.NewScope(nil)
	scope.DefineImport("Nokogiri", "nokogiri.Nokogiri", nil)

	t.Run("alias found", func(t *testing.T) {
		got, ok := lang.ResolveDottedTarget("Nokogiri", "HTML", scope)
		if !ok {
			t.Fatal("expected ok=true")
		}
		want := treesitter.SymbolID("nokogiri.Nokogiri.HTML")
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

func TestRuby_ResolveSelfCall(t *testing.T) {
	lang := ruby.New()
	tests := []struct {
		name string
		to   treesitter.SymbolID
		from treesitter.SymbolID
		want treesitter.SymbolID
	}{
		{
			name: "self call in class method",
			to:   "self.validate",
			from: "nokogiri.User.create",
			want: "nokogiri.User.validate",
		},
		{
			name: "short from — unchanged",
			to:   "self.helper",
			from: "mod.func",
			want: "self.helper",
		},
		{
			name: "non-self — unchanged",
			to:   "Nokogiri.HTML",
			from: "app.Parser.parse",
			want: "Nokogiri.HTML",
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

// Suppress unused import warning
var _ = reflect.DeepEqual
```

- [ ] **Step 2: Run tests to verify they fail**

```
go test -v ./pkg/vex/reachability/transitive/languages/ruby/...
```
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Implement ruby.go**

Create `pkg/vex/reachability/transitive/languages/ruby/ruby.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package ruby

import (
	"path/filepath"
	"strings"
	"unicode"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarruby "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/ruby"
	rubyextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/ruby"
)

var gemModuleMap = map[string]string{
	"nokogiri":      "Nokogiri",
	"rails":         "Rails",
	"activesupport": "ActiveSupport",
	"activerecord":  "ActiveRecord",
	"actionpack":    "ActionPack",
	"faraday":       "Faraday",
	"httparty":      "HTTParty",
	"rest-client":   "RestClient",
	"sidekiq":       "Sidekiq",
	"devise":        "Devise",
	"omniauth":      "OmniAuth",
	"rack":          "Rack",
	"sinatra":       "Sinatra",
	"puma":          "Puma",
	"json":          "JSON",
	"yaml":          "YAML",
	"net-http":      "Net",
	"uri":           "URI",
	"openssl":       "OpenSSL",
	"loofah":        "Loofah",
	"sanitize":      "Sanitize",
}

type Language struct {
	extractor treesitter.LanguageExtractor
}

func New() *Language {
	return &Language{extractor: rubyextractor.New()}
}

func (l *Language) Name() string                            { return "ruby" }
func (l *Language) Ecosystem() string                       { return "rubygems" }
func (l *Language) FileExtensions() []string                { return []string{".rb"} }
func (l *Language) Grammar() unsafe.Pointer                 { return grammarruby.Language() }
func (l *Language) Extractor() treesitter.LanguageExtractor { return l.extractor }

func (l *Language) IsExportedSymbol(sym *treesitter.Symbol) bool {
	if sym == nil {
		return false
	}
	if strings.HasPrefix(sym.Name, "_") {
		return false
	}
	if !sym.IsPublic {
		return false
	}
	switch sym.Kind {
	case treesitter.SymbolFunction, treesitter.SymbolMethod,
		treesitter.SymbolClass, treesitter.SymbolModule:
		return true
	}
	return false
}

func (l *Language) ModulePath(file, sourceDir, packageName string) string {
	rel, err := filepath.Rel(sourceDir, file)
	if err != nil {
		return packageName
	}
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	parts := strings.Split(rel, string(filepath.Separator))
	// Strip "lib/" prefix if present
	if len(parts) > 0 && parts[0] == "lib" {
		parts = parts[1:]
	}
	mod := strings.Join(parts, ".")
	return packageName + "." + mod
}

func (l *Language) SymbolKey(modulePath, symbolName string) string {
	return modulePath + "." + symbolName
}

func (l *Language) NormalizeImports(raw []treesitter.Import) []treesitter.Import {
	out := make([]treesitter.Import, len(raw))
	for i, imp := range raw {
		imp.Module = strings.ReplaceAll(imp.Module, "::", ".")
		// Set alias to the CamelCase module name for scope resolution
		if camel, ok := gemModuleMap[raw[i].Module]; ok {
			imp.Alias = camel
		} else {
			imp.Alias = toCamelCase(raw[i].Module)
		}
		imp.Alias = strings.ReplaceAll(imp.Alias, "::", ".")
		out[i] = imp
	}
	return out
}

func (l *Language) ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool) {
	resolved, ok := scope.LookupImport(prefix)
	if !ok {
		return "", false
	}
	return treesitter.SymbolID(resolved + "." + suffix), true
}

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

func toCamelCase(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-'
	})
	var b strings.Builder
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		runes := []rune(part)
		runes[0] = unicode.ToUpper(runes[0])
		b.WriteString(string(runes))
	}
	if b.Len() == 0 {
		return s
	}
	return b.String()
}
```

- [ ] **Step 4: Run tests to verify they pass**

```
go test -v ./pkg/vex/reachability/transitive/languages/ruby/...
```
Expected: all pass.

- [ ] **Step 5: Commit**

```
git add pkg/vex/reachability/transitive/languages/ruby/ruby.go pkg/vex/reachability/transitive/languages/ruby/ruby_test.go
git commit -m "feat(transitive): add Ruby LanguageSupport implementation"
```

---

### Task 8: Create Ruby ListExports (require-chain walk)

**Files:**
- Create: `pkg/vex/reachability/transitive/languages/ruby/exports.go`
- Create: `pkg/vex/reachability/transitive/languages/ruby/exports_test.go`

- [ ] **Step 1: Write failing tests**

Create `pkg/vex/reachability/transitive/languages/ruby/exports_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package ruby_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/ruby"
)

func writeGem(t *testing.T, name string, files map[string]string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), name)
	for path, content := range files {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
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

func TestListExports_SimpleGem(t *testing.T) {
	root := writeGem(t, "mygem", map[string]string{
		"lib/mygem.rb": `class MyGem
  def hello
    "hi"
  end
end`,
	})
	lang := ruby.New()
	keys, err := lang.ListExports(root, "mygem")
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, keys,
		"mygem.mygem.MyGem",
		"mygem.mygem.MyGem.hello",
	)
}

func TestListExports_NestedRequires(t *testing.T) {
	root := writeGem(t, "mygem", map[string]string{
		"lib/mygem.rb": `require_relative "mygem/parser"

class MyGem
end`,
		"lib/mygem/parser.rb": `class MyGem::Parser
  def parse(input)
    input.strip
  end
end`,
	})
	lang := ruby.New()
	keys, err := lang.ListExports(root, "mygem")
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, keys,
		"mygem.mygem.MyGem",
		"mygem.mygem.parser.MyGem::Parser",
		"mygem.mygem.parser.MyGem::Parser.parse",
	)
}

func TestListExports_PrivateMethodsExcluded(t *testing.T) {
	root := writeGem(t, "mygem", map[string]string{
		"lib/mygem.rb": `class MyGem
  def public_api
    "ok"
  end

  private

  def internal_helper
    "secret"
  end
end`,
	})
	lang := ruby.New()
	keys, err := lang.ListExports(root, "mygem")
	if err != nil {
		t.Fatal(err)
	}
	// Should include public_api but not internal_helper
	found := false
	for _, k := range keys {
		if k == "mygem.mygem.MyGem.internal_helper" {
			t.Error("private method should not be exported")
		}
		if k == "mygem.mygem.MyGem.public_api" {
			found = true
		}
	}
	if !found {
		t.Errorf("missing public_api in exports: %v", keys)
	}
}

func TestListExports_AttrAccessors(t *testing.T) {
	root := writeGem(t, "mygem", map[string]string{
		"lib/mygem.rb": `class Config
  attr_accessor :host
  attr_reader :port
end`,
	})
	lang := ruby.New()
	keys, err := lang.ListExports(root, "mygem")
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, keys,
		"mygem.mygem.Config",
		"mygem.mygem.Config.host",
		"mygem.mygem.Config.host=",
		"mygem.mygem.Config.port",
	)
}

func TestListExports_ExternalRequireSkipped(t *testing.T) {
	root := writeGem(t, "mygem", map[string]string{
		"lib/mygem.rb": `require "json"
require_relative "mygem/core"

class MyGem
end`,
		"lib/mygem/core.rb": `class MyGem::Core
  def run
    "running"
  end
end`,
	})
	lang := ruby.New()
	keys, err := lang.ListExports(root, "mygem")
	if err != nil {
		t.Fatal(err)
	}
	// json should not contribute any symbols
	for _, k := range keys {
		if len(k) > 0 && k[0] == 'j' {
			t.Errorf("external require 'json' leaked into exports: %q", k)
		}
	}
}

func TestListExports_CircularRequire(t *testing.T) {
	root := writeGem(t, "mygem", map[string]string{
		"lib/mygem.rb":       `require_relative "mygem/a"`,
		"lib/mygem/a.rb":     `require_relative "b"
class A; def x; end; end`,
		"lib/mygem/b.rb":     `require_relative "a"
class B; def y; end; end`,
	})
	lang := ruby.New()
	keys, err := lang.ListExports(root, "mygem")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Error("circular require should not crash — expected some exports")
	}
}

func TestListExports_NoEntryFile(t *testing.T) {
	root := writeGem(t, "oddgem", map[string]string{
		"lib/something.rb": `class Something; def x; end; end`,
	})
	lang := ruby.New()
	keys, err := lang.ListExports(root, "oddgem")
	if err != nil {
		t.Fatal(err)
	}
	// Fallback: should still find symbols from lib/
	if len(keys) == 0 {
		t.Error("expected fallback to find symbols in lib/")
	}
}

func TestListExports_HyphenatedGemName(t *testing.T) {
	root := writeGem(t, "my-gem", map[string]string{
		"lib/my/gem.rb": `class MyGem; def x; end; end`,
	})
	lang := ruby.New()
	keys, err := lang.ListExports(root, "my-gem")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Error("hyphenated gem name should find entry file via lib/my/gem.rb")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
go test -run 'TestListExports' -v ./pkg/vex/reachability/transitive/languages/ruby/...
```
Expected: FAIL — `ListExports` method doesn't exist.

- [ ] **Step 3: Implement exports.go**

Create `pkg/vex/reachability/transitive/languages/ruby/exports.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package ruby

import (
	"os"
	"path/filepath"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarruby "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/ruby"
	rubyextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/ruby"
)

func (l *Language) ListExports(sourceDir, packageName string) ([]string, error) {
	entryFile := findEntryFile(sourceDir, packageName)
	var files []string
	if entryFile != "" {
		files = walkRequireChain(entryFile, sourceDir)
	} else {
		// Fallback: all .rb files under lib/
		libDir := filepath.Join(sourceDir, "lib")
		_ = filepath.WalkDir(libDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !d.IsDir() && strings.HasSuffix(path, ".rb") {
				files = append(files, path)
			}
			return nil
		})
	}

	if len(files) == 0 {
		return nil, nil
	}

	ext := rubyextractor.New()
	parser := tree_sitter.NewParser()
	defer parser.Close()
	lang := tree_sitter.NewLanguage(grammarruby.Language())
	if err := parser.SetLanguage(lang); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}
		defer tree.Close()

		symbols, err := ext.ExtractSymbols(file, src, tree)
		if err != nil {
			continue
		}

		modulePath := l.ModulePath(file, sourceDir, packageName)
		for _, sym := range symbols {
			if !l.IsExportedSymbol(sym) {
				continue
			}
			key := l.SymbolKey(modulePath, sym.QualifiedName)
			if !seen[key] {
				seen[key] = true
			}
		}
	}

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	return keys, nil
}

func findEntryFile(sourceDir, packageName string) string {
	candidates := []string{
		filepath.Join(sourceDir, "lib", packageName+".rb"),
		filepath.Join(sourceDir, "lib", strings.ReplaceAll(packageName, "-", string(filepath.Separator))+".rb"),
		filepath.Join(sourceDir, "lib", strings.ReplaceAll(packageName, "-", "_")+".rb"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func walkRequireChain(entryFile, sourceDir string) []string {
	visited := make(map[string]bool)
	var result []string
	var walk func(file string)
	walk = func(file string) {
		abs, err := filepath.Abs(file)
		if err != nil {
			return
		}
		if visited[abs] {
			return
		}
		visited[abs] = true
		result = append(result, abs)

		src, err := os.ReadFile(abs)
		if err != nil {
			return
		}

		parser := tree_sitter.NewParser()
		defer parser.Close()
		lang := tree_sitter.NewLanguage(grammarruby.Language())
		if err := parser.SetLanguage(lang); err != nil {
			return
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			return
		}
		defer tree.Close()

		ext := rubyextractor.New()
		imports, err := ext.ResolveImports(abs, src, tree, "")
		if err != nil {
			return
		}

		for _, imp := range imports {
			resolved := resolveRequire(imp.Module, abs, sourceDir)
			if resolved != "" {
				walk(resolved)
			}
		}
	}
	walk(entryFile)
	return result
}

func resolveRequire(module, currentFile, sourceDir string) string {
	// require_relative: path is relative to current file's directory
	// require: path is relative to lib/ directory
	// We try both interpretations.
	dir := filepath.Dir(currentFile)

	candidates := []string{
		filepath.Join(dir, module+".rb"),
		filepath.Join(dir, module),
		filepath.Join(sourceDir, "lib", module+".rb"),
		filepath.Join(sourceDir, "lib", module),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}
```

- [ ] **Step 4: Run tests to verify they pass**

```
go test -run 'TestListExports' -v ./pkg/vex/reachability/transitive/languages/ruby/...
```
Expected: all pass. Iterate on any failures — the key format must match test expectations exactly.

- [ ] **Step 5: Run full test suite**

```
go test -v ./pkg/vex/reachability/transitive/languages/ruby/...
```
Expected: all pass.

- [ ] **Step 6: Commit**

```
git add pkg/vex/reachability/transitive/languages/ruby/exports.go pkg/vex/reachability/transitive/languages/ruby/exports_test.go
git commit -m "feat(transitive): add Ruby ListExports via require-chain walk"
```

---

## Phase 3 — Registration and fetcher

### Task 9: Register Ruby in LanguageFor and buildFetchers

**Files:**
- Modify: `pkg/vex/reachability/transitive/language.go`
- Modify: `pkg/vex/reachability/transitive/language_test.go`
- Modify: `pkg/vex/transitive_wire.go`

- [ ] **Step 1: Update language_test.go first (TDD)**

In `pkg/vex/reachability/transitive/language_test.go`:

Add `"ruby"` to `TestLanguageFor_RegisteredLanguages`:

```go
{"ruby", "ruby", "rubygems"},
```

Remove `"ruby"` from `TestLanguageFor_UnknownLanguage` (it was previously listed as unsupported).

Add `"ruby"` to the `TestLanguageSupport_Contract` languages slice.

- [ ] **Step 2: Run tests to verify they fail**

```
go test -run 'TestLanguageFor|TestLanguageSupport_Contract' -v ./pkg/vex/reachability/transitive/...
```
Expected: FAIL — `LanguageFor("ruby")` returns "unsupported language".

- [ ] **Step 3: Register Ruby in LanguageFor**

In `pkg/vex/reachability/transitive/language.go`, add to the `LanguageFor` switch:

```go
case "ruby":
    return ruby.New(), nil
```

Add the import:

```go
"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/ruby"
```

- [ ] **Step 4: Register rubygems in buildFetchers**

In `pkg/vex/transitive_wire.go`, add to the `buildFetchers` switch:

```go
case "rubygems":
    return map[string]transitive.Fetcher{"rubygems": &transitive.RubyGemsFetcher{Cache: cache}}
```

Note: `RubyGemsFetcher` doesn't exist yet — this will be created in Task 10. For now, add the case but leave it commented or behind a compile guard. Alternatively, create a minimal stub file first.

- [ ] **Step 5: Run tests to verify registration works**

```
go test -run 'TestLanguageFor|TestLanguageSupport_Contract' -v ./pkg/vex/reachability/transitive/...
```
Expected: all pass.

- [ ] **Step 6: Commit**

```
git add pkg/vex/reachability/transitive/language.go pkg/vex/reachability/transitive/language_test.go
git commit -m "feat(transitive): register Ruby in LanguageFor"
```

---

### Task 10: Create RubyGems fetcher

**Files:**
- Create: `pkg/vex/reachability/transitive/fetcher_rubygems.go`
- Create: `pkg/vex/reachability/transitive/fetcher_rubygems_test.go`

- [ ] **Step 1: Write failing tests**

Create `pkg/vex/reachability/transitive/fetcher_rubygems_test.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

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

func TestRubyGemsFetcher_Ecosystem(t *testing.T) {
	f := &RubyGemsFetcher{}
	if f.Ecosystem() != "rubygems" {
		t.Errorf("Ecosystem() = %q, want %q", f.Ecosystem(), "rubygems")
	}
}

func TestRubyGemsFetcher_Manifest_HappyPath(t *testing.T) {
	gemData := buildTestGem(t, "mygem", "1.0.0", "class MyGem; end",
		"--- !ruby/object:Gem::Specification\nname: mygem\nversion: !ruby/object:Gem::Version\n  version: 1.0.0\ndependencies:\n- !ruby/object:Gem::Dependency\n  name: json\n  type: :runtime\n  requirement: !ruby/object:Gem::Requirement\n    requirements:\n    - - \">=\"\n      - !ruby/object:Gem::Version\n        version: '0'\n- !ruby/object:Gem::Dependency\n  name: rspec\n  type: :development\n  requirement: !ruby/object:Gem::Requirement\n    requirements:\n    - - \">=\"\n      - !ruby/object:Gem::Version\n        version: '0'\n")
	digest := sha256Hex(gemData)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v2/rubygems/mygem/versions/1.0.0.json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"sha": %q, "gem_uri": "%s/downloads/mygem-1.0.0.gem"}`, digest, "")
		case strings.HasSuffix(r.URL.Path, "/downloads/mygem-1.0.0.gem"):
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(gemData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f := &RubyGemsFetcher{BaseURL: srv.URL, HTTPClient: srv.Client(), Cache: NewCache(t.TempDir())}
	m, err := f.Manifest(context.Background(), "mygem", "1.0.0")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if _, ok := m.Dependencies["json"]; !ok {
		t.Error("json not in dependencies")
	}
	if _, ok := m.Dependencies["rspec"]; ok {
		t.Error("rspec (development) should have been filtered")
	}
}

func TestRubyGemsFetcher_Fetch_HappyPath(t *testing.T) {
	gemData := buildTestGem(t, "mini", "0.1.0", "class Mini; def hello; end; end",
		"--- !ruby/object:Gem::Specification\nname: mini\nversion: !ruby/object:Gem::Version\n  version: 0.1.0\ndependencies: []\n")
	digest := sha256Hex(gemData)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v2/rubygems/mini/versions/0.1.0.json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"sha": %q, "gem_uri": "%s/downloads/mini-0.1.0.gem"}`, digest, "")
		case strings.HasSuffix(r.URL.Path, "/downloads/mini-0.1.0.gem"):
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(gemData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f := &RubyGemsFetcher{BaseURL: srv.URL, HTTPClient: srv.Client(), Cache: NewCache(t.TempDir())}
	fr, err := f.Fetch(context.Background(), "mini", "0.1.0", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fr.SourceDir == "" {
		t.Fatal("SourceDir empty")
	}
	// Check that the .rb file exists in the unpacked source
	found := false
	_ = filepath.WalkDir(fr.SourceDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(path, ".rb") {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("no .rb files found in unpacked source")
	}
}

func TestRubyGemsFetcher_Fetch_DigestMismatch(t *testing.T) {
	gemData := buildTestGem(t, "bad", "0.1.0", "class Bad; end",
		"--- !ruby/object:Gem::Specification\nname: bad\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v2/rubygems/bad/versions/0.1.0.json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sha": "deadbeef", "gem_uri": ""}`))
		case strings.HasSuffix(r.URL.Path, "/downloads/bad-0.1.0.gem"):
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(gemData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f := &RubyGemsFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.Fetch(context.Background(), "bad", "0.1.0", nil)
	if err == nil || !strings.Contains(err.Error(), ReasonDigestMismatch) {
		t.Errorf("Fetch: want %q in error, got %v", ReasonDigestMismatch, err)
	}
}

func TestRubyGemsFetcher_Manifest_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	f := &RubyGemsFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.Manifest(context.Background(), "nope", "0.0.1")
	if err == nil {
		t.Fatal("Manifest: expected error, got nil")
	}
}

// buildTestGem creates a minimal .gem file (tar containing data.tar.gz and metadata.gz).
func buildTestGem(t *testing.T, name, version, libContent, gemspecYAML string) []byte {
	t.Helper()

	// Build data.tar.gz (the source files)
	var dataBuf bytes.Buffer
	dataGz := gzip.NewWriter(&dataBuf)
	dataTar := tar.NewWriter(dataGz)
	writeTestTarFile(t, dataTar, "lib/"+name+".rb", libContent)
	if err := dataTar.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dataGz.Close(); err != nil {
		t.Fatal(err)
	}

	// Build metadata.gz
	var metaBuf bytes.Buffer
	metaGz := gzip.NewWriter(&metaBuf)
	if _, err := metaGz.Write([]byte(gemspecYAML)); err != nil {
		t.Fatal(err)
	}
	if err := metaGz.Close(); err != nil {
		t.Fatal(err)
	}

	// Build the outer .gem tar (NOT gzipped)
	var gemBuf bytes.Buffer
	gemTar := tar.NewWriter(&gemBuf)
	writeTestTarBytes(t, gemTar, "data.tar.gz", dataBuf.Bytes())
	writeTestTarBytes(t, gemTar, "metadata.gz", metaBuf.Bytes())
	if err := gemTar.Close(); err != nil {
		t.Fatal(err)
	}

	return gemBuf.Bytes()
}

func writeTestTarFile(t *testing.T, tw *tar.Writer, path, content string) {
	t.Helper()
	hdr := &tar.Header{Name: path, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
}

func writeTestTarBytes(t *testing.T, tw *tar.Writer, path string, data []byte) {
	t.Helper()
	hdr := &tar.Header{Name: path, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
go test -run 'TestRubyGemsFetcher' -v ./pkg/vex/reachability/transitive/...
```
Expected: FAIL — `RubyGemsFetcher` type doesn't exist.

- [ ] **Step 3: Implement fetcher_rubygems.go**

Create `pkg/vex/reachability/transitive/fetcher_rubygems.go`:

```go
// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type RubyGemsFetcher struct {
	BaseURL    string
	HTTPClient *http.Client
	Cache      *Cache
}

func (f *RubyGemsFetcher) Ecosystem() string { return "rubygems" }

func (f *RubyGemsFetcher) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return http.DefaultClient
}

func (f *RubyGemsFetcher) baseURL() string {
	if f.BaseURL != "" {
		return f.BaseURL
	}
	return "https://rubygems.org"
}

type rubygemsVersionMeta struct {
	SHA    string `json:"sha"`
	GemURI string `json:"gem_uri"`
}

func (f *RubyGemsFetcher) fetchMeta(ctx context.Context, name, version string) (*rubygemsVersionMeta, error) {
	url := fmt.Sprintf("%s/api/v2/rubygems/%s/versions/%s.json", f.baseURL(), name, version)
	var m rubygemsVersionMeta
	if err := httpGetJSON(ctx, f.client(), url, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (f *RubyGemsFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	// Download the .gem to extract gemspec from metadata.gz
	gemBody, err := f.downloadGem(ctx, name, version)
	if err != nil {
		return PackageManifest{}, err
	}

	gemspecYAML, err := extractMetadataGz(gemBody)
	if err != nil {
		return PackageManifest{}, fmt.Errorf("%s: parse gemspec: %w", ReasonManifestFetchFailed, err)
	}

	deps := parseGemspecDeps(gemspecYAML)
	return PackageManifest{Dependencies: deps}, nil
}

func (f *RubyGemsFetcher) downloadGem(ctx context.Context, name, version string) ([]byte, error) {
	meta, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}
	gemURL := meta.GemURI
	if gemURL == "" {
		gemURL = fmt.Sprintf("%s/downloads/%s-%s.gem", f.baseURL(), name, version)
	}
	body, err := httpGetBytes(ctx, f.client(), gemURL)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ReasonTarballFetchFailed, err)
	}
	return body, nil
}

//nolint:gocyclo // download-verify-unpack pipeline
func (f *RubyGemsFetcher) Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error) {
	meta, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}

	registryDigest := Digest{Algorithm: "sha256", Hex: meta.SHA}

	if f.Cache != nil {
		if p, ok := f.Cache.Get(registryDigest.String()); ok {
			return FetchResult{SourceDir: p, Digest: registryDigest}, nil
		}
	}

	gemURL := meta.GemURI
	if gemURL == "" {
		gemURL = fmt.Sprintf("%s/downloads/%s-%s.gem", f.baseURL(), name, version)
	}
	body, err := httpGetBytes(ctx, f.client(), gemURL)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonTarballFetchFailed, err)
	}

	actual := Digest{Algorithm: "sha256", Hex: hashHex(body)}
	if !actual.Equals(registryDigest) {
		return FetchResult{}, fmt.Errorf("%s: expected %s, got %s", ReasonDigestMismatch, registryDigest, actual)
	}
	if expectedDigest != nil && !expectedDigest.IsZero() && !expectedDigest.Equals(actual) {
		return FetchResult{}, fmt.Errorf("%s: SBOM expected %s, registry returned %s", ReasonDigestMismatch, expectedDigest, actual)
	}

	tmp, err := os.MkdirTemp("", "rubygems-*")
	if err != nil {
		return FetchResult{}, err
	}

	if err := extractDataTarGz(body, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return FetchResult{}, fmt.Errorf("unpack gem %s: %w", name, err)
	}

	srcDir := tmp
	if f.Cache != nil {
		p, putErr := f.Cache.Put(actual.String(), tmp)
		_ = os.RemoveAll(tmp)
		if putErr != nil {
			return FetchResult{}, putErr
		}
		srcDir = p
	}
	return FetchResult{SourceDir: srcDir, Digest: actual}, nil
}

// extractDataTarGz reads a .gem file (plain tar), finds data.tar.gz, and unpacks it into dst.
func extractDataTarGz(gemData []byte, dst string) error {
	tr := tar.NewReader(bytes.NewReader(gemData))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("data.tar.gz not found in gem")
		}
		if err != nil {
			return err
		}
		if hdr.Name == "data.tar.gz" {
			data, err := io.ReadAll(io.LimitReader(tr, 500<<20)) // 500 MiB limit
			if err != nil {
				return err
			}
			return untarGz(data, dst)
		}
	}
}

// extractMetadataGz reads a .gem file and extracts the gemspec YAML from metadata.gz.
func extractMetadataGz(gemData []byte) (string, error) {
	tr := tar.NewReader(bytes.NewReader(gemData))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return "", fmt.Errorf("metadata.gz not found in gem")
		}
		if err != nil {
			return "", err
		}
		if hdr.Name == "metadata.gz" {
			gz, err := gzip.NewReader(tr)
			if err != nil {
				return "", err
			}
			defer gz.Close() //nolint:errcheck
			data, err := io.ReadAll(io.LimitReader(gz, 10<<20)) // 10 MiB limit
			if err != nil {
				return "", err
			}
			return string(data), nil
		}
	}
}

// parseGemspecDeps extracts runtime dependencies from gemspec YAML.
// Uses simple string parsing — the gemspec YAML format is well-defined.
func parseGemspecDeps(yaml string) map[string]string {
	deps := make(map[string]string)
	lines := strings.Split(yaml, "\n")
	inDep := false
	currentName := ""
	isRuntime := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- !ruby/object:Gem::Dependency") {
			inDep = true
			currentName = ""
			isRuntime = false
			continue
		}
		if inDep {
			if strings.HasPrefix(trimmed, "name: ") {
				currentName = strings.TrimPrefix(trimmed, "name: ")
			} else if strings.HasPrefix(trimmed, "type: ") {
				depType := strings.TrimPrefix(trimmed, "type: ")
				isRuntime = depType == ":runtime"
			} else if strings.HasPrefix(trimmed, "- !ruby/object:Gem::") || (!strings.HasPrefix(trimmed, " ") && !strings.HasPrefix(trimmed, "-") && trimmed != "" && !strings.HasPrefix(trimmed, "requirement") && !strings.HasPrefix(trimmed, "version")) {
				// End of current dependency block
				if isRuntime && currentName != "" {
					deps[currentName] = ">= 0"
				}
				inDep = false
			}
		}
	}
	// Handle last dep
	if inDep && isRuntime && currentName != "" {
		deps[currentName] = ">= 0"
	}
	return deps
}
```

- [ ] **Step 4: Run tests to verify they pass**

```
go test -run 'TestRubyGemsFetcher' -v ./pkg/vex/reachability/transitive/...
```
Expected: all pass.

- [ ] **Step 5: Wire buildFetchers**

Now uncomment/add the rubygems case in `pkg/vex/transitive_wire.go`:

```go
case "rubygems":
    return map[string]transitive.Fetcher{"rubygems": &transitive.RubyGemsFetcher{Cache: cache}}
```

- [ ] **Step 6: Commit**

```
git add pkg/vex/reachability/transitive/fetcher_rubygems.go pkg/vex/reachability/transitive/fetcher_rubygems_test.go pkg/vex/transitive_wire.go
git commit -m "feat(transitive): add RubyGems fetcher with double-unpack"
```

---

## Phase 4 — Integration and judge tests

### Task 11: Create integration test fixtures

Create test fixtures for a real Ruby cross-package vulnerability. The fixture uses a minimal Rails-style app that calls `Nokogiri::HTML(user_input)` — Nokogiri wraps libxml2 and has had CVEs. The safe variant uses only string parsing, no Nokogiri call.

**Files:**
- Create: `testdata/integration/ruby-realworld-cross-package/`
- Create: `testdata/integration/ruby-realworld-cross-package-safe/`
- Modify: `pkg/vex/reachability/transitive/integration_test.go`

- [ ] **Step 1: Create reachable fixture source**

Create `testdata/integration/ruby-realworld-cross-package/source/app.rb`:

```ruby
require 'nokogiri'

class HtmlParser
  def parse(content)
    doc = Nokogiri::HTML(content)
    doc.css('title').text
  end
end

def main
  parser = HtmlParser.new
  puts parser.parse("<html><title>Hello</title></html>")
end

main
```

Create `testdata/integration/ruby-realworld-cross-package/source/Gemfile`:

```
source "https://rubygems.org"
gem "nokogiri", "~> 1.15.0"
```

Create `testdata/integration/ruby-realworld-cross-package/sbom.cdx.json` — a minimal CycloneDX SBOM listing the app and nokogiri as a dependency. Use `pkg:gem/` as the PURL type:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {
    "component": {
      "bom-ref": "app",
      "name": "html-parser-app",
      "version": "0.1.0",
      "type": "application"
    }
  },
  "components": [
    {
      "bom-ref": "pkg:gem/nokogiri@1.15.6",
      "name": "nokogiri",
      "version": "1.15.6",
      "purl": "pkg:gem/nokogiri@1.15.6",
      "type": "library"
    },
    {
      "bom-ref": "pkg:gem/mini_portile2@2.8.5",
      "name": "mini_portile2",
      "version": "2.8.5",
      "purl": "pkg:gem/mini_portile2@2.8.5",
      "type": "library"
    }
  ],
  "dependencies": [
    {
      "ref": "app",
      "dependsOn": ["pkg:gem/nokogiri@1.15.6"]
    },
    {
      "ref": "pkg:gem/nokogiri@1.15.6",
      "dependsOn": ["pkg:gem/mini_portile2@2.8.5"]
    }
  ]
}
```

Create `testdata/integration/ruby-realworld-cross-package/expected.json`:

```json
{
  "description": "Ruby app calling Nokogiri::HTML (transitive reachability through nokogiri gem)",
  "findings": [
    {
      "cve": "hypothetical-nokogiri-vuln",
      "component_purl": "pkg:gem/nokogiri@1.15.6",
      "expected_status": "affected",
      "expected_resolved_by": "transitive_reachability"
    }
  ]
}
```

- [ ] **Step 2: Create safe fixture source**

Create `testdata/integration/ruby-realworld-cross-package-safe/source/app.rb`:

```ruby
require 'json'

class JsonParser
  def parse(content)
    JSON.parse(content)
  end
end

def main
  parser = JsonParser.new
  puts parser.parse('{"title": "Hello"}')
end

main
```

Create `testdata/integration/ruby-realworld-cross-package-safe/source/Gemfile`:

```
source "https://rubygems.org"
gem "json"
gem "nokogiri", "~> 1.15.0"
```

Create `testdata/integration/ruby-realworld-cross-package-safe/sbom.cdx.json` (same components but the app doesn't call Nokogiri):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {
    "component": {
      "bom-ref": "app",
      "name": "json-parser-app",
      "version": "0.1.0",
      "type": "application"
    }
  },
  "components": [
    {
      "bom-ref": "pkg:gem/nokogiri@1.15.6",
      "name": "nokogiri",
      "version": "1.15.6",
      "purl": "pkg:gem/nokogiri@1.15.6",
      "type": "library"
    }
  ],
  "dependencies": [
    {
      "ref": "app",
      "dependsOn": ["pkg:gem/nokogiri@1.15.6"]
    }
  ]
}
```

Create `testdata/integration/ruby-realworld-cross-package-safe/expected.json`:

```json
{
  "description": "Ruby app NOT calling Nokogiri (JSON only — nokogiri in SBOM but not used)",
  "findings": [
    {
      "cve": "hypothetical-nokogiri-vuln",
      "component_purl": "pkg:gem/nokogiri@1.15.6",
      "expected_status": "not_affected",
      "expected_resolved_by": "transitive_reachability"
    }
  ]
}
```

- [ ] **Step 3: Add integration test cases**

In `pkg/vex/reachability/transitive/integration_test.go`, add the `"rubygems"` case to `runIntegrationFixture`'s fetcher switch:

```go
case "rubygems":
    fetcher = &RubyGemsFetcher{Cache: cache}
```

Add the test functions:

```go
func TestIntegration_Transitive_RubyReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "ruby-realworld-cross-package")
	runIntegrationFixture(t, dir, "ruby", "rubygems", "nokogiri", "1.15.6", true)
}

func TestIntegration_Transitive_RubyNotReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "ruby-realworld-cross-package-safe")
	runIntegrationFixture(t, dir, "ruby", "rubygems", "nokogiri", "1.15.6", false)
}
```

Also update `parseSBOMForTest` to handle the rubygems PURL prefix. Add to the ecosystem-to-PURL mapping:

```go
if ecosystem == "rubygems" {
    purlType = "gem"
}
```

- [ ] **Step 4: Run integration tests**

```
go test -tags integration -run 'TestIntegration_Transitive_Ruby' -v -timeout 5m ./pkg/vex/reachability/transitive/...
```
Expected: both pass — reachable finds a path through nokogiri, not-reachable confirms no path.

Note: This test hits the real rubygems.org API. If network issues occur, verify the test fixture SBOMs and source are correct, then retry.

- [ ] **Step 5: Commit**

```
git add testdata/integration/ruby-realworld-cross-package/ testdata/integration/ruby-realworld-cross-package-safe/ pkg/vex/reachability/transitive/integration_test.go
git commit -m "test(transitive): add Ruby cross-package integration test fixtures"
```

---

### Task 12: Add Ruby LLM judge test

**Files:**
- Modify: `pkg/vex/reachability/ruby/llm_judge_test.go`
- Modify: `Taskfile.yml`

- [ ] **Step 1: Add transitive judge test function**

Append to `pkg/vex/reachability/ruby/llm_judge_test.go` (which already exists with the standalone judge tests). Add the transitive variant following the Rust pattern:

```go
func TestLLMJudge_RubyTransitiveReachability(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	reachableDir := filepath.Join(fixtureBase, "ruby-realworld-cross-package")
	notReachableDir := filepath.Join(fixtureBase, "ruby-realworld-cross-package-safe")

	summary := parseSBOMForRubyJudge(t, reachableDir, "rubygems")

	cache := transitive.NewCache(t.TempDir())
	fetcher := &transitive.RubyGemsFetcher{Cache: cache}
	lang, langErr := transitive.LanguageFor("ruby")
	if langErr != nil {
		t.Fatalf("LanguageFor(ruby): %v", langErr)
	}
	ta := &transitive.Analyzer{
		Config:   transitive.DefaultConfig(),
		Language: lang,
		Fetchers: map[string]transitive.Fetcher{"rubygems": fetcher},
	}

	finding := &formats.Finding{
		AffectedName:    "nokogiri",
		AffectedVersion: "1.15.6",
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

	prompt := fmt.Sprintf(`You are a security engineering judge evaluating a transitive dependency reachability analyzer for CRA (Cyber Resilience Act) compliance. The analyzer uses tree-sitter AST parsing for Ruby source code.

VULNERABILITY: hypothetical vulnerability in nokogiri@1.15.6.
VULNERABLE PACKAGE: nokogiri@1.15.6 (direct dependency)
EXPECTED REACHABLE CHAIN: HtmlParser::parse() → Nokogiri::HTML()
EXPECTED SAFE CHAIN: JsonParser::parse() → JSON.parse() [does NOT call Nokogiri]

REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%%v, Confidence=%%s, Degradations=%%v
Call paths found: %s
Evidence: %s

NOT-REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%%v, Confidence=%%s, Degradations=%%v
Evidence: %s

Score the transitive Ruby analyzer (1-10 each):
1. path_accuracy: Are the reported cross-package call paths real and correctly tracing through Nokogiri::HTML?
2. confidence_calibration: Does the confidence level correctly reflect the certainty of transitive Ruby analysis?
3. evidence_quality: Is the stitched call path evidence sufficient for a VEX determination under CRA Article 14?
4. false_positive_rate: Is the not-reachable case (JSON.parse only) correctly identified as not-affected?
5. symbol_resolution: Are the cross-gem symbols correctly resolved (HtmlParser::parse → Nokogiri::HTML)?
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

	var scores struct {
		PathAccuracy          int    `json:"path_accuracy"`
		ConfidenceCalibration int    `json:"confidence_calibration"`
		EvidenceQuality       int    `json:"evidence_quality"`
		FalsePositiveRate     int    `json:"false_positive_rate"`
		SymbolResolution      int    `json:"symbol_resolution"`
		OverallQuality        int    `json:"overall_quality"`
		Reasoning             string `json:"reasoning"`
	}
	if err := json.Unmarshal([]byte(responseText[jsonStart:jsonEnd+1]), &scores); err != nil {
		t.Fatalf("parse scores: %v\nresponse: %s", err, responseText)
	}

	t.Logf("Ruby Transitive LLM Scores: path=%d, confidence=%d, evidence=%d, fp=%d, symbol=%d, overall=%d",
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
```

Add the `parseSBOMForRubyJudge` helper following the Rust pattern — same as `parseSBOMForRustJudge` but with `prefix := "pkg:gem/"`.

Make sure the imports include `transitive`, `formats`, `exec`, `runtime`, `time`, etc.

- [ ] **Step 2: Add Ruby to Taskfile**

In `Taskfile.yml`, add to `test:reachability:transitive:llmjudge` commands:

```yaml
      - go test -race -count=1 -tags llmjudge -run TestLLMJudge_RubyTransitiveReachability -v ./pkg/vex/reachability/ruby/...
```

- [ ] **Step 3: Run the LLM judge test**

```
task test:reachability:transitive:llmjudge
```
Expected: all judge tests pass (Python, JavaScript, Rust, Ruby ≥ 6 per dimension).

- [ ] **Step 4: Commit**

```
git add pkg/vex/reachability/ruby/llm_judge_test.go Taskfile.yml
git commit -m "test(ruby): add transitive reachability LLM judge test"
```

---

## Phase 5 — Final gates

### Task 13: Run full regression suite

- [ ] **Step 1: Run task test**

```
task test
```
Expected: all pass.

- [ ] **Step 2: Run task quality**

```
task quality
```
Expected: lint + format clean.

- [ ] **Step 3: Run transitive integration tests**

```
task test:transitive
```
Expected: all pass including new Ruby cases.

- [ ] **Step 4: Run LLM judge tests**

```
task test:reachability:transitive:llmjudge
```
Expected: Python ≥ 9, JavaScript ≥ 9, Rust ≥ 9, Ruby ≥ 6 per dimension (iterate on fixture if below).

- [ ] **Step 5: Fix any issues and commit**

If any gate fails, fix the issue and create a new commit. Do not amend previous commits.
