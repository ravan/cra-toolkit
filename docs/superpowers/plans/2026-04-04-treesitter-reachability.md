# Tree-sitter Reachability Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add interprocedural call graph reachability analysis via tree-sitter for Python, JS/TS, Java, C#, PHP, and Ruby to the CRA VEX pipeline.

**Architecture:** Per-language analyzers implementing the existing `Analyzer` interface, backed by a shared tree-sitter core (`treesitter/` package) that provides symbol graph construction, BFS reachability, and concurrent file parsing. Each language has its own extractor (AST-to-symbols), grammar package (CGO isolation), and analyzer. Graceful fallback to the existing ripgrep generic analyzer.

**Tech Stack:** Go, tree-sitter (CGO via `github.com/tree-sitter/go-tree-sitter`), per-language grammar bindings.

**Spec:** `docs/superpowers/specs/2026-04-04-treesitter-reachability-design.md`

---

## File Structure

### New Files — Core Infrastructure (`pkg/vex/reachability/treesitter/`)

| File | Responsibility |
|------|----------------|
| `treesitter/types.go` | `SymbolID`, `Symbol`, `SymbolKind`, `Import`, `Edge`, `EdgeKind`, `CallPath`, `CallNode` |
| `treesitter/types_test.go` | Tests for type constructors and helpers |
| `treesitter/graph.go` | `Graph` struct with forward/reverse edge maps, `AddSymbol`, `AddEdge` |
| `treesitter/graph_test.go` | Tests for graph construction |
| `treesitter/reachability.go` | `FindReachablePaths` BFS, confidence scoring, `ReachabilityConfig` |
| `treesitter/reachability_test.go` | Tests for BFS pathfinding, cycles, max depth, confidence |
| `treesitter/parser.go` | Concurrent file parsing orchestration, `ParseFiles` |
| `treesitter/parser_test.go` | Tests for concurrent parsing |
| `treesitter/extractor.go` | `LanguageExtractor` interface definition |
| `treesitter/scope.go` | Scope/symbol table for tracking name bindings within files |
| `treesitter/scope_test.go` | Tests for scope tracking |

### New Files — Grammar Isolation

| File | Responsibility |
|------|----------------|
| `treesitter/grammars/python/python.go` | Exposes `Language() unsafe.Pointer` wrapping `tree_sitter_python.Language()` |
| `treesitter/grammars/javascript/javascript.go` | Same for JavaScript |
| `treesitter/grammars/typescript/typescript.go` | Same for TypeScript |
| `treesitter/grammars/java/java.go` | Same for Java |
| `treesitter/grammars/csharp/csharp.go` | Same for C# |
| `treesitter/grammars/php/php.go` | Same for PHP |
| `treesitter/grammars/ruby/ruby.go` | Same for Ruby |

### New Files — Language Extractors

| File | Responsibility |
|------|----------------|
| `treesitter/python/extractor.go` | Python symbol/import/call extraction from tree-sitter AST |
| `treesitter/python/extractor_test.go` | Tests with real Python source files |
| `treesitter/python/entrypoints.go` | Python entry point discovery (Flask, Django, FastAPI, Celery, Click, `__main__`) |
| `treesitter/python/entrypoints_test.go` | Tests for each framework's entry points |
| `treesitter/javascript/extractor.go` | JS/TS symbol/import/call extraction |
| `treesitter/javascript/extractor_test.go` | Tests with real JS/TS source |
| `treesitter/javascript/entrypoints.go` | JS entry points (Express, Nuxt, SvelteKit, NestJS, Next.js, Remix, Hono, Astro) |
| `treesitter/javascript/entrypoints_test.go` | Tests for each framework |
| `treesitter/java/extractor.go` | Java symbol/import/call extraction + CHA |
| `treesitter/java/extractor_test.go` | Tests with real Java source |
| `treesitter/java/entrypoints.go` | Java entry points (main, Spring, servlets, scheduled) |
| `treesitter/java/entrypoints_test.go` | Tests for each framework |
| `treesitter/csharp/extractor.go` | C# symbol/import/call extraction + CHA |
| `treesitter/csharp/extractor_test.go` | Tests |
| `treesitter/csharp/entrypoints.go` | C# entry points (Main, ASP.NET, Minimal API) |
| `treesitter/csharp/entrypoints_test.go` | Tests |
| `treesitter/php/extractor.go` | PHP symbol/import/call extraction |
| `treesitter/php/extractor_test.go` | Tests |
| `treesitter/php/entrypoints.go` | PHP entry points (Laravel, Symfony) |
| `treesitter/php/entrypoints_test.go` | Tests |
| `treesitter/ruby/extractor.go` | Ruby symbol/import/call extraction |
| `treesitter/ruby/extractor_test.go` | Tests |
| `treesitter/ruby/entrypoints.go` | Ruby entry points (Rails, Sinatra, Sidekiq, Rake) |
| `treesitter/ruby/entrypoints_test.go` | Tests |

### New Files — Per-Language Analyzers

| File | Responsibility |
|------|----------------|
| `pkg/vex/reachability/python/python.go` | Implements `Analyzer` interface using treesitter core + python extractor |
| `pkg/vex/reachability/python/python_test.go` | Unit + integration tests |
| `pkg/vex/reachability/javascript/javascript.go` | Implements `Analyzer` for JS/TS |
| `pkg/vex/reachability/javascript/javascript_test.go` | Tests |
| `pkg/vex/reachability/java/java.go` | Implements `Analyzer` for Java |
| `pkg/vex/reachability/java/java_test.go` | Tests |
| `pkg/vex/reachability/csharp/csharp.go` | Implements `Analyzer` for C# |
| `pkg/vex/reachability/csharp/csharp_test.go` | Tests |
| `pkg/vex/reachability/php/php.go` | Implements `Analyzer` for PHP |
| `pkg/vex/reachability/php/php_test.go` | Tests |
| `pkg/vex/reachability/ruby/ruby.go` | Implements `Analyzer` for Ruby |
| `pkg/vex/reachability/ruby/ruby_test.go` | Tests |

### Modified Files

| File | Change |
|------|--------|
| `pkg/vex/reachability/result.go` | Add `Paths []CallPath` field, `CallPath`, `CallNode` types |
| `pkg/vex/reachability/language.go` | Add `"csharp"`, `"php"`, `"ruby"` to `languageMarkers` |
| `pkg/vex/vex.go` | Update `buildAnalyzers()` to register tree-sitter analyzers with fallback |
| `pkg/vex/reachability_filter.go` | Include path information in evidence string |
| `go.mod` | Add `go-tree-sitter` and grammar dependencies |
| `Taskfile.yml` | Add `test:reachability`, `test:reachability:llmjudge` tasks |

### New Test Fixtures

```
testdata/integration/
├── python-treesitter-reachable/
│   ├── source/          (multi-file Python project calling yaml.load)
│   ├── sbom.cdx.json
│   ��── trivy.json
│   └── expected.json
├── python-treesitter-not-reachable/
│   ├── source/          (imports yaml but uses safe_load only)
│   ├── sbom.cdx.json
│   ├── trivy.json
│   └── expected.json
├── javascript-treesitter-reachable/
│   ├── source/          (Express app calling _.template)
│   ├── sbom.cdx.json
│   ├── grype.json
│   └── expected.json
├── javascript-treesitter-not-reachable/
│   └── ...
├── java-treesitter-reachable/
│   ├── source/          (Spring app using Log4j logger.info)
│   ├── sbom.cdx.json
│   ├── grype.json
│   └── expected.json
├── java-treesitter-not-reachable/
│   └── ...
├── csharp-treesitter-reachable/
│   └── ...
├── csharp-treesitter-not-reachable/
│   └── ...
├── php-treesitter-reachable/
│   └── ...
├── php-treesitter-not-reachable/
│   └── ...
├── ruby-treesitter-reachable/
│   └── ...
└── ruby-treesitter-not-reachable/
    └── ...
```

---

## Phase 1: Core Infrastructure

### Task 1: Add tree-sitter dependencies to go.mod

**Files:**
- Modify: `go.mod`

- [ ] **Step 1: Add go-tree-sitter and grammar dependencies**

```bash
cd /Users/ravan/suse/repo/github/ravan/cra-toolkit
go get github.com/tree-sitter/go-tree-sitter@latest
go get github.com/tree-sitter/tree-sitter-python/bindings/go@latest
go get github.com/tree-sitter/tree-sitter-javascript/bindings/go@latest
go get github.com/tree-sitter/tree-sitter-typescript/bindings/go@latest
go get github.com/tree-sitter/tree-sitter-java/bindings/go@latest
go get github.com/tree-sitter/tree-sitter-c-sharp/bindings/go@latest
go get github.com/tree-sitter/tree-sitter-php/bindings/go@latest
go get github.com/tree-sitter/tree-sitter-ruby/bindings/go@latest
```

- [ ] **Step 2: Verify dependencies resolve**

Run: `go mod tidy`
Expected: clean exit, no errors

- [ ] **Step 3: Verify CGO works with a smoke test**

Create a temporary file to verify the import compiles:

```bash
cat > /tmp/ts_smoke_test.go << 'EOF'
//go:build ignore

package main

import (
	"fmt"
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_python "github.com/tree-sitter/tree-sitter-python/bindings/go"
)

func main() {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	lang := tree_sitter.NewLanguage(tree_sitter_python.Language())
	if err := parser.SetLanguage(lang); err != nil {
		panic(err)
	}
	tree := parser.Parse([]byte("x = 1"), nil)
	defer tree.Close()
	fmt.Println("OK:", tree.RootNode().Kind())
}
EOF
cd /Users/ravan/suse/repo/github/ravan/cra-toolkit && go run /tmp/ts_smoke_test.go
```

Expected: `OK: module`

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "feat(reachability): add tree-sitter and grammar dependencies"
```

---

### Task 2: Extend Result type with CallPath

**Files:**
- Modify: `pkg/vex/reachability/result.go`
- Test: existing tests must still pass

- [ ] **Step 1: Write test for new CallPath types**

Create `pkg/vex/reachability/result_test.go`:

```go
package reachability_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
)

func TestCallPath_String(t *testing.T) {
	path := reachability.CallPath{
		Nodes: []reachability.CallNode{
			{Symbol: "main", File: "main.py", Line: 1},
			{Symbol: "handler", File: "handler.py", Line: 10},
			{Symbol: "yaml.load", File: "yaml/__init__.py", Line: 55},
		},
	}

	s := path.String()
	if s == "" {
		t.Error("expected non-empty string representation")
	}
	if len(path.Nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(path.Nodes))
	}
}

func TestResult_WithPaths(t *testing.T) {
	result := reachability.Result{
		Reachable: true,
		Symbols:   []string{"yaml.load"},
		Paths: []reachability.CallPath{
			{
				Nodes: []reachability.CallNode{
					{Symbol: "main", File: "main.py", Line: 1},
					{Symbol: "yaml.load", File: "", Line: 0},
				},
			},
		},
	}

	if len(result.Paths) != 1 {
		t.Errorf("expected 1 path, got %d", len(result.Paths))
	}
	if len(result.Paths[0].Nodes) != 2 {
		t.Errorf("expected 2 nodes in path, got %d", len(result.Paths[0].Nodes))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/vex/reachability/ -run TestCallPath -v`
Expected: FAIL — `CallPath`, `CallNode` types not defined

- [ ] **Step 3: Implement CallPath and CallNode types**

Update `pkg/vex/reachability/result.go`:

```go
package reachability

import (
	"fmt"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

// Result holds the outcome of a reachability analysis.
type Result struct {
	Reachable  bool               // whether the vulnerable code is reachable
	Confidence formats.Confidence // confidence level of the determination
	Evidence   string             // human-readable evidence description
	Symbols    []string           // symbols found to be reachable (if any)
	Paths      []CallPath         // call paths from entry points to vulnerable symbols
}

// CallPath represents a call chain from an entry point to a vulnerable symbol.
type CallPath struct {
	Nodes []CallNode
}

// String returns a human-readable representation of the call path.
func (p CallPath) String() string {
	parts := make([]string, len(p.Nodes))
	for i, n := range p.Nodes {
		if n.File != "" && n.Line > 0 {
			parts[i] = fmt.Sprintf("%s (%s:%d)", n.Symbol, n.File, n.Line)
		} else {
			parts[i] = n.Symbol
		}
	}
	return strings.Join(parts, " -> ")
}

// CallNode represents a single node in a call path.
type CallNode struct {
	Symbol string // qualified name (e.g., "myapp.handler.process")
	File   string // relative file path
	Line   int    // line number (1-based, 0 if unknown)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/vex/reachability/ -run TestCallPath -v && go test ./pkg/vex/reachability/ -run TestResult_WithPaths -v`
Expected: PASS

- [ ] **Step 5: Run existing tests to verify no regression**

Run: `go test ./pkg/vex/... -count=1`
Expected: all existing tests PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/vex/reachability/result.go pkg/vex/reachability/result_test.go
git commit -m "feat(reachability): extend Result type with CallPath and CallNode"
```

---

### Task 3: Tree-sitter core types

**Files:**
- Create: `pkg/vex/reachability/treesitter/types.go`
- Create: `pkg/vex/reachability/treesitter/types_test.go`

- [ ] **Step 1: Write tests for core types**

Create `pkg/vex/reachability/treesitter/types_test.go`:

```go
package treesitter_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestSymbolID(t *testing.T) {
	id := treesitter.NewSymbolID("myapp", "handler", "process")
	if id == "" {
		t.Error("expected non-empty SymbolID")
	}
	// Qualified name format: package.name
	expected := treesitter.SymbolID("myapp.handler.process")
	if id != expected {
		t.Errorf("expected %q, got %q", expected, id)
	}
}

func TestSymbolKind_String(t *testing.T) {
	tests := []struct {
		kind treesitter.SymbolKind
		want string
	}{
		{treesitter.SymbolFunction, "function"},
		{treesitter.SymbolMethod, "method"},
		{treesitter.SymbolClass, "class"},
		{treesitter.SymbolModule, "module"},
	}
	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.want {
			t.Errorf("SymbolKind(%d).String() = %q, want %q", tt.kind, got, tt.want)
		}
	}
}

func TestEdgeKind_String(t *testing.T) {
	tests := []struct {
		kind treesitter.EdgeKind
		want string
	}{
		{treesitter.EdgeDirect, "direct"},
		{treesitter.EdgeDispatch, "dispatch"},
		{treesitter.EdgeImport, "import"},
	}
	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.want {
			t.Errorf("EdgeKind(%d).String() = %q, want %q", tt.kind, got, tt.want)
		}
	}
}

func TestEdge_DefaultConfidence(t *testing.T) {
	edge := treesitter.Edge{
		From:       "a",
		To:         "b",
		Kind:       treesitter.EdgeDirect,
		Confidence: 1.0,
	}
	if edge.Confidence != 1.0 {
		t.Errorf("expected confidence 1.0, got %f", edge.Confidence)
	}

	dispatchEdge := treesitter.Edge{
		From:       "a",
		To:         "b",
		Kind:       treesitter.EdgeDispatch,
		Confidence: 0.5,
	}
	if dispatchEdge.Confidence != 0.5 {
		t.Errorf("expected confidence 0.5, got %f", dispatchEdge.Confidence)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/vex/reachability/treesitter/ -run TestSymbolID -v`
Expected: FAIL — package does not exist

- [ ] **Step 3: Implement core types**

Create `pkg/vex/reachability/treesitter/types.go`:

```go
// Package treesitter provides the shared tree-sitter analysis core for
// building interprocedural call graphs and performing reachability analysis
// across multiple programming languages.
package treesitter

import "strings"

// SymbolID uniquely identifies a symbol within a project.
type SymbolID string

// NewSymbolID creates a SymbolID from package path components.
// Example: NewSymbolID("myapp", "handler", "process") → "myapp.handler.process"
func NewSymbolID(parts ...string) SymbolID {
	return SymbolID(strings.Join(parts, "."))
}

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
}

// SymbolKind classifies what kind of code construct a symbol represents.
type SymbolKind int

const (
	SymbolFunction SymbolKind = iota
	SymbolMethod
	SymbolClass
	SymbolModule
)

// String returns the string representation of the symbol kind.
func (k SymbolKind) String() string {
	switch k {
	case SymbolFunction:
		return "function"
	case SymbolMethod:
		return "method"
	case SymbolClass:
		return "class"
	case SymbolModule:
		return "module"
	default:
		return "unknown"
	}
}

// Import represents a module import extracted from source code.
type Import struct {
	Module  string   // module name (e.g., "flask" or "express")
	Symbols []string // specific symbols imported (empty = whole module)
	Alias   string   // import alias if any
	File    string   // file where the import occurs
	Line    int      // line number of the import
}

// Edge represents a call relationship between two symbols in the graph.
type Edge struct {
	From       SymbolID
	To         SymbolID
	Kind       EdgeKind
	Confidence float64 // 0.0 to 1.0
	File       string  // file where the call occurs
	Line       int     // line number of the call
}

// EdgeKind classifies the type of call relationship.
type EdgeKind int

const (
	EdgeDirect   EdgeKind = iota // direct function/method call
	EdgeDispatch                 // dynamic/virtual dispatch
	EdgeImport                   // module import relationship
)

// String returns the string representation of the edge kind.
func (k EdgeKind) String() string {
	switch k {
	case EdgeDirect:
		return "direct"
	case EdgeDispatch:
		return "dispatch"
	case EdgeImport:
		return "import"
	default:
		return "unknown"
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/vex/reachability/treesitter/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/treesitter/types.go pkg/vex/reachability/treesitter/types_test.go
git commit -m "feat(treesitter): add core types - Symbol, Edge, Import, SymbolKind, EdgeKind"
```

---

### Task 4: Graph model

**Files:**
- Create: `pkg/vex/reachability/treesitter/graph.go`
- Create: `pkg/vex/reachability/treesitter/graph_test.go`

- [ ] **Step 1: Write tests for graph construction**

Create `pkg/vex/reachability/treesitter/graph_test.go`:

```go
package treesitter_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestGraph_AddSymbol(t *testing.T) {
	g := treesitter.NewGraph()

	sym := &treesitter.Symbol{
		ID:            "main.main",
		Name:          "main",
		QualifiedName: "main.main",
		Kind:          treesitter.SymbolFunction,
		File:          "main.py",
		StartLine:     1,
	}
	g.AddSymbol(sym)

	got := g.GetSymbol("main.main")
	if got == nil {
		t.Fatal("expected to find symbol main.main")
	}
	if got.Name != "main" {
		t.Errorf("expected name 'main', got %q", got.Name)
	}
}

func TestGraph_AddEdge(t *testing.T) {
	g := treesitter.NewGraph()
	g.AddSymbol(&treesitter.Symbol{ID: "a", Name: "a"})
	g.AddSymbol(&treesitter.Symbol{ID: "b", Name: "b"})

	g.AddEdge(treesitter.Edge{
		From:       "a",
		To:         "b",
		Kind:       treesitter.EdgeDirect,
		Confidence: 1.0,
	})

	forward := g.ForwardEdges("a")
	if len(forward) != 1 {
		t.Fatalf("expected 1 forward edge from a, got %d", len(forward))
	}
	if forward[0].To != "b" {
		t.Errorf("expected edge to b, got %q", forward[0].To)
	}

	reverse := g.ReverseEdges("b")
	if len(reverse) != 1 {
		t.Fatalf("expected 1 reverse edge to b, got %d", len(reverse))
	}
	if reverse[0].From != "a" {
		t.Errorf("expected edge from a, got %q", reverse[0].From)
	}
}

func TestGraph_EntryPoints(t *testing.T) {
	g := treesitter.NewGraph()
	g.AddSymbol(&treesitter.Symbol{ID: "main", Name: "main", IsEntryPoint: true})
	g.AddSymbol(&treesitter.Symbol{ID: "helper", Name: "helper", IsEntryPoint: false})
	g.AddSymbol(&treesitter.Symbol{ID: "route", Name: "route", IsEntryPoint: true})

	eps := g.EntryPoints()
	if len(eps) != 2 {
		t.Errorf("expected 2 entry points, got %d", len(eps))
	}
}

func TestGraph_SymbolCount(t *testing.T) {
	g := treesitter.NewGraph()
	if g.SymbolCount() != 0 {
		t.Errorf("expected 0 symbols, got %d", g.SymbolCount())
	}
	g.AddSymbol(&treesitter.Symbol{ID: "a", Name: "a"})
	g.AddSymbol(&treesitter.Symbol{ID: "b", Name: "b"})
	if g.SymbolCount() != 2 {
		t.Errorf("expected 2 symbols, got %d", g.SymbolCount())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/vex/reachability/treesitter/ -run TestGraph -v`
Expected: FAIL — `NewGraph`, `Graph` not defined

- [ ] **Step 3: Implement Graph model**

Create `pkg/vex/reachability/treesitter/graph.go`:

```go
package treesitter

// Graph represents a directed call graph of symbols in a project.
// It supports both forward (caller→callee) and reverse (callee→caller) lookups.
type Graph struct {
	symbols map[SymbolID]*Symbol
	forward map[SymbolID][]Edge
	reverse map[SymbolID][]Edge
}

// NewGraph creates an empty graph.
func NewGraph() *Graph {
	return &Graph{
		symbols: make(map[SymbolID]*Symbol),
		forward: make(map[SymbolID][]Edge),
		reverse: make(map[SymbolID][]Edge),
	}
}

// AddSymbol adds a symbol to the graph. If a symbol with the same ID already
// exists, it is replaced.
func (g *Graph) AddSymbol(sym *Symbol) {
	g.symbols[sym.ID] = sym
}

// GetSymbol returns the symbol with the given ID, or nil if not found.
func (g *Graph) GetSymbol(id SymbolID) *Symbol {
	return g.symbols[id]
}

// AddEdge adds a directed edge from one symbol to another.
// Both forward and reverse indexes are updated.
func (g *Graph) AddEdge(e Edge) {
	g.forward[e.From] = append(g.forward[e.From], e)
	g.reverse[e.To] = append(g.reverse[e.To], e)
}

// ForwardEdges returns all edges originating from the given symbol (callees).
func (g *Graph) ForwardEdges(id SymbolID) []Edge {
	return g.forward[id]
}

// ReverseEdges returns all edges targeting the given symbol (callers).
func (g *Graph) ReverseEdges(id SymbolID) []Edge {
	return g.reverse[id]
}

// EntryPoints returns all symbols marked as entry points.
func (g *Graph) EntryPoints() []SymbolID {
	var eps []SymbolID
	for id, sym := range g.symbols {
		if sym.IsEntryPoint {
			eps = append(eps, id)
		}
	}
	return eps
}

// SymbolCount returns the number of symbols in the graph.
func (g *Graph) SymbolCount() int {
	return len(g.symbols)
}

// AllSymbols returns all symbols in the graph.
func (g *Graph) AllSymbols() []*Symbol {
	syms := make([]*Symbol, 0, len(g.symbols))
	for _, sym := range g.symbols {
		syms = append(syms, sym)
	}
	return syms
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/vex/reachability/treesitter/ -run TestGraph -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/treesitter/graph.go pkg/vex/reachability/treesitter/graph_test.go
git commit -m "feat(treesitter): add Graph model with forward/reverse edge indexes"
```

---

### Task 5: BFS reachability engine

**Files:**
- Create: `pkg/vex/reachability/treesitter/reachability.go`
- Create: `pkg/vex/reachability/treesitter/reachability_test.go`

- [ ] **Step 1: Write tests for BFS pathfinding**

Create `pkg/vex/reachability/treesitter/reachability_test.go`:

```go
package treesitter_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

// buildLinearGraph creates: entry -> middle -> target
func buildLinearGraph() *treesitter.Graph {
	g := treesitter.NewGraph()
	g.AddSymbol(&treesitter.Symbol{ID: "entry", Name: "entry", IsEntryPoint: true})
	g.AddSymbol(&treesitter.Symbol{ID: "middle", Name: "middle"})
	g.AddSymbol(&treesitter.Symbol{ID: "target", Name: "target", IsExternal: true})
	g.AddEdge(treesitter.Edge{From: "entry", To: "middle", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	g.AddEdge(treesitter.Edge{From: "middle", To: "target", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	return g
}

func TestFindReachablePaths_DirectPath(t *testing.T) {
	g := buildLinearGraph()
	cfg := treesitter.ReachabilityConfig{MaxDepth: 50, MaxPaths: 5}

	paths := treesitter.FindReachablePaths(g, g.EntryPoints(), "target", cfg)
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	if len(paths[0].Nodes) != 3 {
		t.Errorf("expected 3 nodes in path, got %d", len(paths[0].Nodes))
	}
	if paths[0].Nodes[0].Symbol != "entry" {
		t.Errorf("expected first node 'entry', got %q", paths[0].Nodes[0].Symbol)
	}
	if paths[0].Nodes[2].Symbol != "target" {
		t.Errorf("expected last node 'target', got %q", paths[0].Nodes[2].Symbol)
	}
}

func TestFindReachablePaths_NoPath(t *testing.T) {
	g := treesitter.NewGraph()
	g.AddSymbol(&treesitter.Symbol{ID: "entry", Name: "entry", IsEntryPoint: true})
	g.AddSymbol(&treesitter.Symbol{ID: "isolated", Name: "isolated"})
	// No edges between entry and isolated
	cfg := treesitter.ReachabilityConfig{MaxDepth: 50, MaxPaths: 5}

	paths := treesitter.FindReachablePaths(g, g.EntryPoints(), "isolated", cfg)
	if len(paths) != 0 {
		t.Errorf("expected 0 paths, got %d", len(paths))
	}
}

func TestFindReachablePaths_CycleDetection(t *testing.T) {
	g := treesitter.NewGraph()
	g.AddSymbol(&treesitter.Symbol{ID: "a", Name: "a", IsEntryPoint: true})
	g.AddSymbol(&treesitter.Symbol{ID: "b", Name: "b"})
	g.AddSymbol(&treesitter.Symbol{ID: "c", Name: "c"})
	g.AddEdge(treesitter.Edge{From: "a", To: "b", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	g.AddEdge(treesitter.Edge{From: "b", To: "a", Kind: treesitter.EdgeDirect, Confidence: 1.0}) // cycle
	g.AddEdge(treesitter.Edge{From: "b", To: "c", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	cfg := treesitter.ReachabilityConfig{MaxDepth: 50, MaxPaths: 5}

	paths := treesitter.FindReachablePaths(g, g.EntryPoints(), "c", cfg)
	if len(paths) != 1 {
		t.Fatalf("expected 1 path despite cycle, got %d", len(paths))
	}
	// Path should be a -> b -> c (not infinite loop)
	if len(paths[0].Nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(paths[0].Nodes))
	}
}

func TestFindReachablePaths_MaxDepth(t *testing.T) {
	g := treesitter.NewGraph()
	// Build chain: n0 -> n1 -> n2 -> ... -> n10
	for i := 0; i <= 10; i++ {
		id := treesitter.SymbolID(fmt.Sprintf("n%d", i))
		g.AddSymbol(&treesitter.Symbol{ID: id, Name: string(id), IsEntryPoint: i == 0})
		if i > 0 {
			prev := treesitter.SymbolID(fmt.Sprintf("n%d", i-1))
			g.AddEdge(treesitter.Edge{From: prev, To: id, Kind: treesitter.EdgeDirect, Confidence: 1.0})
		}
	}

	// MaxDepth=5 should not reach n10
	cfg := treesitter.ReachabilityConfig{MaxDepth: 5, MaxPaths: 5}
	paths := treesitter.FindReachablePaths(g, g.EntryPoints(), "n10", cfg)
	if len(paths) != 0 {
		t.Errorf("expected 0 paths with MaxDepth=5, got %d", len(paths))
	}

	// MaxDepth=15 should reach n10
	cfg.MaxDepth = 15
	paths = treesitter.FindReachablePaths(g, g.EntryPoints(), "n10", cfg)
	if len(paths) != 1 {
		t.Errorf("expected 1 path with MaxDepth=15, got %d", len(paths))
	}
}

func TestFindReachablePaths_MaxPaths(t *testing.T) {
	g := treesitter.NewGraph()
	g.AddSymbol(&treesitter.Symbol{ID: "entry", Name: "entry", IsEntryPoint: true})
	g.AddSymbol(&treesitter.Symbol{ID: "a", Name: "a"})
	g.AddSymbol(&treesitter.Symbol{ID: "b", Name: "b"})
	g.AddSymbol(&treesitter.Symbol{ID: "target", Name: "target"})
	// Two paths: entry->a->target and entry->b->target
	g.AddEdge(treesitter.Edge{From: "entry", To: "a", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	g.AddEdge(treesitter.Edge{From: "entry", To: "b", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	g.AddEdge(treesitter.Edge{From: "a", To: "target", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	g.AddEdge(treesitter.Edge{From: "b", To: "target", Kind: treesitter.EdgeDirect, Confidence: 1.0})

	cfg := treesitter.ReachabilityConfig{MaxDepth: 50, MaxPaths: 1}
	paths := treesitter.FindReachablePaths(g, g.EntryPoints(), "target", cfg)
	if len(paths) != 1 {
		t.Errorf("expected exactly 1 path with MaxPaths=1, got %d", len(paths))
	}
}

func TestPathConfidence(t *testing.T) {
	g := treesitter.NewGraph()
	g.AddSymbol(&treesitter.Symbol{ID: "entry", Name: "entry", IsEntryPoint: true})
	g.AddSymbol(&treesitter.Symbol{ID: "dispatch", Name: "dispatch"})
	g.AddSymbol(&treesitter.Symbol{ID: "target", Name: "target"})
	g.AddEdge(treesitter.Edge{From: "entry", To: "dispatch", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	g.AddEdge(treesitter.Edge{From: "dispatch", To: "target", Kind: treesitter.EdgeDispatch, Confidence: 0.5})
	cfg := treesitter.ReachabilityConfig{MaxDepth: 50, MaxPaths: 5}

	paths := treesitter.FindReachablePaths(g, g.EntryPoints(), "target", cfg)
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	conf := treesitter.PathConfidence(g, paths[0])
	// 1.0 * 0.5 = 0.5
	if conf < 0.49 || conf > 0.51 {
		t.Errorf("expected confidence ~0.5, got %f", conf)
	}
}

func TestMapConfidence(t *testing.T) {
	tests := []struct {
		pathConf float64
		want     string
	}{
		{1.0, "high"},
		{0.8, "high"},
		{0.5, "medium"},
		{0.4, "medium"},
		{0.3, "low"},
		{0.1, "low"},
	}
	for _, tt := range tests {
		got := treesitter.MapConfidence(tt.pathConf)
		if got.String() != tt.want {
			t.Errorf("MapConfidence(%f) = %q, want %q", tt.pathConf, got.String(), tt.want)
		}
	}
}
```

Note: add `"fmt"` to the imports for the `TestFindReachablePaths_MaxDepth` test.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/vex/reachability/treesitter/ -run "TestFindReachablePaths|TestPathConfidence|TestMapConfidence" -v`
Expected: FAIL — functions not defined

- [ ] **Step 3: Implement BFS reachability**

Create `pkg/vex/reachability/treesitter/reachability.go`:

```go
package treesitter

import (
	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
)

// ReachabilityConfig controls the BFS pathfinding behavior.
type ReachabilityConfig struct {
	MaxDepth int // maximum BFS depth (default 50)
	MaxPaths int // maximum paths to return per vulnerability (default 5)
}

// bfsNode tracks a node and the path taken to reach it during BFS.
type bfsNode struct {
	id   SymbolID
	path []SymbolID
}

// FindReachablePaths performs BFS from each entry point to the target symbol.
// Returns all distinct shortest paths found, up to cfg.MaxPaths.
func FindReachablePaths(g *Graph, entryPoints []SymbolID, target SymbolID, cfg ReachabilityConfig) []reachability.CallPath {
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = 50
	}
	if cfg.MaxPaths == 0 {
		cfg.MaxPaths = 5
	}

	var allPaths []reachability.CallPath

	for _, ep := range entryPoints {
		if len(allPaths) >= cfg.MaxPaths {
			break
		}

		paths := bfs(g, ep, target, cfg.MaxDepth, cfg.MaxPaths-len(allPaths))
		allPaths = append(allPaths, paths...)
	}

	return allPaths
}

// bfs performs BFS from start to target, returning up to maxPaths shortest paths.
func bfs(g *Graph, start, target SymbolID, maxDepth, maxPaths int) []reachability.CallPath {
	if start == target {
		sym := g.GetSymbol(start)
		node := reachability.CallNode{Symbol: string(start)}
		if sym != nil {
			node.File = sym.File
			node.Line = sym.StartLine
		}
		return []reachability.CallPath{{Nodes: []reachability.CallNode{node}}}
	}

	var results []reachability.CallPath
	visited := make(map[SymbolID]bool)
	queue := []bfsNode{{id: start, path: []SymbolID{start}}}
	visited[start] = true

	for len(queue) > 0 && len(results) < maxPaths {
		current := queue[0]
		queue = queue[1:]

		if len(current.path) > maxDepth {
			continue
		}

		for _, edge := range g.ForwardEdges(current.id) {
			if edge.To == target {
				// Found a path
				fullPath := append(current.path, target)
				callPath := symbolsToCallPath(g, fullPath)
				results = append(results, callPath)
				if len(results) >= maxPaths {
					return results
				}
				continue
			}

			if !visited[edge.To] {
				visited[edge.To] = true
				newPath := make([]SymbolID, len(current.path)+1)
				copy(newPath, current.path)
				newPath[len(current.path)] = edge.To
				queue = append(queue, bfsNode{id: edge.To, path: newPath})
			}
		}
	}

	return results
}

// symbolsToCallPath converts a slice of SymbolIDs to a CallPath with file/line info.
func symbolsToCallPath(g *Graph, ids []SymbolID) reachability.CallPath {
	nodes := make([]reachability.CallNode, len(ids))
	for i, id := range ids {
		nodes[i] = reachability.CallNode{Symbol: string(id)}
		if sym := g.GetSymbol(id); sym != nil {
			nodes[i].File = sym.File
			nodes[i].Line = sym.StartLine
		}
	}
	return reachability.CallPath{Nodes: nodes}
}

// PathConfidence computes the confidence of a call path as the product of
// edge confidences along the path.
func PathConfidence(g *Graph, path reachability.CallPath) float64 {
	if len(path.Nodes) < 2 {
		return 1.0
	}

	conf := 1.0
	for i := 0; i < len(path.Nodes)-1; i++ {
		from := SymbolID(path.Nodes[i].Symbol)
		to := SymbolID(path.Nodes[i+1].Symbol)

		edgeConf := 0.0
		for _, edge := range g.ForwardEdges(from) {
			if edge.To == to {
				edgeConf = edge.Confidence
				break
			}
		}
		if edgeConf == 0 {
			edgeConf = 1.0 // default if no edge found (shouldn't happen)
		}
		conf *= edgeConf
	}

	return conf
}

// MapConfidence maps a numeric path confidence to a formats.Confidence level.
//
//	>= 0.8 → ConfidenceHigh
//	>= 0.4 → ConfidenceMedium
//	< 0.4 → ConfidenceLow
func MapConfidence(pathConf float64) formats.Confidence {
	switch {
	case pathConf >= 0.8:
		return formats.ConfidenceHigh
	case pathConf >= 0.4:
		return formats.ConfidenceMedium
	default:
		return formats.ConfidenceLow
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/vex/reachability/treesitter/ -run "TestFindReachablePaths|TestPathConfidence|TestMapConfidence" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/treesitter/reachability.go pkg/vex/reachability/treesitter/reachability_test.go
git commit -m "feat(treesitter): add BFS reachability engine with confidence scoring"
```

---

### Task 6: LanguageExtractor interface and scope tracking

**Files:**
- Create: `pkg/vex/reachability/treesitter/extractor.go`
- Create: `pkg/vex/reachability/treesitter/scope.go`
- Create: `pkg/vex/reachability/treesitter/scope_test.go`

- [ ] **Step 1: Write tests for scope tracking**

Create `pkg/vex/reachability/treesitter/scope_test.go`:

```go
package treesitter_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestScope_DefineAndLookup(t *testing.T) {
	scope := treesitter.NewScope(nil)
	scope.Define("foo", "module.foo")

	resolved, ok := scope.Lookup("foo")
	if !ok {
		t.Fatal("expected to find 'foo' in scope")
	}
	if resolved != "module.foo" {
		t.Errorf("expected 'module.foo', got %q", resolved)
	}
}

func TestScope_ParentLookup(t *testing.T) {
	parent := treesitter.NewScope(nil)
	parent.Define("bar", "module.bar")

	child := treesitter.NewScope(parent)

	resolved, ok := child.Lookup("bar")
	if !ok {
		t.Fatal("expected to find 'bar' via parent scope")
	}
	if resolved != "module.bar" {
		t.Errorf("expected 'module.bar', got %q", resolved)
	}
}

func TestScope_ChildShadowsParent(t *testing.T) {
	parent := treesitter.NewScope(nil)
	parent.Define("x", "parent.x")

	child := treesitter.NewScope(parent)
	child.Define("x", "child.x")

	resolved, ok := child.Lookup("x")
	if !ok {
		t.Fatal("expected to find 'x'")
	}
	if resolved != "child.x" {
		t.Errorf("expected 'child.x', got %q", resolved)
	}
}

func TestScope_NotFound(t *testing.T) {
	scope := treesitter.NewScope(nil)
	_, ok := scope.Lookup("nonexistent")
	if ok {
		t.Error("expected lookup to fail for nonexistent name")
	}
}

func TestScope_ImportAlias(t *testing.T) {
	scope := treesitter.NewScope(nil)
	scope.DefineImport("yaml", "PyYAML", []string{})
	scope.DefineImport("np", "numpy", []string{})

	mod, ok := scope.LookupImport("yaml")
	if !ok {
		t.Fatal("expected to find import 'yaml'")
	}
	if mod != "PyYAML" {
		t.Errorf("expected 'PyYAML', got %q", mod)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/vex/reachability/treesitter/ -run TestScope -v`
Expected: FAIL — `Scope` not defined

- [ ] **Step 3: Implement LanguageExtractor interface**

Create `pkg/vex/reachability/treesitter/extractor.go`:

```go
package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

// LanguageExtractor defines the interface that each language must implement
// to extract symbols, imports, and call sites from tree-sitter ASTs.
type LanguageExtractor interface {
	// Language returns the language identifier (e.g., "python", "javascript").
	Language() string

	// FileExtensions returns the file extensions this extractor handles (e.g., ".py").
	FileExtensions() []string

	// ExtractSymbols extracts function, method, and class symbols from a parsed file.
	ExtractSymbols(file string, source []byte, tree *tree_sitter.Tree) ([]Symbol, error)

	// ResolveImports extracts import statements from a parsed file.
	ResolveImports(file string, source []byte, tree *tree_sitter.Tree, moduleRoot string) ([]Import, error)

	// ExtractCalls extracts call sites from a parsed file, returning edges.
	// The scope provides name resolution context from imports and definitions.
	ExtractCalls(file string, source []byte, tree *tree_sitter.Tree, scope *Scope) ([]Edge, error)

	// FindEntryPoints identifies which symbols are entry points for the language.
	FindEntryPoints(symbols []Symbol, projectRoot string) []SymbolID
}
```

- [ ] **Step 4: Implement Scope**

Create `pkg/vex/reachability/treesitter/scope.go`:

```go
package treesitter

// Scope tracks name bindings within a lexical scope, supporting nested
// scopes (functions inside functions) and import aliases.
type Scope struct {
	parent  *Scope
	names   map[string]string // local name → qualified name
	imports map[string]string // alias → module name
}

// NewScope creates a new scope with an optional parent for nested lookups.
func NewScope(parent *Scope) *Scope {
	return &Scope{
		parent:  parent,
		names:   make(map[string]string),
		imports: make(map[string]string),
	}
}

// Define binds a local name to a qualified symbol name.
func (s *Scope) Define(localName, qualifiedName string) {
	s.names[localName] = qualifiedName
}

// Lookup resolves a local name to its qualified name, searching parent
// scopes if not found locally.
func (s *Scope) Lookup(name string) (string, bool) {
	if q, ok := s.names[name]; ok {
		return q, true
	}
	if s.parent != nil {
		return s.parent.Lookup(name)
	}
	return "", false
}

// DefineImport records an import alias mapping.
func (s *Scope) DefineImport(alias, moduleName string, symbols []string) {
	s.imports[alias] = moduleName
	// Also define individual imported symbols
	for _, sym := range symbols {
		s.names[sym] = moduleName + "." + sym
	}
}

// LookupImport resolves an import alias to its module name.
func (s *Scope) LookupImport(alias string) (string, bool) {
	if mod, ok := s.imports[alias]; ok {
		return mod, true
	}
	if s.parent != nil {
		return s.parent.LookupImport(alias)
	}
	return "", false
}

// AllImports returns all import mappings in this scope (not parents).
func (s *Scope) AllImports() map[string]string {
	result := make(map[string]string, len(s.imports))
	for k, v := range s.imports {
		result[k] = v
	}
	return result
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./pkg/vex/reachability/treesitter/ -run TestScope -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/vex/reachability/treesitter/extractor.go pkg/vex/reachability/treesitter/scope.go pkg/vex/reachability/treesitter/scope_test.go
git commit -m "feat(treesitter): add LanguageExtractor interface and Scope tracking"
```

---

### Task 7: Parser orchestration and grammar packages

**Files:**
- Create: `pkg/vex/reachability/treesitter/parser.go`
- Create: `pkg/vex/reachability/treesitter/parser_test.go`
- Create: `pkg/vex/reachability/treesitter/grammars/python/python.go`
- Create: `pkg/vex/reachability/treesitter/grammars/javascript/javascript.go`
- Create: `pkg/vex/reachability/treesitter/grammars/typescript/typescript.go`
- Create: `pkg/vex/reachability/treesitter/grammars/java/java.go`
- Create: `pkg/vex/reachability/treesitter/grammars/csharp/csharp.go`
- Create: `pkg/vex/reachability/treesitter/grammars/php/php.go`
- Create: `pkg/vex/reachability/treesitter/grammars/ruby/ruby.go`

- [ ] **Step 1: Create grammar isolation packages**

Create `pkg/vex/reachability/treesitter/grammars/python/python.go`:

```go
// Package python provides the tree-sitter Python grammar.
// This package is isolated to prevent CGO duplicate symbol errors
// when linking multiple tree-sitter grammars.
package python

import (
	"unsafe"

	tree_sitter_python "github.com/tree-sitter/tree-sitter-python/bindings/go"
)

// Language returns the tree-sitter Python language pointer.
func Language() unsafe.Pointer {
	return tree_sitter_python.Language()
}
```

Create `pkg/vex/reachability/treesitter/grammars/javascript/javascript.go`:

```go
package javascript

import (
	"unsafe"

	tree_sitter_javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
)

func Language() unsafe.Pointer {
	return tree_sitter_javascript.Language()
}
```

Create `pkg/vex/reachability/treesitter/grammars/typescript/typescript.go`:

```go
package typescript

import (
	"unsafe"

	tree_sitter_typescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
)

// Language returns the tree-sitter TypeScript language pointer.
// Note: tree-sitter-typescript exposes LanguageTypescript() for .ts files
// and LanguageTSX() for .tsx files.
func Language() unsafe.Pointer {
	return tree_sitter_typescript.LanguageTypescript()
}

// LanguageTSX returns the tree-sitter TSX language pointer for .tsx files.
func LanguageTSX() unsafe.Pointer {
	return tree_sitter_typescript.LanguageTSX()
}
```

Create `pkg/vex/reachability/treesitter/grammars/java/java.go`:

```go
package java

import (
	"unsafe"

	tree_sitter_java "github.com/tree-sitter/tree-sitter-java/bindings/go"
)

func Language() unsafe.Pointer {
	return tree_sitter_java.Language()
}
```

Create `pkg/vex/reachability/treesitter/grammars/csharp/csharp.go`:

```go
package csharp

import (
	"unsafe"

	tree_sitter_csharp "github.com/tree-sitter/tree-sitter-c-sharp/bindings/go"
)

func Language() unsafe.Pointer {
	return tree_sitter_csharp.Language()
}
```

Create `pkg/vex/reachability/treesitter/grammars/php/php.go`:

```go
package php

import (
	"unsafe"

	tree_sitter_php "github.com/tree-sitter/tree-sitter-php/bindings/go"
)

func Language() unsafe.Pointer {
	return tree_sitter_php.Language()
}
```

Create `pkg/vex/reachability/treesitter/grammars/ruby/ruby.go`:

```go
package ruby

import (
	"unsafe"

	tree_sitter_ruby "github.com/tree-sitter/tree-sitter-ruby/bindings/go"
)

func Language() unsafe.Pointer {
	return tree_sitter_ruby.Language()
}
```

- [ ] **Step 2: Write test for parser orchestration**

Create `pkg/vex/reachability/treesitter/parser_test.go`:

```go
package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/python"
)

func TestParseFile_Python(t *testing.T) {
	// Create a temporary Python file
	dir := t.TempDir()
	pyFile := filepath.Join(dir, "test.py")
	source := []byte("def hello():\n    print('hello')\n\nhello()\n")
	if err := os.WriteFile(pyFile, source, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	tree, src, err := treesitter.ParseFile(pyFile, python.Language())
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	defer tree.Close()

	root := tree.RootNode()
	if root.Kind() != "module" {
		t.Errorf("expected root node kind 'module', got %q", root.Kind())
	}
	if len(src) != len(source) {
		t.Errorf("expected source length %d, got %d", len(source), len(src))
	}
}

func TestParseFiles_Concurrent(t *testing.T) {
	dir := t.TempDir()

	// Create 10 Python files
	for i := 0; i < 10; i++ {
		name := filepath.Join(dir, fmt.Sprintf("mod%d.py", i))
		src := fmt.Sprintf("def func%d():\n    pass\n", i)
		if err := os.WriteFile(name, []byte(src), 0o644); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.py"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}

	results, errs := treesitter.ParseFiles(files, python.Language())
	if len(errs) > 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(results) != 10 {
		t.Errorf("expected 10 parse results, got %d", len(results))
	}

	// Clean up trees
	for _, r := range results {
		r.Tree.Close()
	}
}
```

Note: add `"fmt"` to imports.

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./pkg/vex/reachability/treesitter/ -run "TestParseFile|TestParseFiles" -v`
Expected: FAIL — `ParseFile`, `ParseFiles` not defined

- [ ] **Step 4: Implement parser orchestration**

Create `pkg/vex/reachability/treesitter/parser.go`:

```go
package treesitter

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

// ParseResult holds the result of parsing a single file.
type ParseResult struct {
	File   string
	Source []byte
	Tree   *tree_sitter.Tree
}

// ParseFile parses a single source file using the given tree-sitter language.
// The caller is responsible for calling Tree.Close() on the returned result.
func ParseFile(filePath string, langPtr unsafe.Pointer) (*tree_sitter.Tree, []byte, error) {
	source, err := os.ReadFile(filePath) //nolint:gosec // path from controlled input
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", filePath, err)
	}

	parser := tree_sitter.NewParser()
	defer parser.Close()

	lang := tree_sitter.NewLanguage(langPtr)
	if err := parser.SetLanguage(lang); err != nil {
		return nil, nil, fmt.Errorf("set language: %w", err)
	}

	tree := parser.Parse(source, nil)
	if tree == nil {
		return nil, nil, fmt.Errorf("parse %s: tree-sitter returned nil", filePath)
	}

	return tree, source, nil
}

// ParseFiles parses multiple files concurrently using a worker pool.
// Returns all successful parse results and any errors encountered.
// The caller is responsible for calling Tree.Close() on each result.
func ParseFiles(files []string, langPtr unsafe.Pointer) ([]ParseResult, []error) {
	numWorkers := runtime.NumCPU()
	if numWorkers > len(files) {
		numWorkers = len(files)
	}
	if numWorkers == 0 {
		return nil, nil
	}

	type result struct {
		pr  ParseResult
		err error
	}

	jobs := make(chan string, len(files))
	results := make(chan result, len(files))

	var wg sync.WaitGroup
	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range jobs {
				tree, source, err := ParseFile(file, langPtr)
				if err != nil {
					results <- result{err: err}
					continue
				}
				results <- result{pr: ParseResult{File: file, Source: source, Tree: tree}}
			}
		}()
	}

	for _, f := range files {
		jobs <- f
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var prs []ParseResult
	var errs []error
	for r := range results {
		if r.err != nil {
			errs = append(errs, r.err)
		} else {
			prs = append(prs, r.pr)
		}
	}

	return prs, errs
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./pkg/vex/reachability/treesitter/ -run "TestParseFile|TestParseFiles" -v`
Expected: PASS

- [ ] **Step 6: Verify all treesitter package tests pass**

Run: `go test ./pkg/vex/reachability/treesitter/... -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add pkg/vex/reachability/treesitter/parser.go pkg/vex/reachability/treesitter/parser_test.go pkg/vex/reachability/treesitter/grammars/
git commit -m "feat(treesitter): add concurrent parser and grammar isolation packages"
```

---

## Phase 2: Python

### Task 8: Python extractor — symbol and import extraction

**Files:**
- Create: `pkg/vex/reachability/treesitter/python/extractor.go`
- Create: `pkg/vex/reachability/treesitter/python/extractor_test.go`

- [ ] **Step 1: Write tests for Python symbol extraction**

Create `pkg/vex/reachability/treesitter/python/extractor_test.go`:

```go
package python_test

import (
	"testing"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/python"
	pyextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/python"
)

func parseSource(t *testing.T, source string) (*tree_sitter.Tree, []byte) {
	t.Helper()
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(python.Language())); err != nil {
		t.Fatalf("set language: %v", err)
	}
	src := []byte(source)
	tree := parser.Parse(src, nil)
	if tree == nil {
		t.Fatal("tree-sitter returned nil tree")
	}
	return tree, src
}

func TestExtractSymbols_Functions(t *testing.T) {
	source := `def hello():
    pass

def process(data):
    return data.strip()

class Handler:
    def handle(self, request):
        return self.process(request)

    def process(self, data):
        return data
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := pyextractor.New()
	symbols, err := ext.ExtractSymbols("app.py", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	// Should find: hello, process, Handler, Handler.handle, Handler.process
	if len(symbols) < 5 {
		t.Errorf("expected at least 5 symbols, got %d", len(symbols))
		for _, s := range symbols {
			t.Logf("  %s (%s) at line %d", s.QualifiedName, s.Kind, s.StartLine)
		}
	}

	// Check we have a function
	var foundHello bool
	for _, s := range symbols {
		if s.Name == "hello" && s.Kind == treesitter.SymbolFunction {
			foundHello = true
		}
	}
	if !foundHello {
		t.Error("expected to find function 'hello'")
	}

	// Check we have a class
	var foundHandler bool
	for _, s := range symbols {
		if s.Name == "Handler" && s.Kind == treesitter.SymbolClass {
			foundHandler = true
		}
	}
	if !foundHandler {
		t.Error("expected to find class 'Handler'")
	}

	// Check we have a method
	var foundMethod bool
	for _, s := range symbols {
		if s.Name == "handle" && s.Kind == treesitter.SymbolMethod {
			foundMethod = true
		}
	}
	if !foundMethod {
		t.Error("expected to find method 'handle'")
	}
}

func TestResolveImports_Python(t *testing.T) {
	source := `import yaml
import os.path
from flask import Flask, request
from . import utils
from ..models import User
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := pyextractor.New()
	imports, err := ext.ResolveImports("app.py", src, tree, "/project")
	if err != nil {
		t.Fatalf("ResolveImports failed: %v", err)
	}

	if len(imports) < 4 {
		t.Errorf("expected at least 4 imports, got %d", len(imports))
		for _, imp := range imports {
			t.Logf("  %s (symbols: %v, alias: %q)", imp.Module, imp.Symbols, imp.Alias)
		}
	}

	// Check yaml import
	var foundYaml bool
	for _, imp := range imports {
		if imp.Module == "yaml" && len(imp.Symbols) == 0 {
			foundYaml = true
		}
	}
	if !foundYaml {
		t.Error("expected to find 'import yaml'")
	}

	// Check from-import with specific symbols
	var foundFlask bool
	for _, imp := range imports {
		if imp.Module == "flask" {
			foundFlask = true
			if len(imp.Symbols) != 2 {
				t.Errorf("expected 2 symbols from flask import, got %d", len(imp.Symbols))
			}
		}
	}
	if !foundFlask {
		t.Error("expected to find 'from flask import Flask, request'")
	}
}

func TestExtractCalls_Python(t *testing.T) {
	source := `import yaml

def process():
    data = yaml.load("key: value")
    result = yaml.safe_load(data)
    print(result)
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := pyextractor.New()
	scope := treesitter.NewScope(nil)
	scope.DefineImport("yaml", "yaml", []string{})

	edges, err := ext.ExtractCalls("app.py", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	// Should find calls: yaml.load, yaml.safe_load, print
	if len(edges) < 3 {
		t.Errorf("expected at least 3 call edges, got %d", len(edges))
		for _, e := range edges {
			t.Logf("  %s -> %s (%s)", e.From, e.To, e.Kind)
		}
	}

	// Check yaml.load call is found
	var foundYamlLoad bool
	for _, e := range edges {
		if e.To == "yaml.load" {
			foundYamlLoad = true
			if e.Kind != treesitter.EdgeDirect {
				t.Errorf("expected EdgeDirect for yaml.load call, got %s", e.Kind)
			}
		}
	}
	if !foundYamlLoad {
		t.Error("expected to find call to yaml.load")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/vex/reachability/treesitter/python/ -run "TestExtractSymbols|TestResolveImports|TestExtractCalls" -v`
Expected: FAIL — package does not exist

- [ ] **Step 3: Implement Python extractor**

Create `pkg/vex/reachability/treesitter/python/extractor.go`. This file implements the `LanguageExtractor` interface for Python. It walks the tree-sitter CST to extract:

- Function definitions (`function_definition` nodes)
- Class definitions (`class_definition` nodes)
- Method definitions (function defs nested inside class defs)
- Import statements (`import_statement`, `import_from_statement`)
- Call expressions (`call` nodes) with attribute access resolution (`attribute` nodes for `module.func()`)

The implementation should:
1. Use `tree.RootNode()` and walk `NamedChildren(cursor)` recursively
2. For function_definition: extract name via `ChildByFieldName("name")`, parameters, line numbers
3. For class_definition: extract name, then recurse into body for methods
4. For import_statement: extract module name from `dotted_name` child
5. For import_from_statement: extract module from `module_name` field, symbols from `name` children
6. For call nodes: resolve the callee — if it's an `attribute` (e.g., `yaml.load`), extract object+attribute; if it's an `identifier`, look up in scope

The exact implementation should handle Python's tree-sitter grammar node types:
- `function_definition` → fields: `name`, `parameters`, `body`
- `class_definition` → fields: `name`, `body`
- `import_statement` → child: `dotted_name`
- `import_from_statement` → fields: `module_name`, child `import_list` or `import_from_specifier`
- `call` → fields: `function`, `arguments`
- `attribute` → fields: `object`, `attribute`

This is a substantial implementation (~300-400 lines). Build it incrementally — start with symbol extraction, then imports, then calls. Each test verifies one capability.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/vex/reachability/treesitter/python/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/treesitter/python/
git commit -m "feat(treesitter/python): add Python extractor - symbols, imports, calls"
```

---

### Task 9: Python entry point discovery

**Files:**
- Create: `pkg/vex/reachability/treesitter/python/entrypoints.go`
- Create: `pkg/vex/reachability/treesitter/python/entrypoints_test.go`

- [ ] **Step 1: Write tests for Python entry points**

Create `pkg/vex/reachability/treesitter/python/entrypoints_test.go`:

```go
package python_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	pyextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/python"
)

func TestFindEntryPoints_MainBlock(t *testing.T) {
	symbols := []treesitter.Symbol{
		{ID: "app.main", Name: "main", Kind: treesitter.SymbolFunction, File: "app.py", StartLine: 10},
		{ID: "app.helper", Name: "helper", Kind: treesitter.SymbolFunction, File: "app.py", StartLine: 1},
	}

	ext := pyextractor.New()
	// The entrypoint finder also needs to check the source for if __name__ == "__main__"
	// For now, test with a project root that has an app.py with main block
	eps := ext.FindEntryPoints(symbols, "/project")

	// Without reading files, the extractor should at least mark functions named "main" 
	// or decorated with known framework decorators
	// More comprehensive test after integration fixture is created
	t.Logf("Found %d entry points", len(eps))
}

func TestFindEntryPoints_FlaskRoute(t *testing.T) {
	source := `from flask import Flask

app = Flask(__name__)

@app.route("/health")
def health():
    return "ok"

@app.route("/api/data", methods=["POST"])
def handle_data():
    return process()

def process():
    pass
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := pyextractor.New()
	symbols, err := ext.ExtractSymbols("app.py", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")

	// health and handle_data should be entry points (decorated with @app.route)
	// process should NOT be an entry point
	if len(eps) < 2 {
		t.Errorf("expected at least 2 entry points (Flask routes), got %d", len(eps))
		for _, ep := range eps {
			t.Logf("  entry point: %s", ep)
		}
	}
}

func TestFindEntryPoints_FastAPIRoute(t *testing.T) {
	source := `from fastapi import FastAPI

app = FastAPI()

@app.get("/items")
def list_items():
    return []

@app.post("/items")
async def create_item(item: dict):
    return item
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := pyextractor.New()
	symbols, err := ext.ExtractSymbols("main.py", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")

	if len(eps) < 2 {
		t.Errorf("expected at least 2 entry points (FastAPI routes), got %d", len(eps))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/vex/reachability/treesitter/python/ -run TestFindEntryPoints -v`
Expected: FAIL

- [ ] **Step 3: Implement entry point discovery**

Create `pkg/vex/reachability/treesitter/python/entrypoints.go`. This should identify:

1. Functions with decorators matching `@app.route`, `@app.get`, `@app.post`, `@app.put`, `@app.delete`, `@app.patch` (Flask/FastAPI)
2. Functions with `@router.get`, `@router.post`, etc. (FastAPI routers)
3. Functions decorated with `@app.task`, `@shared_task` (Celery)
4. Functions decorated with `@click.command`, `@click.group` (Click CLI)
5. Functions in files containing `if __name__ == "__main__":` block

The implementation inspects the `decorator` children of `function_definition` nodes during symbol extraction. Decorators are stored as metadata on the `Symbol` (or a separate list), and `FindEntryPoints` checks against known patterns.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/vex/reachability/treesitter/python/ -run TestFindEntryPoints -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/treesitter/python/entrypoints.go pkg/vex/reachability/treesitter/python/entrypoints_test.go
git commit -m "feat(treesitter/python): add entry point discovery - Flask, FastAPI, Celery, Click, __main__"
```

---

### Task 10: Python analyzer (Analyzer interface implementation)

**Files:**
- Create: `pkg/vex/reachability/python/python.go`
- Create: `pkg/vex/reachability/python/python_test.go`

- [ ] **Step 1: Write tests for Python analyzer**

Create `pkg/vex/reachability/python/python_test.go`:

```go
package python_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/python"
)

func TestAnalyzer_Language(t *testing.T) {
	a := python.New()
	if lang := a.Language(); lang != "python" {
		t.Fatalf("expected 'python', got %q", lang)
	}
}

func TestAnalyze_PythonReachable(t *testing.T) {
	// Create a multi-file Python project where main.py calls handler.py
	// which calls yaml.load (the vulnerable function)
	dir := t.TempDir()

	// requirements.txt
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("PyYAML==5.3\n"), 0o644)

	// main.py - entry point
	os.WriteFile(filepath.Join(dir, "main.py"), []byte(`from handler import process_config

if __name__ == "__main__":
    process_config("config.yml")
`), 0o644)

	// handler.py - calls yaml.load
	os.WriteFile(filepath.Join(dir, "handler.py"), []byte(`import yaml

def process_config(path):
    with open(path) as f:
        return yaml.load(f)
`), 0o644)

	analyzer := python.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2020-1747",
		AffectedPURL: "pkg:pypi/PyYAML@5.3",
		AffectedName: "PyYAML",
		Symbols:      []string{"load"},
		Language:     "python",
	}

	result, err := analyzer.Analyze(ctx, dir, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Reachable {
		t.Error("expected Reachable=true, got false")
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", result.Confidence)
	}
	if len(result.Symbols) == 0 {
		t.Error("expected at least one symbol in result")
	}
	if len(result.Paths) == 0 {
		t.Error("expected at least one call path in result")
	}
	if result.Evidence == "" {
		t.Error("expected non-empty evidence")
	}
	t.Logf("Evidence: %s", result.Evidence)
	for i, p := range result.Paths {
		t.Logf("Path %d: %s", i, p)
	}
}

func TestAnalyze_PythonNotReachable(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("PyYAML==5.3\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "app.py"), []byte(`import yaml

def process():
    # Uses safe_load only, not the vulnerable load()
    data = yaml.safe_load("key: value")
    return data
`), 0o644)

	analyzer := python.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2020-1747",
		AffectedPURL: "pkg:pypi/PyYAML@5.3",
		AffectedName: "PyYAML",
		Symbols:      []string{"load"},
		Language:     "python",
	}

	result, err := analyzer.Analyze(ctx, dir, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Reachable {
		t.Error("expected Reachable=false, got true")
	}
	if len(result.Paths) != 0 {
		t.Errorf("expected 0 paths, got %d", len(result.Paths))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/vex/reachability/python/ -run TestAnalyz -v`
Expected: FAIL — package does not exist

- [ ] **Step 3: Implement Python analyzer**

Create `pkg/vex/reachability/python/python.go`:

```go
// Package python implements a reachability analyzer for Python using tree-sitter
// AST analysis with interprocedural call graph construction.
package python

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarpython "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/python"
	pyextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/python"
)

// Analyzer uses tree-sitter to perform AST-based reachability analysis for Python.
type Analyzer struct{}

// New returns a new Python reachability analyzer.
func New() *Analyzer { return &Analyzer{} }

// Language returns "python".
func (a *Analyzer) Language() string { return "python" }

// Analyze builds a call graph from the Python source code and determines whether
// the vulnerable symbols identified in the finding are reachable from entry points.
func (a *Analyzer) Analyze(ctx context.Context, sourceDir string, finding *formats.Finding) (reachability.Result, error) {
	// 1. Glob for Python files
	files, err := filepath.Glob(filepath.Join(sourceDir, "**", "*.py"))
	if err != nil {
		return reachability.Result{}, fmt.Errorf("glob python files: %w", err)
	}
	// Also get files in root directory
	rootFiles, _ := filepath.Glob(filepath.Join(sourceDir, "*.py"))
	files = append(files, rootFiles...)
	files = dedupFiles(files)

	if len(files) == 0 {
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceMedium,
			Evidence:   "no Python source files found",
		}, nil
	}

	// 2. Parse all files concurrently
	results, parseErrs := treesitter.ParseFiles(files, grammarpython.Language())
	if len(results) == 0 {
		return reachability.Result{}, fmt.Errorf("all Python files failed to parse: %v", parseErrs)
	}
	defer func() {
		for _, r := range results {
			r.Tree.Close()
		}
	}()

	// 3. Build the call graph
	ext := pyextractor.New()
	graph := treesitter.NewGraph()

	// Phase 1: Extract symbols and imports from all files
	fileScopes := make(map[string]*treesitter.Scope)
	for _, pr := range results {
		relPath, _ := filepath.Rel(sourceDir, pr.File)

		symbols, err := ext.ExtractSymbols(relPath, pr.Source, pr.Tree)
		if err != nil {
			continue
		}
		for i := range symbols {
			graph.AddSymbol(&symbols[i])
		}

		imports, err := ext.ResolveImports(relPath, pr.Source, pr.Tree, sourceDir)
		if err != nil {
			continue
		}

		scope := treesitter.NewScope(nil)
		for _, imp := range imports {
			scope.DefineImport(imp.Alias, imp.Module, imp.Symbols)
			if imp.Alias == "" {
				scope.DefineImport(imp.Module, imp.Module, imp.Symbols)
			}
		}
		fileScopes[pr.File] = scope
	}

	// Phase 2: Extract call edges
	for _, pr := range results {
		scope := fileScopes[pr.File]
		if scope == nil {
			scope = treesitter.NewScope(nil)
		}
		edges, err := ext.ExtractCalls(pr.File, pr.Source, pr.Tree, scope)
		if err != nil {
			continue
		}
		for _, e := range edges {
			graph.AddEdge(e)
		}
	}

	// 4. Discover entry points
	allSymbols := graph.AllSymbols()
	symSlice := make([]treesitter.Symbol, len(allSymbols))
	for i, s := range allSymbols {
		symSlice[i] = *s
	}
	entryPointIDs := ext.FindEntryPoints(symSlice, sourceDir)
	for _, epID := range entryPointIDs {
		if sym := graph.GetSymbol(epID); sym != nil {
			sym.IsEntryPoint = true
		}
	}

	// 5. Find vulnerable symbols and check reachability
	moduleName := normalizeModuleName(finding.AffectedName)
	var vulnerableSymbolIDs []treesitter.SymbolID
	for _, sym := range finding.Symbols {
		vulnerableSymbolIDs = append(vulnerableSymbolIDs,
			treesitter.SymbolID(moduleName+"."+sym),
		)
	}

	cfg := treesitter.ReachabilityConfig{MaxDepth: 50, MaxPaths: 5}
	var allPaths []reachability.CallPath
	var reachedSymbols []string

	for _, vulnID := range vulnerableSymbolIDs {
		paths := treesitter.FindReachablePaths(graph, graph.EntryPoints(), vulnID, cfg)
		allPaths = append(allPaths, paths...)
		if len(paths) > 0 {
			reachedSymbols = append(reachedSymbols, string(vulnID))
		}
	}

	if len(allPaths) > 0 {
		bestConf := 0.0
		for _, p := range allPaths {
			c := treesitter.PathConfidence(graph, p)
			if c > bestConf {
				bestConf = c
			}
		}
		return reachability.Result{
			Reachable:  true,
			Confidence: treesitter.MapConfidence(bestConf),
			Evidence:   fmt.Sprintf("tree-sitter AST analysis: %s reachable via %d call path(s)", strings.Join(reachedSymbols, ", "), len(allPaths)),
			Symbols:    reachedSymbols,
			Paths:      allPaths,
		}, nil
	}

	return reachability.Result{
		Reachable:  false,
		Confidence: formats.ConfidenceHigh,
		Evidence:   fmt.Sprintf("tree-sitter AST analysis: vulnerable symbols %v not reachable from any entry point (%d symbols, %d edges analyzed)", finding.Symbols, graph.SymbolCount(), len(graph.AllSymbols())),
	}, nil
}

// normalizeModuleName converts PyPI package names to Python import names.
func normalizeModuleName(name string) string {
	pypiToImport := map[string]string{
		"PyYAML":          "yaml",
		"Pillow":          "PIL",
		"scikit-learn":    "sklearn",
		"beautifulsoup4":  "bs4",
		"python-dateutil": "dateutil",
		"msgpack-python":  "msgpack",
		"attrs":           "attr",
		"pycryptodome":    "Crypto",
	}
	if importName, ok := pypiToImport[name]; ok {
		return importName
	}
	return strings.ToLower(name)
}

// dedupFiles removes duplicate file paths.
func dedupFiles(files []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(files))
	for _, f := range files {
		abs, err := filepath.Abs(f)
		if err != nil {
			abs = f
		}
		if !seen[abs] {
			seen[abs] = true
			result = append(result, f)
		}
	}
	return result
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/vex/reachability/python/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/python/
git commit -m "feat(reachability/python): add tree-sitter Python analyzer with call graph"
```

---

### Task 11: Python integration test fixtures and tests

**Files:**
- Create: `testdata/integration/python-treesitter-reachable/source/main.py`
- Create: `testdata/integration/python-treesitter-reachable/source/handler.py`
- Create: `testdata/integration/python-treesitter-reachable/source/requirements.txt`
- Create: `testdata/integration/python-treesitter-reachable/sbom.cdx.json`
- Create: `testdata/integration/python-treesitter-reachable/trivy.json`
- Create: `testdata/integration/python-treesitter-reachable/expected.json`
- Create: `testdata/integration/python-treesitter-not-reachable/source/app.py`
- Create: `testdata/integration/python-treesitter-not-reachable/source/requirements.txt`
- Create: `testdata/integration/python-treesitter-not-reachable/sbom.cdx.json`
- Create: `testdata/integration/python-treesitter-not-reachable/trivy.json`
- Create: `testdata/integration/python-treesitter-not-reachable/expected.json`

- [ ] **Step 1: Create reachable fixture**

The reachable fixture is a multi-file Python project where `main.py` calls `handler.py` which calls `yaml.load()` (the CVE-2020-1747 vulnerable function).

`source/main.py`:
```python
from handler import process_config

if __name__ == "__main__":
    result = process_config("config.yml")
    print(result)
```

`source/handler.py`:
```python
import yaml

def process_config(path):
    with open(path) as f:
        data = yaml.load(f)
    return data

def validate_config(data):
    return "key" in data
```

`source/requirements.txt`:
```
PyYAML==5.3
```

Copy the `sbom.cdx.json` and `trivy.json` from the existing `python-reachable` fixture (same PyYAML 5.3 vulnerability data).

`expected.json`:
```json
{
  "description": "Multi-file Python project where main.py calls handler.py which calls yaml.load() — the vulnerable pattern for CVE-2020-1747. Tree-sitter AST analysis should trace the call path across files.",
  "findings": [
    {
      "cve": "CVE-2020-1747",
      "component_purl": "pkg:pypi/PyYAML@5.3",
      "expected_status": "affected",
      "expected_confidence": "high",
      "expected_resolved_by": "reachability",
      "human_justification": "Tree-sitter call graph traces: main.__main__ -> handler.process_config -> yaml.load. The vulnerable yaml.load() is called without a safe Loader."
    }
  ]
}
```

- [ ] **Step 2: Create not-reachable fixture**

`source/app.py`:
```python
import yaml

def process():
    data = yaml.safe_load("key: value")
    return data

if __name__ == "__main__":
    print(process())
```

`source/requirements.txt`:
```
PyYAML==5.3
```

Same `sbom.cdx.json` and `trivy.json` as the reachable fixture.

`expected.json`:
```json
{
  "description": "Python project that imports PyYAML but only uses yaml.safe_load(), not the vulnerable yaml.load(). Tree-sitter AST analysis should confirm the vulnerable symbol is not reachable.",
  "findings": [
    {
      "cve": "CVE-2020-1747",
      "component_purl": "pkg:pypi/PyYAML@5.3",
      "expected_status": "not_affected",
      "expected_confidence": "high",
      "expected_resolved_by": "reachability",
      "human_justification": "Tree-sitter call graph confirms yaml.load() is never called — only yaml.safe_load() is used."
    }
  ]
}
```

- [ ] **Step 3: Write integration test**

Add to `pkg/vex/reachability/python/python_test.go`:

```go
func TestIntegration_PythonTreesitterReachable(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	sourceDir := filepath.Join(fixtureBase, "python-treesitter-reachable", "source")
	analyzer := python.New()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2020-1747",
		AffectedPURL: "pkg:pypi/PyYAML@5.3",
		AffectedName: "PyYAML",
		Symbols:      []string{"load"},
		Language:     "python",
	}

	result, err := analyzer.Analyze(ctx, sourceDir, &finding)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if !result.Reachable {
		t.Error("expected Reachable=true")
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", result.Confidence)
	}
	if len(result.Paths) == 0 {
		t.Error("expected at least one call path")
	}
	if len(result.Symbols) == 0 {
		t.Error("expected at least one reached symbol")
	}

	t.Logf("Evidence: %s", result.Evidence)
	for i, p := range result.Paths {
		t.Logf("Path %d: %s", i, p)
	}
}

func TestIntegration_PythonTreesitterNotReachable(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	sourceDir := filepath.Join(fixtureBase, "python-treesitter-not-reachable", "source")
	analyzer := python.New()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2020-1747",
		AffectedPURL: "pkg:pypi/PyYAML@5.3",
		AffectedName: "PyYAML",
		Symbols:      []string{"load"},
		Language:     "python",
	}

	result, err := analyzer.Analyze(ctx, sourceDir, &finding)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if result.Reachable {
		t.Error("expected Reachable=false")
	}
	if len(result.Paths) != 0 {
		t.Errorf("expected 0 paths, got %d", len(result.Paths))
	}
}
```

Add `"runtime"` to imports.

- [ ] **Step 4: Run integration tests**

Run: `go test ./pkg/vex/reachability/python/ -run TestIntegration -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add testdata/integration/python-treesitter-reachable/ testdata/integration/python-treesitter-not-reachable/ pkg/vex/reachability/python/python_test.go
git commit -m "test(reachability/python): add tree-sitter integration tests with real PyYAML CVE data"
```

---

### Task 12: Python LLM judge test

**Files:**
- Create: `pkg/vex/reachability/python/llm_judge_test.go`

- [ ] **Step 1: Write LLM judge test**

Create `pkg/vex/reachability/python/llm_judge_test.go`:

```go
//go:build llmjudge

package python_test

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
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/python"
)

type reachabilityScores struct {
	PathAccuracy           int    `json:"path_accuracy"`
	ConfidenceCalibration  int    `json:"confidence_calibration"`
	EvidenceQuality        int    `json:"evidence_quality"`
	FalsePositiveRate      int    `json:"false_positive_rate"`
	SymbolResolution       int    `json:"symbol_resolution"`
	OverallQuality         int    `json:"overall_quality"`
	Reasoning              string `json:"reasoning"`
}

func TestLLMJudge_PythonReachability(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	// Run reachable analysis
	reachableDir := filepath.Join(fixtureBase, "python-treesitter-reachable", "source")
	analyzer := python.New()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2020-1747",
		AffectedPURL: "pkg:pypi/PyYAML@5.3",
		AffectedName: "PyYAML",
		Symbols:      []string{"load"},
		Language:     "python",
	}

	reachableResult, err := analyzer.Analyze(ctx, reachableDir, &finding)
	if err != nil {
		t.Fatalf("Analyze reachable: %v", err)
	}

	// Run not-reachable analysis
	notReachableDir := filepath.Join(fixtureBase, "python-treesitter-not-reachable", "source")
	notReachableResult, err := analyzer.Analyze(ctx, notReachableDir, &finding)
	if err != nil {
		t.Fatalf("Analyze not-reachable: %v", err)
	}

	// Build analysis summary for LLM
	var pathStrs []string
	for _, p := range reachableResult.Paths {
		pathStrs = append(pathStrs, p.String())
	}

	// Write source files to temp for Gemini to read
	reachableSrcFile, _ := os.CreateTemp("", "python-reachable-*.txt")
	defer os.Remove(reachableSrcFile.Name())
	writeSourceFiles(t, reachableDir, reachableSrcFile)
	reachableSrcFile.Close()

	notReachableSrcFile, _ := os.CreateTemp("", "python-not-reachable-*.txt")
	defer os.Remove(notReachableSrcFile.Name())
	writeSourceFiles(t, notReachableDir, notReachableSrcFile)
	notReachableSrcFile.Close()

	prompt := fmt.Sprintf(`You are a security engineering judge evaluating a tree-sitter-based Python reachability analyzer for CRA (Cyber Resilience Act) compliance.

VULNERABILITY: CVE-2020-1747 — PyYAML arbitrary code execution via yaml.load() without safe Loader.
VULNERABLE SYMBOL: yaml.load

REACHABLE PROJECT (read source from: %s):
Analysis result: Reachable=%v, Confidence=%s, Symbols=%v
Call paths found: %s
Evidence: %s

NOT-REACHABLE PROJECT (read source from: %s):
Analysis result: Reachable=%v, Confidence=%s
Evidence: %s

Score the analyzer on these dimensions (1-10 each):
1. path_accuracy: Are the reported call paths real and verifiable against the source code?
2. confidence_calibration: Does the confidence level correctly reflect certainty? High for direct calls, lower for dynamic dispatch?
3. evidence_quality: Would a security engineer trust this evidence to make a VEX determination?
4. false_positive_rate: Is the not-reachable case correctly identified as not-affected?
5. symbol_resolution: Is yaml.load correctly identified and distinguished from yaml.safe_load?
6. overall_quality: Would this analysis pass a CRA market surveillance authority's review?

Respond ONLY with valid JSON:
{"path_accuracy": N, "confidence_calibration": N, "evidence_quality": N, "false_positive_rate": N, "symbol_resolution": N, "overall_quality": N, "reasoning": "brief explanation"}`,
		reachableSrcFile.Name(),
		reachableResult.Reachable, reachableResult.Confidence, reachableResult.Symbols,
		strings.Join(pathStrs, "; "),
		reachableResult.Evidence,
		notReachableSrcFile.Name(),
		notReachableResult.Reachable, notReachableResult.Confidence,
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

	t.Logf("LLM Scores: path=%d, confidence=%d, evidence=%d, fp=%d, symbol=%d, overall=%d",
		scores.PathAccuracy, scores.ConfidenceCalibration, scores.EvidenceQuality,
		scores.FalsePositiveRate, scores.SymbolResolution, scores.OverallQuality)
	t.Logf("Reasoning: %s", scores.Reasoning)

	threshold := 8
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

func writeSourceFiles(t *testing.T, dir string, out *os.File) {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "*.py"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(dir, f)
		fmt.Fprintf(out, "=== %s ===\n%s\n\n", rel, string(data))
	}
}
```

- [ ] **Step 2: Run LLM judge test (optional, requires gemini CLI)**

Run: `go test -tags llmjudge -run TestLLMJudge_PythonReachability -v ./pkg/vex/reachability/python/`
Expected: PASS (all dimensions >= 8)

- [ ] **Step 3: Commit**

```bash
git add pkg/vex/reachability/python/llm_judge_test.go
git commit -m "test(reachability/python): add LLM quality judge test for tree-sitter analysis"
```

---

## Phase 3: JavaScript / TypeScript

### Task 13: JS/TS extractor

**Files:**
- Create: `pkg/vex/reachability/treesitter/javascript/extractor.go`
- Create: `pkg/vex/reachability/treesitter/javascript/extractor_test.go`
- Create: `pkg/vex/reachability/treesitter/javascript/entrypoints.go`
- Create: `pkg/vex/reachability/treesitter/javascript/entrypoints_test.go`

Follow the same pattern as the Python extractor (Task 8-9) but for JavaScript/TypeScript.

- [ ] **Step 1: Write tests for JS symbol, import, and call extraction**

Test with real JS source code covering:
- `function` declarations, arrow functions, class methods
- `import { x } from 'y'` and `const x = require('y')`
- `module.exports` assignments
- Method calls, chained calls, `new` expressions

```go
func TestExtractSymbols_JavaScript(t *testing.T) {
	source := `const _ = require('lodash');
const express = require('express');

function handleRequest(req, res) {
    const template = _.template(req.body.input);
    res.send(template({ user: req.user }));
}

class UserController {
    getUser(req, res) {
        return res.json({ name: "test" });
    }
}

module.exports = { handleRequest, UserController };
`
	// Test extracts: handleRequest (function), UserController (class), getUser (method)
	// Test extracts imports: lodash (as _), express
	// Test extracts calls: _.template, res.send, template(), res.json
}
```

- [ ] **Step 2: Write tests for JS entry point discovery**

Test Express routes, Nuxt `defineEventHandler`, SvelteKit exported handlers, NestJS decorators, Next.js page exports, Remix loaders/actions, Hono routes, Astro API routes.

```go
func TestFindEntryPoints_Express(t *testing.T) {
	source := `const express = require('express');
const app = express();

app.get('/health', (req, res) => {
    res.send('ok');
});

app.post('/api/data', handleData);

function handleData(req, res) {
    res.json(process(req.body));
}

function process(data) {
    return data;
}
`
	// handleData and the arrow function in app.get should be entry points
	// process should NOT be an entry point
}

func TestFindEntryPoints_Nuxt(t *testing.T) {
	source := `export default defineEventHandler((event) => {
    return { status: 'ok' };
});
`
	// File is in server/api/ — the defineEventHandler export is an entry point
}

func TestFindEntryPoints_SvelteKit(t *testing.T) {
	source := `export async function GET({ params }) {
    return json({ id: params.id });
}

export async function POST({ request }) {
    const body = await request.json();
    return json(body);
}
`
	// GET and POST are entry points (SvelteKit +server.ts convention)
}
```

- [ ] **Step 3: Implement JS/TS extractor and entry points**

The JavaScript extractor handles both `.js` and `.ts` files. For TypeScript files, use the TypeScript grammar (which handles type annotations). Key tree-sitter node types:

- `function_declaration` → fields: `name`, `parameters`, `body`
- `arrow_function` → fields: `parameters`, `body`
- `class_declaration` → fields: `name`, `body`
- `method_definition` → fields: `name`, `parameters`, `body`
- `call_expression` → fields: `function`, `arguments`
- `member_expression` → fields: `object`, `property`
- `import_statement` → `import_clause`, `from`
- `variable_declarator` with `require()` call

For TypeScript, additionally extract type annotations from `type_annotation` nodes to improve edge confidence (known type = 1.0 confidence for method calls).

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/vex/reachability/treesitter/javascript/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/treesitter/javascript/
git commit -m "feat(treesitter/javascript): add JS/TS extractor - symbols, imports, calls, entry points"
```

---

### Task 14: JS/TS analyzer and integration tests

**Files:**
- Create: `pkg/vex/reachability/javascript/javascript.go`
- Create: `pkg/vex/reachability/javascript/javascript_test.go`
- Create: `testdata/integration/javascript-treesitter-reachable/`
- Create: `testdata/integration/javascript-treesitter-not-reachable/`
- Create: `pkg/vex/reachability/javascript/llm_judge_test.go`

Follow the same pattern as Python (Task 10-12).

- [ ] **Step 1: Create integration fixtures**

Reachable: Express app that calls `_.template()` from lodash (CVE-2021-23337).

`source/app.js`:
```javascript
const express = require('express');
const _ = require('lodash');
const app = express();

app.post('/render', (req, res) => {
    const compiled = _.template(req.body.template);
    res.send(compiled({ data: req.body.data }));
});

app.listen(3000);
```

`source/package.json`:
```json
{
  "name": "test-app",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "4.17.20"
  }
}
```

Not-reachable: App imports lodash but only uses `_.map()`, never `_.template()`.

Generate SBOM and scan data with lodash 4.17.20 and CVE-2021-23337.

- [ ] **Step 2: Implement JS/TS analyzer**

Same pattern as `pkg/vex/reachability/python/python.go`: glob `.js`/`.ts`/`.jsx`/`.tsx`/`.mjs` files, parse concurrently, build graph, find entry points, run BFS.

Use JavaScript grammar for `.js`/`.jsx`/`.mjs`/`.cjs` files and TypeScript grammar for `.ts`/`.tsx` files.

- [ ] **Step 3: Write unit + integration tests**

- [ ] **Step 4: Write LLM judge test**

Same scoring dimensions as Python.

- [ ] **Step 5: Run all tests**

Run: `go test ./pkg/vex/reachability/javascript/ -v && go test ./pkg/vex/reachability/treesitter/javascript/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/vex/reachability/javascript/ testdata/integration/javascript-treesitter-reachable/ testdata/integration/javascript-treesitter-not-reachable/
git commit -m "feat(reachability/javascript): add tree-sitter JS/TS analyzer with lodash CVE integration tests"
```

---

## Phase 4: Java

### Task 15: Java extractor with CHA

**Files:**
- Create: `pkg/vex/reachability/treesitter/java/extractor.go`
- Create: `pkg/vex/reachability/treesitter/java/extractor_test.go`
- Create: `pkg/vex/reachability/treesitter/java/entrypoints.go`
- Create: `pkg/vex/reachability/treesitter/java/entrypoints_test.go`

- [ ] **Step 1: Write tests for Java extraction + CHA**

```go
func TestExtractSymbols_Java(t *testing.T) {
	source := `package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main(String[] args) {
        logger.info("Starting: {}", args[0]);
    }

    public void process(String input) {
        logger.info("Processing: {}", input);
    }
}
`
	// Should extract: App (class), main (method), process (method)
	// Should extract imports: LogManager, Logger
	// Should extract calls: LogManager.getLogger, logger.info
}

func TestCHA_InterfaceDispatch(t *testing.T) {
	source := `package com.example;

public interface Handler {
    void handle(String input);
}

public class LogHandler implements Handler {
    public void handle(String input) {
        System.out.println(input);
    }
}

public class App {
    public void run(Handler handler) {
        handler.handle("test");
    }
}
`
	// CHA should create EdgeDispatch from handler.handle → LogHandler.handle
	// with confidence 0.5 (interface dispatch)
}
```

- [ ] **Step 2: Write tests for Java entry points**

Test: `public static void main`, Spring `@RestController` + `@GetMapping`/`@PostMapping`, `@Scheduled`, `@Test`.

- [ ] **Step 3: Implement Java extractor**

Key tree-sitter node types for Java:
- `class_declaration` → fields: `name`, `body`, `superclass`, `interfaces`
- `method_declaration` → fields: `name`, `parameters`, `body`, `type`
- `constructor_declaration` → fields: `name`, `parameters`, `body`
- `import_declaration` → child: scoped_identifier
- `method_invocation` → fields: `object`, `name`, `arguments`
- `object_creation_expression` → fields: `type`, `arguments`
- `annotation` → for entry point detection
- `marker_annotation` → for `@Override`, `@Test`

CHA implementation: build a map of `interface/class → implementing classes`, then for method calls on interface types, create `EdgeDispatch` edges to all implementing classes' methods.

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/vex/reachability/treesitter/java/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/vex/reachability/treesitter/java/
git commit -m "feat(treesitter/java): add Java extractor with CHA for interface dispatch"
```

---

### Task 16: Java analyzer and integration tests

**Files:**
- Create: `pkg/vex/reachability/java/java.go`
- Create: `pkg/vex/reachability/java/java_test.go`
- Create: `testdata/integration/java-treesitter-reachable/`
- Create: `testdata/integration/java-treesitter-not-reachable/`
- Create: `pkg/vex/reachability/java/llm_judge_test.go`

- [ ] **Step 1: Create integration fixtures**

Reachable: Spring Boot app that uses `Logger.info()` with user-controlled input (CVE-2021-44228 / Log4Shell).

`source/App.java`:
```java
package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.*;

@RestController
public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    @GetMapping("/api/search")
    public String search(@RequestParam String query) {
        logger.info("Search query: {}", query);
        return "Results for: " + query;
    }
}
```

Not-reachable: App imports Log4j but wraps it in a sanitizer that prevents JNDI lookups.

Generate SBOM and scan data with log4j-core 2.14.1 and CVE-2021-44228.

- [ ] **Step 2: Implement Java analyzer, tests, LLM judge**

Same pattern as Python/JS.

- [ ] **Step 3: Run all tests**

Run: `go test ./pkg/vex/reachability/java/ -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add pkg/vex/reachability/java/ testdata/integration/java-treesitter-reachable/ testdata/integration/java-treesitter-not-reachable/
git commit -m "feat(reachability/java): add tree-sitter Java analyzer with Log4j CVE integration tests"
```

---

## Phase 5: C#, PHP, Ruby

### Task 17: C# extractor, analyzer, and tests

Follow the same pattern. Key details:

**C# tree-sitter node types:**
- `class_declaration`, `method_declaration`, `constructor_declaration`
- `using_directive` (imports)
- `invocation_expression`, `object_creation_expression`
- `attribute_list` for `[HttpGet]`, `[Route]` etc.

**Entry points:** `static void Main`, ASP.NET `[HttpGet]`/`[HttpPost]` controller actions, `[Route]` handlers, Minimal API `MapGet`/`MapPost`, `IHostedService.ExecuteAsync`.

**Integration fixture:** Newtonsoft.Json CVE-2024-21907 — app calling `JsonConvert.DeserializeObject<T>()` with `TypeNameHandling.Auto`.

- [ ] **Step 1: Create extractor with tests**
- [ ] **Step 2: Create entry points with tests**
- [ ] **Step 3: Create analyzer with unit tests**
- [ ] **Step 4: Create integration fixtures and tests**
- [ ] **Step 5: Create LLM judge test**
- [ ] **Step 6: Run all C# tests**

Run: `go test ./pkg/vex/reachability/csharp/ -v && go test ./pkg/vex/reachability/treesitter/csharp/ -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add pkg/vex/reachability/csharp/ pkg/vex/reachability/treesitter/csharp/ testdata/integration/csharp-treesitter-reachable/ testdata/integration/csharp-treesitter-not-reachable/
git commit -m "feat(reachability/csharp): add tree-sitter C# analyzer with Newtonsoft.Json CVE integration tests"
```

---

### Task 18: PHP extractor, analyzer, and tests

**PHP tree-sitter node types:**
- `function_definition`, `method_declaration`, `class_declaration`
- `use_declaration` (namespace imports)
- `function_call_expression`, `member_call_expression`, `scoped_call_expression`
- `attribute_list` for Symfony `#[Route]`

**Entry points:** Laravel `Route::get()`/`Route::post()`, Symfony `#[Route]` attributes, controller constructors, `index.php`.

**Autoloading:** Parse `composer.json` `autoload.psr-4` to map `App\\` → `src/`.

**Integration fixture:** Guzzle CVE-2022-29248 — app using Guzzle client that forwards cookies on redirect.

- [ ] **Step 1: Create extractor with tests**
- [ ] **Step 2: Create entry points with tests**
- [ ] **Step 3: Create analyzer with unit tests**
- [ ] **Step 4: Create integration fixtures and tests**
- [ ] **Step 5: Create LLM judge test**
- [ ] **Step 6: Run all PHP tests**

Run: `go test ./pkg/vex/reachability/php/ -v && go test ./pkg/vex/reachability/treesitter/php/ -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add pkg/vex/reachability/php/ pkg/vex/reachability/treesitter/php/ testdata/integration/php-treesitter-reachable/ testdata/integration/php-treesitter-not-reachable/
git commit -m "feat(reachability/php): add tree-sitter PHP analyzer with Guzzle CVE integration tests"
```

---

### Task 19: Ruby extractor, analyzer, and tests

**Ruby tree-sitter node types:**
- `method`, `singleton_method`, `class`, `module`
- `call` (method calls), `command_call`
- `require` / `require_relative` (extracted from `call` nodes)
- For Rails routes: parse `config/routes.rb` for `get`, `post`, `resources` calls

**Entry points:** Rails routes → controller actions, Rake tasks, Sidekiq `perform`, `bin/*` scripts, Sinatra route blocks.

**Metaprogramming:** `send`/`public_send` → `EdgeDispatch` with 0.3 confidence. `method_missing` → log as unresolved.

**Integration fixture:** Nokogiri CVE-2022-24836 — app calling `Nokogiri::HTML()` with untrusted input.

- [ ] **Step 1: Create extractor with tests**
- [ ] **Step 2: Create entry points with tests**
- [ ] **Step 3: Create analyzer with unit tests**
- [ ] **Step 4: Create integration fixtures and tests**
- [ ] **Step 5: Create LLM judge test**
- [ ] **Step 6: Run all Ruby tests**

Run: `go test ./pkg/vex/reachability/ruby/ -v && go test ./pkg/vex/reachability/treesitter/ruby/ -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add pkg/vex/reachability/ruby/ pkg/vex/reachability/treesitter/ruby/ testdata/integration/ruby-treesitter-reachable/ testdata/integration/ruby-treesitter-not-reachable/
git commit -m "feat(reachability/ruby): add tree-sitter Ruby analyzer with Nokogiri CVE integration tests"
```

---

## Phase 6: Pipeline Integration

### Task 20: Update language detection

**Files:**
- Modify: `pkg/vex/reachability/language.go`
- Modify: `pkg/vex/reachability/language_test.go` (if it exists)

- [ ] **Step 1: Write test for new language markers**

```go
func TestDetectLanguages_AllSupported(t *testing.T) {
	dir := t.TempDir()

	// Create markers for all supported languages
	markers := map[string]string{
		"go.mod":         "go",
		"Cargo.toml":     "rust",
		"package.json":   "javascript",
		"requirements.txt": "python",
		"pom.xml":        "java",
		"App.csproj":     "csharp",
		"composer.json":  "php",
		"Gemfile":        "ruby",
	}
	for file := range markers {
		os.WriteFile(filepath.Join(dir, file), []byte(""), 0o644)
	}

	langs := reachability.DetectLanguages(dir)
	if len(langs) != 8 {
		t.Errorf("expected 8 languages, got %d: %v", len(langs), langs)
	}
}
```

- [ ] **Step 2: Update language.go**

Add to `languageMarkers`:

```go
var languageMarkers = map[string][]string{
	"go":         {"go.mod"},
	"rust":       {"Cargo.toml"},
	"javascript": {"package.json"},
	"python":     {"requirements.txt", "pyproject.toml", "setup.py"},
	"java":       {"pom.xml", "build.gradle", "build.gradle.kts"},
	"csharp":     {"*.csproj", "*.sln"},
	"php":        {"composer.json"},
	"ruby":       {"Gemfile"},
}
```

Note: For C#, the markers use glob patterns (`.csproj`, `.sln`). Update `DetectLanguages` to handle glob patterns in markers:

```go
func DetectLanguages(dir string) []string {
	var langs []string
	for lang, markers := range languageMarkers {
		for _, marker := range markers {
			if strings.Contains(marker, "*") {
				// Glob pattern
				matches, _ := filepath.Glob(filepath.Join(dir, marker))
				if len(matches) > 0 {
					langs = append(langs, lang)
					break
				}
			} else {
				if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
					langs = append(langs, lang)
					break
				}
			}
		}
	}
	return langs
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./pkg/vex/reachability/ -run TestDetectLanguages -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add pkg/vex/reachability/language.go pkg/vex/reachability/language_test.go
git commit -m "feat(reachability): add C#, PHP, Ruby language detection markers"
```

---

### Task 21: Update buildAnalyzers with tree-sitter fallback

**Files:**
- Modify: `pkg/vex/vex.go`

- [ ] **Step 1: Write test for tree-sitter analyzer registration**

Add to `pkg/vex/vex_test.go` or a new test file:

```go
func TestBuildAnalyzers_TreesitterFallback(t *testing.T) {
	// Create a directory with Python manifest
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("PyYAML==5.3"), 0o644)

	analyzers := buildAnalyzers(dir)

	// Should have: python (tree-sitter), generic (fallback)
	if _, ok := analyzers["python"]; !ok {
		t.Error("expected python analyzer to be registered")
	}
	if _, ok := analyzers["generic"]; !ok {
		t.Error("expected generic fallback analyzer")
	}

	// Python analyzer should be tree-sitter, not generic
	if analyzers["python"].Language() != "python" {
		t.Errorf("expected python analyzer language 'python', got %q", analyzers["python"].Language())
	}
}
```

- [ ] **Step 2: Update buildAnalyzers in vex.go**

```go
import (
	// ... existing imports ...
	pythonanalyzer "github.com/ravan/cra-toolkit/pkg/vex/reachability/python"
	jsanalyzer "github.com/ravan/cra-toolkit/pkg/vex/reachability/javascript"
	javaanalyzer "github.com/ravan/cra-toolkit/pkg/vex/reachability/java"
	csharpanalyzer "github.com/ravan/cra-toolkit/pkg/vex/reachability/csharp"
	phpanalyzer "github.com/ravan/cra-toolkit/pkg/vex/reachability/php"
	rubyanalyzer "github.com/ravan/cra-toolkit/pkg/vex/reachability/ruby"
)

func buildAnalyzers(sourceDir string) map[string]reachability.Analyzer {
	analyzers := make(map[string]reachability.Analyzer)

	langs := reachability.DetectLanguages(sourceDir)
	for _, lang := range langs {
		switch lang {
		case "go":
			analyzers["go"] = golang.New()
		case "rust":
			analyzers["rust"] = rust.New()
		case "python":
			analyzers["python"] = pythonanalyzer.New()
		case "javascript":
			analyzers["javascript"] = jsanalyzer.New()
		case "java":
			analyzers["java"] = javaanalyzer.New()
		case "csharp":
			analyzers["csharp"] = csharpanalyzer.New()
		case "php":
			analyzers["php"] = phpanalyzer.New()
		case "ruby":
			analyzers["ruby"] = rubyanalyzer.New()
		}
	}

	// Always add generic as fallback.
	analyzers["generic"] = generic.New("")

	return analyzers
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./pkg/vex/ -v`
Expected: PASS (existing + new tests)

- [ ] **Step 4: Commit**

```bash
git add pkg/vex/vex.go
git commit -m "feat(vex): register tree-sitter analyzers for Python, JS, Java, C#, PHP, Ruby"
```

---

### Task 22: Update reachability filter for path evidence

**Files:**
- Modify: `pkg/vex/reachability_filter.go`

- [ ] **Step 1: Update Evaluate to include path information**

```go
func (f *reachabilityFilter) Evaluate(finding *formats.Finding, components []formats.Component) (Result, bool) {
	// ... existing analyzer selection and execution ...

	if result.Reachable {
		evidence := result.Evidence
		// Append structured path info if available
		if len(result.Paths) > 0 {
			var pathStrs []string
			for _, p := range result.Paths {
				pathStrs = append(pathStrs, p.String())
			}
			evidence = fmt.Sprintf("%s\nCall paths:\n  %s", evidence, strings.Join(pathStrs, "\n  "))
		}
		return Result{
			CVE:           finding.CVE,
			ComponentPURL: finding.AffectedPURL,
			Status:        formats.StatusAffected,
			Confidence:    result.Confidence,
			ResolvedBy:    "reachability_analysis",
			Evidence:      evidence,
		}, true
	}

	return Result{
		CVE:           finding.CVE,
		ComponentPURL: finding.AffectedPURL,
		Status:        formats.StatusNotAffected,
		Justification: formats.JustificationVulnerableCodeNotInExecutePath,
		Confidence:    result.Confidence,
		ResolvedBy:    "reachability_analysis",
		Evidence:      fmt.Sprintf("Reachability analysis: %s", result.Evidence),
	}, true
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./pkg/vex/ -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/vex/reachability_filter.go
git commit -m "feat(vex): include call path evidence in reachability filter results"
```

---

### Task 23: Update Taskfile

**Files:**
- Modify: `Taskfile.yml`

- [ ] **Step 1: Add reachability test tasks**

Add to `Taskfile.yml`:

```yaml
  test:reachability:
    desc: Run reachability tree-sitter integration tests
    cmds:
      - go test -race -count=1 -run TestIntegration ./pkg/vex/reachability/python/...
      - go test -race -count=1 -run TestIntegration ./pkg/vex/reachability/javascript/...
      - go test -race -count=1 -run TestIntegration ./pkg/vex/reachability/java/...
      - go test -race -count=1 -run TestIntegration ./pkg/vex/reachability/csharp/...
      - go test -race -count=1 -run TestIntegration ./pkg/vex/reachability/php/...
      - go test -race -count=1 -run TestIntegration ./pkg/vex/reachability/ruby/...

  test:reachability:llmjudge:
    desc: Run reachability LLM quality judge tests (requires gemini CLI)
    cmds:
      - go test -race -count=1 -tags llmjudge -run TestLLMJudge -v ./pkg/vex/reachability/python/...
      - go test -race -count=1 -tags llmjudge -run TestLLMJudge -v ./pkg/vex/reachability/javascript/...
      - go test -race -count=1 -tags llmjudge -run TestLLMJudge -v ./pkg/vex/reachability/java/...
      - go test -race -count=1 -tags llmjudge -run TestLLMJudge -v ./pkg/vex/reachability/csharp/...
      - go test -race -count=1 -tags llmjudge -run TestLLMJudge -v ./pkg/vex/reachability/php/...
      - go test -race -count=1 -tags llmjudge -run TestLLMJudge -v ./pkg/vex/reachability/ruby/...
```

- [ ] **Step 2: Verify tasks list**

Run: `task --list`
Expected: new tasks appear in list

- [ ] **Step 3: Commit**

```bash
git add Taskfile.yml
git commit -m "feat(taskfile): add reachability tree-sitter test and llmjudge tasks"
```

---

### Task 24: End-to-end VEX pipeline integration tests

**Files:**
- Modify: `pkg/vex/integration_test.go`

- [ ] **Step 1: Add tree-sitter fixture tests to integration test**

Add to `pkg/vex/integration_test.go`:

```go
func TestIntegration_PythonTreesitterFixtures(t *testing.T) {
	tests := []struct {
		name string
		dir  string
	}{
		{"python-treesitter-reachable", "python-treesitter-reachable"},
		{"python-treesitter-not-reachable", "python-treesitter-not-reachable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(fixtureBase, tt.dir)
			expected := loadExpected(t, dir)

			opts := &vex.Options{
				SBOMPath:     filepath.Join(dir, "sbom.cdx.json"),
				ScanPaths:    []string{filepath.Join(dir, "trivy.json")},
				SourceDir:    filepath.Join(dir, "source"),
				OutputFormat: "openvex",
			}

			doc := runPipeline(t, opts)
			verifyExpectations(t, doc, expected, tt.name)
		})
	}
}

func TestIntegration_JavaScriptTreesitterFixtures(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		scan string
	}{
		{"javascript-treesitter-reachable", "javascript-treesitter-reachable", "grype.json"},
		{"javascript-treesitter-not-reachable", "javascript-treesitter-not-reachable", "grype.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(fixtureBase, tt.dir)
			expected := loadExpected(t, dir)

			opts := &vex.Options{
				SBOMPath:     filepath.Join(dir, "sbom.cdx.json"),
				ScanPaths:    []string{filepath.Join(dir, tt.scan)},
				SourceDir:    filepath.Join(dir, "source"),
				OutputFormat: "openvex",
			}

			doc := runPipeline(t, opts)
			verifyExpectations(t, doc, expected, tt.name)
		})
	}
}

// Add similar test functions for Java, C#, PHP, Ruby fixtures
```

- [ ] **Step 2: Run full integration test suite**

Run: `go test ./pkg/vex/ -run TestIntegration -v -count=1`
Expected: ALL PASS — existing Go/Python/Rust fixtures + new tree-sitter fixtures

- [ ] **Step 3: Run full quality gate**

Run: `task quality`
Expected: PASS (fmt, vet, lint, test)

- [ ] **Step 4: Commit**

```bash
git add pkg/vex/integration_test.go
git commit -m "test(vex): add end-to-end pipeline integration tests for tree-sitter analyzers"
```

---

### Task 25: Final verification

- [ ] **Step 1: Run all tests**

Run: `go test -race -count=1 ./...`
Expected: ALL PASS, 0 skipped (tree-sitter tests have no external tool dependency)

- [ ] **Step 2: Run lint**

Run: `task lint`
Expected: PASS

- [ ] **Step 3: Run LLM judge tests (all languages)**

Run: `task test:reachability:llmjudge`
Expected: ALL dimensions >= 8 for all languages

- [ ] **Step 4: Verify build**

Run: `task build`
Expected: binary compiles with CGO, all grammars linked

- [ ] **Step 5: Verify build without tree-sitter**

Run: `go build -tags no_treesitter -o /tmp/cra-no-ts ./cmd/cra`
Expected: compiles without CGO, tree-sitter analyzers excluded, generic fallback active
