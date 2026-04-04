# Tree-sitter Reachability Analysis Design

## Overview

Extend the CRA VEX reachability engine with interprocedural call graph analysis for six additional languages using tree-sitter AST parsing. Currently, Go uses `govulncheck` (high confidence) and Rust uses `cargo-scan` (in progress). All other languages fall back to ripgrep pattern matching (medium confidence). This design introduces production-grade, AST-based reachability analysis for Python, JavaScript/TypeScript, Java, C#, PHP, and Ruby.

The goal: determine whether a known vulnerability's code path is actually reachable from application entry points, producing structured call paths as evidence for VEX statements.

## Industry Context

Research into existing static analysis tools informed the following design decisions:

- **Algorithm choice**: Variable Type Analysis (VTA) is the industry sweet spot between precision and cost. govulncheck uses VTA for Go; PyCG does analogous assignment-based fixpoint iteration for Python. Full pointer analysis is too expensive for a CLI tool. CHA/RTA is too imprecise. Our approach uses CHA for statically-typed languages (Java, C#) and assignment tracking for dynamic languages (Python, JS, Ruby, PHP).
- **Precision over recall**: PyCG achieves ~99% precision / ~70% recall for Python. For vulnerability tooling, false positives (marking unreachable code as reachable) are more harmful than false negatives (missing a reachable path — the vulnerability is still flagged, just not confirmed reachable). Our design prioritizes precision.
- **Tree-sitter is a parser, not an analyzer**: Every production tool (CodeQL, Joern, ACER) layers substantial semantic analysis on top of tree-sitter CSTs. We build import resolution, scope tracking, and call graph construction ourselves.
- **Five levels of reachability** (Endor Labs taxonomy): dependency → package → function → path → runtime. We target function-level with path-level evidence (structured call chains from entry point to vulnerable symbol).

## Architecture

### Directory Structure

```
pkg/vex/reachability/
├── analyzer.go                    # Analyzer interface (existing, unchanged)
├── result.go                      # Result type (extended with Paths)
├── language.go                    # Language detection (existing, unchanged)
├── golang/                        # govulncheck (existing, unchanged)
├── rust/                          # cargo-scan (existing, unchanged)
├── generic/                       # ripgrep fallback (existing, unchanged)
├── python/                        # Python analyzer (NEW)
│   └── python.go
├── javascript/                    # JS/TS analyzer (NEW)
│   └── javascript.go
├── java/                          # Java analyzer (NEW)
│   └── java.go
├── csharp/                        # C# analyzer (NEW)
│   └── csharp.go
├── php/                           # PHP analyzer (NEW)
│   └── php.go
├── ruby/                          # Ruby analyzer (NEW)
│   └── ruby.go
└── treesitter/                    # Shared tree-sitter core (NEW)
    ├── graph.go                   # Unified symbol graph + BFS reachability
    ├── parser.go                  # Tree-sitter parsing orchestration
    ├── extractor.go               # LanguageExtractor interface
    ├── scope.go                   # Scope/symbol table tracking
    ├── grammars/
    │   ├── python/                # tree-sitter-python grammar
    │   ├── javascript/            # tree-sitter-javascript grammar
    │   ├── typescript/            # tree-sitter-typescript grammar
    │   ├── java/                  # tree-sitter-java grammar
    │   ├── csharp/                # tree-sitter-c-sharp grammar
    │   ├── php/                   # tree-sitter-php grammar
    │   └── ruby/                  # tree-sitter-ruby grammar
    ├── python/                    # Python extractor
    │   ├── extractor.go
    │   └── entrypoints.go
    ├── javascript/                # JS/TS extractor
    │   ├── extractor.go
    │   └── entrypoints.go
    ├── java/                      # Java extractor
    │   ├── extractor.go
    │   └── entrypoints.go
    ├── csharp/                    # C# extractor
    │   ├── extractor.go
    │   └── entrypoints.go
    ├── php/                       # PHP extractor
    │   ├── extractor.go
    │   └── entrypoints.go
    └── ruby/                      # Ruby extractor
        ├── extractor.go
        └── entrypoints.go
```

Each language gets:
1. A **per-language analyzer** under `pkg/vex/reachability/<lang>/` implementing the existing `Analyzer` interface
2. A **language extractor** under `treesitter/<lang>/` implementing `LanguageExtractor`
3. A **grammar package** under `treesitter/grammars/<lang>/` isolating CGO symbols

The `treesitter/` package is the shared engine — not an analyzer itself.

### Relationship to Existing Code

- Go analyzer (`golang/`): unchanged, uses `govulncheck`
- Rust analyzer (`rust/`): unchanged, uses `cargo-scan`
- Generic analyzer (`generic/`): unchanged, remains as ultimate fallback
- `Analyzer` interface: unchanged
- `Result` type: extended with `Paths` field
- `vex.go` `buildAnalyzers()`: updated to register tree-sitter analyzers with fallback to generic
- `reachability_filter.go`: updated to include path information in evidence

## Extended Types

### Result (extended)

```go
type Result struct {
    Reachable  bool
    Confidence formats.Confidence
    Evidence   string
    Symbols    []string
    Paths      []CallPath  // NEW: entry point → vulnerable symbol
}

type CallPath struct {
    Nodes []CallNode
}

type CallNode struct {
    Symbol   string // qualified name (e.g., "myapp.handler.process")
    File     string // relative path
    Line     int
}
```

### LanguageExtractor Interface

```go
type LanguageExtractor interface {
    Language() string
    FileExtensions() []string
    ExtractSymbols(file string, tree *sitter.Tree) ([]Symbol, error)
    ResolveImports(file string, tree *sitter.Tree, moduleRoot string) ([]Import, error)
    FindEntryPoints(symbols []Symbol) []SymbolID
}
```

### Symbol Model

```go
type SymbolID string

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

type SymbolKind int
const (
    SymbolFunction SymbolKind = iota
    SymbolMethod
    SymbolClass
    SymbolModule
)
```

### Graph Model

```go
type Graph struct {
    Symbols map[SymbolID]*Symbol
    Forward map[SymbolID][]Edge  // caller → callees
    Reverse map[SymbolID][]Edge  // callee → callers
}

type Edge struct {
    From       SymbolID
    To         SymbolID
    Kind       EdgeKind
    Confidence float64
    File       string
    Line       int
}

type EdgeKind int
const (
    EdgeDirect   EdgeKind = iota  // direct function call
    EdgeDispatch                   // dynamic/virtual dispatch
    EdgeImport                     // module import
)
```

### Import Model

```go
type Import struct {
    Module  string   // "flask" or "express"
    Symbols []string // specific symbols imported (empty = whole module)
    Alias   string   // import alias if any
    File    string
    Line    int
}
```

## Parsing & Graph Construction

### Parsing Orchestration

1. Detect language from manifest files (existing `DetectLanguages()`)
2. For each detected language, glob for matching file extensions
3. Parse files concurrently using a worker pool (`runtime.NumCPU()` workers)
4. Each file parse: tree-sitter CST → `LanguageExtractor.ExtractSymbols()` + `ResolveImports()`
5. All symbols and imports feed into graph construction

### Graph Construction (Two-Phase)

**Phase 1 — Symbol collection**: Gather all symbols and imports from all files. Build the symbol table indexed by qualified name.

**Phase 2 — Edge resolution**: For each call site found during extraction, resolve the target symbol by walking the import chain and scope. Create `Edge` entries. Unresolved calls (dynamic dispatch, reflection, metaprogramming) become `EdgeDispatch` with reduced confidence.

### Import Resolution Per Language

| Language | Strategy |
|----------|----------|
| Python | `import X` / `from X import Y`, relative imports via `__init__.py`, PyPI-to-import name normalization |
| JS/TS | `require()` / `import from`, `node_modules/` resolution, `index.js` convention, barrel exports |
| Java | `import` statements, package→directory mapping, wildcard imports |
| C# | `using` statements, namespace→file mapping |
| PHP | `use` / `require` / `include`, PSR-4 autoload from `composer.json` |
| Ruby | `require` / `require_relative` / `include`, gem path resolution |

### BFS Reachability

```
for each vulnerable symbol V:
    for each entry point E:
        BFS from E following Forward edges
        if V is reached:
            record shortest path E → ... → V
            compute path confidence = product(edge.Confidence)
```

Configuration: `MaxDepth=50`, `MaxPaths=5` per vulnerability. Cycle detection via visited set.

### Confidence Scoring

| Situation | Edge Confidence |
|-----------|----------------|
| Direct function call | 1.0 |
| Method call on known type | 1.0 |
| Dynamic dispatch (duck typing, interface) | 0.5 |
| Wildcard/star import | 0.7 |
| `eval`/`exec`/reflection | 0.3 |
| Import found but symbol usage unclear | 0.4 |

Path confidence = product of edge confidences along the path.

Mapping to `formats.Confidence`:
- Path confidence >= 0.8 → `ConfidenceHigh`
- Path confidence >= 0.4 → `ConfidenceMedium`
- Path confidence < 0.4 → `ConfidenceLow`

## Language-Specific Extraction Rules

### Python

**Symbols extracted**: function defs, class defs, method defs, decorated functions, lambda assignments

**Call sites**: direct calls (`foo()`), method calls (`obj.foo()`), chained calls (`app.route().get()`)

**Entry points**:
- `if __name__ == "__main__"` blocks
- Flask/Django/FastAPI route decorators (`@app.route`, `@router.get`)
- Celery task decorators (`@app.task`, `@shared_task`)
- Click/argparse CLI commands
- `setup.py` / `pyproject.toml` `[project.scripts]` console entry points

**Dynamic dispatch**: Python is duck-typed — method calls on untyped variables produce `EdgeDispatch` (0.5 confidence). Assignment tracking (PyCG-style fixpoint) for the common case of `x = SomeClass(); x.method()`.

### JavaScript / TypeScript

**Symbols extracted**: function declarations, arrow functions, class methods, named exports, `module.exports` assignments

**Call sites**: direct calls, method calls, `new` expressions, `.then()` / `await` chains

**Entry points**:

| Framework | Entry Point Pattern |
|-----------|-------------------|
| Express/Koa/Fastify | `app.get()`, `router.post()` route handlers |
| NestJS | `@Controller`, `@Get` decorator methods |
| Next.js | `getServerSideProps`, `default export` in pages |
| Nuxt 3 | `server/api/**/*.{ts,js}`, `defineEventHandler` exports |
| SvelteKit | `src/routes/**/+server.{ts,js}`, exported `GET`/`POST`/`DELETE`/`PATCH` |
| Remix | `app/routes/**/*.{ts,tsx}`, exported `loader`/`action` |
| Astro | `src/pages/api/` routes |
| Hono | `app.get()` / `app.post()` registrations |
| Nitro (standalone) | `routes/**/*.{ts,js}`, `defineEventHandler` |
| `package.json` | `"main"` and `"bin"` fields |
| Event listeners | `on('event', handler)` |

**TypeScript bonus**: Type annotations provide concrete type info for method resolution — extract type annotations to improve edge confidence to 1.0 when receiver type is known.

**Framework detection**: Check `package.json` dependencies for framework presence, then apply framework-specific entry point discovery.

### Java

**Symbols extracted**: method declarations, constructor declarations, class declarations, interface declarations

**Call sites**: method invocations, constructor calls, static method calls

**Entry points**:
- `public static void main(String[])`
- Spring `@Controller` / `@RestController` / `@RequestMapping` methods
- `@Scheduled` methods
- Servlet `doGet`/`doPost` overrides
- JUnit `@Test` methods

**Inheritance**: Build class hierarchy from `extends`/`implements`. Virtual method calls on a declared type resolve to all overriding implementations — each gets an `EdgeDispatch` edge. This is CHA (Class Hierarchy Analysis).

### C#

**Symbols extracted**: method declarations, property accessors, constructor declarations

**Call sites**: method invocations, constructor calls, LINQ chains, delegate invocations

**Entry points**:
- `static void Main` / top-level statements
- ASP.NET `[HttpGet]`/`[HttpPost]` controller actions
- `[Route]` attribute handlers
- Minimal API `MapGet`/`MapPost` lambdas
- Background services (`IHostedService.ExecuteAsync`)

**Inheritance**: Same CHA approach as Java — `class : Base` and `class : IInterface` build the hierarchy.

### PHP

**Symbols extracted**: function declarations, class method declarations, closures assigned to variables

**Call sites**: function calls, method calls (`$obj->method()`), static calls (`Class::method()`)

**Entry points**:
- Files matching router patterns (`routes/*.php`)
- Laravel `Route::get()` / `Route::post()` registrations
- Symfony `#[Route]` attributes
- Controller class constructors
- Direct script execution (`index.php`)

**Autoloading**: Parse `composer.json` `autoload.psr-4` to map namespaces to directories.

### Ruby

**Symbols extracted**: `def` method definitions, class/module definitions, blocks assigned via `define_method`

**Call sites**: method calls, `send`/`public_send` (dynamic dispatch, 0.3 confidence)

**Entry points**:
- Rails `config/routes.rb` → controller action mapping
- Rake tasks (`task :name do`)
- Sidekiq workers (`perform` method)
- `bin/*` executable scripts
- Sinatra route blocks (`get '/' do`)

**Metaprogramming**: `method_missing`, `define_method`, and `send` produce `EdgeDispatch` edges at 0.3 confidence. Recall will be lower for Ruby than for Java/TS.

## CGO & Grammar Isolation

**Tree-sitter Go bindings**: `github.com/tree-sitter/go-tree-sitter` (official CGO bindings).

**Grammar isolation**: Each language grammar lives in its own Go package under `treesitter/grammars/<lang>/` to avoid CGO duplicate symbol errors. Each package exposes `Language() *sitter.Language`.

**Build tags**: `//go:build !no_treesitter` on tree-sitter analyzer packages. Users who only need govulncheck can build without CGO via `go build -tags no_treesitter`.

**Graceful degradation**: If tree-sitter analyzers are excluded via build tags or a grammar fails to load at runtime, the system falls back to the generic/ripgrep analyzer. Tree-sitter is an upgrade, not a hard dependency.

**Binary size**: Each grammar adds ~200-500KB. Total overhead for all seven grammars: ~2-3MB.

**CI requirements**: C compiler required when CGO is enabled (standard on most CI runners).

## Integration with VEX Pipeline

### Analyzer Registration

`buildAnalyzers()` in `vex.go` updated:

```
Detected "python"     → treesitter/python analyzer  → fallback to generic/ripgrep
Detected "javascript" → treesitter/javascript analyzer → fallback to generic/ripgrep
Detected "java"       → treesitter/java analyzer     → fallback to generic/ripgrep
Detected "csharp"     → treesitter/csharp analyzer   → fallback to generic/ripgrep
Detected "php"        → treesitter/php analyzer       → fallback to generic/ripgrep
Detected "ruby"       → treesitter/ruby analyzer      → fallback to generic/ripgrep
Detected "go"         → govulncheck (unchanged)
Detected "rust"       → cargo-scan (unchanged)
```

### Analyzer Flow

Each tree-sitter analyzer's `Analyze()` method:
1. Glob for source files matching the language
2. Parse all files via tree-sitter (concurrent, `runtime.NumCPU()` workers)
3. Extract symbols and imports via `LanguageExtractor`
4. Build the `Graph` (two-phase: symbol collection → edge resolution)
5. Discover entry points
6. Run BFS reachability from entry points to vulnerable symbols (`Finding.Symbols`)
7. Return `Result` with paths, confidence, and evidence

### Evidence Format

```
Reachable via: main() → handler() → process() → vulnlib.Execute()
  main.py:15 → handler.py:42 → process.py:88 → vulnlib (external)
Confidence: high (all direct calls)
```

### Timeout

Existing 120-second timeout per analysis applies. Tree-sitter parsing is fast (milliseconds per file); the budget is primarily for graph construction and BFS on large repos.

## Testing Strategy

### Unit Tests

Per language extractor (`treesitter/<lang>/extractor_test.go`):
- Symbol extraction from real source files
- Import resolution correctness
- Entry point discovery for each framework
- Call site extraction and edge creation

Shared core (`treesitter/graph_test.go`):
- Graph construction from symbols and edges
- BFS shortest path finding
- Cycle detection
- Confidence computation along paths
- Max depth / max paths limits

### Integration Tests

Fixture structure:

```
testdata/integration/
├── python-treesitter-reachable/
│   ├── source/
│   ├── sbom.cdx.json
│   ├── grype.json
│   └── expected.json
├── python-treesitter-not-reachable/
│   └── ...
├── javascript-treesitter-reachable/
│   └── ...
├── javascript-treesitter-not-reachable/
│   └── ...
├── java-treesitter-reachable/
│   └── ...
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

**Real OSS vulnerability data per language:**

| Language | Package | CVE | Vulnerable Symbol |
|----------|---------|-----|-------------------|
| Python | PyYAML | CVE-2020-1747 | `yaml.load()` (unsafe loader) |
| JS/TS | lodash | CVE-2021-23337 | `_.template()` (code injection) |
| Java | Log4j | CVE-2021-44228 | `Logger.info()` with JNDI lookup |
| C# | Newtonsoft.Json | CVE-2024-21907 | `JsonConvert.DeserializeObject()` with TypeNameHandling |
| PHP | Guzzle | CVE-2022-29248 | Cookie forwarding on redirect |
| Ruby | Nokogiri | CVE-2022-24836 | `Nokogiri::HTML()` with crafted input |

All integration tests must pass 100% with no tests skipped. Tree-sitter is bundled via CGO — no external tool dependency to skip on.

### LLM Judge Tests

Build tag: `//go:build llmjudge`

Scoring dimensions (threshold >= 8 for all):

| Dimension | What it measures |
|-----------|-----------------|
| `path_accuracy` | Are reported call paths real and verifiable in source? |
| `confidence_calibration` | Does confidence reflect actual certainty? |
| `evidence_quality` | Would a security engineer trust the evidence for VEX? |
| `false_positive_rate` | Are not-reachable cases correctly identified? |
| `symbol_resolution` | Are vulnerable symbols correctly matched to usage? |
| `overall_quality` | Would this pass CRA market surveillance authority review? |

## Implementation Order

Each phase is a complete vertical slice: extractor + analyzer + tests + integration fixtures. Each phase is independently shippable.

**Phase 1: Core infrastructure**
- Extended `Result` type with `Paths` and `CallPath`
- `treesitter/graph.go` — symbol graph, BFS reachability, confidence scoring
- `treesitter/parser.go` — concurrent file parsing orchestration
- `treesitter/extractor.go` — `LanguageExtractor` interface
- `treesitter/scope.go` — scope/symbol table tracking
- Grammar isolation packages under `treesitter/grammars/`
- Unit tests for graph, parser, scope

**Phase 2: Python**
- Python extractor: symbols, imports, call sites, assignment tracking
- Entry points: `__main__`, Flask, Django, FastAPI, Celery, Click
- Python analyzer package
- Integration tests: PyYAML CVE-2020-1747 reachable + not-reachable
- LLM judge test

**Phase 3: JavaScript / TypeScript**
- JS/TS extractor: symbols, imports/requires, call sites
- Entry points: Express, Nuxt, SvelteKit, Remix, NestJS, Next.js, Hono, Astro
- JS/TS analyzer package
- Integration tests: lodash CVE-2021-23337 reachable + not-reachable
- LLM judge test

**Phase 4: Java**
- Java extractor: symbols, imports, call sites, class hierarchy (CHA)
- Entry points: `main`, Spring controllers, servlets, scheduled jobs
- Java analyzer package
- Integration tests: Log4j CVE-2021-44228 reachable + not-reachable
- LLM judge test

**Phase 5: C#, PHP, Ruby**
- Same pattern for each: extractor + analyzer + integration tests + LLM judge
- C#: Newtonsoft.Json CVE-2024-21907
- PHP: Guzzle CVE-2022-29248
- Ruby: Nokogiri CVE-2022-24836

**Phase 6: Pipeline integration**
- Update `buildAnalyzers()` in `vex.go` to register tree-sitter analyzers with fallback
- Build tag support (`!no_treesitter`)
- End-to-end VEX integration tests with tree-sitter analyzers in filter chain
- Update Taskfile with CGO build commands
