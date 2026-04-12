# Ruby Transitive Language Support — Design

Status: draft
Date: 2026-04-12
Supersedes: —
Depends on: `2026-04-11-transitive-language-support-foundation-design.md`, `2026-04-10-transitive-reachability-design.md`, `2026-04-11-rust-transitive-language-support-design.md`

## 1. Overview

Add production-grade Ruby support to the transitive cross-package reachability analyzer. Ruby follows the same integration pattern as Rust: one new language subpackage under `transitive/languages/ruby/`, one new fetcher (`rubygems`), one `LanguageFor` case, and one `buildFetchers` case. However, Ruby also requires targeted improvements to the existing tree-sitter Ruby extractor at `pkg/vex/reachability/treesitter/ruby/` — the current extractor flattens nested class/module scope, ignores mixins, skips `attr_*` generated methods, and does not use the `Scope` parameter during call resolution. These gaps compound across hops in the transitive system, so they are fixed as part of this spec rather than deferred.

The design goal is accuracy at production quality. The Ruby LLM judge score must match the Python, JavaScript, and Rust bar (≥ 9), and the analyzer must produce correct verdicts on real RubyGems dependency chains involving nested modules, mixins, and generated accessor methods — patterns that appear in virtually every non-trivial Ruby gem.

## 2. Goals and non-goals

### 2.1 Goals

- Full `LanguageSupport` implementation for Ruby, registered in `LanguageFor`.
- `RubyGemsFetcher` implementation of the `Fetcher` interface backed by the rubygems.org API, with double-unpack handling for `.gem` archives (tar containing `data.tar.gz` + `metadata.gz`), dependency extraction from the embedded gemspec, and on-disk cache parity with existing fetchers.
- `ExportLister` implementation that walks the gem's entry file (`lib/<gem_name>.rb`), follows its `require`/`require_relative` chain, and enumerates all non-private methods in loaded files as the gem's public API surface.
- `CrossFileStateExtractor` implementation that accumulates a mixin registry and class hierarchy across files during symbol extraction, enabling cross-file mixin method resolution during call extraction.
- Four targeted improvements to the existing Ruby tree-sitter extractor:
  1. Nested class/module scope tracking — `module Admin; class UsersController; def create` produces `Admin::UsersController::create`, not `UsersController::create`.
  2. Mixin resolution — `include`/`extend`/`prepend` statements are recorded; calls to mixin-provided methods resolve through the mixin chain.
  3. `attr_accessor`/`attr_reader`/`attr_writer` — generate synthetic getter/setter method symbols.
  4. Scope-aware call resolution — `ExtractCalls` consults the `Scope` parameter to resolve calls against imports.
- Parity with Python/JavaScript/Rust on regression gates: `task test`, `task test:transitive`, `task test:reachability:transitive:llmjudge`.
- A new LLM judge test case exercising a real-world Ruby vulnerability, scoring ≥ 9 against the judge.

### 2.2 Non-goals

- **Full metaprogramming support.** `define_method`, `method_missing`, `eval`/`instance_eval`/`class_eval`, `const_missing`, and `alias`/`alias_method` are not statically resolvable with tree-sitter. Documented as known limitations; `method_missing` detection continues to produce evidence notes as it does today.
- **Gemfile/Gemfile.lock parsing.** The transitive system resolves dependencies from the SBOM, not from Ruby's own lock file. The fetcher resolves per-gem dependencies from the embedded gemspec.
- **Conditional requires.** `require 'foo' if condition` — tree-sitter parses both branches. The analyzer treats all requires as active (conservative for reachability).
- **Refinements.** Ruby refinements (`using Module`) scope method overrides lexically. They are rare in gem source and not tracked; documented as a known limitation.
- **Dynamic constant assignment.** `Module::ClassName = SomeClass` — not statically analyzable.
- **Block/proc parameter methods.** Calls to methods on yielded block parameters are not tracked through the block boundary.

## 3. Architecture

### 3.1 Files touched

**New:**
- `pkg/vex/reachability/transitive/languages/ruby/ruby.go` — Ruby `LanguageSupport` implementation (11 required methods + `ExportLister` + `CrossFileStateExtractor`).
- `pkg/vex/reachability/transitive/languages/ruby/ruby_test.go` — unit tests.
- `pkg/vex/reachability/transitive/languages/ruby/exports.go` — entry-file require-chain walk, visibility filtering, export enumeration.
- `pkg/vex/reachability/transitive/languages/ruby/exports_test.go` — unit tests for export enumeration.
- `pkg/vex/reachability/transitive/fetcher_rubygems.go` — `RubyGemsFetcher`.
- `pkg/vex/reachability/transitive/fetcher_rubygems_test.go` — httptest-backed unit tests.

**Modified in `pkg/vex/reachability/treesitter/ruby/`:**
- `extractor.go` — nested scope tracking, mixin detection, `attr_*` generation, scope-aware call resolution. These are the four accuracy improvements described in section 4.

**Modified in `pkg/vex/reachability/transitive/`:**
- `language.go` — add `"ruby"` case to `LanguageFor`.
- `language_test.go` — add `"ruby"` to `TestLanguageFor_RegisteredLanguages`, extend contract test.

**Modified in `pkg/vex/`:**
- `transitive_wire.go` — add `"rubygems"` case to `buildFetchers`.

**Modified in `pkg/vex/reachability/treesitter/ruby/`:**
- `extractor_test.go` — extended tests for nested scope, mixins, `attr_*`, and scope-aware resolution.

**LLM judge:**
- New or modified `llm_judge_test.go` — add Ruby transitive judge case.

### 3.2 Interfaces implemented

Ruby implements both optional capability interfaces already defined in `language.go` (introduced by the Rust spec):

**`ExportLister`** — because Ruby's public API surface is determined by the require chain from the gem's entry file, not by parsing every `.rb` file in the gem.

**`CrossFileStateExtractor`** — because mixin modules are typically defined in one file and included in another. The mixin registry must be accumulated across files during Phase 1 (symbol extraction) and restored before Phase 3 (call extraction).

```go
// Ruby's cross-file state: mixin registry + class hierarchy.
type CrossFileState struct {
    // Mixins maps a fully-qualified class/module name to the list of
    // fully-qualified module names it includes/extends/prepends.
    // Key: "Admin::UsersController", Value: ["Cacheable", "Serializable"]
    Mixins map[string][]MixinEntry

    // Hierarchy maps a class name to its superclass name.
    // Key: "Admin::UsersController", Value: "ApplicationController"
    Hierarchy map[string]string

    // ModuleMethods maps a fully-qualified module name to its method names.
    // Key: "Cacheable", Value: ["cache_key", "expire_cache"]
    ModuleMethods map[string][]string
}

type MixinEntry struct {
    Module string   // Fully-qualified module name
    Kind   string   // "include", "extend", or "prepend"
}
```

`SnapshotState()` returns a deep copy of the current `CrossFileState`. `RestoreState(s)` merges the snapshot into the extractor's live state using append-unique semantics (identical to Rust's trait-impl snapshot pattern). `RunHop` snapshots after each per-file `ExtractSymbols` and replays all snapshots before the Phase 3 `ExtractCalls` loop.

## 4. Ruby extractor improvements

These changes are made to the existing extractor at `pkg/vex/reachability/treesitter/ruby/extractor.go`. They improve accuracy for both the standalone Ruby analyzer and the new transitive system.

### 4.1 Nested class/module scope tracking

**Problem.** The current extractor assigns flat qualified names: `module Admin; class UsersController; def create` produces `UsersController::create`. In the transitive system, hop 1 exports `Admin::UsersController::create` and hop 2 tries to match — the flat name fails.

**Fix.** Maintain a scope stack (`[]string`) during AST traversal. When entering a `class` or `module` node, push its name onto the stack. When leaving, pop. The qualified name of any symbol is `strings.Join(scopeStack, "::")`.

**Implementation.** The `walkProgram` function currently receives a flat `className` parameter. Replace this with a `scopeStack []string` parameter threaded through recursive calls. When a `class` or `module` node is encountered:

1. Extract the class/module name from the node. Handle both simple names (`class Foo`) and compound names (`class Admin::Foo`) by splitting on `::` and pushing each segment.
2. Push onto the scope stack.
3. Recurse into the body with the extended stack.
4. Pop after recursion returns.

Method symbols become `strings.Join(scopeStack, "::")` + `::` + `methodName`. Class and module symbols become the joined scope stack.

**Edge case: reopened classes.** Ruby allows reopening classes across files:
```ruby
# file1.rb
class Foo
  def bar; end
end

# file2.rb
class Foo
  def baz; end
end
```

Both `Foo::bar` and `Foo::baz` are valid. The scope stack approach handles this naturally — each file's traversal pushes `Foo` independently and produces correctly qualified names.

### 4.2 Mixin resolution (include/extend/prepend)

**Problem.** When a class includes a module, the module's methods become available on instances of the class. Without tracking this, calls to mixin-provided methods resolve to nowhere.

**Detection.** During `walkProgram`, when inside a class or module body, detect calls to `include`, `extend`, and `prepend`:

```ruby
class UsersController < ApplicationController
  include Cacheable
  extend ClassMethods
  prepend Auditable
end
```

These appear in the tree-sitter AST as `call` nodes where the method name is `include`/`extend`/`prepend` and the first argument is a constant. Extract the constant name (which may be compound: `ActiveModel::Serialization`).

**Recording.** Store mixin relationships in the extractor's `CrossFileState.Mixins` map, keyed by the fully-qualified class/module name (from the scope stack). Each entry records the mixin module name and the kind (`include`/`extend`/`prepend`).

**Resolution during `ExtractCalls`.** When a method call `obj.method_name` cannot be resolved directly:

1. Look up the receiver's type (if known from scope — see 4.4).
2. If the type is a class with mixins, check each mixin's `ModuleMethods` for `method_name`.
3. Follow Ruby's MRO: prepend modules first (in reverse order), then the class itself, then include modules (in reverse order), then the superclass chain.
4. If found, emit an `EdgeDirect` with confidence 0.7 (lower than a direct static call at 1.0, because mixin resolution depends on the class hierarchy being complete).

**Scope resolution for constants.** Mixin module names like `Cacheable` must be resolved against the current scope. A module `Cacheable` defined in the same namespace as the including class resolves to the fully-qualified name. If not found in the current namespace, fall back to the top-level constant. This mirrors Ruby's constant lookup algorithm (lexical scope first, then inheritance chain).

### 4.3 `attr_accessor`/`attr_reader`/`attr_writer`

**Problem.** These Ruby metaprogramming shortcuts generate getter and/or setter methods. A significant portion of a gem's public API surface consists of attribute accessors. Without synthesizing them, the analyzer misses method calls and export enumeration is incomplete.

**Detection.** During `walkProgram`, detect calls to `attr_accessor`, `attr_reader`, and `attr_writer` at class/module scope:

```ruby
class Config
  attr_accessor :host, :port
  attr_reader :frozen
  attr_writer :logger
end
```

These appear as `call` nodes (or `command_call` nodes for the no-parens form) with the method name being one of the three `attr_*` variants. Arguments are symbol literals (`:host`, `:port`).

**Synthesis.** For each detected attribute:

| Declaration | Generated symbols |
|---|---|
| `attr_reader :name` | `ClassName::name` (getter, `SymbolMethod`) |
| `attr_writer :name` | `ClassName::name=` (setter, `SymbolMethod`) |
| `attr_accessor :name` | Both getter and setter |

Generated symbols are marked with `IsEntryPoint: false`, `IsExternal: false`, and carry the file/line of the `attr_*` declaration. Their `Kind` is `SymbolMethod`.

**Impact on exports.** When `IsExportedSymbol` evaluates a generated accessor, it follows the same rules as any other method — if the name does not start with `_`, it is exported. This is correct: attribute accessors are part of a gem's public API unless they are declared after a `private` call.

**Private/protected tracking.** Ruby's `private` and `protected` are method calls that affect visibility of subsequently defined methods:

```ruby
class Foo
  def public_method; end

  private

  def private_method; end
  attr_reader :private_attr
end
```

Track the current visibility modifier during `walkProgram`. When a standalone `private`, `protected`, or `public` call is encountered (no arguments), update a visibility flag on the scope. All subsequently extracted methods and `attr_*` symbols inherit this visibility. When `private :method_name` is called with arguments, only the named method is affected.

Store visibility on `Symbol` by using a naming convention: symbols whose visibility is `private` or `protected` get `IsPublic = false`. `IsExportedSymbol` checks this field.

### 4.4 Scope-aware call resolution

**Problem.** The extractor's `ExtractCalls` receives a `Scope` parameter but ignores it. Call targets are constructed from literal receiver text (`"Nokogiri::HTML"`) rather than resolving through imports.

**Fix.** After constructing a call target from the AST, attempt resolution through the scope:

1. Split the target on `::` or `.` to get a prefix and suffix.
2. Look up the prefix in `scope.LookupImport(prefix)`.
3. If found, replace the prefix with the resolved module path.
4. If not found, leave the target as-is (it may be a local constant or a fully-qualified path).

**Example:**
```ruby
require 'nokogiri'
# scope: "nokogiri" → "Nokogiri" (via gem module map normalization)

Nokogiri::HTML(content)
# prefix: "Nokogiri", suffix: "HTML"
# scope lookup: "Nokogiri" → resolves to "nokogiri" gem's module
# resolved target: "nokogiri.Nokogiri.HTML" (dotted key form)
```

This enables cross-package matching: the callee side exports `nokogiri.Nokogiri.HTML` via `ListExports`, and the caller side now resolves `Nokogiri::HTML` to the same key.

## 5. Callee-side pipeline — `ruby.ListExports`

`ListExports` determines the public API surface of a Ruby gem. Its input is the unpacked gem source directory and the gem name; its output is the deduplicated set of dotted symbol keys representing every exported method, class, and module.

### 5.1 Stage 1 — Entry file discovery

The canonical entry point for a Ruby gem is `lib/<gem_name>.rb`. For gems whose name contains hyphens, the convention is to replace `-` with `/`: the gem `activerecord-import` has entry file `lib/activerecord/import.rb` (or sometimes `lib/activerecord-import.rb`). The discovery algorithm:

1. Try `lib/<gem_name>.rb` (exact match).
2. Try `lib/<gem_name_with_hyphens_replaced_by_slashes>.rb`.
3. Try `lib/<gem_name_with_hyphens_replaced_by_underscores>.rb`.
4. If none exist, fall back to enumerating all `.rb` files under `lib/` (degraded mode — documented as evidence note).

### 5.2 Stage 2 — Require chain walk

Starting from the entry file, recursively follow all `require` and `require_relative` statements to discover which source files the gem loads:

1. Parse the entry file.
2. Extract all `require` and `require_relative` calls.
3. For `require_relative`, resolve the path relative to the current file's directory, append `.rb` if no extension.
4. For `require` of local files (those that resolve to a path under `lib/`), resolve as `lib/<path>.rb`.
5. For `require` of external gems (paths that don't resolve locally), skip — those are external dependencies, not part of this gem's API.
6. Recurse into each resolved file, tracking visited files to prevent cycles.

The result is the set of files that are loaded when the gem is required — this is the gem's effective API surface.

### 5.3 Stage 3 — Export enumeration

For each file in the require chain, parse and extract symbols using the improved extractor (with nested scope tracking, mixin detection, and `attr_*` generation). Filter by visibility:

- **Exported:** All methods, classes, and modules that are not marked `private` or `protected`. In Ruby, the default visibility for class methods is `public`, so the absence of a `private`/`protected` modifier means exported.
- **Not exported:** Methods declared after a `private` or `protected` call, or explicitly made private via `private :method_name`.
- **Modules and classes:** Always exported (they are constants; Ruby has no private constant mechanism outside `private_constant`, which is rare and not tracked).

For each exported symbol with fully-qualified name `Admin::UsersController::create`, the dotted key is `gem_name.Admin.UsersController.create`. The gem name prefix ensures cross-gem uniqueness. The `::` to `.` conversion matches the dotted key scheme used by all languages.

### 5.4 Gem module map

The existing `gemModuleMap` in the standalone Ruby analyzer provides the CamelCase module name for common gems. This map is promoted to a shared location accessible by both the standalone analyzer and the `LanguageSupport` implementation. It is used in two places:

1. **`NormalizeImports`** — when a `require 'nokogiri'` produces an import with module `"nokogiri"`, the map provides the canonical Ruby constant name `"Nokogiri"` as an alias, enabling scope-based resolution of `Nokogiri::HTML` calls.
2. **`ListExports` key prefix** — the gem name (lowercase) is used as the key prefix, not the CamelCase module name. The normalization happens on the caller side via `NormalizeImports`.

For gems not in the map, the default assumption is that the module name matches the gem name with the first letter capitalized and underscores converted to CamelCase (`active_support` → `ActiveSupport`). This heuristic covers the RubyGems naming convention.

## 6. Caller-side pipeline

### 6.1 Identity methods

| Method | Return |
|---|---|
| `Name()` | `"ruby"` |
| `Ecosystem()` | `"rubygems"` |
| `FileExtensions()` | `[]string{".rb"}` |
| `Grammar()` | `grammars/ruby.Language()` (existing tree-sitter Ruby grammar) |
| `Extractor()` | `treesitter/ruby.New()` (improved extractor) |

### 6.2 `IsExportedSymbol`

```go
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
```

Ruby convention: underscore-prefixed methods are considered internal. The `IsPublic` field (set by the improved extractor based on `private`/`protected` tracking) is the primary gatekeeper.

### 6.3 `ModulePath`

Maps a source file to its dotted module path within the gem:

1. Compute the relative path from `sourceDir` to `file`.
2. Strip the `lib/` prefix if present.
3. Strip the `.rb` extension.
4. Replace `/` with `.`.
5. Prepend the `packageName` (gem name).

**Example:** `sourceDir=/tmp/cache/nokogiri-1.15.0`, `file=/tmp/cache/nokogiri-1.15.0/lib/nokogiri/html/document.rb`, `packageName=nokogiri` → `nokogiri.nokogiri.html.document`.

**Special cases:**
- Files outside `lib/` (e.g., `test/`, `spec/`, `bin/`) produce paths starting with the directory name, ensuring the generic prefix filter in `RunHop` can exclude them.
- The gem's entry file `lib/<gem_name>.rb` produces `gem_name.gem_name` — the repeated name is intentional and matches how Ruby's module hierarchy works.

### 6.4 `SymbolKey`

```go
func (l *Language) SymbolKey(modulePath, symbolName string) string {
    return modulePath + "." + symbolName
}
```

Dotted concatenation, consistent with all other languages.

### 6.5 `NormalizeImports`

Ruby's `require` statements produce import entries with the gem name as the module path. `NormalizeImports` enriches these with the CamelCase module mapping:

1. For each import, look up `import.Module` in the gem module map.
2. If found, set `import.Alias` to the CamelCase name (e.g., `"Nokogiri"`) so that scope resolution can match `Nokogiri::HTML` calls.
3. If not found, apply the default heuristic: capitalize first letter, convert underscores to CamelCase.
4. Replace `::` with `.` in both `Module` and `Alias` fields.

### 6.6 `ResolveDottedTarget`

Identical semantics to Python/JavaScript/Rust:

```go
func (l *Language) ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool) {
    resolved, ok := scope.LookupImport(prefix)
    if !ok {
        return "", false
    }
    return treesitter.SymbolID(resolved + "." + suffix), true
}
```

The scope contains entries like `"Nokogiri" → "nokogiri.Nokogiri"` (from `NormalizeImports`, mapping the constant name to the gem's module path), so `ResolveDottedTarget("Nokogiri", "HTML", scope)` returns `"nokogiri.Nokogiri.HTML"`, matching the export key produced by `ListExports`.

### 6.7 `ResolveSelfCall`

Ruby uses `self.method_name` for calls within a class. Rewriting follows the same pattern as Python and Rust:

```go
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

## 7. RubyGems fetcher

### 7.1 API contract

`RubyGemsFetcher` implements `Fetcher` with ecosystem key `"rubygems"`. Backing endpoints:

- **Metadata.** `GET https://rubygems.org/api/v2/rubygems/{name}/versions/{version}.json` returns JSON with `sha` (SHA-256 of the `.gem` file), `gem_uri` (download URL), and version metadata.
- **Download.** `GET https://rubygems.org/downloads/{name}-{version}.gem` (or use `gem_uri` from metadata).

Dependencies are extracted from the gemspec inside the `.gem` archive rather than from an API endpoint — this is the approach approved in the brainstorming phase and provides the most accurate version-specific dependency data.

### 7.2 `.gem` file format

A `.gem` file is a tar archive (not gzipped) containing:
- `metadata.gz` — gzipped YAML gemspec.
- `data.tar.gz` — gzipped tar of the gem's source files.
- `checksums.yaml.gz` — gzipped YAML with SHA checksums.

The double-unpack process:
1. Open the `.gem` as a tar reader.
2. Extract `metadata.gz` → gunzip → parse YAML for dependency information.
3. Extract `data.tar.gz` → gunzip + untar → source directory.

### 7.3 `Fetch` implementation

1. Call metadata endpoint to get `sha` (expected SHA-256) and `gem_uri`.
2. Check cache by digest string; short-circuit on hit.
3. Download the `.gem` file from `gem_uri`.
4. Verify SHA-256 matches the API-declared `sha` and the caller's `expectedDigest` if non-nil.
5. Double-unpack:
   a. Open `.gem` as tar → find `data.tar.gz` entry.
   b. Untar `data.tar.gz` into cache directory.
6. `FetchResult.SourceDir` points to the unpacked source root.

### 7.4 `Manifest` implementation

1. Download the `.gem` file (or use cached copy).
2. Extract `metadata.gz` from the tar.
3. Gunzip and parse the YAML gemspec.
4. Map `runtime_dependencies` to `PackageManifest.Dependencies`. Each dependency has a name and version requirement string.
5. Exclude `development_dependencies` — they are not part of the runtime dependency tree.

### 7.5 Error mapping

| Condition | Degradation reason |
|---|---|
| Network / non-200 on metadata | `ReasonManifestFetchFailed` |
| Network / non-200 on download | `ReasonTarballFetchFailed` |
| SHA-256 mismatch (API vs downloaded) | `ReasonDigestMismatch` |
| SHA-256 mismatch (caller-provided vs downloaded) | `ReasonDigestMismatch` (SBOM marker) |
| Missing `data.tar.gz` in `.gem` | Generic unpack error |
| Malformed gemspec YAML | `ReasonManifestFetchFailed` (sub-reason) |
| No `.rb` files in `data.tar.gz` | `SourceUnavailable = true` (native extension gem) |

## 8. Cross-file state — Mixin registry and class hierarchy

### 8.1 State accumulated during Phase 1

During `ExtractSymbols` for each file, the improved extractor records:

- **Mixin relationships:** For each `include`/`extend`/`prepend` call inside a class or module body, record `(fully_qualified_class, mixin_module, kind)`.
- **Class hierarchy:** For each `class Foo < Bar` declaration, record `(Foo, Bar)`.
- **Module methods:** For each method extracted inside a module (not a class), record `(fully_qualified_module, method_name)`.

These are stored in the `CrossFileState` structure (section 3.2).

### 8.2 State usage during Phase 3

During `ExtractCalls`, when a method call cannot be directly resolved:

1. Look up the receiver's class in `CrossFileState.Mixins`.
2. For each mixin (following Ruby MRO — prepend first, then include in reverse order):
   a. Check `CrossFileState.ModuleMethods[mixin_module]` for the called method.
   b. If found, emit an edge to `mixin_module::method_name` with confidence 0.7 and `EdgeDirect` kind.
3. If not found in mixins, check the superclass chain via `CrossFileState.Hierarchy`.
4. Walk up the hierarchy, checking each ancestor's methods and mixins.

### 8.3 Snapshot/restore semantics

`SnapshotState()` returns a deep copy of the current `CrossFileState`. Maps are copied, not shared — mutations after snapshot do not affect the snapshot.

`RestoreState(s)` merges the snapshot into live state:
- For `Mixins`: for each key, append any entries not already present (dedup by module name + kind).
- For `Hierarchy`: for each key, set if not already present (first-seen wins — class hierarchy should be consistent across files).
- For `ModuleMethods`: for each key, append any method names not already present.

This append-unique semantic matches Rust's trait-impl snapshot pattern and ensures that state from all files is available during Phase 3 regardless of file processing order.

## 9. Testing strategy

### 9.1 Extractor improvement tests — `treesitter/ruby/extractor_test.go`

Extend the existing test file with:

**Nested scope:**
- `TestExtractSymbols_NestedModule` — `module Admin; class UsersController; def create` → symbol ID `Admin::UsersController::create`.
- `TestExtractSymbols_DeeplyNested` — three levels of nesting: `module A; module B; class C; def d` → `A::B::C::d`.
- `TestExtractSymbols_CompoundClassName` — `class Admin::UsersController` → `Admin::UsersController`.
- `TestExtractSymbols_ReopenedClass` — same class opened in two files produces symbols in the same namespace.

**Mixins:**
- `TestExtractSymbols_IncludeModule` — `class Foo; include Bar` records mixin entry.
- `TestExtractSymbols_ExtendModule` — `class Foo; extend Bar` records mixin entry.
- `TestExtractSymbols_PrependModule` — `class Foo; prepend Bar` records mixin entry.
- `TestExtractCalls_MixinMethodResolution` — call to mixin-provided method resolves through include chain.

**attr_*:**
- `TestExtractSymbols_AttrAccessor` — `attr_accessor :name, :email` produces four method symbols (two getters + two setters).
- `TestExtractSymbols_AttrReader` — `attr_reader :id` produces one getter symbol.
- `TestExtractSymbols_AttrWriter` — `attr_writer :password` produces one setter symbol.
- `TestExtractSymbols_AttrWithPrivate` — `attr_accessor` after `private` produces non-public symbols.

**Scope-aware resolution:**
- `TestExtractCalls_ScopeResolution` — `require 'nokogiri'; Nokogiri::HTML(doc)` with scope containing `"Nokogiri" → "nokogiri"` produces resolved target.
- `TestExtractCalls_UnresolvedFallback` — call with unknown receiver falls back to literal text.

**Visibility:**
- `TestExtractSymbols_PrivateMethod` — method after `private` call has `IsPublic = false`.
- `TestExtractSymbols_ProtectedMethod` — method after `protected` call has `IsPublic = false`.
- `TestExtractSymbols_ExplicitPrivate` — `private :method_name` marks only that method as non-public.

### 9.2 Unit tests — `languages/ruby/`

**`ruby_test.go`:**
- `Name`, `Ecosystem`, `FileExtensions`, `Grammar`, `Extractor` return expected values.
- `IsExportedSymbol` — public method → true, private method → false, underscore-prefixed → false, class → true, nil → false.
- `ModulePath` — `lib/nokogiri/html/document.rb` → `nokogiri.nokogiri.html.document`; `spec/foo_spec.rb` → `spec.foo_spec`.
- `SymbolKey` — dotted concatenation.
- `NormalizeImports` — `"nokogiri"` gets alias `"Nokogiri"` from gem map; `"unknown_gem"` gets heuristic alias `"UnknownGem"`; `::` replaced with `.`.
- `ResolveDottedTarget` — scope lookup with substitution; miss returns false.
- `ResolveSelfCall` — `self.method` rewrites to `class.method`; non-self target passes through.

**`exports_test.go`:**
- Simple gem: `lib/foo.rb` with one public method → one exported key.
- Gem with nested requires: `lib/foo.rb` requires `lib/foo/bar.rb` → both files' public symbols exported.
- Gem with private methods: only public methods appear in exports.
- Gem with `attr_accessor`: generated methods appear in exports.
- Gem with `require` of external gem: external gem's files not walked.
- Gem with circular requires: no infinite loop.
- Gem with hyphenated name: entry file discovery tries all conventions.
- Gem with no entry file: falls back to all `lib/` files.

### 9.3 Unit tests — `fetcher_rubygems_test.go`

`httptest.Server` serves canned responses matching the rubygems.org API shape:

- Happy path: metadata → download → double-unpack → source dir populated → gemspec parsed → dependencies returned.
- SHA-256 mismatch between API-declared and downloaded body.
- SHA-256 mismatch between caller-supplied `expectedDigest` and downloaded body.
- 404 on metadata endpoint → `ReasonManifestFetchFailed`.
- 404 on download endpoint → `ReasonTarballFetchFailed`.
- `.gem` with no `data.tar.gz` → unpack error.
- Gemspec with runtime and development deps → only runtime deps in manifest.
- Cache hit short-circuits download.
- Native extension gem (no `.rb` files in source) → `SourceUnavailable = true`.

### 9.4 Contract tests — `language_test.go`

Extend `TestLanguageFor_RegisteredLanguages` with `{"ruby", "ruby", "rubygems"}`. Add `"ruby"` to `TestLanguageSupport_Contract`.

### 9.5 Wire tests

Add a case asserting `buildFetchers(cache, "rubygems")` returns a non-nil map containing the `"rubygems"` key wired to a `*RubyGemsFetcher`.

### 9.6 Integration test

Add one end-to-end case against a real RubyGems dependency chain. Fixture selection criteria:

- A real CVE against a Ruby gem, published to rubygems.org, with a known vulnerable version.
- The vulnerable code path is reachable through at least one intermediate dependency — the application does not depend directly on the vulnerable gem.
- The application source is small enough to commit as a test fixture.

Candidate: a vulnerability in `nokogiri` (which wraps `libxml2`) reachable through a Rails controller that parses user-supplied HTML. Nokogiri is the most common XML/HTML parsing gem in Ruby and has had multiple CVEs. The fixture would be a minimal Rails controller that calls `Nokogiri::HTML(params[:input])`, pulled in through a gem like `loofah` or `rails-html-sanitizer` that depends on `nokogiri`.

### 9.7 LLM judge test

Add one Ruby case to the LLM judge suite. Parallels Python, JavaScript, and Rust cases: small, deliberate, real-world-shaped application code that either does or does not reach a known-vulnerable symbol. Acceptance bar: score ≥ 9.

### 9.8 Regression gates

Every existing gate must still pass unchanged:
- `task test`
- `task test:transitive`
- `task test:reachability:transitive:llmjudge` — Python ≥ 9, JavaScript ≥ 9, Rust ≥ 9, Ruby ≥ 9 (new).

## 10. File-by-file implementation sequence

1. **Extractor improvements (nested scope)** — modify `treesitter/ruby/extractor.go` to use scope stack. Write tests first (TDD). Run `task test` to confirm no regressions in standalone Ruby analyzer.

2. **Extractor improvements (visibility tracking)** — add `private`/`protected`/`public` visibility state tracking. Set `IsPublic` on extracted symbols. Write tests first.

3. **Extractor improvements (attr_*)** — detect `attr_accessor`/`attr_reader`/`attr_writer` and synthesize method symbols. Write tests first.

4. **Extractor improvements (mixin detection)** — detect `include`/`extend`/`prepend`, record in `CrossFileState`. Write tests first.

5. **Extractor improvements (scope-aware call resolution)** — modify `ExtractCalls` to consult `Scope` parameter. Write tests first.

6. **Cross-file state** — implement `SnapshotState`/`RestoreState` on the Ruby extractor. Write tests for snapshot/restore merge semantics.

7. **Language subpackage** — create `transitive/languages/ruby/ruby.go` implementing all 11 `LanguageSupport` methods. Write `ruby_test.go` (TDD).

8. **Export enumeration** — create `transitive/languages/ruby/exports.go` implementing `ListExports`. Write `exports_test.go` (TDD).

9. **Registration** — add `"ruby"` case to `LanguageFor` in `language.go`. Extend `language_test.go`.

10. **RubyGems fetcher** — create `transitive/fetcher_rubygems.go`. Write `fetcher_rubygems_test.go` (TDD).

11. **Wire** — add `"rubygems"` case to `buildFetchers` in `transitive_wire.go`.

12. **Integration test** — select fixture, commit source tree, write integration test.

13. **LLM judge test** — add Ruby case. Iterate on fixture until score ≥ 9.

14. **Full gate suite** — `task test`, `task test:transitive`, `task test:reachability:transitive:llmjudge`, `task quality`. All green.

## 11. Edge cases and known limitations

- **Metaprogramming beyond attr_*.** `define_method`, `method_missing`, `eval` variants, `alias`/`alias_method` are not statically analyzable via tree-sitter. `method_missing` presence is detected and noted in evidence. Other dynamic method generation is invisible.
- **Refinements.** `using Module` scopes method overrides lexically — not tracked.
- **Monkey patching.** Ruby allows reopening any class including stdlib classes. Class reopening within the analyzed source is handled (nested scope produces correct qualified names); monkey patching of external classes is not attributed to the patching gem's API surface.
- **Native extensions.** Gems with C extensions (e.g., `nokogiri` wrapping `libxml2`) have their C code invisible to tree-sitter. Only the Ruby wrapper layer is analyzed. If a gem ships no `.rb` files at all, `SourceUnavailable = true` is returned.
- **Conditional method definitions.** `if RUBY_VERSION >= '3.0'; def foo; end; end` — the method is extracted regardless of the condition (conservative).
- **Singleton methods on specific objects.** `def obj.method` — currently extracted as `singleton_method` but not correctly scoped to the object. Low-impact; rare in gem public APIs.
- **Mixin resolution accuracy.** Mixin method resolution depends on all relevant files being parsed before call extraction. The `CrossFileStateExtractor` mechanism ensures this for files within a single package; cross-package mixin resolution (gem A includes a module from gem B) requires the intermediate hop to export the module's methods, which `ListExports` handles.
- **Gem naming edge cases.** Gems with very unusual naming conventions (e.g., `ruby-openid` mapping to `OpenID` module) may not resolve via the heuristic. The gem module map covers the most common cases; others fall back to the capitalization heuristic.

## 12. Acceptance criteria

The work is complete when:

1. All files in section 3.1 are created or modified as specified.
2. All extractor improvements in section 4 are implemented and tested.
3. `task test` passes.
4. `task test:transitive` passes.
5. `task test:reachability:transitive:llmjudge` passes with scores ≥ 9 for Python, JavaScript, Rust, and Ruby.
6. `task quality` passes (lint + format clean).
7. The integration test produces a `Reachable: true` verdict with a stitched call path through at least one intermediate gem on a real RubyGems vulnerability fixture.
8. Adding a further new language still requires only: one subpackage under `languages/<lang>/`, one `LanguageFor` case, and one `buildFetchers` case if the ecosystem is new.
