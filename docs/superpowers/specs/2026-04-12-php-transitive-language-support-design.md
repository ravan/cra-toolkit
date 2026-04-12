# PHP Transitive Cross-Package Reachability Support

**Date**: 2026-04-12
**Status**: Approved
**Scope**: Add PHP to the transitive cross-package reachability analyzer

## Context

The transitive reachability system supports Python, JavaScript, Rust, and Ruby. PHP has a production-grade tree-sitter extractor (`treesitter/php/`) and grammar (`grammars/php/`), plus a working single-language analyzer (`reachability/php/`) that scores 9/10 on the LLM judge. The missing pieces are: the `LanguageSupport` subpackage, a Packagist fetcher, and wiring.

## Components

### 1. Language Support — `languages/php/php.go`

Implements the `LanguageSupport` interface.

**Identity**:
- `Name()` → `"php"`
- `Ecosystem()` → `"packagist"`
- `FileExtensions()` → `[".php"]`
- `Grammar()` → `grammars/php.Language()` (existing)
- `Extractor()` → returns a **normalizing wrapper** around the raw PHP extractor (see below)

#### Separator Normalization

PHP uses `\` for namespaces and `::` for method dispatch. The shared graph machinery (`resolveTarget`, scope lookup, BFS) uniformly uses `.` as the separator. This creates a mismatch: the PHP extractor emits symbol IDs like `App\Controllers\UserController::index` and call targets like `Utils::readLine`, but `resolveTarget` only splits on `.`.

**Solution**: The `Extractor()` method returns a thin wrapper (`normalizedExtractor`) around the raw PHP extractor that converts both `\` and `::` to `.` in all output:

- `ExtractSymbols`: Symbol IDs and QualifiedNames are normalized (`App.Controllers.UserController.index`)
- `ExtractCalls`: Both `From` and `To` edges are normalized (`Utils.readLine`)
- `ResolveImports`: Module paths are normalized (`GuzzleHttp.Psr7.Utils`)
- `FindEntryPoints`: Returned SymbolIDs are normalized

The raw PHP extractor (`treesitter/php/`) is unchanged — it remains used as-is by the single-language analyzer. Only the transitive LanguageSupport wraps it.

This approach mirrors how Ruby and Rust normalize `::` to `.` in `NormalizeImports`, but applied at the extractor level since PHP uses non-dot separators in both symbol IDs and call targets (not just imports).

**IsExportedSymbol**: Public methods, functions, and classes are exported. PHP has no underscore-prefix convention (unlike Python/Ruby), so visibility is determined solely by the extractor's `IsPublic` flag and symbol kind (`Function`, `Method`, `Class`).

**NormalizeImports**: Identity function — normalization is already handled by the wrapper extractor. The raw imports from the wrapper are already dot-separated.

**ModulePath**: Derives a dotted module path from a PHP source file:
- Strip conventional `src/` or `lib/` prefix (like Ruby strips `lib/`)
- Replace path separators with `.`
- Prepend the package name
- Example: `src/Psr7/Utils.php` under `guzzlehttp/psr7` → `guzzlehttp/psr7.Psr7.Utils`

**SymbolKey**: `modulePath + "." + symbolName` — same as all other languages.

**ResolveDottedTarget**: Standard scope lookup. Given prefix `Utils` and suffix `readLine`, look up `Utils` in scope imports to get `GuzzleHttp.Psr7.Utils`, return `GuzzleHttp.Psr7.Utils.readLine`.

**ResolveSelfCall**: PHP uses `$this->method()` and `self::method()`. The raw extractor emits call targets as `this::method` and `self::method`. After the normalizing wrapper converts `::` to `.`, these become `this.X` and `self.X`. Rewrite both to `ClassName.X` by extracting the class portion from the `from` symbol's qualified name (all dot-separated parts except the last). Requires `from` to have at least 3 parts (package.Class.method) to determine the class context. Targets not prefixed with `this.` or `self.` pass through unchanged — same pattern as Python/Ruby.

### 2. PHP ExportLister — `languages/php/exports.go`

Implements the optional `ExportLister` interface to enumerate the package's public API by following `composer.json`'s PSR-4 autoload mapping.

**Algorithm**:
1. Read `composer.json` from the source directory
2. Extract `autoload.psr-4` namespace-to-directory mappings
3. Walk only the autoloaded directories (skip `tests/`, `examples/`, `vendor/`)
4. Parse each `.php` file, extract symbols, filter to public
5. Build fully-qualified symbol keys using namespace prefix from PSR-4

**Fallback**: If no `composer.json` or no PSR-4 mapping exists, scan all `.php` files under `src/` then `lib/` then the root directory. This handles older PHP packages without PSR-4 autoloading.

### 3. Packagist Fetcher — `fetcher_packagist.go`

Implements the `Fetcher` interface for the Composer/Packagist ecosystem.

**Registry API**:
- Primary: `GET https://repo.packagist.org/p2/{vendor}/{package}.json` — returns version metadata including dist URLs, SHA256 digests, and dependency declarations
- The response contains a `packages` map with version entries, each having a `dist` object with `url`, `type` (zip), and `shasum` fields, plus a `require` map for dependencies

**Fetch**:
- Download the ZIP archive from the dist URL in the metadata
- Verify SHA256 digest against the registry-provided value and any SBOM-provided expected digest
- Unpack using the existing `unzip()` helper from `fetcher_zip.go`
- Composer ZIPs contain a single root directory (e.g., `guzzlehttp-psr7-abcdef/`); locate and use it as the source root
- Cache via the shared `Cache` mechanism

**Manifest**:
- Parse the `require` field from the registry metadata to extract runtime dependencies
- Filter out PHP platform requirements (`php`, `ext-*`) since they are not fetchable packages

**Package naming**: Composer uses `vendor/package` format (e.g., `guzzlehttp/psr7`). PURL scheme: `pkg:composer/vendor/package@version`.

### 4. Wiring

**`language.go`** — add to `LanguageFor`:
```go
case "php":
    return php.New(), nil
```

**`transitive_wire.go`** — add to `buildFetchers`:
```go
case "packagist":
    return map[string]transitive.Fetcher{"packagist": &transitive.PackagistFetcher{Cache: cache}}
```

**`language_test.go`** — add `"php"` to the `registered` slice in `TestLanguageSupport_Contract` and add PHP cases to `TestLanguageFor_RegisteredLanguages`.

### 5. Test Fixtures

**`testdata/integration/php-realworld-cross-package/`**: Positive case — rename/restructure from existing `php-realworld-transitive/` content. App calls `RequestParser::parse()` which calls `Utils::readLine()` from `guzzlehttp/psr7`.

**`testdata/integration/php-realworld-cross-package-safe/`**: Negative case — app uses `file_get_contents()` (PHP built-in) instead of Guzzle PSR7. Same SBOM declares `guzzlehttp/psr7` as a dependency, but no code path reaches the vulnerable symbols.

### 6. Tests

**`languages/php/php_test.go`**: Unit tests for all `LanguageSupport` methods — identity, `IsExportedSymbol`, `ModulePath`, `SymbolKey`, `NormalizeImports`, `ResolveDottedTarget`, `ResolveSelfCall`. Follows the exact pattern from `languages/ruby/ruby_test.go`.

**`languages/php/exports_test.go`**: Tests for PSR-4 based export enumeration, including fallback behavior when `composer.json` is absent.

**`fetcher_packagist_test.go`**: Tests using `httptest.Server` to mock Packagist API responses — happy path fetch, manifest parsing, digest mismatch, 404 handling. Follows `fetcher_rubygems_test.go` pattern.

**`pkg/vex/reachability/php/llm_judge_test.go`**: Add `TestLLMJudge_PHPTransitiveReachability` — constructs a `transitive.Analyzer` with `PackagistFetcher`, runs both positive and negative cross-package fixtures, scores on 6 CRA dimensions with threshold 6.

## What Does NOT Change

- PHP tree-sitter extractor (`treesitter/php/`) — already production-grade
- PHP grammar binding (`grammars/php/`) — already exists
- PHP single-language analyzer (`reachability/php/`) — already passes LLM judge at score 9
- Shared walker, hop, exports machinery — language-agnostic by design
