# Java & C# Transitive Cross-Package Reachability Support

**Date**: 2026-04-12
**Status**: Draft
**Scope**: Add Java and C# to the transitive cross-package reachability analyzer, including Maven and NuGet fetchers with SCM clone fallback

## Context

The transitive reachability system supports Python, JavaScript, Rust, Ruby, and PHP. Production-grade tree-sitter extractors already exist for both Java (`treesitter/java/`) and C# (`treesitter/csharp/`), and both grammars are vendored in `go.mod`. The Java extractor includes CHA (Class Hierarchy Analysis) for interface dispatch resolution with cross-file state snapshot/restore. The C# extractor handles both block-scoped and file-scoped namespaces, attribute-based entry points, and minimal API patterns.

The missing pieces are: `LanguageSupport` subpackages, Maven and NuGet fetchers, a shared SCM clone fallback utility, and wiring.

### Key Design Decisions

- **Source-first analysis**: Use tree-sitter on source code, not bytecode. Maven Central's `-sources.jar` and SCM clone provide source for Java. NuGet relies primarily on SCM clone since `.nupkg` rarely contains source.
- **SCM clone fallback**: Both fetchers fall back to cloning from the repository URL declared in package metadata (POM `<scm>`, `.nuspec` `repository`) when source archives are unavailable.
- **Overload collapsing**: Method overloads are treated as a single symbol at the name level. Symbol keys use `modulePath.methodName` without type signatures. This matches how vulnerability advisories reference affected functions and is consistent with the granularity of all existing languages.
- **Separate fetchers, shared SCM helper**: `MavenFetcher` and `NuGetFetcher` are independent fetcher implementations. SCM clone logic lives in a shared `scm_clone.go` utility both can call.

## Components

### 1. Language Support — `languages/java/java.go`

Implements the `LanguageSupport` interface.

**Identity**:
- `Name()` → `"java"`
- `Ecosystem()` → `"maven"`
- `FileExtensions()` → `[".java"]`
- `Grammar()` → `grammars/java.Language()` (existing)
- `Extractor()` → returns the existing `treesitter/java.Extractor`

**IsExportedSymbol**: `sym.IsPublic && (kind == Function || kind == Method || kind == Class)`. Java's visibility model is explicit — public means exported. No naming convention filtering needed.

**ModulePath**: Derives a dotted module path from the Java `package` declaration in the source file. The extractor already parses `package` statements and stores them on symbols via `classPackage`. The module path becomes `packageName.javaPackage.ClassName`.

Example: For Maven artifact `com.google.code.gson:gson`, a file declaring `package com.google.gson;` containing class `Gson` produces module path `gson.com.google.gson.Gson`.

The Maven `groupId:artifactId` is decoupled from Java package names. Rather than heuristic mapping, the actual `package` declaration in each `.java` file is authoritative. This is the same approach PHP uses — read the code to discover the namespace.

**SymbolKey**: `modulePath + "." + symbolName` — same as all other languages. Example: `gson.com.google.gson.Gson.fromJson`.

**NormalizeImports**: Identity function. Java imports are already fully-qualified dotted paths (`import org.apache.logging.log4j.Logger`). No separator conversion needed.

**ResolveDottedTarget**: Standard scope lookup. Given prefix `Logger` and suffix `getLogger`, look up `Logger` in scope imports to find `org.apache.logging.log4j.Logger`, return `org.apache.logging.log4j.Logger.getLogger`.

**ResolveSelfCall**: Rewrite `this.X` to `ClassName.X`. Extract class context from the `from` symbol's qualified name (all dot-separated parts except the last). Targets not prefixed with `this.` pass through unchanged.

**CrossFileStateExtractor**: Java's extractor already implements CHA snapshot/restore (the `CHASnapshot` struct captures interface-to-implementor mappings and parameter type information). The language plugin delegates `SnapshotState()` and `RestoreState()` directly to the underlying extractor. This enables cross-file interface dispatch resolution — when a method in package A takes an interface parameter and package B provides the concrete implementor, CHA resolves the dispatch across file boundaries.

### 2. Java ExportLister — `languages/java/exports.go`

Implements the optional `ExportLister` interface to enumerate the package's public API. Java's export surface is determined by public classes and their public methods.

**Algorithm**:
1. Walk all `.java` files in the source directory
2. Parse each file with tree-sitter, extract symbols
3. Read `package` declarations to build the namespace map
4. Filter to public symbols via `IsExportedSymbol`
5. Build fully-qualified symbol keys using the actual Java package path
6. Skip test directories (`src/test/`, `**/test/`, `**/tests/`)
7. Return sorted, deduplicated list

**Maven source layout convention**: Java projects conventionally place production source under `src/main/java/`. The export lister scans from this directory when it exists, falling back to the source root. Test sources under `src/test/java/` are always excluded.

### 3. Language Support — `languages/csharp/csharp.go`

Implements the `LanguageSupport` interface.

**Identity**:
- `Name()` → `"csharp"`
- `Ecosystem()` → `"nuget"`
- `FileExtensions()` → `[".cs"]`
- `Grammar()` → `grammars/csharp.Language()` (existing)
- `Extractor()` → returns the existing `treesitter/csharp.Extractor`

**IsExportedSymbol**: `sym.IsPublic && (kind == Function || kind == Method || kind == Class)`. C#'s `public` modifier is explicit. Internal/private symbols are excluded.

**ModulePath**: Reads the `namespace` declaration from the source file. Handles both block-scoped (`namespace Foo.Bar { }`) and file-scoped (`namespace Foo.Bar;`) syntax. The module path becomes `packageName.namespace.ClassName`.

Example: For NuGet package `Newtonsoft.Json`, a file declaring `namespace Newtonsoft.Json` containing class `JsonConvert` produces module path `Newtonsoft.Json.Newtonsoft.Json.JsonConvert`.

Like Java, C# namespace declarations are authoritative — no heuristic mapping from NuGet package ID to C# namespace is needed.

**SymbolKey**: `modulePath + "." + symbolName`. Example: `Newtonsoft.Json.Newtonsoft.Json.JsonConvert.DeserializeObject`.

**NormalizeImports**: Identity function. C# `using` directives are already dotted paths (`using System.Text.Json`). No separator conversion needed.

**ResolveDottedTarget**: Standard scope lookup. Given prefix `JsonConvert` and suffix `DeserializeObject`, look up `JsonConvert` in scope imports, return the fully-qualified form.

**ResolveSelfCall**: Rewrite `this.X` to `ClassName.X`. Same pattern as Java — extract class context from the `from` symbol's qualified name.

### 4. C# ExportLister — `languages/csharp/exports.go`

Implements the optional `ExportLister` interface.

**Algorithm**:
1. Walk all `.cs` files in the source directory
2. Parse each file, extract symbols, read namespace declarations
3. Filter to public symbols
4. Build fully-qualified keys using the actual C# namespace
5. Skip test directories, `obj/`, `bin/`
6. Return sorted, deduplicated list

**NuGet source layout**: .NET projects have no single convention like Java's `src/main/`. Source may be at the root, under `src/`, or under project-specific directories. The export lister scans from the source root, excluding `obj/`, `bin/`, and directories matching common test patterns (`*Test*`, `*Tests*`, `*Spec*`).

### 5. SCM Clone Utility — `scm_clone.go`

A shared helper for cloning package source from a Git repository URL when source archives are unavailable. Both `MavenFetcher` and `NuGetFetcher` call this as a fallback.

**Interface**:
```go
type SCMCloneResult struct {
    SourceDir string
    Digest    Digest
}

func scmClone(ctx context.Context, repoURL, version string, cache *Cache) (SCMCloneResult, error)
```

**Algorithm**:
1. Normalize the repository URL (strip `.git` suffix, handle `git://` → `https://` conversion, handle common hosting patterns)
2. Compute a cache key from `repoURL + "@" + version`
3. Check cache — return early if already cloned
4. Execute `git clone --depth 1 --branch <tag> <url> <tmpdir>` via `os/exec`
5. Tag matching strategy (try in order):
   - Exact version: `v1.2.3`, `1.2.3`
   - Common prefixes: `release-1.2.3`, `release/1.2.3`
   - If no tag matches, clone default branch and log a degradation warning
6. Remove `.git/` directory from the clone to save cache space
7. Hash the directory contents for the cache digest
8. Store in cache, return source directory

**Error handling**: If the repository URL is missing, empty, or the clone fails (private repo, deleted repo, invalid tag), the caller receives a descriptive error. The fetcher translates this to the appropriate `Reason*` degradation.

**Security**: Repository URLs are validated before execution. Only `https://` and `git://` schemes are accepted. SSH URLs (`git@`) are rejected to avoid credential prompts in automated pipelines. Path traversal in clone output is guarded by the cache's own path sanitization.

### 6. Maven Fetcher — `fetcher_maven.go`

Implements the `Fetcher` interface for the Maven Central ecosystem.

**Registry API**:
- Metadata: `GET https://repo1.maven.org/maven2/<groupPath>/<artifactId>/<version>/<artifactId>-<version>.pom` — POM XML containing dependency declarations and SCM metadata
- Sources JAR: `GET https://repo1.maven.org/maven2/<groupPath>/<artifactId>/<version>/<artifactId>-<version>-sources.jar`
- SHA-1 checksums: append `.sha1` to any artifact URL

Where `<groupPath>` is the `groupId` with dots replaced by slashes (e.g., `com.google.code.gson` → `com/google/code/gson`).

**Struct**:
```go
type MavenFetcher struct {
    BaseURL    string       // defaults to https://repo1.maven.org/maven2
    HTTPClient *http.Client
    Cache      *Cache
}
```

**Ecosystem**: `"maven"`

**Manifest**:
1. Fetch the POM XML for `(groupId:artifactId, version)`
   - The `name` parameter uses Maven's `groupId:artifactId` format (e.g., `com.google.code.gson:gson`)
   - Split on `:` to extract groupId and artifactId
2. Parse `<dependencies>` section, filter to `<scope>compile</scope>` and `<scope>runtime</scope>` (exclude `test`, `provided`, `system`)
3. Dependency names use the same `groupId:artifactId` format for consistency with SBOM component names
4. Return `PackageManifest{Dependencies: deps}`

**Fetch**:
1. Parse `name` to extract groupId and artifactId
2. Compute the `-sources.jar` URL
3. Check cache by digest
4. Attempt to download the sources JAR
5. If sources JAR exists:
   - Download, verify SHA-1 checksum
   - Verify against expectedDigest if provided
   - Unpack JAR (which is a ZIP) using `unzip()`
   - Store in cache, return source directory
6. If sources JAR returns 404:
   - Parse the POM to extract `<scm><url>` and `<scm><tag>`
   - Call `scmClone(ctx, scmURL, version, cache)`
   - If SCM clone succeeds: locate Java source directory (`src/main/java/` or root), return it
   - If SCM clone fails: return error with `ReasonSourceUnavailable`

**Maven coordinate handling**: SBOMs encode Maven packages with PURLs like `pkg:maven/com.google.code.gson/gson@2.10.1`, but CycloneDX stores just the artifactId as the component `name` (e.g., `"name": "gson"`). The groupId is only available in the PURL. Since the Maven fetcher needs the full `groupId:artifactId` coordinate, `buildTransitiveSummary` must parse the PURL for Maven components to extract the groupId and construct `Package.Name` as `groupId:artifactId` (e.g., `com.google.code.gson:gson`). This is a Maven-specific PURL parsing step — all other ecosystems continue using the component name directly.

### 7. NuGet Fetcher — `fetcher_nuget.go`

Implements the `Fetcher` interface for the NuGet ecosystem.

**Registry API**:
- Package metadata: `GET https://api.nuget.org/v3/registration5-gz-semver2/<lowercaseId>/index.json` — registration index with version metadata
- Package content: `GET https://api.nuget.org/v3-flatcontainer/<lowercaseId>/<version>/<lowercaseId>.<version>.nupkg` — the package archive
- Nuspec: `GET https://api.nuget.org/v3-flatcontainer/<lowercaseId>/<version>/<lowercaseId>.nuspec` — package metadata XML

NuGet package IDs are case-insensitive. All API URLs use lowercase.

**Struct**:
```go
type NuGetFetcher struct {
    BaseURL    string       // defaults to https://api.nuget.org
    HTTPClient *http.Client
    Cache      *Cache
}
```

**Ecosystem**: `"nuget"`

**Manifest**:
1. Fetch the `.nuspec` file for `(name, version)`
2. Parse `<dependencies>` section from the XML
3. Handle target framework groups — collect dependencies from all framework groups (union), since we're analyzing source, not a specific runtime target
4. Dependency names are NuGet package IDs
5. Return `PackageManifest{Dependencies: deps}`

**Fetch**:
1. Attempt to download the `.nupkg` file
2. Check if it contains source files:
   - Unpack the ZIP, look for `.cs` files outside `obj/` and `bin/`
   - Some packages (especially source-only packages) include C# source directly
3. If source files found in `.nupkg`:
   - Verify SHA-512 hash from the catalog (NuGet uses SHA-512)
   - Store in cache, return source directory
4. If no source in `.nupkg` (the common case):
   - Fetch the `.nuspec` to extract `<repository url="..." />` and `<repository commit="..." />`
   - Call `scmClone(ctx, repoURL, version, cache)`
   - If SCM clone succeeds: locate C# source directory, return it
   - If SCM clone fails: return error with `ReasonSourceUnavailable`

**NuGet coordinate handling**: SBOMs encode NuGet packages with PURLs like `pkg:nuget/Newtonsoft.Json@13.0.3`. The package name maps directly — no groupId/artifactId split needed.

### 8. Wiring — `language.go` and `transitive_wire.go`

**LanguageFor factory** (`language.go`):
```go
case "java":
    return java.New(), nil
case "csharp", "c#", "cs":
    return csharp.New(), nil
```

**buildFetchers switch** (`transitive_wire.go`):
```go
case "maven":
    return map[string]transitive.Fetcher{"maven": &transitive.MavenFetcher{Cache: cache}}
case "nuget":
    return map[string]transitive.Fetcher{"nuget": &transitive.NuGetFetcher{Cache: cache}}
```

**buildTransitiveSummary PURL prefixes**: Add `"pkg:maven/"` and `"pkg:nuget/"` ecosystem matching.

### 9. Testing Strategy

**Unit tests per component** (following TDD — tests first):

- `languages/java/java_test.go` — LanguageSupport method tests: ModulePath, SymbolKey, IsExportedSymbol, ResolveDottedTarget, ResolveSelfCall, NormalizeImports
- `languages/java/exports_test.go` — ExportLister tests with fixture Java source trees
- `languages/csharp/csharp_test.go` — same scope as Java
- `languages/csharp/exports_test.go` — same scope as Java
- `fetcher_maven_test.go` — httptest server, POM parsing, sources JAR download, SCM fallback path
- `fetcher_nuget_test.go` — httptest server, nuspec parsing, nupkg source detection, SCM fallback path
- `scm_clone_test.go` — tag matching, URL normalization, cache integration

**Integration tests** (real-world packages):

- Java: Use a well-known Maven package (e.g., `com.google.code.gson:gson`) with a known vulnerability. Verify transitive call graph chaining from application code through dependency chain to vulnerable function.
- C#: Use a well-known NuGet package (e.g., `Newtonsoft.Json`) with a known vulnerability. Same verification.

**LLM judge tests**: Following the established pattern, add LLM judge tests that evaluate the quality and accuracy of the transitive reachability analysis for Java and C# against real-world findings.

### 10. Degradation Modes

The following degradation reasons apply to Java and C# in addition to the existing set:

| Reason | When | Effect |
|--------|------|--------|
| `source_unavailable` | No sources JAR and SCM clone both fail | Package treated as leaf; path broken at this hop |
| `manifest_fetch_failed` | POM/nuspec fetch fails | Package has no dependency edges in graph |
| `tarball_fetch_failed` | Sources JAR or nupkg download fails | Falls through to SCM clone |
| `scm_clone_failed` | Git clone fails (private repo, no matching tag) | If no other source, `source_unavailable` |
| `path_broken` | No callers found at a hop | Walk terminates early for this path |

## File Inventory

| File | Purpose | New/Modified |
|------|---------|-------------|
| `languages/java/java.go` | Java LanguageSupport implementation | New |
| `languages/java/exports.go` | Java ExportLister | New |
| `languages/java/java_test.go` | Java language plugin tests | New |
| `languages/java/exports_test.go` | Java export tests | New |
| `languages/csharp/csharp.go` | C# LanguageSupport implementation | New |
| `languages/csharp/exports.go` | C# ExportLister | New |
| `languages/csharp/csharp_test.go` | C# language plugin tests | New |
| `languages/csharp/exports_test.go` | C# export tests | New |
| `fetcher_maven.go` | Maven Central fetcher | New |
| `fetcher_maven_test.go` | Maven fetcher tests | New |
| `fetcher_nuget.go` | NuGet fetcher | New |
| `fetcher_nuget_test.go` | NuGet fetcher tests | New |
| `scm_clone.go` | Shared SCM clone utility | New |
| `scm_clone_test.go` | SCM clone tests | New |
| `language.go` | Add java/csharp cases to LanguageFor | Modified |
| `transitive_wire.go` | Add maven/nuget cases to buildFetchers | Modified |

All new language files under `pkg/vex/reachability/transitive/languages/`. All new fetcher files under `pkg/vex/reachability/transitive/`.
