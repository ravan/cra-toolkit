# Transitive Reachability Analysis Design

## Overview

Extend the CRA VEX reachability engine to determine function-level reachability of vulnerabilities that sit inside **transitive dependencies** for Python and JavaScript projects, producing VEX evidence that stitches a continuous call path from the application, through one or more intermediate dependency packages, to the vulnerable function.

The current tree-sitter reachability analyzers (`pkg/vex/reachability/python/`, `pkg/vex/reachability/javascript/`, and the five other non-Go analyzers) can only confirm reachability to symbols in **direct** dependencies. When the vulnerable function is inside a transitive dependency and the application reaches it through intermediate library code the user does not own, the current analyzer's call graph terminates at the first external symbol because dependency source code is never parsed. Go is the exception: its analyzer delegates to `govulncheck`, which performs whole-program call graph analysis across direct and transitive dependencies natively.

This design closes the transitive gap for Python and JavaScript in v1, with an architecture that is language-agnostic in its orchestration layer so Java, C#, PHP, Ruby, and Rust can follow later as pure extractor + fetcher work.

## Goals

1. Resolve the transitive dependency reachability gap for Python and JavaScript using the existing tree-sitter extractors.
2. Produce structured, stitched call-path evidence (`app.fn → direct_dep.fn → transitive_dep.fn → CVE_fn`) for VEX justifications, matching the existing `reachability.CallPath` shape.
3. Operate hermetically: no requirement for a populated virtualenv, `node_modules`, or any local build system. Same SBOM in, same result out, on a laptop or on a CI runner that only has network access.
4. Verify every fetched package against SBOM-declared digests as a supply-chain integrity check.
5. Degrade explicitly: when source is unavailable, SBOM edges are missing, or bounds are exceeded, emit evidence that says so rather than silently dropping findings.
6. Keep the orchestration language-agnostic so the other five non-Go languages follow additively.

## Non-goals (v1)

1. Fetching from private package registries (internal PyPI, GitHub Packages, Artifactory, etc.). A follow-on adds authentication and registry-URL overrides.
2. LLM-assisted narrowing of the vulnerable symbol set. v1 uses the conservative "all exported symbols of the vulnerable package" strategy. Strategy is documented in "Path forward" below.
3. Support for binary-only Python packages (numpy, cryptography, pydantic-core). v1 marks these `source_unavailable` and treats calls into them as opaque sinks.
4. Support for languages other than Python and JavaScript. The architecture is explicitly designed to extend, and the path forward is documented, but v1 ships only two languages.
5. Replacing the existing per-language analyzers. Transitive analysis runs *before* the current "direct only" fallback and only when the SBOM contains a finding whose affected package is reachable (by dependency graph) from the application root. The existing behavior remains intact for every other case.

## Background: prior art

A short survey informed the choice not to reuse existing tools for acquisition or analysis:

- **jelly** (cs-au-dk/jelly, Aarhus research group). Performs cross-library call graph construction for JavaScript. Requires a pre-populated `node_modules/` on disk. No lockfile reading, no fetching, no version verification. Packages with native addons are treated as "unknown code" — a silent soundness hole. Not SBOM-aware.
- **Pysa** (facebook/pyre-check). Python taint analysis built on Pyre. Requires an active virtualenv; reuses Python's `site.getsitepackages()` to locate packages and relies on typeshed `.pyi` stubs for anything untyped. Binary-only wheels degrade to user-written `.pysa` models. Not SBOM-aware.

Both tools delegate dependency acquisition to the ecosystem's native package manager. This is workable for a developer iterating on their project, but wrong for a CRA compliance workflow that runs against an SBOM produced by some upstream build pipeline on a CI runner that has no project checkout. We need "what you analyzed equals what you shipped," verifiable from the SBOM; that means we cannot rely on whatever happens to be in a venv.

The chosen approach therefore acquires dependency source by fetching tarballs directly from the public registries (PyPI JSON API, npm registry), keyed by the SBOM's version pins and verified against SBOM-declared digests. This sidesteps package managers entirely.

## Architecture

### At a glance

```
[ SBOM + Finding ]
        │
        ▼
 dependency-graph builder  ─────► registry manifests (PyPI JSON, npm registry)
        │
        ▼
 pruned subgraph from CVE package V back toward application
        │
        ▼
 pairwise reverse walker  ◄───── source fetcher (tarballs, content-addressed cache)
        │                             │
        │                             ▼
        │                     per-hop extractor
        │                     (existing tree-sitter)
        │                             │
        ▼                             ▼
 short-circuit verdict + stitched call path evidence
        │
        ▼
 existing VEX statement builder + reachability filter
```

The new subsystem is a thin orchestrator around components we already have. Tree-sitter extractors, the forward reachability analyzer, and the VEX evidence machinery all remain unchanged — they are invoked with additional source roots and enriched target sets.

### Module layout

New Go package: `pkg/vex/reachability/transitive/`.

| File | Purpose |
|---|---|
| `transitive.go` | Top-level `Analyzer`. Driver entry point, bounds enforcement, result aggregation across SBOM paths. |
| `sbom_graph.go` | Parse SBOM for the version-pinned package list; consult registry manifests to build the dependency graph; prune to the reverse-reachable set from the vulnerable package V. |
| `fetcher.go` | Language-agnostic `Fetcher` interface: given `(ecosystem, name, version, digest)` return a local directory containing readable source, or a source-unavailable error. |
| `fetcher_pypi.go` | PyPI JSON API lookup → prefer sdist (`.tar.gz`) → fall back to pure-Python wheel (`py3-none-any`) → record `source_unavailable` if neither exists. |
| `fetcher_npm.go` | npm registry tarball fetch and unpack. Always raw source; no fallback needed. |
| `walker.go` | Pairwise reverse-walk driver. For each SBOM path to V, walks hop by hop, invokes `hop.go`, applies the short-circuit rule, collects per-hop evidence. |
| `hop.go` | Per-hop primitive. Given a source root and a set of target symbols, uses the existing tree-sitter extractor and `FindReachablePaths` to return the set of caller symbols that reach any target. |
| `evidence.go` | Stitch per-hop call paths into a single continuous `reachability.CallPath` for VEX. |
| `cache.go` | Content-addressed cache under `~/.cache/cra-toolkit/pkgs/<sha256>/`. Shared across paths and findings. |
| `bounds.go` | Configuration and enforcement of walk depth, path count, target set fan-out, and timeouts. |
| `transitive_test.go` | Unit tests against golden fixtures. |

The per-language analyzers at `pkg/vex/reachability/python/python.go` and `pkg/vex/reachability/javascript/javascript.go` each receive a small change: they consult the new `transitive.Analyzer` before falling back to the current "direct-only" behavior. The consult is gated on the presence of an SBOM (already required by the toolkit facade) and on the finding's affected package being present in the dependency graph's reverse-reachable set.

## Algorithm

### Inputs

- An SBOM (CycloneDX JSON or SPDX JSON) as already parsed by `pkg/formats/`.
- A single `formats.Finding` carrying the affected package purl and CVE identifier.
- The application source directory for forward analysis.
- A `transitive.Config` with bounds and cache directory.

### Stages

**Stage A — Build the pruned dependency subgraph.**
Read the SBOM to obtain the version-pinned `(name, version)` set. The "application root" is the SBOM's top-level component: in CycloneDX this is `metadata.component`; in SPDX it is the package referenced by a `DESCRIBES` relationship. When no root component is present (a pure flat-list SBOM), the analyzer treats every package declared as a direct dependency of the application project file (requirements.txt / pyproject.toml / package.json) as a root entry point; when neither is available, the finding is deferred to the direct-only analyzer with `transitive_not_applicable: no_application_root`.

Ignore SBOM `dependsOn` edges entirely. For each package the walk might traverse, fetch the package's registry manifest once (PyPI `https://pypi.org/pypi/<pkg>/<version>/json`, npm `https://registry.npmjs.org/<pkg>/<version>`) to read declared dependencies. Intersect with the pinned set. Build our own forward dependency graph, compute reverse-reachability from the vulnerable package V, and retain only the subgraph of packages that sit on some path from the application root to V. If V is not reverse-reachable from the application root, the finding is out of scope for transitive analysis — defer to the existing direct-only analyzer and return.

Manifests are small JSON documents and cache trivially alongside tarballs. This step replaces and supersedes any dependency-edge data the SBOM may contain; the SBOM is used only as the authoritative list of what was shipped and at what version.

**Stage B — Identify CVE target symbols in V.**
v1 strategy: fetch V's tarball and run the language's tree-sitter extractor to collect the package's public (exported) symbols. The target set starts as "all exports." This is deliberately conservative; it may fan out more than necessary but never misses a true reach. Evidence records that symbol identification was coarse (`target_identification: "coarse_all_exports"`). When V's source is unavailable (binary-only Python wheel, fetch failure, digest mismatch), mark V `source_unavailable`, emit the finding as reachable with `low` confidence and reason "source of vulnerable package unavailable; conservative assumption" — consistent with how other tools treat opaque sinks.

**Stage C — Walk each SBOM path backwards, one hop at a time.**
For each distinct dependency path `app → D1 → D2 → … → Dn → V` in the pruned subgraph, run the pairwise walk:

1. Start with `target_set = {V's exported symbols}`.
2. For each upstream package `Dk` in reverse order (`Dn, Dn-1, …, D1`):
   - Fetch and cache `Dk`'s tarball if not already present. If fetch fails or source is unavailable, emit `hop_degraded` evidence for this link and treat the hop as "reachable with degraded confidence" — we cannot prove the link broken without source.
   - Unpack into the cache directory.
   - Run the existing tree-sitter extractor on `Dk`'s source root. Build an intra-package call graph. Resolve `Dk`'s imports such that any call statement targeting a symbol in the previous hop's package becomes a cross-package edge with confidence attached by the extractor's usual rules.
   - Run `treesitter.FindReachablePaths` with `target_set` as the targets. The result is a set of `Dk` symbols that transitively reach any element of `target_set`.
   - If the reachable set is **empty**, the link is broken. Short-circuit this path. Emit `path_broken` evidence naming the broken hop (e.g., `werkzeug → urllib3: no caller of urllib3 exports found in werkzeug source`). Move to the next SBOM path.
   - Otherwise, replace `target_set` with `Dk`'s reachable symbols and continue to `Dk-1`.
3. The final upstream step is the application itself, not a fetched dependency. Run the existing per-language analyzer (`pkg/vex/reachability/python/python.go` or `.../javascript/javascript.go`) in its current forward mode against the application source with the now-final `target_set` as targets. This step is the existing "is the direct dep called from the application" check, reused verbatim with an enriched target set.
4. If the application-level check reaches any target, collect the full call path (app entry → target). Stitch it with the per-hop call paths in evidence order to produce a single continuous path from the app entry to the vulnerable symbol in V.

**Stage D — Aggregate across paths.**
The finding is reachable if *any* SBOM path to V is reachable. Evidence records the reach on the successful path. If every path short-circuited or all were degraded, emit not-reachable with per-path reasons. If some paths reached and some degraded, pick the strongest positive result.

### Short-circuit invariants

- As soon as any hop returns an empty reachable set, the driver stops walking that path. Earlier hops on that path are never fetched. This is both a performance property and a correctness property — not-reachable evidence says exactly which link is broken.
- Hops that cannot be analyzed (source unavailable, fetch failed, digest mismatch) are **not** treated as "broken." They are treated as "reachable with degraded confidence" so we do not claim not-reachable when we cannot prove it. This matches the conservative stance required for CRA evidence.

### Cross-package edge resolution

Each hop's extraction pass uses the extractor's existing import resolver with the downstream package's symbol table injected as a known external scope (via the `treesitter.Scope` import-definition mechanism already used by `pkg/vex/reachability/treesitter/javascript/extractor.go` and the Python equivalent). From the extractor's point of view, the downstream package's public symbols look exactly like any other imported module, and `import urllib3` followed by `urllib3.foo()` becomes an edge from the caller symbol to `urllib3.foo` without the extractor knowing anything about transitive analysis.

### Bounds (defaults, all configurable via `transitive.Config`)

| Bound | Default | Rationale |
|---|---|---|
| Max SBOM hops per path | 8 | Very few real dependency chains are deeper; deeper chains are usually infrastructure packages that don't participate in real call paths. |
| Max paths considered per finding | 16 | Diamond-dependency cap. Paths beyond the cap are recorded in evidence as `skipped_for_bound`. |
| Max target symbols per hop | 256 | Fan-out control. Coarse target sets (Stage B "all exports") on very large packages get truncated with an evidence note. |
| Per-hop extract+analyze timeout | 30s | Prevents pathological files from stalling the run. |
| Per-finding wall-clock budget | 5 minutes | Prevents unbounded runs on complex apps. |

Hitting any bound produces not-reachable with a `bound_exceeded` reason, never silent truncation.

## Data flow and interfaces

### New `transitive.Analyzer`

```go
package transitive

type Analyzer struct {
    Config     Config
    Fetchers   map[string]Fetcher  // keyed by ecosystem: "pypi", "npm"
    Extractors map[string]treesitter.LanguageExtractor
    Cache      *Cache
}

func (a *Analyzer) Analyze(
    ctx context.Context,
    sbom *formats.SBOM,
    finding *formats.Finding,
    sourceDir string,
) (reachability.Result, error)
```

`Result` is the existing `reachability.Result` type with `Paths` populated (already supports multi-hop call paths from `pkg/vex/reachability/result.go`). A new `Degradations []string` field is added to `Result` to record structured degradation reasons surfaced as VEX evidence.

### `Fetcher` interface

```go
package transitive

type Fetcher interface {
    Ecosystem() string  // "pypi", "npm"
    Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error)
    Manifest(ctx context.Context, name, version string) (PackageManifest, error)
}

type FetchResult struct {
    SourceDir        string  // absolute path into the cache
    SourceUnavailable bool   // true if we can verify the package exists but has no readable source
    Digest           Digest  // actual digest of what was fetched
}

type PackageManifest struct {
    Dependencies map[string]string  // name → version constraint as declared by the package
}
```

### Integration with existing per-language analyzers

`pkg/vex/reachability/python/python.go` and `pkg/vex/reachability/javascript/javascript.go` each gain a single pre-check before their current logic:

```go
if a.Transitive != nil && shouldTryTransitive(sbom, finding) {
    res, err := a.Transitive.Analyze(ctx, sbom, finding, sourceDir)
    if err == nil && res.Reachable {
        return res, nil
    }
    // fall through to existing direct-only analysis on error or not-reachable
}
```

`shouldTryTransitive` returns true only when an SBOM is available, the finding has a parseable purl for a supported ecosystem, and the affected package is reverse-reachable from the application root in the pruned subgraph. Otherwise we defer to the existing direct-only path.

### SBOM source of truth

Version pins come from the SBOM's component list. Dependency structure comes from registry manifests. This decoupling is deliberate and addresses the known weakness in Python SBOMs generated by Syft/Trivy without a live virtualenv: their `dependsOn` edges are often missing or collapsed. By ignoring SBOM edges, transitive analysis is unaffected by SBOM quality beyond "the package list is correct" — which is a much weaker and more commonly-satisfied precondition.

## Error handling and degradation

Every degradation is explicit and shows up in VEX evidence. The full set:

| Condition | Response | Evidence reason |
|---|---|---|
| V not in pruned subgraph | Defer to existing direct-only analyzer | `transitive_not_applicable` |
| Registry manifest fetch failure (network) | Treat package as a leaf; do not walk past it on that path | `manifest_fetch_failed` |
| Tarball fetch failure | Hop is degraded: reachable with low confidence | `tarball_fetch_failed` |
| Digest mismatch between fetched tarball and SBOM-declared hash | Hard fail; do not analyze the tampered artifact | `digest_mismatch` |
| Source unavailable (binary-only Python wheel, no sdist, no VCS) | Mark package `source_unavailable`; hop treated as opaque sink with low confidence | `source_unavailable` |
| Bound exceeded (hops, paths, symbols, timeout) | Not-reachable for that path; other paths continue | `bound_exceeded` |
| Extractor error on a fetched package | Hop degraded: reachable with low confidence | `extractor_error` |
| No entry points found in application | Existing behavior: degrade forward analysis confidence | (existing) |

Degraded outcomes never silently drop a finding. A user inspecting the VEX output can always see exactly which step degraded and why, which is a CRA-relevant property for the evidence trail.

## CLI and configuration

The CLI surface is additive. No new commands; two new flags on the existing `cra vex` command:

- `--transitive` (default `true`). Disable with `--transitive=false` to restore the previous direct-only behavior.
- `--transitive-cache-dir <path>` (default `~/.cache/cra-toolkit/pkgs`). Overrides the content-addressed cache location, useful in CI.

Bounds are configured through an optional `transitive` stanza in the existing product-config YAML:

```yaml
reachability:
  transitive:
    max_hops: 8
    max_paths: 16
    max_target_symbols_per_hop: 256
    hop_timeout: 30s
    finding_budget: 5m
```

All fields are optional and have the defaults listed under "Bounds" above.

## Testing strategy

The existing `testdata/integration/*-realworld-transitive` fixtures are **not** what their name suggests. The Python and JavaScript "transitive" fixtures test *intra-application indirect calls* (one app file calling another app file that calls a direct dep), not cross-package transitive calls through a real dependency tree. They pass today and will continue to pass under the new analyzer because those scenarios are already handled by the existing direct-only path.

We therefore need **new fixtures** that exercise the cross-package case. v1 will ship at minimum two:

### `testdata/integration/python-realworld-cross-package/`

- **CVE:** Something in a real transitive dep. Candidate: a CVE in `urllib3` reached through `requests` or through `flask → werkzeug`. Final selection done during implementation against a current vuln database.
- **Structure:** Minimal Flask (or similar) application that invokes the intermediate direct dep's public API, which internally calls the vulnerable function. Expected: reachable, high confidence, stitched call path spanning app + direct dep + transitive dep.
- **Paired `not-reachable` fixture:** Same SBOM, same direct deps, but the application only uses a code path through the direct dep that does not hit the vulnerable function. Expected: not-reachable, short-circuit at a specific hop, evidence naming the broken link.

### `testdata/integration/javascript-realworld-cross-package/`

- **CVE:** Something reachable through an Express-ecosystem package chain. Candidate: a CVE in `lodash` reached through a view-engine or a middleware that depends on lodash internally. Final selection done during implementation.
- **Structure:** Express app using the intermediate dep without directly importing lodash. Expected: reachable, stitched call path.
- **Paired `not-reachable` fixture:** Same SBOM, different app usage that avoids the vulnerable code path.

### Unit test coverage

Inside `pkg/vex/reachability/transitive/`:

- `sbom_graph_test.go` — pruning correctness, diamond dependencies, reverse-reachable set computation, behavior when V is not in the graph.
- `fetcher_pypi_test.go` — sdist preferred, wheel fallback, source-unavailable detection, digest verification. Uses canned tarballs in `testdata/`.
- `fetcher_npm_test.go` — tarball fetch and unpack, digest verification.
- `walker_test.go` — short-circuit on broken hop, degradation on fetch failure, bound enforcement, evidence assembly.
- `hop_test.go` — reuses existing tree-sitter extractors against small fixture packages to verify that target-set propagation works end to end.

Per the user's project-level policy, tests use real OSS project data — no mocks. The fetchers are tested against real tarballs captured once into `testdata/transitive/` and replayed via a local HTTP fixture server.

### Integration test

A new Taskfile target `task test:transitive` runs the two realworld cross-package fixtures end-to-end through the CLI, asserting:

- The reachable fixture produces a VEX statement with `status: affected`, `justification` referencing the stitched call path, and a `reached_by` path containing the expected symbols.
- The not-reachable fixture produces `status: not_affected`, `reachability_analysis` justification, and evidence naming the exact broken hop.

### LLM judgment test upgrade

The existing LLM judgment tests in `pkg/vex/reachability/python/llm_judge_test.go` and `.../javascript/llm_judge_test.go` must be updated alongside the new fixtures so the LLM judge sees the transitive evidence and evaluates it. This is required by the project-level policy to upgrade LLM judgment tests when real-world integration tests change.

## v1 scope

In scope:

- `pkg/vex/reachability/transitive/` package with all files listed above.
- PyPI and npm fetchers with content-addressed caching and digest verification.
- Pairwise reverse walker with short-circuit and bound enforcement.
- Evidence stitching into existing `reachability.CallPath` format.
- Integration with existing Python and JavaScript analyzers via the pre-check pattern.
- CLI flags `--transitive` and `--transitive-cache-dir`.
- Two new realworld cross-package fixtures (Python + JavaScript) with reachable and not-reachable variants.
- Unit tests per file listed above.
- LLM judgment test updates.
- Documentation site pages under `site/docs/tools/vex.md` describing the new capability.
- A new showcase entry demonstrating the pipeline end-to-end on a real project.

Out of scope (see "Path forward" below):

- LLM-assisted CVE symbol narrowing.
- Binary-only Python wheel support beyond the `source_unavailable` degradation.
- Languages other than Python and JavaScript.
- Private registries / authenticated fetch.
- Parallelism: v1 walks paths sequentially. Parallelizing across SBOM paths is trivial because each walk is independent; deferring it to v1.1 keeps v1 implementation simple.

## Path forward to v1-full

Each item below is independently deliverable after v1 lands and does not require architectural change to the base pipeline. They are listed in recommended order of implementation:

### 1. LLM-assisted CVE symbol narrowing

**Motivation:** v1's Stage B uses "all exported symbols of V" as the target set. For large packages this produces low-signal confirmations — anything the app does through that package may trivially reach *some* exported symbol. Narrowing the symbol set to the actually-vulnerable function(s) dramatically raises confidence.

**Approach:** Add an optional `SymbolNarrower` interface to `transitive.Config`. A default implementation reads the OSV/GHSA advisory text, the CVE description, and the package's declared public API, and asks an LLM to identify the likely vulnerable function(s) by name. The narrower returns a subset of the "all exports" target set, annotated with per-symbol confidence from the model. When a symbol has model confidence above a configurable threshold, the pairwise walk uses the narrowed set; otherwise it falls back to the full export set. Evidence records both the narrowed set and the model confidence.

**Integration:** Slots between Stages A and B of the algorithm. Per-package result is cached by `(cve, package, version)` so the LLM call is paid once across all runs that touch that CVE. The existing LLM-judgment test infrastructure (see `pkg/vex/reachability/python/llm_judge_test.go`) is reused to validate the narrower.

### 2. Parallel path walking

**Motivation:** v1 walks SBOM paths sequentially. On projects with many diamond dependencies, this can be slow on cold caches.

**Approach:** Parallelize the outer loop of `walker.go` with a bounded worker pool. Each path walk is independent because the cache is content-addressed and safe under concurrent fetches (use single-flight on fetch to avoid duplicate downloads for shared prefixes). Short-circuit semantics are preserved per path.

### 3. Binary-only Python wheel handling

**Motivation:** Currently numpy, cryptography, pydantic-core, and similar ship as platform-specific binary wheels with no Python source to analyze. These are marked `source_unavailable` and treated as opaque sinks in v1. For CVEs inside these packages specifically, v1 always reports reachable-with-low-confidence.

**Approach:** Two complementary strategies.
1. Fetch from upstream VCS tag when PyPI metadata references a source URL. Works for many packages that publish source to GitHub but publish binary-only wheels.
2. For packages without a fetchable source, maintain a small curated table of "cross-package call surface" stubs — a machine-readable description of which public functions in the binary package call which functions in which other packages. This is substantially smaller than a full taint model; it only needs to capture cross-package edges, not intra-package behavior. Community contributions can populate the table incrementally.

### 4. Support for the other five languages

**Motivation:** Java, C#, PHP, Ruby, and Rust all have existing tree-sitter extractors in `pkg/vex/reachability/treesitter/`. Extending transitive analysis to them is primarily a fetcher + fixture work-item, not new orchestration logic.

**Approach:** Add one fetcher per ecosystem (Maven Central, NuGet, Packagist, RubyGems, crates.io) implementing the `Fetcher` interface. Each is a thin HTTPS client over a well-documented public API. Then wire each language's existing analyzer through the same pre-check pattern used by Python and JavaScript in v1. Ship realworld cross-package fixtures for each language.

### 5. Private registry and authenticated fetch

**Motivation:** Enterprise users need to analyze applications that depend on internal packages.

**Approach:** Add per-ecosystem authentication configuration to `transitive.Config`, with environment variable and netrc support. Registry URLs become configurable overrides. Content-addressed cache is unaffected; only the fetch layer changes.

### 6. Incremental analysis cache

**Motivation:** Large applications with many CVEs re-parse the same intermediate dependencies repeatedly.

**Approach:** Cache per-package call graphs (symbol tables + intra-package edges) keyed by `(ecosystem, name, version, extractor_version)` under the existing content-addressed cache directory. Walker consults the cache before parsing. Invalidation is automatic on extractor version change.

## Open items (none blocking)

These will be resolved during implementation without architectural change:

- Exact bound defaults may be tuned once we have benchmark data from the realworld fixtures.
- The `source_unavailable` confidence level (current proposal: `low`) may be adjusted based on CRA reporting review.
- The `reachability.Result.Degradations` field addition requires a one-line type change and update to the VEX evidence schema, which flows through to the existing `reachability_filter` and `vex` report paths.

## References

- `docs/superpowers/specs/2026-04-04-treesitter-reachability-design.md` — the existing tree-sitter reachability design this work extends.
- `docs/superpowers/specs/2026-04-06-realworld-reachability-integration-design.md` — the realworld fixture methodology we will follow for new fixtures.
- `pkg/vex/reachability/treesitter/reachability.go` — the existing BFS and confidence mapping primitives reused by the per-hop analyzer.
- `pkg/vex/reachability/golang/golang.go` — reference for how the existing Go analyzer integrates transitive reachability via an external tool, for architectural comparison.
- cs-au-dk/jelly — prior art for cross-library JavaScript call graph construction (not SBOM-aware; not used directly).
- facebook/pyre-check / Pysa — prior art for Python cross-package taint analysis (not SBOM-aware; not used directly).
- docs/eu-cyber-resilience-act.pdf — underlying CRA regulatory framework these capabilities support.
