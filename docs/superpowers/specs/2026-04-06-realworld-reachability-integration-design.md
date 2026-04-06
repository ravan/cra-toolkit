# Real-World Reachability Integration Test Suite

**Date:** 2026-04-06
**Status:** Approved

## Goal

Prove that the CRA toolkit's reachability analysis works consistently and correctly across all 8 supported languages using real CVEs from real open-source projects. Every test for every language must pass 100%.

This suite serves two purposes:
1. **Trust signal** — demonstrates production-grade accuracy to adopters
2. **Regression gate** — catches analyzer regressions against known ground truth

## Deliverables

| Deliverable | Description |
|---|---|
| Rust analyzer | Full production implementation in `pkg/vex/reachability/rust/` — no placeholder, no generic fallback |
| 48 fixtures | 6 per language x 8 languages, extracted from real OSS projects with provenance |
| Test runner | Build-tag gated integration test with per-language and cross-language consistency reporting |
| Taskfile entry | `task test:integration` command |

## Rust Analyzer — Full Production Implementation

The current Rust analyzer is a placeholder. It must be replaced with a first-class implementation that understands Rust's unique semantics.

### Analysis Approach

`cargo metadata` for dependency graph resolution + tree-sitter-rust for source-level call graph construction + Rust-specific semantic handling.

### Rust-Specific Reachability Concerns

- **Trait dispatch** — `impl Trait for Type` means a call to `trait.method()` could resolve to any implementor. The analyzer builds a trait-impl map (analogous to Java's CHA but for traits).
- **`unsafe` blocks** — Vulnerable code inside `unsafe` is reachable only if the enclosing `unsafe` block is reachable. The analyzer tracks `unsafe` scope.
- **Macro expansions** — `macro_rules!` and proc macros can generate call sites invisible in source. Tree-sitter sees the pre-expansion AST, so the analyzer uses `cargo expand` output when available, falling back to pattern-matching macro invocation sites.
- **Feature flags** — Cargo features gate conditional compilation (`#[cfg(feature = "...")]`). The analyzer reads `Cargo.toml` resolved features to determine which code paths are compiled in.
- **Workspace/dependency graph** — `cargo metadata --format-version=1` provides the full resolved dependency tree, mapping crate names to source paths.

### Implementation Structure

```
pkg/vex/reachability/rust/
  rust.go              # Analyzer entry point, implements reachability.Analyzer
  cargo.go             # cargo metadata parsing, feature resolution
  extractor.go         # tree-sitter-rust symbol extraction
  traits.go            # trait-impl dispatch resolution
  unsafe_scope.go      # unsafe block tracking
  rust_test.go         # unit tests
```

### External Dependencies

`cargo` must be on PATH. No `cargo-audit` or `cargo-geiger` needed — we do our own call graph analysis using the tree-sitter-rust grammar plus cargo metadata for dependency resolution.

### Confidence Levels

- **High** — full source available, features resolved, no unresolvable macros
- **Medium** — macro expansion unavailable or partial feature resolution

## Extended `expected.json` Format

Each fixture's `expected.json` gains provenance fields:

```json
{
  "description": "PyYAML unsafe load in real Flask app",
  "provenance": {
    "source_project": "pallets/flask",
    "source_url": "https://github.com/pallets/flask",
    "commit": "a1b2c3d4e5f6",
    "cve": "CVE-2020-1747",
    "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-1747",
    "language": "python",
    "pattern": "direct_call",
    "ground_truth_notes": "app.py:45 calls yaml.load() with untrusted input, no SafeLoader"
  },
  "findings": [
    {
      "cve": "CVE-2020-1747",
      "component_purl": "pkg:pypi/pyyaml@5.3",
      "expected_status": "affected",
      "expected_justification": "",
      "expected_resolved_by": "reachability_analysis",
      "expected_call_depth_min": 1,
      "expected_symbols": ["yaml.load"]
    }
  ]
}
```

New fields:
- `provenance` block — source project, commit, CVE URL, language, pattern category, ground truth notes
- `expected_resolved_by` — verifies the correct filter resolved the finding
- `expected_call_depth_min` — verifies call chain depth for reachable findings
- `expected_symbols` — verifies the correct vulnerable symbols were identified

## Six Reachability Patterns Per Language

Each language gets 6 fixtures covering distinct patterns:

| # | Pattern | Expected Status | What It Proves |
|---|---------|----------------|----------------|
| 1 | **Direct call** — app directly calls vulnerable function | `affected` | Basic symbol resolution and call detection |
| 2 | **Transitive call** — app calls A, A calls B, B calls vulnerable function (2+ hops) | `affected` | Call graph traversal across multiple frames |
| 3 | **Language-specific dispatch** — vulnerable code reached via virtual/dynamic dispatch | `affected` | Language-aware dispatch resolution |
| 4 | **Imported but unused** — vulnerable package imported, vulnerable function never called | `not_affected` | Distinguishes import from invocation |
| 5 | **Guarded path** — vulnerable function behind unreachable conditional/disabled feature | `not_affected` | Control flow sensitivity |
| 6 | **Dev/test-only dependency** — vulnerable package only in test/dev scope | `not_affected` | Scope-aware analysis |

### Language-Specific Dispatch Examples

| Language | Dispatch Pattern |
|---|---|
| Go | Interface method call resolved to concrete impl |
| Python | Duck typing / `__getattr__` dynamic dispatch |
| JavaScript | Prototype chain / callback passing |
| Java | Interface to implementation (CHA) |
| C# | Interface / virtual method override |
| PHP | Late static binding / magic methods |
| Ruby | `method_missing` / mixin includes |
| Rust | Trait impl dispatch |

## CVE Candidates Per Language

All CVEs are real, well-documented vulnerabilities from real open-source projects with known affected symbols.

### Go

| # | Pattern | CVE | Package | Vulnerable Symbol |
|---|---------|-----|---------|-------------------|
| 1 | Direct call | CVE-2022-32149 | `golang.org/x/text` | `language.Parse()` |
| 2 | Transitive | CVE-2022-41723 | `golang.org/x/net/http2` | HPACK decoder via HTTP server |
| 3 | Dispatch | CVE-2024-24790 | `net/netip` | `Addr.Is4In6()` via `net.Conn` interface |
| 4 | Imported unused | CVE-2023-39325 | `golang.org/x/net/http2` | Imported but only gRPC used |
| 5 | Guarded path | CVE-2022-27664 | `golang.org/x/net/http2` | Behind inactive build tag |
| 6 | Dev/test only | CVE-2023-44487 | `golang.org/x/net` | In test helper only |

### Python

| # | Pattern | CVE | Package | Vulnerable Symbol |
|---|---------|-----|---------|-------------------|
| 1 | Direct call | CVE-2020-1747 | PyYAML | `yaml.load()` without SafeLoader |
| 2 | Transitive | CVE-2019-19844 | Django | Password reset via view -> form -> model |
| 3 | Dispatch | CVE-2021-32052 | Django | `URLValidator` through form field chain |
| 4 | Imported unused | CVE-2022-42969 | py library | Imported but never called |
| 5 | Guarded path | CVE-2021-23336 | Python `urllib.parse` | Behind `LEGACY_QUERY_PARSING=False` |
| 6 | Dev/test only | CVE-2023-43804 | `urllib3` | Only in test HTTP client |

### JavaScript

| # | Pattern | CVE | Package | Vulnerable Symbol |
|---|---------|-----|---------|-------------------|
| 1 | Direct call | CVE-2021-23337 | lodash | `template()` RCE in SSR |
| 2 | Transitive | CVE-2022-46175 | `json5` | Prototype pollution via config loader |
| 3 | Dispatch | CVE-2019-10744 | lodash | `defaultsDeep` via middleware callback |
| 4 | Imported unused | CVE-2021-3807 | `ansi-regex` | In package.json, only chalk uses it |
| 5 | Guarded path | CVE-2022-25883 | `semver` | Behind env var that defaults off |
| 6 | Dev/test only | CVE-2023-26136 | `tough-cookie` | Only in test suite mocking |

### Java

| # | Pattern | CVE | Package | Vulnerable Symbol |
|---|---------|-----|---------|-------------------|
| 1 | Direct call | CVE-2022-1471 | SnakeYAML | `Yaml.load()` in config reader |
| 2 | Transitive | CVE-2021-44228 | Log4j (Log4Shell) | logger -> appender -> JNDI lookup |
| 3 | Dispatch | CVE-2022-22965 | Spring (Spring4Shell) | `WebDataBinder` -> `BeanWrapper` interface |
| 4 | Imported unused | CVE-2023-20861 | Spring Expression Language | SpEL never invoked |
| 5 | Guarded path | CVE-2022-22976 | Spring Security | Behind `security.enabled=false` |
| 6 | Dev/test only | CVE-2023-34034 | Spring Security | Only in integration test config |

### C#

| # | Pattern | CVE | Package | Vulnerable Symbol |
|---|---------|-----|---------|-------------------|
| 1 | Direct call | CVE-2023-29331 | .NET `X509Certificate2` | Private key extraction in cert validator |
| 2 | Transitive | CVE-2023-33170 | ASP.NET Core | Auth bypass via middleware pipeline |
| 3 | Dispatch | CVE-2022-34716 | .NET `SignedXml` | Virtual override in custom `XmlResolver` |
| 4 | Imported unused | CVE-2023-36049 | .NET `Uri` | `System.Net` imported, `Uri` never called |
| 5 | Guarded path | CVE-2023-36799 | .NET `X509Chain` | Behind `#if DEBUG` preprocessor |
| 6 | Dev/test only | CVE-2023-38178 | .NET Kestrel HTTP/2 | Only in load test project |

### PHP

| # | Pattern | CVE | Package | Vulnerable Symbol |
|---|---------|-----|---------|-------------------|
| 1 | Direct call | CVE-2021-43608 | Symfony Serializer | Code execution in API deserializer |
| 2 | Transitive | CVE-2022-24894 | Symfony HTTP cache | Kernel -> cache -> response handler |
| 3 | Dispatch | CVE-2023-46734 | Twig | Late static binding through filter chain |
| 4 | Imported unused | CVE-2022-31091 | Guzzle | Imported but `file_get_contents` used instead |
| 5 | Guarded path | CVE-2023-43655 | Composer runtime | Behind `APP_ENV=production` disabling plugins |
| 6 | Dev/test only | CVE-2022-24775 | `guzzlehttp/psr7` | Only in PHPUnit test doubles |

### Ruby

| # | Pattern | CVE | Package | Vulnerable Symbol |
|---|---------|-----|---------|-------------------|
| 1 | Direct call | CVE-2022-23633 | Action Pack | Response body leak in streaming |
| 2 | Transitive | CVE-2022-32224 | ActiveRecord | Model -> serializer -> YAML deser |
| 3 | Dispatch | CVE-2023-22795 | Action Dispatch | `method_missing` through middleware |
| 4 | Imported unused | CVE-2022-44570 | Rack | In Gemfile but custom server used |
| 5 | Guarded path | CVE-2023-22796 | Active Support | Behind `config.use_legacy_time_parsing = false` |
| 6 | Dev/test only | CVE-2023-28362 | Action Text | Only in RSpec feature tests |

### Rust

| # | Pattern | CVE | Package | Vulnerable Symbol |
|---|---------|-----|---------|-------------------|
| 1 | Direct call | CVE-2024-24576 | `std::process::Command` | Arg injection in CLI wrapper |
| 2 | Transitive | CVE-2023-38497 | Cargo | Build script -> download -> extract chain |
| 3 | Dispatch | CVE-2022-36114 | Cargo tar extraction | `Read` trait impl on decompressor |
| 4 | Imported unused | CVE-2024-32650 | `rustls` | In Cargo.toml but `native-tls` used, feature disabled |
| 5 | Guarded path | CVE-2023-34411 | `xml-rs` | Behind `#[cfg(feature = "xml")]` not enabled |
| 6 | Dev/test only | CVE-2022-46176 | Cargo SSH | Only in `[dev-dependencies]` test harness |

## Fixture Directory Structure

Each fixture lives in `testdata/integration/` alongside existing fixtures:

```
testdata/integration/
  ... (existing fixtures)
  go-realworld-direct-call/
    expected.json          # with provenance block
    sbom.cdx.json          # real CycloneDX SBOM
    grype.json             # real Grype scan output
    source/                # minimal reproducer from real project
      go.mod
      go.sum
      main.go
  go-realworld-transitive/
    ...
  python-realworld-direct-call/
    ...
```

Naming convention: `{language}-realworld-{pattern}` where pattern is one of:
- `direct-call`
- `transitive`
- `dispatch`
- `imported-unused`
- `guarded-path`
- `dev-only`

## Integration Test Runner

New test function in `pkg/vex/integration_test.go`, build-tag gated:

```go
//go:build integration

func TestIntegration_RealWorldReachability(t *testing.T) {
    fixtures := discoverFixtures(t, "realworld")
    byLanguage := groupByLanguage(fixtures)

    for lang, langFixtures := range byLanguage {
        t.Run(lang, func(t *testing.T) {
            for _, fx := range langFixtures {
                t.Run(fx.Name, func(t *testing.T) {
                    expected := loadExpected(t, fx.Dir)
                    requireProvenance(t, expected)

                    results := runVEX(t, fx)

                    for _, ef := range expected.Findings {
                        result := findResult(results, ef.CVE, ef.ComponentPURL)
                        assert.Equal(t, ef.ExpectedStatus, result.Status)
                        assert.Equal(t, ef.ExpectedResolvedBy, result.ResolvedBy)

                        if ef.ExpectedStatus == "affected" {
                            assert.NotEmpty(t, result.CallPaths, "affected must have call paths")
                            assert.GreaterOrEqual(t, result.MaxCallDepth, ef.ExpectedCallDepthMin)
                            assertSymbolsPresent(t, ef.ExpectedSymbols, result.Symbols)
                        }

                        assert.NotEmpty(t, result.Evidence)
                    }
                })
            }
            reportLanguageConsistency(t, lang, langFixtures)
        })
    }
    reportOverallConsistency(t, byLanguage)
}
```

### Consistency Report Output

```
=== Real-World Reachability Consistency Report ===
Language    | Total | Pass | Fail | Reachable    | NotReachable  |
go          |     6 |    6 |    0 |          3/3 |           3/3 |
python      |     6 |    6 |    0 |          3/3 |           3/3 |
javascript  |     6 |    6 |    0 |          3/3 |           3/3 |
java        |     6 |    6 |    0 |          3/3 |           3/3 |
csharp      |     6 |    6 |    0 |          3/3 |           3/3 |
php         |     6 |    6 |    0 |          3/3 |           3/3 |
ruby        |     6 |    6 |    0 |          3/3 |           3/3 |
rust        |     6 |    6 |    0 |          3/3 |           3/3 |
----------------------------------------------------------------
TOTAL       |    48 |   48 |    0 |        24/24 |         24/24 |
```

**Requirement: 100% pass rate across all languages. Any failure is a test failure.**

## Taskfile Integration

```yaml
test:integration:
  desc: Run real-world integration tests
  cmds:
    - go test -tags integration -v -timeout 10m ./pkg/vex/...
```

## Out of Scope

- Automated CVE harvesting (future work)
- Changes to existing synthetic fixtures
- Changes to core VEX pipeline logic (pipeline is correct — we are proving it with better test data)

## Success Criteria

1. All 48 fixtures pass with 100% accuracy
2. Every `affected` finding has non-empty call paths with correct symbols
3. Every `not_affected` finding has the correct justification
4. Every fixture has complete provenance metadata
5. Consistency report shows 100% pass rate per language and overall
6. Rust analyzer is production-grade with trait dispatch, unsafe scope, feature flags
7. Tests run offline (no network dependencies)
8. `task test:integration` runs cleanly in CI
