# cra-vex Design Spec

**Date:** 2026-04-03
**Status:** Draft
**Tool:** cra-vex — VEX Status Determination (Deterministic Mode)

## Purpose

cra-vex takes an SBOM, vulnerability scan results, and source code directory, then auto-determines VEX status for each CVE using deterministic filters and source code reachability analysis. It produces a VEX document with per-CVE status, justification, confidence level, and evidence chain.

The key differentiator is **source-aware reachability analysis**: not just "is the vulnerable package in your SBOM?" but "does your code actually call the vulnerable function?" This is the gap no existing open-source tool fills comprehensively.

## Implementation Order Context

cra-vex is the first of five Phase 1 tools, built in this order:
1. **cra-vex** (this spec) — foundational data producer
2. **cra-csaf** — scanner-to-advisory bridge (consumes VEX output)
3. **cra-policykit** — CRA Annex I policy evaluation (checks VEX assessments exist)
4. **cra-report** — Art. 14 notification generator (consumes VEX + scan data)
5. **cra-evidence** — compliance evidence bundler (bundles all outputs)

cra-vex comes first because it defines the shared types in `pkg/formats/` that all downstream tools reuse.

## Inputs

All input formats are auto-detected — no user-specified format flags.

### SBOM (required, `--sbom`)
- **CycloneDX JSON** — detected by `bomFormat` key
- **SPDX JSON (2.3 + 3.0)** — detected by `spdxVersion` key

### Vulnerability Scan Results (required, `--scan`, repeatable)
- **Grype JSON** — detected by `matches` array with `vulnerability` objects
- **Trivy JSON** — detected by `Results` array with `Vulnerabilities` arrays
- **SARIF** — detected by `$schema` containing `sarif`

### Upstream VEX (optional, `--upstream-vex`, repeatable)
- **OpenVEX** — detected by `@context` containing `openvex`
- **CSAF VEX profile** — detected by `document.category` containing `csaf`

### Source Code (optional but recommended, `--source-dir`)
- Defaults to current directory if it contains a recognizable project (go.mod, Cargo.toml, etc.)
- Required for Tier 2 reachability analysis
- Without it, only Tier 1 metadata filters run

## Output

Controlled by `--output-format` flag:
- **OpenVEX** (default) — full VEX document with per-CVE statements
- **CSAF VEX profile** — OASIS CSAF 2.0 document with VEX profile

Each VEX statement includes:
- CVE ID
- Affected component (PURL)
- VEX status (`not_affected`, `affected`, `fixed`, `under_investigation`)
- Justification code (OpenVEX standard: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `inline_mitigations_already_exist`)
- Confidence level (`high`, `medium`, `low`)
- Evidence chain (which filter resolved it, what data it compared, source of truth)

## Filter Pipeline

Filters evaluate in order. First filter to resolve a finding wins. Each filter returns `(result, resolved bool)`.

### Tier 1: Metadata Filters

| # | Filter | Logic | VEX Status | Justification | Confidence |
|---|--------|-------|------------|---------------|------------|
| 1 | Upstream VEX | Vendor published VEX/CSAF statement for this CVE+component | *vendor's status* | *vendor's justification* | high |
| 2 | Component Presence | Affected component (by PURL) not in SBOM | `not_affected` | `component_not_present` | high |
| 3 | Version Range | Installed version outside affected version range | `not_affected` | `vulnerable_code_not_present` | high |
| 4 | Platform Match | CVE's platform/OS doesn't match SBOM target | `not_affected` | `vulnerable_code_not_in_execute_path` | high |
| 5 | Patch Status | SBOM version >= fix version | `fixed` | *(fix version noted)* | high |

### Tier 2: Source Code Reachability

| # | Filter | Languages | Method | Confidence |
|---|--------|-----------|--------|------------|
| 6 | Go Reachability | Go | `govulncheck` via `golang.org/x/vuln` — full call-graph analysis, CVE-to-symbol mapping via Go vulndb | high |
| 7 | Rust Reachability | Rust | `cargo-scan` — transitive call-graph reachability from top-level package | high |
| 8 | Generic Symbol Search | All others | ripgrep-based import + function name search, language-aware patterns | medium |

### Default

| # | Filter | Logic | VEX Status | Confidence |
|---|--------|-------|------------|------------|
| 9 | Default | No filter resolved the finding | `under_investigation` | n/a |

Tier 2 filters only run when `--source-dir` is provided. Without source code, unresolved findings after Tier 1 go directly to `under_investigation`.

## Reachability Analyzer Interface

The reachability layer uses a clean interface. Go and Rust have dedicated implementations. All other languages use the generic ripgrep-based analyzer. Adding a new language-specific analyzer (e.g., Java via Eclipse Steady in the future, or LLM-driven analysis in Phase 2) means implementing this interface.

```go
package reachability

// Analyzer determines whether a vulnerable symbol is reachable from application code.
type Analyzer interface {
    // Language returns the language this analyzer handles (e.g., "go", "rust").
    Language() string

    // Analyze checks if the vulnerable symbols associated with a finding
    // are reachable from the source code in the given directory.
    Analyze(ctx context.Context, sourceDir string, finding formats.Finding) (Result, error)
}

type Result struct {
    Reachable  bool       // true = vulnerable code path is reachable
    Confidence Confidence // high, medium, low
    Evidence   string     // human-readable explanation
    Symbols    []string   // vulnerable symbols that were checked
}

type Confidence int

const (
    Low    Confidence = iota
    Medium
    High
)
```

**Factory function** detects language from source directory:
- `go.mod` → Go analyzer
- `Cargo.toml` → Rust analyzer
- Anything else → Generic analyzer

Multi-language repos: multiple analyzers run, each for findings matching their language.

### Generic Analyzer (ripgrep-based)

For languages without call-graph tooling, the generic analyzer:
1. Identifies the vulnerable symbol/function name from the CVE advisory data
2. Detects the language from file extensions and project files
3. Searches for imports of the affected module using language-aware patterns
4. If imported: searches for usage of the specific vulnerable function/symbol
5. Reports `not_affected` (medium confidence) if no import or no symbol usage found
6. Reports `affected` (medium confidence) if both import and symbol usage found

Confidence is `medium` because ripgrep can't trace transitive calls or understand dynamic dispatch.

## Package Structure

```
pkg/formats/
    sbom.go              # Component type, SBOMParser interface
    finding.go           # Finding type, ScanParser interface
    vexstatement.go      # VEXStatement type, VEXParser/VEXWriter interfaces
    detect.go            # Format auto-detection
    cyclonedx/
        cyclonedx.go     # CycloneDX SBOM parser
    spdx/
        spdx.go          # SPDX 2.3 + 3.0 SBOM parser
    grype/
        grype.go         # Grype JSON scan parser
    trivy/
        trivy.go         # Trivy JSON scan parser
    sarif/
        sarif.go         # SARIF scan parser
    openvex/
        openvex.go       # OpenVEX parser + writer
    csafvex/
        csafvex.go       # CSAF VEX profile parser + writer

pkg/vex/
    vex.go               # Run() orchestrator — loads inputs, runs pipeline, writes output
    filter.go            # Filter interface + chain runner
    upstream.go          # Upstream VEX filter
    presence.go          # Component presence filter
    version.go           # Version range filter
    platform.go          # Platform match filter
    patch.go             # Patch status filter
    reachability_filter.go # Reachability filter (delegates to analyzer)
    result.go            # VEXResult type with evidence chain
    reachability/
        analyzer.go      # Analyzer interface + factory
        result.go        # ReachabilityResult type
        language.go      # Language detection from source dir
        golang/
            golang.go    # govulncheck-based implementation
        rust/
            rust.go      # cargo-scan-based implementation
        generic/
            generic.go   # ripgrep-based symbol search
            patterns.go  # Language-aware import/call patterns

internal/cli/
    vex.go               # CLI wiring (flags, argument parsing, calls pkg/vex.Run)
```

## CLI Interface

```
cra vex \
  --sbom product.cdx.json \
  --scan grype-results.json \
  --scan trivy-results.json \
  --upstream-vex vendor.openvex.json \
  --source-dir /path/to/repo \
  --output-format openvex \
  --output results.vex.json
```

| Flag | Required | Description |
|------|----------|-------------|
| `--sbom` | yes | Path to SBOM file (CycloneDX or SPDX JSON). Auto-detected. |
| `--scan` | yes | Path to scan results (Grype, Trivy, or SARIF JSON). Repeatable. Auto-detected. |
| `--upstream-vex` | no | Path to upstream VEX/CSAF document. Repeatable. Auto-detected. |
| `--source-dir` | no | Path to source code for reachability analysis. Defaults to `.` if a recognizable project is found (go.mod, Cargo.toml, package.json, etc.). If omitted and `.` contains no recognizable project, Tier 2 reachability filters are skipped entirely. |
| `--output-format` | no | `openvex` (default) or `csaf` |
| `--output` / `-o` | no | Output file path. Defaults to stdout. |

Global flags (`--format json|text`, `--quiet`, `--verbose`) inherited from root command.

**Text output** (default `--format text`): summary table showing CVE, component, status, justification, confidence, and which filter resolved it.

**JSON output** (`--format json`): the full VEX document (OpenVEX or CSAF).

## Testing Strategy

**Methodology:** TDD. Tests written first, then implementation until green. No mocking or stubbing anywhere. All tests use real data from real open-source projects.

### Test Data

Pinned commits of real OSS projects stored as git submodules in `testdata/integration/`. Each fixture includes pre-generated SBOM and scan data plus a manually curated `expected.json` with ground truth.

```
testdata/
    integration/
        go-reachable/          # Go project where vulnerable function IS called
            source/            # git submodule at pinned commit
            sbom.cdx.json
            sbom.spdx.json
            grype.json
            trivy.json
            expected.json      # manually verified ground truth
        go-not-reachable/      # Go project where vulnerable function is NOT called
            source/
            sbom.cdx.json
            grype.json
            expected.json
        rust-reachable/        # Rust project with reachable vulnerable function
            source/
            sbom.cdx.json
            grype.json
            expected.json
        rust-not-reachable/    # Rust project with unreachable vulnerable function
            source/
            sbom.cdx.json
            grype.json
            expected.json
        python-reachable/      # Python project — ripgrep detects import + call
            source/
            sbom.cdx.json
            trivy.json
            expected.json
        python-not-reachable/  # Python project — ripgrep finds no import
            source/
            sbom.cdx.json
            trivy.json
            expected.json
        js-reachable/          # JavaScript — ripgrep detects require + call
            source/
            sbom.cdx.json
            trivy.json
            expected.json
        multi-scanner/         # Project with Grype + Trivy + SARIF all present
            source/
            sbom.cdx.json
            sbom.spdx.json
            grype.json
            trivy.json
            osv-scanner.sarif.json
            expected.json
        upstream-vex/          # Project with published Chainguard/Red Hat VEX
            sbom.cdx.json
            grype.json
            chainguard.openvex.json
            redhat.csaf.json
            expected.json
    generate.sh                # Regenerates SBOMs and scan data from pinned sources
```

### Test Levels

**Format parser tests** — each parser tested against its real data file:
- Correct component/finding/statement counts
- All fields extracted correctly (PURL, version, CVE ID, severity, etc.)
- Auto-detection selects the right parser

**Individual filter tests** — each filter tested against real findings:
- Version range filter: CVE with known affected range vs installed version
- Platform filter: Linux-only CVE against Windows SBOM
- Patch status: installed version >= known fix version

**Reachability analyzer tests** — each analyzer against real source code:
- Go: govulncheck correctly identifies reachable/unreachable vulnerable symbols
- Rust: cargo-scan correctly identifies reachable/unreachable crate functions
- Generic: ripgrep finds/doesn't find import + symbol usage

**Full pipeline tests** — end-to-end `cra vex` command:
- Real SBOM + real scan + real source → VEX document
- Every CVE status matches `expected.json`
- Output validates against OpenVEX/CSAF JSON schema
- Evidence chain present and accurate for every determination

**Output validation tests:**
- Generated OpenVEX documents validate against OpenVEX JSON schema
- Generated CSAF documents validate against CSAF 2.0 JSON schema

### Test Data Curation

The `expected.json` files are the trust layer. Each entry is manually verified and includes a human justification:

```json
{
  "findings": [
    {
      "cve": "CVE-2023-44487",
      "component": "pkg:golang/golang.org/x/net@v0.7.0",
      "expected_status": "not_affected",
      "expected_justification": "vulnerable_code_not_in_execute_path",
      "expected_confidence": "high",
      "human_justification": "Project imports x/net but does not use HTTP/2 server functionality where the rapid reset vulnerability exists. govulncheck confirms no call path to affected symbols.",
      "resolved_by": "go_reachability"
    }
  ]
}
```

## Development Approach

TDD throughout:
1. Write parser tests against real data files → implement parsers
2. Write filter tests against real findings → implement filters
3. Write reachability tests against real source repos → implement analyzers
4. Write pipeline tests → implement orchestrator
5. Write CLI tests → wire up CLI

## Dependencies

| Dependency | Purpose |
|---|---|
| `github.com/CycloneDX/cyclonedx-go` | CycloneDX SBOM parsing |
| `github.com/spdx/tools-golang` | SPDX SBOM parsing |
| `github.com/openvex/go-vex` | OpenVEX parsing + writing |
| `golang.org/x/vuln` | govulncheck reachability analysis for Go |
| `github.com/urfave/cli/v3` | CLI framework (already in go.mod) |

External tool dependencies (must be installed):
| Tool | Purpose |
|---|---|
| `cargo-scan` | Rust reachability analysis |
| `ripgrep` (`rg`) | Generic symbol search |

## Phase 2 Upgrade Path

The `reachability.Analyzer` interface is the seam for Phase 2. The LLM-powered agent implements this interface:
- Replaces the generic ripgrep analyzer for all languages
- Adds high-confidence call chain analysis for Java, Python, JS, C/C++
- Can also enhance Go/Rust determinations where static analysis is inconclusive
- The filter pipeline, VEX output, and everything else stays unchanged

## CRA Articles Addressed

- **Art. 13(6)** — Vulnerability handling: systematic identification and documentation of vulnerabilities
- **Annex I Part II** — Vulnerability handling requirements: identify and document vulnerabilities, address and remediate without delay, apply effective and regular tests and reviews
