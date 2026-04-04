# cra-csaf Design Spec: Scanner-to-Advisory Bridge

**Date:** 2026-04-04
**Status:** Draft
**Author:** Ravan Naidoo + Claude

## 1. Purpose

`cra csaf` converts vulnerability scanner output + VEX assessments + SBOM metadata into CSAF 2.0 `csaf_security_advisory` profile documents for downstream user notification per CRA Article 14(8).

Article 14(8) requires manufacturers to inform users of vulnerabilities "in a structured, machine-readable format that is easily automatically processable." CSAF security advisories are the industry-standard format for this obligation.

### What This Is Not

- **Not a VEX tool** -- `cra vex` already determines VEX status and can output CSAF VEX profile. `cra csaf` produces richer security advisories with remediations, CVSS scores, threats, and structured notes.
- **Not a report generator** -- `cra report` (future) handles the Art. 14 three-stage notification pipeline. `cra csaf` produces the machine-readable advisory that accompanies those notifications.

## 2. Regulatory Context

**CRA Article 14(8):** "After becoming aware of an actively exploited vulnerability or a severe incident having an impact on the security of the product with digital elements, the manufacturer shall inform the impacted users of the product with digital elements, and where appropriate all users, of that vulnerability or incident and, where necessary, of any risk mitigation and corrective measures that the users can deploy to mitigate the impact of that vulnerability or incident, where appropriate in a structured, machine-readable format that is easily automatically processable."

CSAF 2.0 `csaf_security_advisory` profile satisfies this requirement by providing:
- Structured vulnerability details with CVSS scores
- Remediation instructions (vendor fixes, workarounds)
- Affected product identification via PURLs
- Machine-readable, automatically processable JSON format

## 3. Inputs

All inputs are required:

| Input | Flag | Purpose | Reuses |
|-------|------|---------|--------|
| SBOM | `--sbom` | Component metadata: supplier, hashes, platform, arch for product tree | `pkg/formats/` auto-detect (CycloneDX/SPDX) |
| Scanner results | `--scan` (repeatable) | CVE details: severity, CVSS, description, fix version | `pkg/formats/` auto-detect (Grype/Trivy/SARIF) |
| VEX results | `--vex` | Assessed status, justification, confidence, evidence | `pkg/formats/` auto-detect (OpenVEX/CSAF VEX) |

Required metadata flags:

| Flag | Purpose |
|------|---------|
| `--publisher-name` | Organization name (e.g., "SUSE") |
| `--publisher-namespace` | Organization URL (e.g., "https://suse.com") |

Optional metadata flags:

| Flag | Default | Purpose |
|------|---------|---------|
| `--tracking-id` | Auto-generated from timestamp | Advisory identifier |
| `--title` | Auto-generated from CVE list | Advisory title |
| `--output` | stdout | Output file path |

## 4. CLI Interface

```bash
cra csaf \
  --sbom sbom.cdx.json \
  --scan grype.json \
  --scan trivy.json \
  --vex vex-results.json \
  --publisher-name "ACME Corp" \
  --publisher-namespace "https://acme.com" \
  --tracking-id "ACME-2024-001" \
  --output advisory.json
```

CLI wiring in `internal/cli/csaf.go` follows the same pattern as `internal/cli/vex.go`:
- urfave/cli v3 command with typed flags
- Calls `csaf.Run(opts, writer)` with an `Options` struct
- Uses `OutputWriter()` helper for file/stdout output

## 5. Architecture: Pipeline with Enrichment Stages

Each stage is a pure function that takes inputs and returns enriched CSAF document state. No side effects, fully testable.

```
Parse Inputs (SBOM + Scans + VEX)
        |
        v
Build Product Tree
  SBOM components -> hierarchical branches with PURL, hashes, supplier
        |
        v
Map Vulnerabilities
  Correlate Findings + VEXResults by CVE+PURL -> product_status entries
        |
        v
Enrich Scores
  Finding.CVSS + Finding.Severity -> CVSS v3.1 score structs per vulnerability
        |
        v
Add Remediations
  Finding.FixVersion -> "vendor_fix" / "none_available" per vulnerability
        |
        v
Add Threats
  Finding.Severity -> threat impact category per product
        |
        v
Build Notes
  Summary + per-vuln descriptions + VEX evidence -> document and vuln notes
        |
        v
Assemble & Write
  Complete csafDocument with metadata, tracking, publisher -> JSON output
```

### Stage Details

**Build Product Tree:**
- Top-level branch: `vendor` category with publisher name
- Second level: `product_name` category per component
- Leaf level: `product_version` with `product_identification_helper` containing PURL + hashes from SBOM
- Product ID = PURL (consistent with existing csafvex writer)

**Map Vulnerabilities:**
- Correlation key: CVE + component PURL
- Findings without matching VEXResult -> `under_investigation`
- VEXResult status maps to CSAF product_status:
  - `not_affected` -> `known_not_affected` (+ justification flag)
  - `affected` -> `known_affected`
  - `fixed` -> `fixed`
  - `under_investigation` -> `under_investigation`

**Enrich Scores:**
- CVSS v3.1 vector and base score from scanner Finding
- Base severity derived from score: Critical (9.0-10.0), High (7.0-8.9), Medium (4.0-6.9), Low (0.1-3.9)

**Add Remediations:**
- If Finding.FixVersion is set: category `vendor_fix`, details include fix version
- If no fix available: category `none_available`
- Each remediation references affected product IDs

**Add Threats:**
- Category: `impact`
- Details: mapped from Finding.Severity (critical/high/medium/low)
- Each threat references affected product IDs

**Build Notes:**
- Document-level summary note listing all CVEs addressed
- Per-vulnerability description note from Finding.Description
- VEX evidence included as detail notes when confidence is high

## 6. CSAF Document Model

Types in `pkg/csaf/document.go`. The `csaf_security_advisory` profile extends the base CSAF types with:

```go
// Score represents a CVSS score for a vulnerability affecting specific products.
type score struct {
    Products []string `json:"products"`
    CVSS3    *cvssV3  `json:"cvss_v3,omitempty"`
}

type cvssV3 struct {
    Version      string  `json:"version"`       // "3.1"
    VectorString string  `json:"vectorString"`
    BaseScore    float64 `json:"baseScore"`
    BaseSeverity string  `json:"baseSeverity"`  // "CRITICAL", "HIGH", "MEDIUM", "LOW"
}

// Remediation describes how to fix a vulnerability for specific products.
type remediation struct {
    Category   string   `json:"category"`    // "vendor_fix", "workaround", "none_available"
    Details    string   `json:"details"`
    ProductIDs []string `json:"product_ids"`
    URL        string   `json:"url,omitempty"`
}

// Threat describes the severity impact for specific products.
type threat struct {
    Category   string   `json:"category"`    // "impact"
    Details    string   `json:"details"`     // "Critical", "Important", "Moderate", "Low"
    ProductIDs []string `json:"product_ids"`
}

// CWE classification for a vulnerability.
type cwe struct {
    ID   string `json:"id"`   // "CWE-502"
    Name string `json:"name"` // "Deserialization of Untrusted Data"
}

// Note is a document-level or vulnerability-level annotation.
type note struct {
    Category string `json:"category"` // "summary", "description", "details", "general"
    Text     string `json:"text"`
    Title    string `json:"title,omitempty"`
}

// Reference is a link to external information.
type reference struct {
    Category string `json:"category,omitempty"` // "external", "self"
    Summary  string `json:"summary"`
    URL      string `json:"url"`
}
```

Product tree and base document types follow the same structure as `pkg/formats/csafvex/` but are independently defined in `pkg/csaf/` to keep the packages decoupled.

## 7. File Layout

```
pkg/csaf/
  csaf.go              # Run() entry point, Options struct, pipeline orchestration
  document.go          # CSAF document types
  product_tree.go      # buildProductTree()
  vulnerabilities.go   # mapVulnerabilities()
  scores.go            # enrichScores()
  remediations.go      # addRemediations()
  threats.go           # addThreats()
  notes.go             # buildNotes()
  product_tree_test.go
  vulnerabilities_test.go
  scores_test.go
  remediations_test.go
  threats_test.go
  notes_test.go
  integration_test.go  # Tier 2: end-to-end with real fixtures
  llm_judge_test.go    # Tier 3: LLM quality judge (build tag: llmjudge)

internal/cli/
  csaf.go              # Updated CLI wiring with flags (replaces stub)

testdata/integration/
  csaf-single-cve/     # One CVE, one component
    sbom.cdx.json
    grype.json
    vex-results.json
    expected.json
  csaf-multi-cve/      # Multiple CVEs, one component
    ...
  csaf-multi-component/# One CVE, multiple components
    ...
  csaf-mixed-status/   # Mixed VEX statuses
    ...

testdata/csaf-references/  # Real vendor advisories for LLM quality comparison
  redhat-rhsa-2021_5127.json
  cisco-sa-apache-log4j.json
  suse-su-2021_4111-1.json
```

## 8. Testing Strategy

### Tier 1: Unit Tests (per pipeline stage)

Table-driven tests with real data for each stage function. No mocks or stubs. Each test file validates one pipeline stage in isolation using real SBOM components, scanner Findings, and VEX results.

### Tier 2: Integration Tests (end-to-end with real fixtures)

Four scenarios using real OSS vulnerability data:

| Scenario | CVE(s) | Components | Purpose |
|----------|--------|------------|---------|
| `csaf-single-cve` | CVE-2022-32149 | golang.org/x/text | Baseline: one vuln, one component |
| `csaf-multi-cve` | CVE-2022-32149 + CVE-2022-27664 | golang.org/x/text + golang.org/x/net | Multiple vulns at different severities |
| `csaf-multi-component` | CVE-2021-44228 | Multiple log4j consumers | One CVE affecting multiple products |
| `csaf-mixed-status` | Mix | Mix | All VEX statuses with appropriate remediations |

Each scenario directory contains real SBOM, scanner output, VEX results, and `expected.json` assertions.

Integration tests verify:
- Valid JSON output
- `document.category` == `csaf_security_advisory`
- Correct vulnerability count and CVE IDs
- All product_status entries match VEX input
- Scores, remediations, and threats present for each vulnerability
- Product tree has correct branch hierarchy with PURLs and hashes
- All integration tests pass 100%, no skips

### Tier 3: LLM Quality Judge (local only)

Build tag: `//go:build llmjudge`
Taskfile target: `task test:llmjudge`

For each generated advisory, the test:
1. Shells out to `gemini` CLI with a structured prompt
2. Prompt contains: generated advisory + reference advisory (Red Hat/SUSE/Cisco) + scoring rubric
3. Scoring rubric dimensions (1-10 each):
   - Schema compliance (valid CSAF 2.0 security_advisory)
   - Product tree quality (hierarchy, PURL identification, completeness)
   - Vulnerability detail (CVSS scores, descriptions)
   - Remediation clarity (actionable fix information, correct categories)
   - Notes quality (clear summary, useful details)
   - Overall advisory quality (would a security team trust this?)
4. Pass threshold: >= 8/10 on every dimension
5. Skips gracefully if `gemini` CLI not found in PATH

## 9. Taskfile Targets

```yaml
test:integration:
  desc: Run CSAF integration tests only
  cmds:
    - go test -race -count=1 -run TestIntegration ./pkg/csaf/...

test:llmjudge:
  desc: Run LLM quality judge tests (requires gemini CLI)
  cmds:
    - go test -race -count=1 -tags llmjudge -run TestLLMJudge ./pkg/csaf/...
```

- `task test` -- continues to run all unit + integration tests (no change to existing behavior)
- `task test:integration` -- runs just the CSAF integration suite
- `task test:llmjudge` -- runs LLM quality judge tests separately (local only, requires gemini CLI)
- `task quality` -- continues to gate on `task test` (excludes llmjudge since it's behind a build tag)

## 10. What Changes vs What's New

**Replaces stubs:**
- `pkg/csaf/csaf.go` -- replaces `ErrNotImplemented` stub
- `internal/cli/csaf.go` -- replaces stub CLI command

**New files:**
- `pkg/csaf/document.go` and all pipeline stage files
- All test files in `pkg/csaf/`
- Test fixture directories under `testdata/integration/csaf-*`

**Untouched:**
- `pkg/formats/csafvex/` -- continues serving `cra vex` CSAF output
- `pkg/vex/` -- no changes
- All existing tests -- no changes
- `Taskfile.yml` -- updated with new targets only

## 11. Quality Bar

The output from `cra csaf` must be:
- **Schema-compliant** -- valid CSAF 2.0 `csaf_security_advisory` profile
- **Complete** -- includes all sections that Red Hat, Cisco, and SUSE include in their advisories: product tree with PURLs, CVSS scores, remediations, threats, structured notes
- **Accurate** -- CVSS scores match scanner input, VEX statuses correctly mapped, product IDs traceable to SBOM
- **Superior** -- LLM judge scores >= 8/10 against real vendor advisories on all quality dimensions
- **Trustworthy** -- organizations adopt this tool because the output is production-ready for CRA compliance
