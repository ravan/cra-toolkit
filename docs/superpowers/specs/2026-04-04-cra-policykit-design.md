# cra-policykit Design Spec

**Date:** 2026-04-04
**Status:** Draft
**CRA References:** Annex I (Parts I & II), Article 13

## Overview

`cra policykit` evaluates product artifacts against CRA Annex I essential cybersecurity requirements encoded as OPA/Rego policies. It produces a structured compliance report with PASS/FAIL/SKIP results for 7 machine-checkable rules and explicitly flags 8 requirements that need human review.

The tool is deterministic, offline-capable, and designed for CI/CD integration. Policies are embedded in the binary and extensible via user-supplied Rego files.

## Architecture

### Pipeline (5 Stages)

1. **Parse artifacts** — Load SBOM, scan results, VEX document, provenance attestation, signatures, and product config. Reuse existing `pkg/formats` parsers for SBOM/scan/VEX.
2. **Fetch external data** — Download CISA KEV catalog (cached locally, overridable with `--kev` flag for offline/CI use).
3. **Build evaluation input** — Assemble a unified `map[string]any` input document from all parsed artifacts + KEV data.
4. **Evaluate policies** — Load embedded + custom Rego policies, evaluate each via OPA's `rego` package. Each policy produces a structured result.
5. **Assemble report** — Collect all policy results into a JSON or markdown report written to stdout or `--output`.

### Entry Point

```go
type Options struct {
    SBOMPath       string
    ScanPaths      []string
    VEXPath        string
    ProvenancePath string
    SignaturePaths []string
    ProductConfig  string
    KEVPath        string   // local override; auto-fetched if empty
    PolicyDir      string   // custom Rego policies directory
    OutputFormat   string   // "json" (default) or "markdown"
}

func Run(opts *Options, out io.Writer) error
```

### File Decomposition

| File | Responsibility |
|------|---------------|
| `policykit.go` | Pipeline orchestration (`Run()`) |
| `input.go` | Input document assembly from parsed artifacts |
| `engine.go` | OPA engine wrapper (load policies, evaluate, collect results) |
| `kev.go` | CISA KEV fetching, caching, and parsing |
| `report.go` | Report structure, JSON serialization, markdown rendering |
| `provenance.go` | SLSA provenance attestation parsing (v0.2 and v1.0) |
| `signature.go` | Cryptographic signature file detection and parsing |

### Dependencies

```
github.com/open-policy-agent/opa/v1/rego   # OPA Go SDK for policy evaluation
gopkg.in/yaml.v3                           # Product config YAML parsing
```

Policies embedded via `embed.FS` from `policies/` directory. Rego files use OPA v1 syntax (`import rego.v1`).

## CLI Flags

```
cra policykit \
  --sbom <path>                    # Required. CycloneDX or SPDX SBOM
  --scan <path> [--scan <path>]    # Required. Grype/Trivy/SARIF scan results (repeatable)
  --vex <path>                     # Required. VEX document (OpenVEX or CSAF)
  --provenance <path>              # Optional. SLSA provenance attestation JSON
  --signature <path> [...]         # Optional. Signature files (repeatable)
  --product-config <path>          # Optional. Product metadata YAML/JSON
  --kev <path>                     # Optional. Local CISA KEV override (auto-fetched if omitted)
  --policy-dir <path>              # Optional. Directory of custom Rego policies
  --format json|markdown           # Optional. Output format (default: json)
  --output <path>                  # Optional. Output file (default: stdout)
```

Policies with missing optional inputs evaluate to `SKIP` with a message explaining the missing input. Required inputs (`--sbom`, `--scan`, `--vex`) are enforced by the CLI.

## Machine-Checkable Policies (7)

Each policy is a standalone `.rego` file in `policies/`.

### CRA-AI-1.1 — SBOM exists and is valid

- **File:** `cra_sbom_valid.rego`
- **CRA Reference:** Annex I Part II.1
- **Severity:** Critical
- **Input:** `input.sbom`
- **Checks:**
  - Format is valid CycloneDX or SPDX
  - Top-level metadata present (name, version, supplier)
  - At least one component exists
  - Components have PURLs
- **Evidence:** format, version, component count, PURL coverage, supplier presence

### CRA-AI-2.1 — No known exploited vulnerabilities

- **File:** `cra_no_kev.rego`
- **CRA Reference:** Annex I Part I.2(a)
- **Severity:** Critical
- **Input:** `input.scan.findings`, `input.kev.cves`
- **Checks:**
  - Cross-reference all CVE IDs from scan results against CISA KEV catalog
  - Any match = FAIL
- **Evidence:** list of matching KEV CVEs, KEV catalog date, total CVEs checked

### CRA-AI-2.2 — All critical/high CVEs have VEX assessment

- **File:** `cra_vex_coverage.rego`
- **CRA Reference:** Annex I Part I.2(a)
- **Severity:** High
- **Input:** `input.scan.findings`, `input.vex.statements`
- **Checks:**
  - Identify all findings with CVSS >= 7.0
  - Each must have a corresponding VEX statement (matched by CVE + component PURL)
  - Missing assessment = FAIL
- **Evidence:** total critical/high CVEs, assessed count, unassessed CVE list

### CRA-AI-3.1 — Build provenance exists (SLSA L1+)

- **File:** `cra_provenance.rego`
- **CRA Reference:** Art. 13
- **Severity:** High
- **Input:** `input.provenance`
- **Checks:**
  - Provenance attestation exists
  - Has builder ID
  - Has source repository reference
  - Has build invocation metadata
- **Evidence:** builder ID, source repo, build type, SLSA level
- **SKIP if:** `--provenance` not provided

### CRA-AI-3.2 — Artifacts cryptographically signed

- **File:** `cra_signatures.rego`
- **CRA Reference:** Art. 13
- **Severity:** High
- **Input:** `input.signatures`
- **Checks:**
  - At least one signature file exists
  - Signature files are parseable (cosign bundle, PGP, or x509)
- **Evidence:** signature count, formats detected
- **SKIP if:** `--signature` not provided

### CRA-AI-4.1 — Support period declared and > 5 years

- **File:** `cra_support_period.rego`
- **CRA Reference:** Annex I Part II
- **Severity:** Medium
- **Input:** `input.product`
- **Checks:**
  - `support_end_date` is declared
  - `release_date` is declared
  - Duration between release and end-of-support is >= 5 years
- **Evidence:** release date, support end date, duration in years
- **SKIP if:** `--product-config` not provided

### CRA-AI-4.2 — Secure update mechanism documented

- **File:** `cra_update_mechanism.rego`
- **CRA Reference:** Annex I Part II.7
- **Severity:** Medium
- **Input:** `input.product.update_mechanism`
- **Checks:**
  - Update mechanism is declared
  - Has type (automatic/manual/hybrid)
  - Has URL
  - Has `auto_update_default` field
  - Has `security_updates_separate` field
- **Evidence:** mechanism type, URL present, auto-update default, separate security updates
- **SKIP if:** `--product-config` not provided

## Human-Flagged Items (8)

These appear in every report with status `HUMAN` and auditor guidance. They are not evaluated — they serve as a checklist.

| Rule ID | Requirement | CRA Source | Auditor Guidance |
|---------|-------------|------------|-----------------|
| CRA-HU-1.1 | Appropriate cybersecurity level | Annex I Part I.1 | Verify risk assessment performed and cybersecurity measures are proportionate to identified risks |
| CRA-HU-1.2 | Secure by default configuration | Annex I Part I.2(b) | Verify product ships with secure defaults and users can reset to original state |
| CRA-HU-1.3 | Access control mechanisms | Annex I Part I.2(d) | Verify authentication, identity, and access management systems protect against unauthorised access |
| CRA-HU-1.4 | Data encryption at rest and in transit | Annex I Part I.2(e) | Verify confidentiality of stored, transmitted, and processed data using state of the art encryption |
| CRA-HU-1.5 | Data integrity protection | Annex I Part I.2(f) | Verify integrity of stored, transmitted data, commands, programs, and configuration against unauthorised modification |
| CRA-HU-1.6 | Data minimisation | Annex I Part I.2(g) | Verify only adequate, relevant, and limited data is processed for the product's intended purpose |
| CRA-HU-1.7 | Attack surface minimisation | Annex I Part I.2(j) | Verify product is designed to limit attack surfaces including external interfaces |
| CRA-HU-1.8 | Risk assessment performed | Art. 13(2) | Verify cybersecurity risk assessment has been carried out and is documented |

## Product Config Format

A YAML or JSON file providing product metadata for policies CRA-AI-4.1 and CRA-AI-4.2:

```yaml
product:
  name: "my-product"
  version: "2.1.0"
  release_date: "2025-06-01"
  support_end_date: "2031-06-01"
  update_mechanism:
    type: "automatic"
    url: "https://updates.example.com/my-product"
    auto_update_default: true
    security_updates_separate: true
  vulnerability_disclosure:
    contact: "security@example.com"
    policy_url: "https://example.com/.well-known/security.txt"
```

## OPA Input Document

All artifacts assembled into a single input document for Rego evaluation:

```json
{
  "sbom": {
    "format": "cyclonedx",
    "version": "1.6",
    "metadata": {
      "name": "my-product",
      "version": "2.1.0",
      "supplier": "ACME Corp"
    },
    "components": [
      {"name": "golang.org/x/text", "version": "0.3.7", "purl": "pkg:golang/golang.org/x/text@0.3.7", "type": "library"}
    ]
  },
  "scan": {
    "findings": [
      {"cve": "CVE-2022-32149", "purl": "pkg:golang/golang.org/x/text@0.3.7", "cvss": 7.5, "severity": "HIGH", "fix_version": "0.3.8"}
    ],
    "critical_high_count": 1
  },
  "vex": {
    "statements": [
      {"cve": "CVE-2022-32149", "purl": "pkg:golang/golang.org/x/text@0.3.7", "status": "not_affected", "justification": "vulnerable_code_not_present"}
    ]
  },
  "kev": {
    "catalog_date": "2026-04-03",
    "cves": ["CVE-2024-3094", "CVE-2023-44487"]
  },
  "provenance": {
    "exists": true,
    "builder_id": "https://github.com/actions/runner",
    "source_repo": "https://github.com/acme/my-product",
    "build_type": "https://slsa.dev/provenance/v1"
  },
  "signatures": {
    "exists": true,
    "files": [
      {"path": "my-product.sig", "format": "cosign"}
    ]
  },
  "product": {
    "exists": true,
    "name": "my-product",
    "version": "2.1.0",
    "release_date": "2025-06-01",
    "support_end_date": "2031-06-01",
    "support_years": 6,
    "update_mechanism": {
      "type": "automatic",
      "url": "https://updates.example.com/my-product",
      "auto_update_default": true,
      "security_updates_separate": true
    }
  }
}
```

## Rego Policy Contract

Every policy must produce a `result` object at `data.cra.<package>.result`:

```rego
package cra.sbom_valid

import rego.v1

# Default: FAIL (proven innocent, not assumed)
default result := {
    "rule_id": "CRA-AI-1.1",
    "name": "SBOM exists and is valid",
    "cra_reference": "Annex I Part II.1",
    "status": "FAIL",
    "severity": "critical",
    "evidence": {}
}

# PASS when all checks satisfied
result := r if {
    input.sbom.format in {"cyclonedx", "spdx"}
    input.sbom.metadata.name != ""
    input.sbom.metadata.version != ""
    count(input.sbom.components) > 0
    purl_count := count([c | some c in input.sbom.components; c.purl != ""])

    r := {
        "rule_id": "CRA-AI-1.1",
        "name": "SBOM exists and is valid",
        "cra_reference": "Annex I Part II.1",
        "status": "PASS",
        "severity": "critical",
        "evidence": {
            "sbom_format": input.sbom.format,
            "sbom_version": input.sbom.version,
            "component_count": count(input.sbom.components),
            "components_with_purl": purl_count,
            "has_metadata": true,
            "has_supplier": input.sbom.metadata.supplier != ""
        }
    }
}
```

### SKIP Handling

Policies with optional inputs check for existence first:

```rego
package cra.provenance

import rego.v1

result := r if {
    not input.provenance.exists
    r := {
        "rule_id": "CRA-AI-3.1",
        "name": "Build provenance exists (SLSA L1+)",
        "cra_reference": "Art. 13",
        "status": "SKIP",
        "severity": "high",
        "evidence": {"reason": "No provenance attestation provided (--provenance flag)"}
    }
}
```

### Engine Behavior

1. Load all embedded `.rego` files from `policies/` via `embed.FS`
2. If `--policy-dir` provided, load additional `.rego` files (custom policies follow the same contract)
3. Discover all policy packages by querying `data.cra`
4. For each package, evaluate `data.cra.<package>.result` with the unified input
5. Collect results; policies that return no result default to FAIL
6. Custom policies are additive — duplicate rule_id across embedded and custom produces an error

## CISA KEV Integration

### Fetching

- Default: HTTP GET from `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Cache: Written to `$XDG_CACHE_HOME/suse-cra-toolkit/kev.json` (or `~/.cache/...`)
- Cache TTL: 24 hours — re-fetched if stale
- Override: `--kev` flag provides a local file, skips fetch entirely
- Offline: If fetch fails and no cache exists and no `--kev`, policy CRA-AI-2.1 produces SKIP with error reason

### Parsing

The KEV JSON contains a `vulnerabilities` array with `cveID` fields. We extract all CVE IDs into a set for O(1) lookup.

## Report Output

### JSON Format

See the OPA Input Document section for the `results` array structure. Top-level report includes:

- `report_id` — Unique ID with timestamp
- `toolkit_version` — Binary version
- `timestamp` — RFC 3339
- `summary` — Counts of PASS/FAIL/SKIP/HUMAN
- `results` — Array of policy results (machine-checked first, then human-flagged)

### Markdown Format

Human-readable report suitable for auditors:

- Title with report metadata
- Summary table
- Machine-checked policies grouped by status (FAIL first, then PASS, then SKIP)
- Human review checklist with auditor guidance
- FAILs include actionable remediation guidance

## Testing Strategy

### Unit Tests

Per-file tests with real data, no mocks:

| File | Coverage |
|------|----------|
| `input_test.go` | Input document assembly — valid SBOM, missing optional fields, components with/without PURLs |
| `engine_test.go` | OPA engine loads embedded policies, loads custom policies, evaluates policies, returns structured results |
| `kev_test.go` | KEV JSON parsing, CVE lookup, malformed KEV data handling |
| `report_test.go` | Report assembly, JSON serialization, markdown rendering, summary counts |
| `provenance_test.go` | SLSA provenance parsing — valid v0.2/v1.0, missing fields, invalid JSON |
| `signature_test.go` | Signature file detection and parsing — cosign bundles, PGP |

### Integration Tests

Fixtures in `testdata/integration/policykit-*/`:

| Scenario | Description | Expected |
|----------|-------------|----------|
| `policykit-all-pass` | Valid SBOM, no KEV hits, full VEX coverage, provenance, signatures, valid product config | All 7 PASS |
| `policykit-kev-fail` | Project with CVE in CISA KEV (CVE-2024-3094 xz-utils) | CRA-AI-2.1 FAIL |
| `policykit-vex-gap` | Critical CVEs without VEX assessment | CRA-AI-2.2 FAIL |
| `policykit-missing-optional` | No provenance, signatures, or product config | CRA-AI-3.1, 3.2, 4.1, 4.2 SKIP |
| `policykit-invalid-sbom` | Malformed SBOM (missing metadata, no components) | CRA-AI-1.1 FAIL |
| `policykit-mixed` | Realistic mixed scenario | Mixed results |

Each fixture contains real artifacts and an `expected.json` with assertions.

**Real test data sources:**
- CVE-2022-32149 (golang.org/x/text) — reused from vex/csaf fixtures
- CVE-2024-3094 (xz-utils) — in real CISA KEV catalog, perfect for KEV cross-check
- SBOMs generated by Syft, scans by Grype — same toolchain as vex/csaf

### LLM Judge Tests

Build-tagged `//go:build llmjudge`. Invokes Gemini CLI.

**Scoring dimensions** (1-10, threshold >= 8):

1. **Regulatory accuracy** — Rule IDs and CRA references correctly cite Annex I / Art. 13
2. **Evidence quality** — Evidence is specific, verifiable, and actionable
3. **Completeness** — All machine-checkable requirements covered, human-review items listed
4. **Report clarity** — Understandable by a compliance officer without CRA expertise
5. **Accuracy** — PASS/FAIL/SKIP statuses correct given the input artifacts
6. **Overall quality** — Acceptable as part of an Annex VII technical file

Reference: Actual CRA Annex I text from EU regulation PDF.

### Taskfile Targets

```yaml
test:policykit:
  desc: Run policykit integration tests
  cmds:
    - go test -race -count=1 -run TestIntegration ./pkg/policykit/...

test:policykit:llmjudge:
  desc: Run policykit LLM quality judge tests (requires gemini CLI)
  cmds:
    - go test -race -count=1 -tags llmjudge -run TestLLMJudge -v ./pkg/policykit/...
```

## Custom Policies

Users can provide additional Rego policies via `--policy-dir`. Custom policies:

- Must follow the same contract (`data.cra.<package>.result`)
- Are additive — they cannot override embedded policies
- Duplicate `rule_id` across embedded and custom produces an error
- Are evaluated with the same unified input document

This allows organizations to add internal security policies (e.g., "no GPL dependencies", "minimum test coverage") alongside the CRA checks.
