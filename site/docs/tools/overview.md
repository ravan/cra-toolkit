# How the Tools Work Together

The CRA Compliance Toolkit provides five commands that form a complete compliance pipeline. Each tool produces standard-format output that downstream tools can consume, letting you run a single tool in isolation or chain the entire pipeline for full CRA compliance.

## The Compliance Pipeline

![CRA Compliance Pipeline](../assets/diagrams/tool-pipeline.svg)

### Data Flow

1. **External tools generate inputs** — SBOM generators (syft, cdxgen) produce a software bill of materials, and vulnerability scanners (Grype, Trivy) produce scan results. These are the raw inputs to the toolkit.

2. **`cra vex`** consumes an SBOM, scan results, optional upstream VEX documents, and optional source code. It performs reachability analysis and produces a VEX document in OpenVEX or CSAF format that captures vulnerability exploitability assessments for every finding.

3. **`cra policykit`** consumes an SBOM, scan results, VEX document, and optional provenance, signatures, or product configuration. It evaluates Annex I security requirements against embedded OPA policies and produces a policy evaluation report showing which requirements pass, fail, or need attention.

4. **`cra report`** consumes an SBOM, scan results, optional VEX document, product configuration, and optional KEV/EPSS enrichment data. It produces Article 14 notification documents suitable for submission to ENISA and national CSIRTs.

5. **`cra csaf`** consumes an SBOM, scan results, and an optional VEX document. It produces CSAF 2.0 security advisories that conform to the OASIS standard for machine-readable vulnerability disclosure.

6. **`cra evidence`** consumes outputs from all other tools plus any manual artifacts. It produces a signed evidence bundle that packages every compliance artifact into a single, verifiable archive.

## Composability

Every tool in the toolkit is designed to work standalone or as part of a chain. Each tool's output is a standard format — OpenVEX, CSAF 2.0, JSON policy reports, Markdown notifications — that other tools can consume directly. There is no proprietary intermediate format.

For example, you can:

- Run just `cra vex` to get vulnerability exploitability assessments without generating a full report.
- Run `cra vex` followed by `cra report` to produce Article 14 notifications enriched with reachability data.
- Run the entire pipeline from `cra vex` through `cra evidence` to produce a complete, signed compliance bundle.

## Format Auto-Detection

The toolkit automatically detects input file formats by probing JSON structure. You never need to pass format flags — just point a command at a file and the toolkit figures out what it is.

Discriminating keys used for detection:

| Key | Detected Format |
|---|---|
| `bomFormat` | CycloneDX SBOM |
| `spdxVersion` | SPDX SBOM |
| `matches` | Grype scan results |
| `Results` | Trivy scan results |
| `runs` | SARIF scan results |
| `@context` containing `openvex` | OpenVEX document |
| `document.category` | CSAF advisory |

## Shared Concepts

These concepts appear across multiple tools and flow through the pipeline:

**PURLs** — Package URL identifiers (e.g., `pkg:golang/golang.org/x/text@v0.3.7`) used across all tools for consistent component identification. Every finding, policy check, and advisory references components by PURL.

**Findings** — A unified vulnerability finding structure containing the CVE ID, affected PURL, severity level, CVSS score, and fix version. Scanners produce findings, and every downstream tool consumes them in this normalized form.

**Call Paths** — Reachability evidence expressed as function call chains from an entry point to vulnerable code. The `cra vex` command generates call paths during reachability analysis, and they propagate through `cra report` and `cra evidence` so reviewers can see exactly how a vulnerability is reachable.

**Confidence Scores** — Reachability confidence levels (`high`, `medium`, `low`) indicating the quality of the reachability analysis. A `high` confidence score means static analysis confirmed the call path; `low` means the assessment is based on heuristics or incomplete data.

## Global CLI Flags

Every command inherits these flags:

| Flag | Description | Default |
|---|---|---|
| `--format`, `-f` | Output format: `json` or `text` | `json` |
| `--output`, `-o` | Output file path | stdout |
| `--quiet`, `-q` | Suppress non-essential output | `false` |
| `--verbose` | Enable debug logging | `false` |
