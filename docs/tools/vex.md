# VEX (Vulnerability Exploitability eXchange)

`cra vex` is a VEX determination pipeline that automates the assessment of vulnerability exploitability for a software product. It takes SBOMs and vulnerability scan results as input and generates VEX statements that clearly communicate whether a vulnerability is applicable and why.

## Overview

The Cyber Resilience Act requires software manufacturers to provide accurate information about the security of their products. `cra vex` helps meet this requirement by automatically determining the exploitability status of vulnerabilities found by scanners.

## How it Works

`cra vex` uses a **deterministic filter chain** to assess each vulnerability finding. The chain applies a series of checks, from upstream information down to deep reachability analysis.

### The Filter Chain

1.  **Upstream Filter:** Checks if an upstream VEX document already provides a status for the vulnerability.
2.  **Presence Filter:** Determines if the vulnerable component is actually present in the final product.
3.  **Version Filter:** Verifies if the component version falls within the vulnerable range.
4.  **Platform Filter:** Checks if the vulnerability is specific to a platform (OS/Architecture) different from the product's.
5.  **Patch Filter:** Determines if the vulnerability has already been patched in the component's source.
6.  **Reachability Filter:** Performs code analysis to see if the vulnerable function or path is actually reachable in the product's execution.

### Reachability Analysis

`cra vex` supports reachability analysis for multiple languages:

-   **Go:** Uses `govulncheck` and call-graph analysis.
-   **Rust:** Uses cargo-specific vulnerability database checks and call-graph analysis.
-   **Generic:** A fallback analyzer for other languages based on static file analysis.

## Usage

### Basic Command

```bash
cra vex --sbom <path-to-sbom> --scan <path-to-scan-results>
```

### Advanced Usage with Reachability

```bash
cra vex --sbom sbom.json --scan results.sarif --source-dir ./src --output-format csaf
```

### Command Flags

| Flag | Description | Required |
| --- | --- | --- |
| `--sbom` | Path to SBOM file (CycloneDX or SPDX format). | Yes |
| `--scan` | Path to vulnerability scan results (Grype, Trivy, or SARIF). Can be repeated. | Yes |
| `--upstream-vex` | Path to an upstream VEX document (OpenVEX or CSAF). Can be repeated. | No |
| `--source-dir` | Path to the source code directory for reachability analysis. | No |
| `--output-format` | Output format for VEX results: `openvex` (default) or `csaf`. | No |
| `--output`, `-o` | Output file path (default: stdout). | No |

## Supported Formats

### Input Formats

-   **SBOM:** CycloneDX (JSON), SPDX (JSON/Tag-Value).
-   **Vulnerability Scans:** Grype (JSON), Trivy (JSON), SARIF.
-   **Upstream VEX:** OpenVEX (JSON), CSAF (JSON).

### Output Formats

-   **OpenVEX:** The default industry-standard format for VEX data.
-   **CSAF (Common Security Advisory Framework):** Standardized advisory format.

## Example

Suppose you have a CycloneDX SBOM (`sbom.cdx.json`) and a Grype scan result (`scan.json`). To generate an OpenVEX document while performing reachability analysis on your Go source code:

```bash
cra vex --sbom sbom.cdx.json --scan scan.json --source-dir . --output-format openvex -o vex.json
```
