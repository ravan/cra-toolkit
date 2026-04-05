# Vulnerability Scanners

The CRA toolkit consumes vulnerability scan results from multiple scanners. Each scanner outputs JSON that the toolkit auto-detects — no format flags needed. This page covers how to generate compatible output from each supported scanner.

---

## Grype

[Grype](https://github.com/anchore/grype) is an open-source vulnerability scanner from Anchore. It matches software components against known vulnerability databases and produces detailed findings with CVE identifiers, severity scores, and fix version information.

Grype supports scanning container images, filesystems, directories, and SBOMs directly. Its JSON output is natively supported by `cra vex` and `cra csaf`.

### Generating compatible output

```bash
# Scan an SBOM
grype sbom:sbom.cdx.json -o json > grype.json

# Scan a directory
grype dir:. -o json > grype.json

# Scan a container image
grype myimage:latest -o json > grype.json
```

The `-o json` flag is required — the toolkit does not accept Grype's table or other output formats.

### Using with the toolkit

```bash
# VEX determination from Grype scan
cra vex --sbom sbom.cdx.json --scan grype.json -o vex.json

# CSAF advisory from Grype scan
cra csaf --sbom sbom.cdx.json --scan grype.json \
  --publisher-name "My Org" --publisher-namespace "https://example.com" \
  -o advisory.json
```

---

## Trivy

[Trivy](https://github.com/aquasecurity/trivy) is an open-source vulnerability scanner from Aqua Security. It scans container images, filesystems, git repositories, and SBOMs for known vulnerabilities, misconfigurations, and exposed secrets.

Trivy's JSON output is natively supported by `cra vex` and `cra csaf`.

### Generating compatible output

```bash
# Scan filesystem
trivy fs --format json --output trivy.json .

# Scan container image
trivy image --format json --output trivy.json myimage:latest

# Scan SBOM
trivy sbom --format json --output trivy.json sbom.cdx.json
```

The `--format json` flag is required. Trivy's table, SARIF, and CycloneDX output modes are not accepted as scan input (though Trivy SARIF output can be used via the SARIF input path).

### Using with the toolkit

```bash
# VEX determination from Trivy scan
cra vex --sbom sbom.cdx.json --scan trivy.json -o vex.json

# Multiple scan sources
cra vex --sbom sbom.cdx.json --scan grype.json --scan trivy.json -o vex.json
```

---

## SARIF Producers

Any tool that outputs [SARIF](standards.md#sarif) (Static Analysis Results Interchange Format) can feed into the CRA toolkit. SARIF is a widely adopted standard for static analysis results, supported by dozens of security tools.

### Generating compatible output

**CodeQL** (GitHub):

```bash
codeql database analyze db --format=sarif-latest --output=results.sarif
```

**Semgrep** (Semgrep, Inc.):

```bash
semgrep --config auto --sarif --output results.sarif .
```

**Other SARIF producers** — any tool that writes valid SARIF JSON can be used. Common examples include ESLint (with SARIF formatter), Checkov, Bandit, and Snyk Code.

### Using with the toolkit

```bash
# VEX determination from SARIF scan
cra vex --sbom sbom.cdx.json --scan results.sarif -o vex.json

# Combine SARIF with other scan formats
cra vex --sbom sbom.cdx.json --scan grype.json --scan results.sarif -o vex.json
```

---

## Multiple Scanners

The `--scan` flag is repeatable across all toolkit tools. Combining multiple scanners improves vulnerability coverage — different scanners use different vulnerability databases and detection methods.

```bash
# Combine Grype, Trivy, and SARIF results
cra vex --sbom sbom.cdx.json \
  --scan grype.json \
  --scan trivy.json \
  --scan results.sarif \
  -o vex.json
```

When the same CVE is reported by multiple scanners, the toolkit deduplicates findings by CVE ID and component PURL, using the most detailed report for scoring and metadata.
