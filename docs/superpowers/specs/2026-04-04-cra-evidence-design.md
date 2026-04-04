# cra-evidence: CRA Compliance Evidence Bundler — Design Spec

## Overview

`cra-evidence` bundles compliance outputs from all other toolkit tools (SBOM, VEX, scans, policy reports, CSAF advisories, Art. 14 notifications) plus manufacturer-provided documents into a signed, versioned CRA evidence package for Annex VII technical documentation.

**CRA Articles covered:** Art. 13(4), Art. 13(12-13), Art. 31, Annex VII (all 8 sections), Annex VIII (supporting evidence for conformity assessment)

**Scope:**
- Collect and organize artifacts into Annex VII directory structure
- Cross-validate consistency across artifacts
- Generate completeness report mapping artifacts to Annex VII sections
- Generate Annex VII summary from real parsed artifact data
- Compute SHA-256 manifest and Cosign-sign the bundle
- Optionally produce a `.tar.gz` archive

**Phase 1 constraints:** Deterministic, no LLM. Summary stats extracted from real data. No content synthesis or fabrication.

## Regulatory Honesty Notes

These constraints are documented upfront so the tool does not create false confidence:

1. **Completeness score is a toolkit quality metric.** The CRA does not define completeness percentages or thresholds. The weighted score helps manufacturers identify gaps before a conformity assessment. It is not a regulatory compliance measure.

2. **Weights are indicative, not regulatory.** They reflect our assessment of relative importance based on Annex VII content requirements and Annex VIII examination procedures. A market surveillance authority may weigh sections differently.

3. **"Covered" means the artifact exists in the bundle.** It does not mean the content is sufficient. A manufacturer-provided risk assessment could be one page or one hundred — the tool cannot judge content quality of opaque documents.

4. **The tool is a bundler, not an assessor.** It organizes evidence for conformity assessment. It does not perform conformity assessment. The manufacturer retains full responsibility for the adequacy of the technical documentation per Art. 31.

5. **Signing is a toolkit integrity feature.** The CRA does not mandate cryptographic signing of the technical documentation bundle. Cosign signing is our value-add so manufacturers can demonstrate the bundle hasn't been tampered with since assembly. If Cosign is unavailable, the bundle is still valid — just unsigned.

6. **Cross-validation catches inconsistencies, not compliance gaps.** A bundle where all cross-validation checks pass is consistent, not necessarily compliant. Compliance depends on the content quality of each artifact, which is the manufacturer's responsibility.

## Architecture: Staged Pipeline

Stateless, single-pass pipeline. Each stage is a separate function, independently testable.

### Pipeline Flow

```
Run(opts, io.Writer)
|
+- 1. parseInputs(opts) -> BundleContext
|     +- loadProductConfig (extended with evidence section)
|     +- resolveArtifactPaths (check each file exists)
|     +- detectFormats (reuse formats package for SBOM/VEX/scan)
|
+- 2. validate(ctx) -> []ValidationCheck
|     +- validateSBOM (valid CycloneDX or SPDX)
|     +- validateVEX (valid OpenVEX or CSAF VEX)
|     +- validateScans (valid Grype/Trivy/SARIF)
|     +- validatePolicyReport (valid policykit JSON)
|     +- validateCSAF (valid CSAF 2.0)
|     +- validateReport (valid Art. 14 JSON)
|     +- manufacturer docs: existence check only (opaque files)
|
+- 3. crossValidate(ctx) -> []ValidationCheck
|     +- checkSBOMvsVEX: SBOM component PURLs match VEX subjects
|     +- checkSBOMvsScans: scanned components exist in SBOM
|     +- checkProductIdentity: product name/version consistent across artifacts
|     +- checkVEXvsScan: CVEs in scan results have VEX assessments
|     +- checkPolicyvsArtifacts: policy report references match bundled evidence
|     +- checkPolicyvsVEX: policy VEX coverage rules match VEX doc
|     +- checkCSAFvsVEX: CSAF advisory CVEs match VEX statuses
|     +- checkCSAFvsSBOM: CSAF product tree matches SBOM product
|     +- checkReportvsScans: Art. 14 notification CVEs exist in scan results
|
+- 4. assemble(ctx, outputDir) -> []ArtifactEntry
|     +- create Annex VII directory structure
|     +- copy artifacts into structure
|     +- compute SHA-256 manifest
|
+- 5. summarize(ctx) -> CompletenessReport, AnnexVIISummary
|     +- mapArtifactsToSections: which Annex VII sections are covered
|     +- computeCompleteness: weighted score based on section coverage
|     +- extractSBOMStats: component count, format, top deps (from real SBOM)
|     +- extractVulnStats: assessed CVE count, status breakdown (from real VEX)
|     +- extractPolicyStats: pass/fail/human counts (from real policy report)
|     +- extractScanStats: severity distribution (from real scan data)
|
+- 6. sign(manifestPath) -> *SignatureInfo
|     +- locate cosign binary
|     +- if found: cosign sign-blob --bundle manifest.sha256
|     +- if not found: warn, return SignatureInfo{Method: "unsigned"}
|
+- 7. render(bundle, format) -> output
|     +- JSON: marshal Bundle struct
|     +- Markdown: render completeness + summary + validation results
|
+- 8. archive(outputDir) -> .tar.gz (if --archive flag)
```

### Key Design Decisions

- **No data synthesis.** Summary stats are extracted directly from parsed artifacts. `SBOMStats.ComponentCount` comes from parsing the real SBOM and counting components. `VulnHandlingStats.AssessedCVEs` comes from parsing the real VEX document. The tool never fabricates content.
- **Manufacturer docs are opaque.** We check they exist and include them in the bundle, but we don't parse PDFs or Word documents. We record their SHA-256 and map them to Annex VII sections.
- **Cross-validation is strict.** Product identity mismatches and PURL mismatches are `"fail"`, not `"warn"`. If the SBOM says product X v1.0 but the policy report says product Y v2.0, that's a real problem the user must fix.
- **SBOM in two locations.** Annex VII point 2(b) requires SBOM as part of vulnerability handling evidence. Point 8 requires SBOM for market surveillance. Same file, referenced in both sections.
- **Signing is best-effort.** Cosign missing = warning in completeness report, not an error. Bundle is still valid and useful.
- **Permissive bundling.** The tool bundles whatever is provided. Missing artifacts are gaps in the completeness report, not errors. The CRA says Annex VII content is included "as applicable to the relevant product" — not every product needs every section.
- **Extended product config.** The existing `product-config.yaml` used by policykit and report is extended with an `evidence` section for Annex VII metadata. Single source of truth for product identity.

## Data Model

### Options

```go
type Options struct {
    // Toolkit-generated artifacts
    SBOMPath       string
    VEXPath        string
    ScanPaths      []string
    PolicyReport   string
    CSAFPath       string
    ReportPath     string   // Art. 14 notification

    // Manufacturer-provided documents
    RiskAssessment    string
    ArchitectureDocs  string
    ProductionProcess string
    EUDeclaration     string
    CVDPolicy         string
    StandardsDoc      string

    // Configuration
    ProductConfig  string
    OutputDir      string
    OutputFormat   string   // "json" or "markdown"
    Archive        bool     // produce .tar.gz alongside directory
    SigningKey     string   // optional Cosign key path (keyless if empty)
}
```

### Bundle (Top-Level Output)

```go
type Bundle struct {
    BundleID        string              `json:"bundle_id"`
    ToolkitVersion  string              `json:"toolkit_version"`
    Timestamp       string              `json:"timestamp"`
    Product         ProductIdentity     `json:"product"`
    Artifacts       []ArtifactEntry     `json:"artifacts"`
    Validation      ValidationReport    `json:"validation"`
    Completeness    CompletenessReport  `json:"completeness"`
    Summary         AnnexVIISummary     `json:"annex_vii_summary"`
    Manifest        Manifest            `json:"manifest"`
    Signature       *SignatureInfo      `json:"signature,omitempty"`
}
```

### ProductIdentity (Extended Product Config)

```go
type ProductIdentity struct {
    Name                string   `json:"name"`
    Version             string   `json:"version"`
    Manufacturer        string   `json:"manufacturer"`
    IntendedPurpose     string   `json:"intended_purpose"`
    ProductClass        string   `json:"product_class"`        // default, important-I, important-II, critical
    SupportPeriodEnd    string   `json:"support_period_end"`
    ConformityProcedure string   `json:"conformity_procedure"` // module-A, module-B, module-C, module-H
    SecurityContact     string   `json:"security_contact"`
    CVDPolicyURL        string   `json:"cvd_policy_url"`
}
```

### ArtifactEntry

```go
type ArtifactEntry struct {
    Path          string `json:"path"`           // relative path in bundle
    AnnexVIIRef   string `json:"annex_vii_ref"`  // e.g. "2b", "6", "8"
    Format        string `json:"format"`         // e.g. "cyclonedx-json", "csaf-2.0"
    SHA256        string `json:"sha256"`
    Source        string `json:"source"`          // "toolkit" or "manufacturer"
    Description   string `json:"description"`
}
```

### ValidationReport

```go
type ValidationReport struct {
    Checks   []ValidationCheck `json:"checks"`
    Passed   int               `json:"passed"`
    Failed   int               `json:"failed"`
    Warnings int               `json:"warnings"`
}

type ValidationCheck struct {
    CheckID     string `json:"check_id"`
    Description string `json:"description"`
    Status      string `json:"status"`   // "pass", "fail", "warn"
    Details     string `json:"details"`
    ArtifactA   string `json:"artifact_a"`
    ArtifactB   string `json:"artifact_b,omitempty"`
}
```

### CompletenessReport

```go
type CompletenessReport struct {
    Sections      []AnnexVIISection `json:"sections"`
    Score         float64           `json:"score"`
    TotalWeight   int               `json:"total_weight"`
    CoveredWeight int               `json:"covered_weight"`
}

type AnnexVIISection struct {
    ID        string   `json:"id"`           // "1a", "2b-sbom", "6", etc.
    Title     string   `json:"title"`
    CRARef    string   `json:"cra_ref"`      // "Annex VII, point 2(b)"
    Required  bool     `json:"required"`
    Covered   bool     `json:"covered"`
    Artifacts []string `json:"artifacts"`     // paths of artifacts covering this section
    Gap       string   `json:"gap,omitempty"` // what's missing
}
```

### AnnexVIISummary

```go
type AnnexVIISummary struct {
    ProductDescription    string             `json:"product_description"`
    SBOMStats             *SBOMStats         `json:"sbom_stats,omitempty"`
    VulnHandlingStats     *VulnHandlingStats `json:"vuln_handling_stats,omitempty"`
    PolicyComplianceStats *PolicyStats       `json:"policy_compliance_stats,omitempty"`
    ScanStats             *ScanStats         `json:"scan_stats,omitempty"`
    SupportPeriod         string             `json:"support_period"`
    ConformityProcedure   string             `json:"conformity_procedure"`
    StandardsApplied      []string           `json:"standards_applied,omitempty"`
}
```

### Manifest and Signature

```go
type Manifest struct {
    Algorithm string            `json:"algorithm"` // "sha256"
    Entries   map[string]string `json:"entries"`   // path -> hash
}

type SignatureInfo struct {
    Method      string `json:"method"`      // "cosign-keyless", "cosign-key", "unsigned"
    Signature   string `json:"signature"`   // base64 or path
    Certificate string `json:"certificate,omitempty"`
    LogIndex    *int64 `json:"log_index,omitempty"` // Rekor transparency log
}
```

## Cross-Validation Checks

| Check ID | Artifacts | What it checks | Severity |
|---|---|---|---|
| `CV-SBOM-VEX-PURL` | SBOM + VEX | Every VEX subject PURL exists as a component in the SBOM | fail |
| `CV-SBOM-SCAN-COMP` | SBOM + Scans | Scanned components (by PURL) exist in the SBOM | fail |
| `CV-SCAN-VEX-CVE` | Scans + VEX | Every CVE in scan results has a corresponding VEX assessment | warn |
| `CV-PRODUCT-IDENTITY` | All artifacts | Product name and version consistent across SBOM, policy report, CSAF product tree, product config | fail |
| `CV-POLICY-SBOM` | Policy + SBOM | Policy report evaluated the same SBOM (component count sanity check) | fail |
| `CV-POLICY-VEX` | Policy + VEX | If policy checks VEX assessment coverage, the VEX doc should cover those CVEs | warn |
| `CV-CSAF-VEX` | CSAF + VEX | CSAF advisory CVEs have matching VEX statuses | warn |
| `CV-CSAF-SBOM` | CSAF + SBOM | CSAF product tree product matches SBOM product | fail |
| `CV-REPORT-SCAN` | Art.14 + Scans | CVEs in Art. 14 notification exist in scan results | fail |

### Rules

- **fail** = inconsistency that would undermine credibility with a market surveillance authority. Bundle is still created, but the validation report clearly flags it.
- **warn** = potential gap that the user should review but isn't necessarily wrong (e.g., a scan CVE with no VEX assessment might be intentionally under investigation).
- Checks only run when both artifacts are present. If there's no VEX document, `CV-SBOM-VEX-PURL` is skipped — the completeness report already flags the missing VEX.
- Each check reports the specific mismatched items (e.g., "PURL pkg:golang/x/text@v0.3.7 in VEX but not in SBOM").

## Completeness Report — Annex VII Mapping

Weights reflect regulatory importance based on Annex VII content requirements and Annex VIII examination procedures.

| ID | Annex VII Section | Weight | Covered By |
|---|---|---|---|
| `1a` | General description — intended purpose | 10 | Product config `intended_purpose` field |
| `1b` | Versions affecting compliance | 5 | SBOM product version + component versions |
| `1c` | Hardware photos/illustrations | 0 | N/A for software products (weight 0) |
| `1d` | User information per Annex II | 5 | Product config fields (security contact, CVD URL, support period) |
| `2a` | Design/development/architecture | 10 | Manufacturer-provided architecture document |
| `2b-sbom` | Vulnerability handling — SBOM | 15 | SBOM artifact |
| `2b-cvd` | Vulnerability handling — CVD policy | 10 | CVD policy document or product config `cvd_policy_url` |
| `2b-updates` | Vulnerability handling — secure update mechanism | 5 | Product config or manufacturer document |
| `2c` | Production/monitoring processes | 5 | Manufacturer-provided document |
| `3` | Cybersecurity risk assessment | 15 | Manufacturer-provided risk assessment |
| `4` | Support period determination | 5 | Product config `support_period_end` |
| `5` | Harmonised standards applied | 5 | Standards document or product config `standards_applied` |
| `6` | Test/verification reports | 10 | Policy report + scan results + VEX results |
| `7` | EU declaration of conformity | 10 | Manufacturer-provided EU DoC |
| `8` | SBOM (market surveillance) | 5 | Same SBOM as 2b-sbom (auto-covered if SBOM present) |

### Score Calculation

```
score = covered_weight / total_applicable_weight * 100
```

`total_applicable_weight` excludes sections with weight 0 (e.g., 1c for software products). A pure-software product has `total_applicable_weight = 115`.

## Output Directory Structure

```
evidence-bundle-{product}-{version}-{timestamp}/
  annex-vii/
    1-general-description/
      product-config.yaml
    2a-design-development/
      architecture.pdf (if provided)
    2b-vulnerability-handling/
      sbom.cdx.json
      vex.json
      cvd-policy.md (if provided)
    2c-production-monitoring/
      production-process.pdf (if provided)
    3-risk-assessment/
      risk-assessment.pdf (if provided)
    4-support-period/
      (covered by product-config.yaml in 1-general-description/)
    5-standards/
      standards.md (if provided)
    6-test-reports/
      policy-report.json
      vex-results.json
      grype.json / trivy.json
      csaf.json (if provided)
      art14-notification.json (if provided)
    7-eu-declaration/
      eu-doc.pdf (if provided)
    8-sbom/
      sbom.cdx.json (copy from 2b — no symlinks for archive portability)
  bundle.json            (the Bundle struct — full machine-readable output)
  completeness.md        (rendered completeness report)
  annex-vii-summary.md   (rendered summary with real stats)
  manifest.sha256
  manifest.sha256.sig    (if signed)
```

## CLI Interface

```go
func newEvidenceCmd() *urfave.Command {
    return &urfave.Command{
        Name:  "evidence",
        Usage: "Bundle compliance outputs into a signed CRA evidence package for Annex VII",
        Flags: []urfave.Flag{
            // Toolkit-generated artifacts
            &urfave.StringFlag{Name: "sbom", Usage: "Path to SBOM (CycloneDX or SPDX)"},
            &urfave.StringFlag{Name: "vex", Usage: "Path to VEX document (OpenVEX or CSAF)"},
            &urfave.StringSliceFlag{Name: "scan", Usage: "Path to scan results (Grype/Trivy/SARIF), repeatable"},
            &urfave.StringFlag{Name: "policy-report", Usage: "Path to cra-policykit report (JSON)"},
            &urfave.StringFlag{Name: "csaf", Usage: "Path to CSAF advisory"},
            &urfave.StringFlag{Name: "art14-report", Usage: "Path to Art. 14 notification (JSON)"},

            // Manufacturer-provided documents
            &urfave.StringFlag{Name: "risk-assessment", Usage: "Path to cybersecurity risk assessment document"},
            &urfave.StringFlag{Name: "architecture", Usage: "Path to design/development architecture document"},
            &urfave.StringFlag{Name: "production-process", Usage: "Path to production/monitoring process document"},
            &urfave.StringFlag{Name: "eu-declaration", Usage: "Path to EU declaration of conformity"},
            &urfave.StringFlag{Name: "cvd-policy", Usage: "Path to coordinated vulnerability disclosure policy"},
            &urfave.StringFlag{Name: "standards", Usage: "Path to harmonised standards document"},

            // Configuration
            &urfave.StringFlag{Name: "product-config", Usage: "Path to product configuration (YAML)"},
            &urfave.StringFlag{Name: "output-dir", Usage: "Output directory for evidence bundle"},
            &urfave.StringFlag{Name: "format", Value: "json", Usage: "Output format: json, markdown"},
            &urfave.BoolFlag{Name: "archive", Usage: "Also produce .tar.gz archive"},
            &urfave.StringFlag{Name: "signing-key", Usage: "Cosign key path (keyless if omitted)"},
        },
        Action: func(_ context.Context, cmd *urfave.Command) error {
            opts := &evidence.Options{
                SBOMPath:          cmd.String("sbom"),
                VEXPath:           cmd.String("vex"),
                ScanPaths:         cmd.StringSlice("scan"),
                PolicyReport:      cmd.String("policy-report"),
                CSAFPath:          cmd.String("csaf"),
                ReportPath:        cmd.String("art14-report"),
                RiskAssessment:    cmd.String("risk-assessment"),
                ArchitectureDocs:  cmd.String("architecture"),
                ProductionProcess: cmd.String("production-process"),
                EUDeclaration:     cmd.String("eu-declaration"),
                CVDPolicy:         cmd.String("cvd-policy"),
                StandardsDoc:      cmd.String("standards"),
                ProductConfig:     cmd.String("product-config"),
                OutputDir:         cmd.String("output-dir"),
                OutputFormat:      cmd.String("format"),
                Archive:           cmd.Bool("archive"),
                SigningKey:         cmd.String("signing-key"),
            }
            w, closer := OutputWriter(cmd)
            defer closer()
            return evidence.Run(opts, w)
        },
    }
}
```

### Usage Examples

```bash
# Full pipeline: bundle all toolkit outputs + manufacturer docs
cra evidence \
  --sbom sbom.cdx.json \
  --vex vex-results.json \
  --scan grype.json \
  --policy-report policykit-report.json \
  --csaf advisory.csaf.json \
  --art14-report art14-notification.json \
  --risk-assessment risk-assessment.pdf \
  --architecture architecture.pdf \
  --eu-declaration eu-doc.pdf \
  --cvd-policy cvd-policy.md \
  --product-config product-config.yaml \
  --output-dir ./evidence-bundle \
  --archive

# Minimal: just SBOM + scan (completeness report shows gaps)
cra evidence \
  --sbom sbom.cdx.json \
  --scan grype.json \
  --product-config product-config.yaml \
  --output-dir ./evidence-bundle
```

## Extended Product Config

The existing `product-config.yaml` is extended with an `evidence` section:

```yaml
# Existing fields (shared with policykit/report)
product:
  name: "my-product"
  version: "1.0.0"
  manufacturer: "ACME Corp"
  member_state: "DE"
  support_period_end: "2031-12-31"

# New evidence section
evidence:
  intended_purpose: "Container runtime for orchestrating workloads in enterprise environments"
  product_class: "important-II"           # default, important-I, important-II, critical
  conformity_procedure: "module-A"        # module-A, module-B, module-C, module-H
  security_contact: "security@acme.com"
  cvd_policy_url: "https://acme.com/.well-known/security.txt"
  standards_applied:
    - "EN ISO/IEC 27001:2022"
    - "ISO/IEC 62443-4-1:2018"
```

## Testing Strategy

### Integration Test Fixtures

Each fixture directory under `testdata/integration/evidence-*/` contains real artifacts from open-source projects:

| Fixture | Scenario | Key Assertion |
|---|---|---|
| `evidence-full-bundle` | All artifacts present (SBOM, VEX, scan, policy, CSAF, manufacturer docs) | Completeness score 100%, all cross-validation checks pass, signed manifest |
| `evidence-minimal` | Only SBOM + scan + product config | Completeness report shows specific gaps, bundle still created |
| `evidence-cross-validation-mismatch` | SBOM product name differs from policy report product name | `CV-PRODUCT-IDENTITY` check fails, validation report flags it |
| `evidence-purl-mismatch` | VEX contains PURLs not in SBOM | `CV-SBOM-VEX-PURL` check fails with specific mismatched PURLs listed |
| `evidence-no-signing` | Full bundle but cosign not on PATH | Bundle created, `signature.method = "unsigned"`, completeness warns |
| `evidence-multiple-scans` | Two scan files (grype + trivy) for same product | Both included under section 6, cross-validation runs against both |

### Integration Test Structure

```go
type expectedEvidence struct {
    Description string `json:"description"`
    Assertions  struct {
        ArtifactCount        int      `json:"artifact_count"`
        MinCompleteness      float64  `json:"min_completeness"`
        MaxCompleteness      float64  `json:"max_completeness"`
        CoveredSections      []string `json:"covered_sections"`
        MissingSections      []string `json:"missing_sections"`
        ValidationPassed     int      `json:"validation_passed"`
        ValidationFailed     int      `json:"validation_failed"`
        ValidationWarnings   int      `json:"validation_warnings"`
        FailedChecks         []string `json:"failed_checks"`
        ProductName          string   `json:"product_name"`
        ProductVersion       string   `json:"product_version"`
        HasSignature         bool     `json:"has_signature"`
        SBOMComponentCount   int      `json:"sbom_component_count"`
        VEXAssessedCVEs      int      `json:"vex_assessed_cves"`
        Error                string   `json:"error"`
    } `json:"assertions"`
}
```

### LLM Judge Test

`llm_judge_test.go` with `//go:build llmjudge` tag. Generates a full evidence bundle from the `evidence-full-bundle` fixture, then asks the LLM to evaluate:

| Dimension | What it evaluates |
|---|---|
| `annex_vii_coverage` | Does the bundle structure map correctly to Annex VII sections? |
| `cross_validation_rigor` | Are consistency checks meaningful and correctly reported? |
| `completeness_accuracy` | Does the completeness report honestly reflect what's present vs missing? |
| `summary_accuracy` | Are Annex VII summary stats derived from real data, not fabricated? |
| `regulatory_honesty` | Does the output avoid overstating compliance or the tool's role? |
| `overall_quality` | Would a compliance officer trust this for conformity assessment preparation? |

Threshold: 8/10 on all dimensions.

### Unit Tests

| File | Coverage |
|---|---|
| `validate_test.go` | Format detection and validation for each artifact type |
| `crossvalidate_test.go` | Each cross-validation check with real mismatched data |
| `completeness_test.go` | Score calculation and section mapping |
| `manifest_test.go` | SHA-256 computation and manifest generation |
| `summary_test.go` | Stats extraction from real SBOM/VEX/policy/scan data |

## File Structure

```
pkg/evidence/
├── evidence.go           # Run() pipeline orchestrator, Options struct
├── types.go              # Bundle, ArtifactEntry, ValidationReport, CompletenessReport, etc.
├── collect.go            # parseInputs, resolveArtifactPaths, detectFormats
├── validate.go           # per-artifact format/schema validation
├── crossvalidate.go      # cross-artifact consistency checks
├── assemble.go           # directory structure creation, file copying, manifest generation
├── completeness.go       # Annex VII section mapping, weighted score calculation
├── summary.go            # AnnexVIISummary extraction from real artifact data
├── sign.go               # Cosign invocation with graceful degradation
├── render.go             # JSON + markdown rendering
├── archive.go            # tar.gz creation from output directory
├── integration_test.go   # fixture-based integration tests
├── llm_judge_test.go     # LLM quality validation (build tag: llmjudge)
├── validate_test.go      # unit tests for format validation
├── crossvalidate_test.go # unit tests for cross-validation checks
├── completeness_test.go  # unit tests for completeness scoring
├── manifest_test.go      # unit tests for SHA-256 manifest
└── summary_test.go       # unit tests for stats extraction

internal/cli/
└── evidence.go           # CLI wiring (replaces current stub)

testdata/integration/
├── evidence-full-bundle/
├── evidence-minimal/
├── evidence-cross-validation-mismatch/
├── evidence-purl-mismatch/
├── evidence-no-signing/
└── evidence-multiple-scans/
```
