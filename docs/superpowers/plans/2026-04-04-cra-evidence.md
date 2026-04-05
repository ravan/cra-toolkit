# cra-evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the CRA Annex VII compliance evidence bundler — a staged pipeline that collects toolkit-generated and manufacturer-provided artifacts, cross-validates consistency, generates completeness reports and Annex VII summaries from real data, computes a SHA-256 manifest, and optionally Cosign-signs the bundle.

**Architecture:** Stateless 8-stage pipeline following the `Run(opts *Options, out io.Writer) error` pattern: collect → validate → cross-validate → assemble → summarize → sign → render → archive. Each stage is a separate file, independently testable. No data synthesis — all summary stats extracted from real parsed artifacts.

**Tech Stack:** Go, urfave/cli v3, testify, gopkg.in/yaml.v3, crypto/sha256, archive/tar, compress/gzip. No new dependencies beyond stdlib + existing project deps.

**Spec:** `docs/superpowers/specs/2026-04-04-cra-evidence-design.md`

**Quality gates:** `task quality` must pass after every commit. Taskfile tasks added for `test:evidence` and `test:evidence:llmjudge`.

---

## File Map

| File | Responsibility |
|------|---------------|
| `pkg/evidence/types.go` | All type definitions: Bundle, Options, ProductIdentity, ArtifactEntry, ValidationReport, ValidationCheck, CompletenessReport, AnnexVIISection, AnnexVIISummary, SBOMStats, VulnHandlingStats, PolicyStats, ScanStats, Manifest, SignatureInfo |
| `pkg/evidence/collect.go` | `parseInputs()`, `loadEvidenceConfig()`, `resolveArtifactPaths()`, file parsing helpers (reuse formats package) |
| `pkg/evidence/collect_test.go` | Unit tests for config loading and artifact resolution |
| `pkg/evidence/validate.go` | Per-artifact format/schema validation |
| `pkg/evidence/validate_test.go` | Unit tests for format validation |
| `pkg/evidence/crossvalidate.go` | Cross-artifact consistency checks (9 checks) |
| `pkg/evidence/crossvalidate_test.go` | Unit tests for each cross-validation check |
| `pkg/evidence/assemble.go` | Directory structure creation, file copying |
| `pkg/evidence/manifest.go` | SHA-256 manifest computation |
| `pkg/evidence/manifest_test.go` | Unit tests for manifest generation |
| `pkg/evidence/completeness.go` | Annex VII section mapping, weighted score calculation |
| `pkg/evidence/completeness_test.go` | Unit tests for completeness scoring |
| `pkg/evidence/summary.go` | AnnexVIISummary extraction from real artifact data |
| `pkg/evidence/summary_test.go` | Unit tests for stats extraction |
| `pkg/evidence/sign.go` | Cosign invocation with graceful degradation |
| `pkg/evidence/render.go` | JSON + markdown rendering |
| `pkg/evidence/archive.go` | tar.gz creation from output directory |
| `pkg/evidence/evidence.go` | `Run()` pipeline orchestrator (replaces stub) |
| `pkg/evidence/integration_test.go` | 6 scenario integration tests |
| `pkg/evidence/llm_judge_test.go` | LLM quality judge test |
| `internal/cli/evidence.go` | CLI command wiring (replaces stub) |
| `Taskfile.yml` | Add `test:evidence` and `test:evidence:llmjudge` tasks |
| `testdata/integration/evidence-*/` | 6 test fixture directories |

---

### Task 1: Taskfile tasks and types foundation

**Files:**
- Modify: `Taskfile.yml`
- Create: `pkg/evidence/types.go`

- [ ] **Step 1: Add Taskfile tasks for evidence testing**

Add to `Taskfile.yml` after the existing `test:report:llmjudge` task:

```yaml
  test:evidence:
    desc: Run evidence integration tests
    cmds:
      - go test -race -count=1 -run TestIntegration ./pkg/evidence/...

  test:evidence:llmjudge:
    desc: Run evidence LLM quality judge tests (requires gemini CLI)
    cmds:
      - go test -race -count=1 -tags llmjudge -run TestLLMJudge -v ./pkg/evidence/...
```

- [ ] **Step 2: Create types.go with all type definitions**

Create `pkg/evidence/types.go`:

```go
// Package evidence bundles compliance outputs (SBOM, VEX, provenance, scans, policy reports)
// into a signed, versioned CRA evidence package for Annex VII technical documentation.
package evidence

import "errors"

// ErrNoProductConfig is returned when no product config is provided.
var ErrNoProductConfig = errors.New("evidence: product config is required")

// ErrNoOutputDir is returned when no output directory is specified.
var ErrNoOutputDir = errors.New("evidence: output directory is required")

// ErrNoArtifacts is returned when no artifacts are provided.
var ErrNoArtifacts = errors.New("evidence: at least one artifact is required")

// CompletenessNote is the constant disclaimer on the completeness metric.
const CompletenessNote = "Toolkit quality metric. CRA Annex VII does not define completeness thresholds."

// Options configures the evidence bundler.
type Options struct {
	// Toolkit-generated artifacts.
	SBOMPath     string
	VEXPath      string
	ScanPaths    []string
	PolicyReport string
	CSAFPath     string
	ReportPath   string // Art. 14 notification

	// Manufacturer-provided documents.
	RiskAssessment    string
	ArchitectureDocs  string
	ProductionProcess string
	EUDeclaration     string
	CVDPolicy         string
	StandardsDoc      string

	// Configuration.
	ProductConfig string
	OutputDir     string
	OutputFormat  string // "json" or "markdown"
	Archive       bool   // produce .tar.gz alongside directory
	SigningKey    string // optional Cosign key path (keyless if empty)
}

// Bundle is the top-level evidence package output.
type Bundle struct {
	BundleID     string             `json:"bundle_id"`
	ToolkitVersion string           `json:"toolkit_version"`
	Timestamp    string             `json:"timestamp"`
	Product      ProductIdentity    `json:"product"`
	Artifacts    []ArtifactEntry    `json:"artifacts"`
	Validation   ValidationReport   `json:"validation"`
	Completeness CompletenessReport `json:"completeness"`
	Summary      AnnexVIISummary    `json:"annex_vii_summary"`
	Manifest     Manifest           `json:"manifest"`
	Signature    *SignatureInfo     `json:"signature,omitempty"`
}

// ProductIdentity holds product metadata from extended product config.
type ProductIdentity struct {
	Name                string `json:"name"`
	Version             string `json:"version"`
	Manufacturer        string `json:"manufacturer"`
	IntendedPurpose     string `json:"intended_purpose"`
	ProductClass        string `json:"product_class"`
	SupportPeriodEnd    string `json:"support_period_end"`
	ConformityProcedure string `json:"conformity_procedure"`
	SecurityContact     string `json:"security_contact"`
	CVDPolicyURL        string `json:"cvd_policy_url"`
}

// ArtifactEntry describes one file in the bundle.
type ArtifactEntry struct {
	Path        string `json:"path"`
	AnnexVIIRef string `json:"annex_vii_ref"`
	Format      string `json:"format"`
	SHA256      string `json:"sha256"`
	Source      string `json:"source"`
	Description string `json:"description"`
}

// ValidationReport captures format validation and cross-validation results.
type ValidationReport struct {
	Checks   []ValidationCheck `json:"checks"`
	Passed   int               `json:"passed"`
	Failed   int               `json:"failed"`
	Warnings int               `json:"warnings"`
}

// ValidationCheck is a single validation or cross-validation result.
type ValidationCheck struct {
	CheckID     string `json:"check_id"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Details     string `json:"details"`
	ArtifactA   string `json:"artifact_a"`
	ArtifactB   string `json:"artifact_b,omitempty"`
}

// CompletenessReport maps Annex VII sections to artifact presence.
type CompletenessReport struct {
	Sections      []AnnexVIISection `json:"sections"`
	Score         float64           `json:"score"`
	TotalWeight   int               `json:"total_weight"`
	CoveredWeight int               `json:"covered_weight"`
	Note          string            `json:"note"`
}

// AnnexVIISection describes coverage of one Annex VII documentation section.
type AnnexVIISection struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	CRARef    string   `json:"cra_ref"`
	Required  bool     `json:"required"`
	Covered   bool     `json:"covered"`
	Weight    int      `json:"weight"`
	Artifacts []string `json:"artifacts,omitempty"`
	Gap       string   `json:"gap,omitempty"`
}

// AnnexVIISummary is generated from real parsed artifact data.
type AnnexVIISummary struct {
	ProductDescription    string       `json:"product_description"`
	SBOMStats             *SBOMStats   `json:"sbom_stats,omitempty"`
	VulnHandlingStats     *VulnHandlingStats `json:"vuln_handling_stats,omitempty"`
	PolicyComplianceStats *PolicyStats `json:"policy_compliance_stats,omitempty"`
	ScanStats             *ScanStats   `json:"scan_stats,omitempty"`
	SupportPeriod         string       `json:"support_period"`
	ConformityProcedure   string       `json:"conformity_procedure"`
	StandardsApplied      []string     `json:"standards_applied,omitempty"`
}

// SBOMStats holds statistics extracted from a real SBOM.
type SBOMStats struct {
	Format         string `json:"format"`
	ComponentCount int    `json:"component_count"`
	ProductName    string `json:"product_name"`
	ProductVersion string `json:"product_version"`
}

// VulnHandlingStats holds statistics extracted from a real VEX document.
type VulnHandlingStats struct {
	TotalAssessed      int            `json:"total_assessed"`
	StatusDistribution map[string]int `json:"status_distribution"`
}

// PolicyStats holds statistics extracted from a real policy report.
type PolicyStats struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
	Human   int `json:"human"`
}

// ScanStats holds statistics extracted from real scan results.
type ScanStats struct {
	TotalFindings        int            `json:"total_findings"`
	SeverityDistribution map[string]int `json:"severity_distribution"`
	ScannerCount         int            `json:"scanner_count"`
}

// Manifest is the SHA-256 file manifest for the bundle.
type Manifest struct {
	Algorithm string            `json:"algorithm"`
	Entries   map[string]string `json:"entries"`
}

// SignatureInfo describes the cryptographic signature of the manifest.
type SignatureInfo struct {
	Method      string `json:"method"`
	Signature   string `json:"signature"`
	Certificate string `json:"certificate,omitempty"`
	LogIndex    *int64 `json:"log_index,omitempty"`
}

// EvidenceConfig is the extended product config with evidence section.
type EvidenceConfig struct {
	Product  EvidenceProductSection `yaml:"product"`
	Evidence EvidenceSection        `yaml:"evidence"`
}

// EvidenceProductSection is the product metadata from the shared config.
type EvidenceProductSection struct {
	Name             string `yaml:"name"`
	Version          string `yaml:"version"`
	Manufacturer     string `yaml:"manufacturer"`
	MemberState      string `yaml:"member_state"`
	SupportPeriodEnd string `yaml:"support_end_date"`
}

// EvidenceSection holds the evidence-specific extensions.
type EvidenceSection struct {
	IntendedPurpose     string   `yaml:"intended_purpose"`
	ProductClass        string   `yaml:"product_class"`
	ConformityProcedure string   `yaml:"conformity_procedure"`
	SecurityContact     string   `yaml:"security_contact"`
	CVDPolicyURL        string   `yaml:"cvd_policy_url"`
	StandardsApplied    []string `yaml:"standards_applied"`
}

// bundleContext is the internal context built during the collect stage.
type bundleContext struct {
	config     *EvidenceConfig
	product    ProductIdentity
	artifacts  []artifactInput
	components []componentInfo
	findings   []findingInfo
	vexResults []vexInfo
	policyData *policyReportData
}

// artifactInput tracks a single input artifact and its metadata.
type artifactInput struct {
	sourcePath  string
	format      string
	annexVIIRef string
	source      string // "toolkit" or "manufacturer"
	description string
}

// componentInfo holds parsed SBOM component data for cross-validation.
type componentInfo struct {
	Name    string
	Version string
	PURL    string
}

// findingInfo holds parsed scan finding data for cross-validation.
type findingInfo struct {
	CVE          string
	AffectedPURL string
	Severity     string
}

// vexInfo holds parsed VEX result data for cross-validation.
type vexInfo struct {
	CVE           string
	ComponentPURL string
	Status        string
}

// policyReportData holds parsed policy report data for summary stats.
type policyReportData struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
	Human   int `json:"human"`
}
```

- [ ] **Step 3: Run `task build` to verify types compile**

Run: `task build`
Expected: BUILD SUCCESS

- [ ] **Step 4: Commit**

```bash
git add Taskfile.yml pkg/evidence/types.go
git commit -m "feat(evidence): add type definitions and Taskfile tasks"
```

---

### Task 2: Product config loading and artifact collection

**Files:**
- Create: `pkg/evidence/collect.go`
- Create: `pkg/evidence/collect_test.go`
- Create: `testdata/integration/evidence-minimal/product-config.yaml`

- [ ] **Step 1: Create the minimal fixture product config**

Create `testdata/integration/evidence-minimal/product-config.yaml`:

```yaml
product:
  name: "cra-toolkit"
  version: "1.0.0"
  manufacturer: "SUSE"
  member_state: "DE"
  support_end_date: "2031-12-31"

evidence:
  intended_purpose: "CLI toolkit for CRA compliance automation"
  product_class: "default"
  conformity_procedure: "module-A"
  security_contact: "security@suse.com"
  cvd_policy_url: "https://www.suse.com/support/security/"
  standards_applied:
    - "ISO/IEC 27001:2022"
```

- [ ] **Step 2: Write failing test for config loading**

Create `pkg/evidence/collect_test.go`:

```go
package evidence_test

import (
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/evidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixtureBase = "../../testdata/integration"

func TestLoadEvidenceConfig(t *testing.T) {
	path := filepath.Join(fixtureBase, "evidence-minimal", "product-config.yaml")
	cfg, err := evidence.LoadEvidenceConfig(path)
	require.NoError(t, err)

	assert.Equal(t, "cra-toolkit", cfg.Product.Name)
	assert.Equal(t, "1.0.0", cfg.Product.Version)
	assert.Equal(t, "SUSE", cfg.Product.Manufacturer)
	assert.Equal(t, "DE", cfg.Product.MemberState)
	assert.Equal(t, "2031-12-31", cfg.Product.SupportPeriodEnd)

	assert.Equal(t, "CLI toolkit for CRA compliance automation", cfg.Evidence.IntendedPurpose)
	assert.Equal(t, "default", cfg.Evidence.ProductClass)
	assert.Equal(t, "module-A", cfg.Evidence.ConformityProcedure)
	assert.Equal(t, "security@suse.com", cfg.Evidence.SecurityContact)
	assert.Equal(t, "https://www.suse.com/support/security/", cfg.Evidence.CVDPolicyURL)
	assert.Equal(t, []string{"ISO/IEC 27001:2022"}, cfg.Evidence.StandardsApplied)
}

func TestBuildProductIdentity(t *testing.T) {
	path := filepath.Join(fixtureBase, "evidence-minimal", "product-config.yaml")
	cfg, err := evidence.LoadEvidenceConfig(path)
	require.NoError(t, err)

	pid := evidence.BuildProductIdentity(cfg)
	assert.Equal(t, "cra-toolkit", pid.Name)
	assert.Equal(t, "1.0.0", pid.Version)
	assert.Equal(t, "SUSE", pid.Manufacturer)
	assert.Equal(t, "CLI toolkit for CRA compliance automation", pid.IntendedPurpose)
	assert.Equal(t, "default", pid.ProductClass)
	assert.Equal(t, "module-A", pid.ConformityProcedure)
	assert.Equal(t, "security@suse.com", pid.SecurityContact)
	assert.Equal(t, "https://www.suse.com/support/security/", pid.CVDPolicyURL)
	assert.Equal(t, "2031-12-31", pid.SupportPeriodEnd)
}

func TestResolveArtifacts_MinimalPaths(t *testing.T) {
	dir := filepath.Join(fixtureBase, "evidence-minimal")
	opts := &evidence.Options{
		SBOMPath:      filepath.Join(dir, "sbom.cdx.json"),
		ScanPaths:     []string{filepath.Join(dir, "grype.json")},
		ProductConfig: filepath.Join(dir, "product-config.yaml"),
		OutputDir:     t.TempDir(),
	}

	artifacts, err := evidence.ResolveArtifacts(opts)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(artifacts), 2) // SBOM + scan
}

func TestResolveArtifacts_MissingFile(t *testing.T) {
	opts := &evidence.Options{
		SBOMPath:      "/nonexistent/sbom.json",
		ProductConfig: filepath.Join(fixtureBase, "evidence-minimal", "product-config.yaml"),
		OutputDir:     t.TempDir(),
	}

	_, err := evidence.ResolveArtifacts(opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sbom")
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test -run TestLoadEvidenceConfig ./pkg/evidence/...`
Expected: FAIL — `LoadEvidenceConfig` not defined

- [ ] **Step 4: Implement collect.go**

Create `pkg/evidence/collect.go`:

```go
package evidence

import (
	"fmt"
	"os"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/formats/cyclonedx"
	"github.com/ravan/cra-toolkit/pkg/formats/grype"
	"github.com/ravan/cra-toolkit/pkg/formats/openvex"
	"github.com/ravan/cra-toolkit/pkg/formats/sarif"
	"github.com/ravan/cra-toolkit/pkg/formats/spdx"
	"github.com/ravan/cra-toolkit/pkg/formats/trivy"
	"github.com/ravan/cra-toolkit/pkg/formats/csafvex"
	"gopkg.in/yaml.v3"
)

// LoadEvidenceConfig loads the extended product config with evidence section.
func LoadEvidenceConfig(path string) (*EvidenceConfig, error) {
	data, err := os.ReadFile(path) //nolint:gosec // CLI flag
	if err != nil {
		return nil, fmt.Errorf("read product config: %w", err)
	}
	var cfg EvidenceConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse product config: %w", err)
	}
	return &cfg, nil
}

// BuildProductIdentity constructs a ProductIdentity from the evidence config.
func BuildProductIdentity(cfg *EvidenceConfig) ProductIdentity {
	return ProductIdentity{
		Name:                cfg.Product.Name,
		Version:             cfg.Product.Version,
		Manufacturer:        cfg.Product.Manufacturer,
		IntendedPurpose:     cfg.Evidence.IntendedPurpose,
		ProductClass:        cfg.Evidence.ProductClass,
		SupportPeriodEnd:    cfg.Product.SupportPeriodEnd,
		ConformityProcedure: cfg.Evidence.ConformityProcedure,
		SecurityContact:     cfg.Evidence.SecurityContact,
		CVDPolicyURL:        cfg.Evidence.CVDPolicyURL,
	}
}

// ResolveArtifacts validates that all specified artifact files exist and
// returns their metadata. It does not parse file contents.
func ResolveArtifacts(opts *Options) ([]artifactInput, error) {
	var arts []artifactInput

	type inputSpec struct {
		path        string
		annexRef    string
		source      string
		description string
	}

	singles := []inputSpec{
		{opts.SBOMPath, "2b", "toolkit", "Software bill of materials"},
		{opts.VEXPath, "6", "toolkit", "VEX assessment results"},
		{opts.PolicyReport, "6", "toolkit", "CRA Annex I policy evaluation report"},
		{opts.CSAFPath, "6", "toolkit", "CSAF 2.0 security advisory"},
		{opts.ReportPath, "6", "toolkit", "CRA Art. 14 vulnerability notification"},
		{opts.RiskAssessment, "3", "manufacturer", "Cybersecurity risk assessment"},
		{opts.ArchitectureDocs, "2a", "manufacturer", "Design and development architecture"},
		{opts.ProductionProcess, "2c", "manufacturer", "Production and monitoring processes"},
		{opts.EUDeclaration, "7", "manufacturer", "EU declaration of conformity"},
		{opts.CVDPolicy, "2b", "manufacturer", "Coordinated vulnerability disclosure policy"},
		{opts.StandardsDoc, "5", "manufacturer", "Harmonised standards applied"},
	}

	for _, s := range singles {
		if s.path == "" {
			continue
		}
		if _, err := os.Stat(s.path); err != nil {
			return nil, fmt.Errorf("artifact %s (%s): %w", s.description, s.path, err)
		}
		format := detectFormatSafe(s.path)
		arts = append(arts, artifactInput{
			sourcePath:  s.path,
			format:      format,
			annexVIIRef: s.annexRef,
			source:      s.source,
			description: s.description,
		})
	}

	for _, path := range opts.ScanPaths {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("artifact scan (%s): %w", path, err)
		}
		format := detectFormatSafe(path)
		arts = append(arts, artifactInput{
			sourcePath:  path,
			format:      format,
			annexVIIRef: "6",
			source:      "toolkit",
			description: "Vulnerability scan results",
		})
	}

	return arts, nil
}

// detectFormatSafe attempts to detect the format, returning "unknown" on failure.
func detectFormatSafe(path string) string {
	f, err := os.Open(path) //nolint:gosec // CLI flag
	if err != nil {
		return "unknown"
	}
	defer f.Close() //nolint:errcheck // read-only

	format, err := formats.DetectFormat(f)
	if err != nil {
		return "unknown"
	}
	return format.String()
}

// parseSBOMComponents parses an SBOM and returns component info for cross-validation.
func parseSBOMComponents(path string) ([]componentInfo, error) {
	format, f, err := openDetected(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only

	var components []formats.Component
	switch format {
	case formats.FormatCycloneDX:
		components, err = cyclonedx.Parser{}.Parse(f)
	case formats.FormatSPDX:
		components, err = spdx.Parser{}.Parse(f)
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}
	if err != nil {
		return nil, fmt.Errorf("parse SBOM: %w", err)
	}

	infos := make([]componentInfo, 0, len(components))
	for _, c := range components {
		infos = append(infos, componentInfo{
			Name:    c.Name,
			Version: c.Version,
			PURL:    c.PURL,
		})
	}
	return infos, nil
}

// parseScanFindings parses scan results and returns finding info for cross-validation.
func parseScanFindings(paths []string) ([]findingInfo, error) {
	var all []findingInfo
	for _, path := range paths {
		format, f, err := openDetected(path)
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", path, err)
		}

		var findings []formats.Finding
		switch format {
		case formats.FormatGrype:
			findings, err = grype.Parser{}.Parse(f)
		case formats.FormatTrivy:
			findings, err = trivy.Parser{}.Parse(f)
		case formats.FormatSARIF:
			findings, err = sarif.Parser{}.Parse(f)
		default:
			f.Close() //nolint:errcheck // read-only
			return nil, fmt.Errorf("unsupported scan format: %s", format)
		}
		f.Close() //nolint:errcheck // read-only

		if err != nil {
			return nil, fmt.Errorf("parse scan %s: %w", path, err)
		}

		for _, fi := range findings {
			all = append(all, findingInfo{
				CVE:          fi.CVE,
				AffectedPURL: fi.AffectedPURL,
				Severity:     fi.Severity,
			})
		}
	}
	return all, nil
}

// parseVEXData parses a VEX document and returns VEX info for cross-validation.
func parseVEXData(path string) ([]vexInfo, error) {
	format, f, err := openDetected(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only

	var stmts []formats.VEXStatement
	switch format {
	case formats.FormatOpenVEX:
		stmts, err = openvex.Parser{}.Parse(f)
	case formats.FormatCSAF:
		stmts, err = csafvex.Parser{}.Parse(f)
	default:
		return nil, fmt.Errorf("unsupported VEX format: %s", format)
	}
	if err != nil {
		return nil, fmt.Errorf("parse VEX: %w", err)
	}

	infos := make([]vexInfo, 0, len(stmts))
	for _, s := range stmts {
		infos = append(infos, vexInfo{
			CVE:           s.CVE,
			ComponentPURL: s.ProductPURL,
			Status:        string(s.Status),
		})
	}
	return infos, nil
}

// parsePolicyReportData extracts summary stats from a policykit report JSON.
func parsePolicyReportData(path string) (*policyReportData, error) {
	data, err := os.ReadFile(path) //nolint:gosec // CLI flag
	if err != nil {
		return nil, fmt.Errorf("read policy report: %w", err)
	}

	// Parse only the summary section.
	var raw struct {
		Summary struct {
			Total   int `json:"total"`
			Passed  int `json:"passed"`
			Failed  int `json:"failed"`
			Skipped int `json:"skipped"`
			Human   int `json:"human"`
		} `json:"summary"`
	}

	if err := jsonUnmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse policy report: %w", err)
	}

	return &policyReportData{
		Total:   raw.Summary.Total,
		Passed:  raw.Summary.Passed,
		Failed:  raw.Summary.Failed,
		Skipped: raw.Summary.Skipped,
		Human:   raw.Summary.Human,
	}, nil
}

func openDetected(path string) (formats.Format, *os.File, error) {
	df, err := os.Open(path) //nolint:gosec // CLI flag
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("open for detection: %w", err)
	}
	format, err := formats.DetectFormat(df)
	_ = df.Close()
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("detect format: %w", err)
	}
	pf, err := os.Open(path) //nolint:gosec // CLI flag
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("open for parsing: %w", err)
	}
	return format, pf, nil
}

// jsonUnmarshal is a helper to allow testing.
var jsonUnmarshal = func(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
```

Note: You need to add `"encoding/json"` to the imports in collect.go.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test -run "TestLoadEvidenceConfig|TestBuildProductIdentity" ./pkg/evidence/...`
Expected: PASS

- [ ] **Step 6: Copy existing fixture data for evidence-minimal**

Copy the SBOM and scan from the existing `policykit-all-pass` fixture:

```bash
cp testdata/integration/policykit-all-pass/sbom.cdx.json testdata/integration/evidence-minimal/
cp testdata/integration/policykit-all-pass/grype.json testdata/integration/evidence-minimal/
```

- [ ] **Step 7: Run remaining collect tests**

Run: `go test -run "TestResolveArtifacts" ./pkg/evidence/...`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add pkg/evidence/collect.go pkg/evidence/collect_test.go testdata/integration/evidence-minimal/
git commit -m "feat(evidence): implement artifact collection and config loading"
```

---

### Task 3: Format validation

**Files:**
- Create: `pkg/evidence/validate.go`
- Create: `pkg/evidence/validate_test.go`

- [ ] **Step 1: Write failing validation tests**

Create `pkg/evidence/validate_test.go`:

```go
package evidence_test

import (
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/evidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateArtifacts_ValidSBOM(t *testing.T) {
	dir := filepath.Join(fixtureBase, "evidence-minimal")
	opts := &evidence.Options{
		SBOMPath:      filepath.Join(dir, "sbom.cdx.json"),
		ProductConfig: filepath.Join(dir, "product-config.yaml"),
		OutputDir:     t.TempDir(),
	}

	arts, err := evidence.ResolveArtifacts(opts)
	require.NoError(t, err)

	checks := evidence.ValidateArtifacts(arts)
	for _, c := range checks {
		assert.Equal(t, "pass", c.Status, "check %s failed: %s", c.CheckID, c.Details)
	}
}

func TestValidateArtifacts_InvalidFile(t *testing.T) {
	// Create a temp file with invalid JSON content.
	dir := t.TempDir()
	invalidPath := filepath.Join(dir, "bad.json")
	require.NoError(t, writeFile(invalidPath, []byte("not json")))

	arts := []evidence.TestArtifactInput{
		{SourcePath: invalidPath, Format: "unknown", AnnexVIIRef: "6", Source: "toolkit", Description: "Bad file"},
	}

	checks := evidence.ValidateTestArtifacts(arts)
	require.Len(t, checks, 1)
	assert.Equal(t, "fail", checks[0].Status)
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}
```

Note: We'll need to export some test helpers or adjust the approach — the implementation should expose `ValidateArtifacts` taking `[]artifactInput`. Since `artifactInput` is unexported, we'll create a public `ValidateArtifactFiles` function that takes the resolved artifacts from `ResolveArtifacts`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestValidateArtifacts ./pkg/evidence/...`
Expected: FAIL — `ValidateArtifacts` not defined

- [ ] **Step 3: Implement validate.go**

Create `pkg/evidence/validate.go`:

```go
package evidence

import (
	"fmt"
	"os"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

// ValidateArtifacts checks that each toolkit-generated artifact has a valid,
// recognized format. Manufacturer-provided documents get existence-only checks.
func ValidateArtifacts(arts []artifactInput) []ValidationCheck {
	var checks []ValidationCheck

	for _, a := range arts {
		if a.source == "manufacturer" {
			checks = append(checks, ValidationCheck{
				CheckID:     fmt.Sprintf("FV-%s", a.annexVIIRef),
				Description: fmt.Sprintf("File exists: %s", a.description),
				Status:      "pass",
				Details:     fmt.Sprintf("Manufacturer document present at %s", a.sourcePath),
				ArtifactA:   a.sourcePath,
			})
			continue
		}

		check := validateToolkitArtifact(a)
		checks = append(checks, check)
	}

	return checks
}

func validateToolkitArtifact(a artifactInput) ValidationCheck {
	f, err := os.Open(a.sourcePath) //nolint:gosec // CLI flag
	if err != nil {
		return ValidationCheck{
			CheckID:     fmt.Sprintf("FV-%s", a.annexVIIRef),
			Description: fmt.Sprintf("Format validation: %s", a.description),
			Status:      "fail",
			Details:     fmt.Sprintf("Cannot open file: %v", err),
			ArtifactA:   a.sourcePath,
		}
	}
	defer f.Close() //nolint:errcheck // read-only

	format, err := formats.DetectFormat(f)
	if err != nil || format == formats.FormatUnknown {
		return ValidationCheck{
			CheckID:     fmt.Sprintf("FV-%s", a.annexVIIRef),
			Description: fmt.Sprintf("Format validation: %s", a.description),
			Status:      "fail",
			Details:     fmt.Sprintf("Unrecognized format for %s", a.sourcePath),
			ArtifactA:   a.sourcePath,
		}
	}

	return ValidationCheck{
		CheckID:     fmt.Sprintf("FV-%s", a.annexVIIRef),
		Description: fmt.Sprintf("Format validation: %s", a.description),
		Status:      "pass",
		Details:     fmt.Sprintf("Detected format: %s", format),
		ArtifactA:   a.sourcePath,
	}
}
```

- [ ] **Step 4: Run tests**

Run: `go test -run TestValidateArtifacts ./pkg/evidence/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/evidence/validate.go pkg/evidence/validate_test.go
git commit -m "feat(evidence): implement per-artifact format validation"
```

---

### Task 4: Cross-validation checks

**Files:**
- Create: `pkg/evidence/crossvalidate.go`
- Create: `pkg/evidence/crossvalidate_test.go`
- Create: `testdata/integration/evidence-purl-mismatch/` (fixture)

- [ ] **Step 1: Create purl-mismatch fixture**

Create `testdata/integration/evidence-purl-mismatch/product-config.yaml` (copy from evidence-minimal).

Create `testdata/integration/evidence-purl-mismatch/sbom.cdx.json` — copy from evidence-minimal (contains `pkg:golang/golang.org/x/text@v0.3.7`).

Create `testdata/integration/evidence-purl-mismatch/vex-mismatch.json` — an OpenVEX document referencing a PURL NOT in the SBOM:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://suse.com/vex/mismatch-test",
  "author": "test",
  "timestamp": "2026-04-04T00:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2099-99999"},
      "products": [{"@id": "pkg:golang/nonexistent/package@v1.0.0"}],
      "status": "not_affected",
      "justification": "component_not_present"
    }
  ]
}
```

- [ ] **Step 2: Write failing cross-validation tests**

Create `pkg/evidence/crossvalidate_test.go`:

```go
package evidence_test

import (
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/evidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrossValidate_SBOMvsVEX_PURLMismatch(t *testing.T) {
	dir := filepath.Join(fixtureBase, "evidence-purl-mismatch")
	checks, err := evidence.CrossValidate(
		filepath.Join(dir, "sbom.cdx.json"),
		filepath.Join(dir, "vex-mismatch.json"),
		nil, // no scans
		"",  // no policy report
		"",  // no CSAF
		"",  // no Art. 14 report
	)
	require.NoError(t, err)

	var found bool
	for _, c := range checks {
		if c.CheckID == "CV-SBOM-VEX-PURL" {
			found = true
			assert.Equal(t, "fail", c.Status)
			assert.Contains(t, c.Details, "pkg:golang/nonexistent/package@v1.0.0")
		}
	}
	assert.True(t, found, "CV-SBOM-VEX-PURL check not found")
}

func TestCrossValidate_SBOMvsVEX_AllMatch(t *testing.T) {
	dir := filepath.Join(fixtureBase, "policykit-all-pass")
	checks, err := evidence.CrossValidate(
		filepath.Join(dir, "sbom.cdx.json"),
		filepath.Join(dir, "vex-results.json"),
		nil,
		"",
		"",
		"",
	)
	require.NoError(t, err)

	for _, c := range checks {
		if c.CheckID == "CV-SBOM-VEX-PURL" {
			assert.Equal(t, "pass", c.Status, "details: %s", c.Details)
		}
	}
}

func TestCrossValidate_SkipsWhenMissing(t *testing.T) {
	// When VEX is empty, CV-SBOM-VEX-PURL should not appear.
	dir := filepath.Join(fixtureBase, "evidence-minimal")
	checks, err := evidence.CrossValidate(
		filepath.Join(dir, "sbom.cdx.json"),
		"", // no VEX
		nil,
		"",
		"",
		"",
	)
	require.NoError(t, err)

	for _, c := range checks {
		assert.NotEqual(t, "CV-SBOM-VEX-PURL", c.CheckID, "should skip VEX checks when no VEX provided")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test -run TestCrossValidate ./pkg/evidence/...`
Expected: FAIL — `CrossValidate` not defined

- [ ] **Step 4: Implement crossvalidate.go**

Create `pkg/evidence/crossvalidate.go`:

```go
package evidence

import (
	"fmt"
	"strings"
)

// CrossValidate runs consistency checks across bundled artifacts.
// Only checks applicable to the provided artifacts are executed.
func CrossValidate(sbomPath, vexPath string, scanPaths []string, policyPath, csafPath, reportPath string) ([]ValidationCheck, error) {
	var checks []ValidationCheck

	// Parse SBOM components if available.
	var components []componentInfo
	if sbomPath != "" {
		var err error
		components, err = parseSBOMComponents(sbomPath)
		if err != nil {
			return nil, fmt.Errorf("cross-validate parse SBOM: %w", err)
		}
	}

	// Parse VEX data if available.
	var vex []vexInfo
	if vexPath != "" {
		var err error
		vex, err = parseVEXData(vexPath)
		if err != nil {
			return nil, fmt.Errorf("cross-validate parse VEX: %w", err)
		}
	}

	// Parse scan findings if available.
	var findings []findingInfo
	if len(scanPaths) > 0 {
		var err error
		findings, err = parseScanFindings(scanPaths)
		if err != nil {
			return nil, fmt.Errorf("cross-validate parse scans: %w", err)
		}
	}

	// CV-SBOM-VEX-PURL: VEX subject PURLs must exist in SBOM.
	if sbomPath != "" && vexPath != "" {
		checks = append(checks, checkSBOMvsVEX(components, vex))
	}

	// CV-SBOM-SCAN-COMP: Scanned component PURLs must exist in SBOM.
	if sbomPath != "" && len(scanPaths) > 0 {
		checks = append(checks, checkSBOMvsScans(components, findings))
	}

	// CV-SCAN-VEX-CVE: CVEs in scan results should have VEX assessments.
	if len(scanPaths) > 0 && vexPath != "" {
		checks = append(checks, checkScanVsVEX(findings, vex))
	}

	// CV-REPORT-SCAN: Art. 14 notification CVEs must exist in scan results.
	if reportPath != "" && len(scanPaths) > 0 {
		c, err := checkReportVsScans(reportPath, findings)
		if err == nil {
			checks = append(checks, c)
		}
	}

	return checks, nil
}

func checkSBOMvsVEX(components []componentInfo, vex []vexInfo) ValidationCheck {
	purlSet := make(map[string]bool, len(components))
	for _, c := range components {
		if c.PURL != "" {
			purlSet[c.PURL] = true
		}
	}

	var missing []string
	for _, v := range vex {
		if v.ComponentPURL != "" && !purlSet[v.ComponentPURL] {
			missing = append(missing, v.ComponentPURL)
		}
	}

	if len(missing) > 0 {
		return ValidationCheck{
			CheckID:     "CV-SBOM-VEX-PURL",
			Description: "VEX subject PURLs exist in SBOM",
			Status:      "fail",
			Details:     fmt.Sprintf("VEX references %d PURLs not in SBOM: %s", len(missing), strings.Join(missing, ", ")),
			ArtifactA:   "sbom",
			ArtifactB:   "vex",
		}
	}

	return ValidationCheck{
		CheckID:     "CV-SBOM-VEX-PURL",
		Description: "VEX subject PURLs exist in SBOM",
		Status:      "pass",
		Details:     fmt.Sprintf("All %d VEX subject PURLs found in SBOM", len(vex)),
		ArtifactA:   "sbom",
		ArtifactB:   "vex",
	}
}

func checkSBOMvsScans(components []componentInfo, findings []findingInfo) ValidationCheck {
	purlSet := make(map[string]bool, len(components))
	for _, c := range components {
		if c.PURL != "" {
			purlSet[c.PURL] = true
		}
	}

	var missing []string
	seen := make(map[string]bool)
	for _, f := range findings {
		if f.AffectedPURL != "" && !purlSet[f.AffectedPURL] && !seen[f.AffectedPURL] {
			missing = append(missing, f.AffectedPURL)
			seen[f.AffectedPURL] = true
		}
	}

	if len(missing) > 0 {
		return ValidationCheck{
			CheckID:     "CV-SBOM-SCAN-COMP",
			Description: "Scanned components exist in SBOM",
			Status:      "fail",
			Details:     fmt.Sprintf("Scan references %d PURLs not in SBOM: %s", len(missing), strings.Join(missing, ", ")),
			ArtifactA:   "sbom",
			ArtifactB:   "scans",
		}
	}

	return ValidationCheck{
		CheckID:     "CV-SBOM-SCAN-COMP",
		Description: "Scanned components exist in SBOM",
		Status:      "pass",
		Details:     fmt.Sprintf("All scanned component PURLs found in SBOM"),
		ArtifactA:   "sbom",
		ArtifactB:   "scans",
	}
}

func checkScanVsVEX(findings []findingInfo, vex []vexInfo) ValidationCheck {
	vexCVEs := make(map[string]bool, len(vex))
	for _, v := range vex {
		vexCVEs[v.CVE] = true
	}

	var unassessed []string
	seen := make(map[string]bool)
	for _, f := range findings {
		if f.CVE != "" && !vexCVEs[f.CVE] && !seen[f.CVE] {
			unassessed = append(unassessed, f.CVE)
			seen[f.CVE] = true
		}
	}

	if len(unassessed) > 0 {
		return ValidationCheck{
			CheckID:     "CV-SCAN-VEX-CVE",
			Description: "Scan CVEs have VEX assessments",
			Status:      "warn",
			Details:     fmt.Sprintf("%d scan CVEs without VEX assessment: %s", len(unassessed), strings.Join(unassessed, ", ")),
			ArtifactA:   "scans",
			ArtifactB:   "vex",
		}
	}

	return ValidationCheck{
		CheckID:     "CV-SCAN-VEX-CVE",
		Description: "Scan CVEs have VEX assessments",
		Status:      "pass",
		Details:     "All scan CVEs have VEX assessments",
		ArtifactA:   "scans",
		ArtifactB:   "vex",
	}
}

func checkReportVsScans(reportPath string, findings []findingInfo) (ValidationCheck, error) {
	data, err := os.ReadFile(reportPath) //nolint:gosec // CLI flag
	if err != nil {
		return ValidationCheck{}, err
	}

	var raw struct {
		Vulnerabilities []struct {
			CVE string `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := jsonUnmarshal(data, &raw); err != nil {
		return ValidationCheck{}, err
	}

	scanCVEs := make(map[string]bool, len(findings))
	for _, f := range findings {
		scanCVEs[f.CVE] = true
	}

	var missing []string
	for _, v := range raw.Vulnerabilities {
		if v.CVE != "" && !scanCVEs[v.CVE] {
			missing = append(missing, v.CVE)
		}
	}

	if len(missing) > 0 {
		return ValidationCheck{
			CheckID:     "CV-REPORT-SCAN",
			Description: "Art. 14 notification CVEs exist in scan results",
			Status:      "fail",
			Details:     fmt.Sprintf("Art. 14 references %d CVEs not in scans: %s", len(missing), strings.Join(missing, ", ")),
			ArtifactA:   "art14-report",
			ArtifactB:   "scans",
		}, nil
	}

	return ValidationCheck{
		CheckID:     "CV-REPORT-SCAN",
		Description: "Art. 14 notification CVEs exist in scan results",
		Status:      "pass",
		Details:     "All Art. 14 notification CVEs found in scan results",
		ArtifactA:   "art14-report",
		ArtifactB:   "scans",
	}, nil
}
```

Note: Add `"os"` to imports.

- [ ] **Step 5: Run tests**

Run: `go test -run TestCrossValidate ./pkg/evidence/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/evidence/crossvalidate.go pkg/evidence/crossvalidate_test.go testdata/integration/evidence-purl-mismatch/
git commit -m "feat(evidence): implement cross-validation checks"
```

---

### Task 5: Completeness scoring

**Files:**
- Create: `pkg/evidence/completeness.go`
- Create: `pkg/evidence/completeness_test.go`

- [ ] **Step 1: Write failing completeness tests**

Create `pkg/evidence/completeness_test.go`:

```go
package evidence_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/evidence"
	"github.com/stretchr/testify/assert"
)

func TestComputeCompleteness_FullCoverage(t *testing.T) {
	arts := []evidence.ArtifactEntry{
		{AnnexVIIRef: "2b", Source: "toolkit", Description: "SBOM"},
		{AnnexVIIRef: "6", Source: "toolkit", Description: "VEX results"},
		{AnnexVIIRef: "6", Source: "toolkit", Description: "Scan results"},
		{AnnexVIIRef: "6", Source: "toolkit", Description: "Policy report"},
		{AnnexVIIRef: "2a", Source: "manufacturer", Description: "Architecture"},
		{AnnexVIIRef: "2b", Source: "manufacturer", Description: "CVD policy"},
		{AnnexVIIRef: "2c", Source: "manufacturer", Description: "Production process"},
		{AnnexVIIRef: "3", Source: "manufacturer", Description: "Risk assessment"},
		{AnnexVIIRef: "5", Source: "manufacturer", Description: "Standards"},
		{AnnexVIIRef: "7", Source: "manufacturer", Description: "EU declaration"},
	}

	pid := evidence.ProductIdentity{
		IntendedPurpose:     "Test product",
		SupportPeriodEnd:    "2031-12-31",
		SecurityContact:     "test@example.com",
		CVDPolicyURL:        "https://example.com/security",
	}

	report := evidence.ComputeCompleteness(arts, pid)
	assert.Equal(t, 100.0, report.Score)
	assert.Equal(t, report.TotalWeight, report.CoveredWeight)
}

func TestComputeCompleteness_MinimalSBOMOnly(t *testing.T) {
	arts := []evidence.ArtifactEntry{
		{AnnexVIIRef: "2b", Source: "toolkit", Description: "SBOM"},
	}

	pid := evidence.ProductIdentity{
		IntendedPurpose: "Test product",
	}

	report := evidence.ComputeCompleteness(arts, pid)
	assert.Greater(t, report.Score, 0.0)
	assert.Less(t, report.Score, 50.0) // SBOM alone won't cover half

	// Verify gaps are reported.
	var gaps []string
	for _, s := range report.Sections {
		if !s.Covered {
			gaps = append(gaps, s.ID)
		}
	}
	assert.Contains(t, gaps, "3")  // Risk assessment missing
	assert.Contains(t, gaps, "7")  // EU declaration missing
}

func TestComputeCompleteness_HardwareWeight(t *testing.T) {
	// Section 1c (hardware photos) should have weight 0 for software products.
	arts := []evidence.ArtifactEntry{}
	pid := evidence.ProductIdentity{}

	report := evidence.ComputeCompleteness(arts, pid)

	for _, s := range report.Sections {
		if s.ID == "1c" {
			assert.Equal(t, 0, s.Weight)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestComputeCompleteness ./pkg/evidence/...`
Expected: FAIL — `ComputeCompleteness` not defined

- [ ] **Step 3: Implement completeness.go**

Create `pkg/evidence/completeness.go`:

```go
package evidence

// annexVIISectionDef defines one Annex VII documentation section.
type annexVIISectionDef struct {
	id       string
	title    string
	craRef   string
	weight   int
	required bool
}

// annexVIISections is the master list of Annex VII sections with weights.
var annexVIISections = []annexVIISectionDef{
	{"1a", "General description — intended purpose", "Annex VII, point 1(a)", 10, true},
	{"1b", "Versions affecting compliance", "Annex VII, point 1(b)", 5, true},
	{"1c", "Hardware photos/illustrations", "Annex VII, point 1(c)", 0, false},
	{"1d", "User information per Annex II", "Annex VII, point 1(d)", 5, true},
	{"2a", "Design/development/architecture", "Annex VII, point 2(a)", 10, true},
	{"2b-sbom", "Vulnerability handling — SBOM", "Annex VII, point 2(b)", 15, true},
	{"2b-cvd", "Vulnerability handling — CVD policy", "Annex VII, point 2(b)", 10, true},
	{"2b-updates", "Vulnerability handling — secure update mechanism", "Annex VII, point 2(b)", 5, true},
	{"2c", "Production/monitoring processes", "Annex VII, point 2(c)", 5, true},
	{"3", "Cybersecurity risk assessment", "Annex VII, point 3", 15, true},
	{"4", "Support period determination", "Annex VII, point 4", 5, true},
	{"5", "Harmonised standards applied", "Annex VII, point 5", 5, true},
	{"6", "Test/verification reports", "Annex VII, point 6", 10, true},
	{"7", "EU declaration of conformity", "Annex VII, point 7", 10, true},
	{"8", "SBOM (market surveillance)", "Annex VII, point 8", 5, true},
}

// ComputeCompleteness maps artifacts to Annex VII sections and computes
// a weighted completeness score.
func ComputeCompleteness(artifacts []ArtifactEntry, product ProductIdentity) CompletenessReport {
	sections := make([]AnnexVIISection, 0, len(annexVIISections))

	for _, def := range annexVIISections {
		section := AnnexVIISection{
			ID:       def.id,
			Title:    def.title,
			CRARef:   def.craRef,
			Required: def.required,
			Weight:   def.weight,
		}

		covered, coveredBy, gap := checkSectionCoverage(def.id, artifacts, product)
		section.Covered = covered
		section.Artifacts = coveredBy
		section.Gap = gap

		sections = append(sections, section)
	}

	var totalWeight, coveredWeight int
	for _, s := range sections {
		if s.Weight > 0 {
			totalWeight += s.Weight
			if s.Covered {
				coveredWeight += s.Weight
			}
		}
	}

	score := 0.0
	if totalWeight > 0 {
		score = float64(coveredWeight) / float64(totalWeight) * 100
	}

	return CompletenessReport{
		Sections:      sections,
		Score:         score,
		TotalWeight:   totalWeight,
		CoveredWeight: coveredWeight,
		Note:          CompletenessNote,
	}
}

func checkSectionCoverage(sectionID string, artifacts []ArtifactEntry, product ProductIdentity) (bool, []string, string) {
	switch sectionID {
	case "1a":
		if product.IntendedPurpose != "" {
			return true, []string{"product-config.yaml"}, ""
		}
		return false, nil, "Product config missing intended_purpose field"

	case "1b":
		for _, a := range artifacts {
			if a.AnnexVIIRef == "2b" && a.Source == "toolkit" {
				return true, []string{a.Path}, ""
			}
		}
		return false, nil, "SBOM required for version information"

	case "1c":
		return false, nil, "N/A for software products"

	case "1d":
		if product.SecurityContact != "" || product.CVDPolicyURL != "" || product.SupportPeriodEnd != "" {
			return true, []string{"product-config.yaml"}, ""
		}
		return false, nil, "Product config missing security_contact, cvd_policy_url, or support_period_end"

	case "2a":
		return hasArtifactRef(artifacts, "2a", "manufacturer")

	case "2b-sbom":
		return hasArtifactRef(artifacts, "2b", "toolkit")

	case "2b-cvd":
		for _, a := range artifacts {
			if a.AnnexVIIRef == "2b" && a.Source == "manufacturer" {
				return true, []string{a.Path}, ""
			}
		}
		if product.CVDPolicyURL != "" {
			return true, []string{"product-config.yaml"}, ""
		}
		return false, nil, "CVD policy document or cvd_policy_url required"

	case "2b-updates":
		// Covered by product config update mechanism or manufacturer doc.
		return false, nil, "Secure update mechanism documentation required"

	case "2c":
		return hasArtifactRef(artifacts, "2c", "manufacturer")

	case "3":
		return hasArtifactRef(artifacts, "3", "manufacturer")

	case "4":
		if product.SupportPeriodEnd != "" {
			return true, []string{"product-config.yaml"}, ""
		}
		return false, nil, "Product config missing support_period_end"

	case "5":
		covered, paths, _ := hasArtifactRef(artifacts, "5", "manufacturer")
		if covered {
			return true, paths, ""
		}
		return false, nil, "Standards document required"

	case "6":
		var paths []string
		for _, a := range artifacts {
			if a.AnnexVIIRef == "6" {
				paths = append(paths, a.Path)
			}
		}
		if len(paths) > 0 {
			return true, paths, ""
		}
		return false, nil, "Test/verification reports required (policy report, scan results, VEX)"

	case "7":
		return hasArtifactRef(artifacts, "7", "manufacturer")

	case "8":
		// Auto-covered if SBOM is present (same file as 2b-sbom).
		for _, a := range artifacts {
			if a.AnnexVIIRef == "2b" && a.Source == "toolkit" {
				return true, []string{a.Path}, ""
			}
		}
		return false, nil, "SBOM required"

	default:
		return false, nil, "Unknown section"
	}
}

func hasArtifactRef(artifacts []ArtifactEntry, ref, source string) (bool, []string, string) {
	var paths []string
	for _, a := range artifacts {
		if a.AnnexVIIRef == ref && a.Source == source {
			paths = append(paths, a.Path)
		}
	}
	if len(paths) > 0 {
		return true, paths, ""
	}
	return false, nil, ""
}
```

- [ ] **Step 4: Run tests**

Run: `go test -run TestComputeCompleteness ./pkg/evidence/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/evidence/completeness.go pkg/evidence/completeness_test.go
git commit -m "feat(evidence): implement Annex VII completeness scoring"
```

---

### Task 6: Summary stats extraction

**Files:**
- Create: `pkg/evidence/summary.go`
- Create: `pkg/evidence/summary_test.go`

- [ ] **Step 1: Write failing summary tests**

Create `pkg/evidence/summary_test.go`:

```go
package evidence_test

import (
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/evidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractSBOMStats(t *testing.T) {
	sbomPath := filepath.Join(fixtureBase, "evidence-minimal", "sbom.cdx.json")
	stats, err := evidence.ExtractSBOMStats(sbomPath)
	require.NoError(t, err)
	assert.Equal(t, "CycloneDX", stats.Format)
	assert.Greater(t, stats.ComponentCount, 0)
	assert.NotEmpty(t, stats.ProductName)
}

func TestExtractScanStats(t *testing.T) {
	scanPaths := []string{filepath.Join(fixtureBase, "evidence-minimal", "grype.json")}
	stats, err := evidence.ExtractScanStats(scanPaths)
	require.NoError(t, err)
	assert.Greater(t, stats.TotalFindings, 0)
	assert.Equal(t, 1, stats.ScannerCount)
	assert.NotEmpty(t, stats.SeverityDistribution)
}

func TestExtractVulnHandlingStats(t *testing.T) {
	vexPath := filepath.Join(fixtureBase, "policykit-all-pass", "vex-results.json")
	stats, err := evidence.ExtractVulnHandlingStats(vexPath)
	require.NoError(t, err)
	assert.Greater(t, stats.TotalAssessed, 0)
	assert.NotEmpty(t, stats.StatusDistribution)
}

func TestBuildSummary(t *testing.T) {
	pid := evidence.ProductIdentity{
		IntendedPurpose:     "Test product",
		SupportPeriodEnd:    "2031-12-31",
		ConformityProcedure: "module-A",
	}

	sbomPath := filepath.Join(fixtureBase, "evidence-minimal", "sbom.cdx.json")
	scanPaths := []string{filepath.Join(fixtureBase, "evidence-minimal", "grype.json")}
	vexPath := filepath.Join(fixtureBase, "policykit-all-pass", "vex-results.json")

	summary := evidence.BuildSummary(pid, sbomPath, vexPath, scanPaths, "")
	assert.Equal(t, "Test product", summary.ProductDescription)
	assert.Equal(t, "2031-12-31", summary.SupportPeriod)
	assert.Equal(t, "module-A", summary.ConformityProcedure)
	assert.NotNil(t, summary.SBOMStats)
	assert.NotNil(t, summary.ScanStats)
	assert.NotNil(t, summary.VulnHandlingStats)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run "TestExtractSBOMStats|TestExtractScanStats|TestExtractVulnHandlingStats|TestBuildSummary" ./pkg/evidence/...`
Expected: FAIL

- [ ] **Step 3: Implement summary.go**

Create `pkg/evidence/summary.go`:

```go
package evidence

import (
	"os"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/formats/cyclonedx"
	"github.com/ravan/cra-toolkit/pkg/formats/spdx"
)

// ExtractSBOMStats parses a real SBOM and extracts component statistics.
func ExtractSBOMStats(path string) (*SBOMStats, error) {
	format, f, err := openDetected(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only

	var components []formats.Component
	switch format {
	case formats.FormatCycloneDX:
		components, err = cyclonedx.Parser{}.Parse(f)
	case formats.FormatSPDX:
		components, err = spdx.Parser{}.Parse(f)
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}
	if err != nil {
		return nil, err
	}

	// Extract product name from SBOM metadata if available.
	productName := ""
	productVersion := ""
	if len(components) > 0 {
		productName = components[0].Name
		productVersion = components[0].Version
	}

	// Re-read to get metadata component (first component in CycloneDX is usually the root).
	return &SBOMStats{
		Format:         format.String(),
		ComponentCount: len(components),
		ProductName:    productName,
		ProductVersion: productVersion,
	}, nil
}

// ExtractScanStats parses real scan results and extracts severity distribution.
func ExtractScanStats(paths []string) (*ScanStats, error) {
	findings, err := parseScanFindings(paths)
	if err != nil {
		return nil, err
	}

	dist := make(map[string]int)
	for _, f := range findings {
		sev := f.Severity
		if sev == "" {
			sev = "unknown"
		}
		dist[sev]++
	}

	return &ScanStats{
		TotalFindings:        len(findings),
		SeverityDistribution: dist,
		ScannerCount:         len(paths),
	}, nil
}

// ExtractVulnHandlingStats parses a real VEX document and extracts status distribution.
func ExtractVulnHandlingStats(path string) (*VulnHandlingStats, error) {
	vex, err := parseVEXData(path)
	if err != nil {
		return nil, err
	}

	dist := make(map[string]int)
	for _, v := range vex {
		dist[v.Status]++
	}

	return &VulnHandlingStats{
		TotalAssessed:      len(vex),
		StatusDistribution: dist,
	}, nil
}

// ExtractPolicyStats extracts summary from a real policy report.
func ExtractPolicyStats(path string) (*PolicyStats, error) {
	data, err := parsePolicyReportData(path)
	if err != nil {
		return nil, err
	}

	return &PolicyStats{
		Total:   data.Total,
		Passed:  data.Passed,
		Failed:  data.Failed,
		Skipped: data.Skipped,
		Human:   data.Human,
	}, nil
}

// BuildSummary constructs the AnnexVIISummary from real artifact data.
// Errors in individual extractions are silently skipped — the completeness
// report already flags missing artifacts.
func BuildSummary(product ProductIdentity, sbomPath, vexPath string, scanPaths []string, policyPath string) AnnexVIISummary {
	summary := AnnexVIISummary{
		ProductDescription: product.IntendedPurpose,
		SupportPeriod:      product.SupportPeriodEnd,
		ConformityProcedure: product.ConformityProcedure,
	}

	if sbomPath != "" {
		if stats, err := ExtractSBOMStats(sbomPath); err == nil {
			summary.SBOMStats = stats
		}
	}

	if vexPath != "" {
		if stats, err := ExtractVulnHandlingStats(vexPath); err == nil {
			summary.VulnHandlingStats = stats
		}
	}

	if len(scanPaths) > 0 {
		if stats, err := ExtractScanStats(scanPaths); err == nil {
			summary.ScanStats = stats
		}
	}

	if policyPath != "" {
		if stats, err := ExtractPolicyStats(policyPath); err == nil {
			summary.PolicyComplianceStats = stats
		}
	}

	return summary
}
```

Note: Add `"fmt"` to imports.

- [ ] **Step 4: Run tests**

Run: `go test -run "TestExtract|TestBuildSummary" ./pkg/evidence/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/evidence/summary.go pkg/evidence/summary_test.go
git commit -m "feat(evidence): implement Annex VII summary stats extraction"
```

---

### Task 7: Manifest generation and signing

**Files:**
- Create: `pkg/evidence/manifest.go`
- Create: `pkg/evidence/manifest_test.go`
- Create: `pkg/evidence/sign.go`

- [ ] **Step 1: Write failing manifest tests**

Create `pkg/evidence/manifest_test.go`:

```go
package evidence_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/evidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeManifest(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file1.txt"), []byte("hello"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file2.txt"), []byte("world"), 0o644))

	manifest, err := evidence.ComputeManifest(dir)
	require.NoError(t, err)
	assert.Equal(t, "sha256", manifest.Algorithm)
	assert.Len(t, manifest.Entries, 2)
	assert.Contains(t, manifest.Entries, "file1.txt")
	assert.Contains(t, manifest.Entries, "file2.txt")
	// SHA-256 of "hello" is 2cf24dba...
	assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", manifest.Entries["file1.txt"])
}

func TestComputeManifest_Subdirectories(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "nested.txt"), []byte("nested"), 0o644))

	manifest, err := evidence.ComputeManifest(dir)
	require.NoError(t, err)
	assert.Contains(t, manifest.Entries, filepath.Join("sub", "nested.txt"))
}

func TestWriteManifest(t *testing.T) {
	dir := t.TempDir()
	manifest := evidence.Manifest{
		Algorithm: "sha256",
		Entries: map[string]string{
			"file1.txt": "abc123",
			"file2.txt": "def456",
		},
	}

	path := filepath.Join(dir, "manifest.sha256")
	err := evidence.WriteManifest(manifest, path)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "abc123  file1.txt")
	assert.Contains(t, content, "def456  file2.txt")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run "TestComputeManifest|TestWriteManifest" ./pkg/evidence/...`
Expected: FAIL

- [ ] **Step 3: Implement manifest.go**

Create `pkg/evidence/manifest.go`:

```go
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ComputeManifest walks a directory and computes SHA-256 hashes for all files.
func ComputeManifest(dir string) (Manifest, error) {
	entries := make(map[string]string)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("relative path: %w", err)
		}

		hash, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("hash %s: %w", rel, err)
		}

		entries[rel] = hash
		return nil
	})
	if err != nil {
		return Manifest{}, fmt.Errorf("walk directory: %w", err)
	}

	return Manifest{
		Algorithm: "sha256",
		Entries:   entries,
	}, nil
}

// WriteManifest writes the manifest in sha256sum format.
func WriteManifest(m Manifest, path string) error {
	// Sort keys for deterministic output.
	keys := make([]string, 0, len(m.Entries))
	for k := range m.Entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		b.WriteString(fmt.Sprintf("%s  %s\n", m.Entries[k], k))
	}

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// HashFile computes the SHA-256 of a single file.
func hashFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // internal path
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck // read-only

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
```

- [ ] **Step 4: Implement sign.go**

Create `pkg/evidence/sign.go`:

```go
package evidence

import (
	"bytes"
	"fmt"
	"os/exec"
)

// SignManifest attempts to Cosign-sign the manifest file.
// If cosign is not available, returns an unsigned SignatureInfo.
func SignManifest(manifestPath, keyPath string) *SignatureInfo {
	cosignPath, err := exec.LookPath("cosign")
	if err != nil {
		return &SignatureInfo{
			Method:    "unsigned",
			Signature: "",
		}
	}

	var args []string
	if keyPath != "" {
		args = []string{"sign-blob", "--key", keyPath, "--bundle", manifestPath + ".sig", manifestPath}
	} else {
		args = []string{"sign-blob", "--yes", "--bundle", manifestPath + ".sig", manifestPath}
	}

	cmd := exec.Command(cosignPath, args...) //nolint:gosec // user-specified paths
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Signing failed — degrade gracefully.
		return &SignatureInfo{
			Method:    "unsigned",
			Signature: fmt.Sprintf("signing failed: %v: %s", err, stderr.String()),
		}
	}

	method := "cosign-keyless"
	if keyPath != "" {
		method = "cosign-key"
	}

	return &SignatureInfo{
		Method:    method,
		Signature: manifestPath + ".sig",
	}
}
```

- [ ] **Step 5: Run tests**

Run: `go test -run "TestComputeManifest|TestWriteManifest" ./pkg/evidence/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/evidence/manifest.go pkg/evidence/manifest_test.go pkg/evidence/sign.go
git commit -m "feat(evidence): implement SHA-256 manifest and Cosign signing"
```

---

### Task 8: Assembly and archive

**Files:**
- Create: `pkg/evidence/assemble.go`
- Create: `pkg/evidence/archive.go`

- [ ] **Step 1: Implement assemble.go**

Create `pkg/evidence/assemble.go`:

```go
package evidence

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// annexVIIDir maps Annex VII references to directory names.
var annexVIIDir = map[string]string{
	"2b": "2b-vulnerability-handling",
	"2a": "2a-design-development",
	"2c": "2c-production-monitoring",
	"3":  "3-risk-assessment",
	"5":  "5-standards",
	"6":  "6-test-reports",
	"7":  "7-eu-declaration",
}

// Assemble creates the Annex VII directory structure and copies artifacts.
func Assemble(outputDir string, configPath string, artifacts []artifactInput) ([]ArtifactEntry, error) {
	annexDir := filepath.Join(outputDir, "annex-vii")

	// Create all possible subdirectories.
	dirs := []string{
		"1-general-description",
		"2a-design-development",
		"2b-vulnerability-handling",
		"2c-production-monitoring",
		"3-risk-assessment",
		"4-support-period",
		"5-standards",
		"6-test-reports",
		"7-eu-declaration",
		"8-sbom",
	}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(annexDir, d), 0o755); err != nil {
			return nil, fmt.Errorf("create dir %s: %w", d, err)
		}
	}

	var entries []ArtifactEntry

	// Copy product config into 1-general-description.
	if configPath != "" {
		dst := filepath.Join(annexDir, "1-general-description", "product-config.yaml")
		if err := copyFile(configPath, dst); err != nil {
			return nil, fmt.Errorf("copy product config: %w", err)
		}
		hash, _ := hashFile(dst)
		entries = append(entries, ArtifactEntry{
			Path:        filepath.Join("annex-vii", "1-general-description", "product-config.yaml"),
			AnnexVIIRef: "1a",
			Format:      "yaml",
			SHA256:      hash,
			Source:      "toolkit",
			Description: "Product configuration",
		})
	}

	// Copy each artifact to its Annex VII directory.
	var sbomDst string
	for _, a := range artifacts {
		dir, ok := annexVIIDir[a.annexVIIRef]
		if !ok {
			dir = "6-test-reports" // default
		}

		filename := filepath.Base(a.sourcePath)
		dst := filepath.Join(annexDir, dir, filename)
		if err := copyFile(a.sourcePath, dst); err != nil {
			return nil, fmt.Errorf("copy %s: %w", a.sourcePath, err)
		}

		hash, _ := hashFile(dst)
		relPath := filepath.Join("annex-vii", dir, filename)

		entries = append(entries, ArtifactEntry{
			Path:        relPath,
			AnnexVIIRef: a.annexVIIRef,
			Format:      a.format,
			SHA256:      hash,
			Source:      a.source,
			Description: a.description,
		})

		// Track SBOM for 8-sbom copy.
		if a.annexVIIRef == "2b" && a.source == "toolkit" && sbomDst == "" {
			sbomDst = dst
		}
	}

	// Copy SBOM to section 8 (market surveillance).
	if sbomDst != "" {
		filename := filepath.Base(sbomDst)
		dst8 := filepath.Join(annexDir, "8-sbom", filename)
		if err := copyFile(sbomDst, dst8); err != nil {
			return nil, fmt.Errorf("copy SBOM to section 8: %w", err)
		}
		hash, _ := hashFile(dst8)
		entries = append(entries, ArtifactEntry{
			Path:        filepath.Join("annex-vii", "8-sbom", filename),
			AnnexVIIRef: "8",
			Format:      "CycloneDX",
			SHA256:      hash,
			Source:      "toolkit",
			Description: "SBOM for market surveillance (Annex VII point 8)",
		})
	}

	return entries, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // internal path
	if err != nil {
		return err
	}
	defer in.Close() //nolint:errcheck // read-only

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close() //nolint:errcheck // will check write err

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
```

- [ ] **Step 2: Implement archive.go**

Create `pkg/evidence/archive.go`:

```go
package evidence

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// CreateArchive produces a .tar.gz of the output directory.
func CreateArchive(sourceDir, archivePath string) error {
	outFile, err := os.Create(archivePath)
	if err != nil {
		return fmt.Errorf("create archive: %w", err)
	}
	defer outFile.Close() //nolint:errcheck // will check write err

	gw := gzip.NewWriter(outFile)
	defer gw.Close() //nolint:errcheck // will check write err

	tw := tar.NewWriter(gw)
	defer tw.Close() //nolint:errcheck // will check write err

	baseName := filepath.Base(sourceDir)

	err = filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.Join(baseName, rel)

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		f, err := os.Open(path) //nolint:gosec // internal path
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck // read-only

		_, err = io.Copy(tw, f)
		return err
	})

	if err != nil {
		return fmt.Errorf("archive walk: %w", err)
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar: %w", err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("close gzip: %w", err)
	}
	return outFile.Close()
}
```

- [ ] **Step 3: Run `task build`**

Run: `task build`
Expected: BUILD SUCCESS

- [ ] **Step 4: Commit**

```bash
git add pkg/evidence/assemble.go pkg/evidence/archive.go
git commit -m "feat(evidence): implement directory assembly and tar.gz archiving"
```

---

### Task 9: Markdown rendering

**Files:**
- Create: `pkg/evidence/render.go`

- [ ] **Step 1: Implement render.go**

Create `pkg/evidence/render.go`:

```go
package evidence

import (
	"fmt"
	"strings"
)

// RenderCompletenessMarkdown produces a human-readable completeness report.
func RenderCompletenessMarkdown(report CompletenessReport) string {
	var b strings.Builder

	b.WriteString("# CRA Annex VII Completeness Report\n\n")
	b.WriteString(fmt.Sprintf("> %s\n\n", report.Note))

	b.WriteString("## Score\n\n")
	b.WriteString(fmt.Sprintf("**%.0f%%** (%d / %d weight covered)\n\n", report.Score, report.CoveredWeight, report.TotalWeight))

	b.WriteString("## Sections\n\n")
	b.WriteString("| ID | Section | CRA Reference | Weight | Status |\n")
	b.WriteString("| --- | --- | --- | --- | --- |\n")

	for _, s := range report.Sections {
		status := "MISSING"
		if s.Weight == 0 {
			status = "N/A"
		} else if s.Covered {
			status = "COVERED"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %s |\n", s.ID, s.Title, s.CRARef, s.Weight, status))
	}
	b.WriteString("\n")

	// Gaps section.
	var gaps []AnnexVIISection
	for _, s := range report.Sections {
		if !s.Covered && s.Weight > 0 {
			gaps = append(gaps, s)
		}
	}
	if len(gaps) > 0 {
		b.WriteString("## Gaps\n\n")
		for _, g := range gaps {
			b.WriteString(fmt.Sprintf("- **%s** (%s): %s\n", g.ID, g.Title, g.Gap))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// RenderSummaryMarkdown produces a human-readable Annex VII summary.
func RenderSummaryMarkdown(summary AnnexVIISummary) string {
	var b strings.Builder

	b.WriteString("# CRA Annex VII Technical Documentation Summary\n\n")
	b.WriteString("> This summary is generated from real artifact data. No content is synthesized.\n\n")

	if summary.ProductDescription != "" {
		b.WriteString("## Product Description\n\n")
		b.WriteString(fmt.Sprintf("%s\n\n", summary.ProductDescription))
	}

	if summary.SBOMStats != nil {
		b.WriteString("## SBOM (Annex VII, point 2(b) and point 8)\n\n")
		b.WriteString("| Metric | Value |\n| --- | --- |\n")
		b.WriteString(fmt.Sprintf("| Format | %s |\n", summary.SBOMStats.Format))
		b.WriteString(fmt.Sprintf("| Component Count | %d |\n", summary.SBOMStats.ComponentCount))
		b.WriteString(fmt.Sprintf("| Product | %s %s |\n", summary.SBOMStats.ProductName, summary.SBOMStats.ProductVersion))
		b.WriteString("\n")
	}

	if summary.VulnHandlingStats != nil {
		b.WriteString("## Vulnerability Handling (Annex VII, point 2(b))\n\n")
		b.WriteString("| Metric | Value |\n| --- | --- |\n")
		b.WriteString(fmt.Sprintf("| Total Assessed | %d |\n", summary.VulnHandlingStats.TotalAssessed))
		for status, count := range summary.VulnHandlingStats.StatusDistribution {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", status, count))
		}
		b.WriteString("\n")
	}

	if summary.ScanStats != nil {
		b.WriteString("## Test Reports — Vulnerability Scans (Annex VII, point 6)\n\n")
		b.WriteString("| Metric | Value |\n| --- | --- |\n")
		b.WriteString(fmt.Sprintf("| Total Findings | %d |\n", summary.ScanStats.TotalFindings))
		b.WriteString(fmt.Sprintf("| Scanner Count | %d |\n", summary.ScanStats.ScannerCount))
		for sev, count := range summary.ScanStats.SeverityDistribution {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", sev, count))
		}
		b.WriteString("\n")
	}

	if summary.PolicyComplianceStats != nil {
		b.WriteString("## Test Reports — Policy Evaluation (Annex VII, point 6)\n\n")
		b.WriteString("| Metric | Value |\n| --- | --- |\n")
		b.WriteString(fmt.Sprintf("| Total Rules | %d |\n", summary.PolicyComplianceStats.Total))
		b.WriteString(fmt.Sprintf("| Passed | %d |\n", summary.PolicyComplianceStats.Passed))
		b.WriteString(fmt.Sprintf("| Failed | %d |\n", summary.PolicyComplianceStats.Failed))
		b.WriteString(fmt.Sprintf("| Human Review | %d |\n", summary.PolicyComplianceStats.Human))
		b.WriteString("\n")
	}

	if summary.SupportPeriod != "" {
		b.WriteString("## Support Period (Annex VII, point 4)\n\n")
		b.WriteString(fmt.Sprintf("Support period ends: %s\n\n", summary.SupportPeriod))
	}

	if summary.ConformityProcedure != "" {
		b.WriteString("## Conformity Procedure\n\n")
		b.WriteString(fmt.Sprintf("Procedure: %s\n\n", summary.ConformityProcedure))
	}

	return b.String()
}

// RenderValidationMarkdown renders cross-validation results.
func RenderValidationMarkdown(report ValidationReport) string {
	var b strings.Builder

	b.WriteString("## Cross-Validation Results\n\n")
	b.WriteString(fmt.Sprintf("Passed: %d | Failed: %d | Warnings: %d\n\n", report.Passed, report.Failed, report.Warnings))

	if len(report.Checks) > 0 {
		b.WriteString("| Check | Status | Details |\n| --- | --- | --- |\n")
		for _, c := range report.Checks {
			b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", c.CheckID, strings.ToUpper(c.Status), c.Details))
		}
		b.WriteString("\n")
	}

	return b.String()
}
```

- [ ] **Step 2: Run `task build`**

Run: `task build`
Expected: BUILD SUCCESS

- [ ] **Step 3: Commit**

```bash
git add pkg/evidence/render.go
git commit -m "feat(evidence): implement markdown rendering for completeness and summary"
```

---

### Task 10: Run pipeline orchestrator and CLI wiring

**Files:**
- Modify: `pkg/evidence/evidence.go`
- Modify: `internal/cli/evidence.go`

- [ ] **Step 1: Replace the evidence.go stub with the full Run pipeline**

Replace `pkg/evidence/evidence.go`:

```go
package evidence

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"time"
)

// Run executes the evidence bundling pipeline.
func Run(opts *Options, out io.Writer) error { //nolint:gocognit,gocyclo // pipeline has many sequential stages
	// 0. Validate required options.
	if opts.ProductConfig == "" {
		return ErrNoProductConfig
	}
	if opts.OutputDir == "" {
		return ErrNoOutputDir
	}

	// 1. Parse inputs.
	cfg, err := LoadEvidenceConfig(opts.ProductConfig)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	product := BuildProductIdentity(cfg)

	arts, err := ResolveArtifacts(opts)
	if err != nil {
		return fmt.Errorf("resolve artifacts: %w", err)
	}

	if len(arts) == 0 {
		return ErrNoArtifacts
	}

	// 2. Validate artifact formats.
	formatChecks := ValidateArtifacts(arts)

	// 3. Cross-validate consistency.
	crossChecks, err := CrossValidate(opts.SBOMPath, opts.VEXPath, opts.ScanPaths, opts.PolicyReport, opts.CSAFPath, opts.ReportPath)
	if err != nil {
		return fmt.Errorf("cross-validate: %w", err)
	}

	// Merge all validation checks.
	allChecks := append(formatChecks, crossChecks...)
	var passed, failed, warnings int
	for _, c := range allChecks {
		switch c.Status {
		case "pass":
			passed++
		case "fail":
			failed++
		case "warn":
			warnings++
		}
	}

	// 4. Assemble directory structure.
	entries, err := Assemble(opts.OutputDir, opts.ProductConfig, arts)
	if err != nil {
		return fmt.Errorf("assemble: %w", err)
	}

	// 5. Summarize.
	completeness := ComputeCompleteness(entries, product)
	summary := BuildSummary(product, opts.SBOMPath, opts.VEXPath, opts.ScanPaths, opts.PolicyReport)
	summary.StandardsApplied = cfg.Evidence.StandardsApplied

	// 6. Compute manifest.
	manifest, err := ComputeManifest(opts.OutputDir)
	if err != nil {
		return fmt.Errorf("compute manifest: %w", err)
	}
	manifestPath := filepath.Join(opts.OutputDir, "manifest.sha256")
	if err := WriteManifest(manifest, manifestPath); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	// 7. Sign.
	sig := SignManifest(manifestPath, opts.SigningKey)

	// 8. Build bundle.
	bundle := &Bundle{
		BundleID:       "CRA-EVD-" + time.Now().UTC().Format("20060102T150405Z"),
		ToolkitVersion: "0.1.0",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Product:        product,
		Artifacts:      entries,
		Validation: ValidationReport{
			Checks:   allChecks,
			Passed:   passed,
			Failed:   failed,
			Warnings: warnings,
		},
		Completeness: completeness,
		Summary:      summary,
		Manifest:     manifest,
		Signature:    sig,
	}

	// Write rendered markdown files into the bundle directory.
	writeMarkdownFiles(opts.OutputDir, completeness, summary, bundle.Validation)

	// Write bundle.json into the output directory.
	bundleJSON, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bundle: %w", err)
	}
	if err := writeFileBytes(filepath.Join(opts.OutputDir, "bundle.json"), bundleJSON); err != nil {
		return fmt.Errorf("write bundle.json: %w", err)
	}

	// 9. Archive (optional).
	if opts.Archive {
		archivePath := opts.OutputDir + ".tar.gz"
		if err := CreateArchive(opts.OutputDir, archivePath); err != nil {
			return fmt.Errorf("create archive: %w", err)
		}
	}

	// 10. Write to output writer.
	if opts.OutputFormat == "markdown" {
		_, err := io.WriteString(out, RenderCompletenessMarkdown(completeness))
		if err != nil {
			return err
		}
		_, err = io.WriteString(out, RenderSummaryMarkdown(summary))
		return err
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(bundle)
}

func writeMarkdownFiles(dir string, comp CompletenessReport, summary AnnexVIISummary, validation ValidationReport) {
	_ = writeFileBytes(filepath.Join(dir, "completeness.md"), []byte(RenderCompletenessMarkdown(comp)))
	_ = writeFileBytes(filepath.Join(dir, "annex-vii-summary.md"), []byte(RenderSummaryMarkdown(summary)))
}

func writeFileBytes(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}
```

Note: Add `"os"` to imports.

- [ ] **Step 2: Update CLI wiring**

Replace `internal/cli/evidence.go`:

```go
package cli

import (
	"context"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/cra-toolkit/pkg/evidence"
)

func newEvidenceCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "evidence",
		Usage: "Bundle compliance outputs into a signed CRA evidence package for Annex VII",
		Flags: []urfave.Flag{
			&urfave.StringFlag{Name: "sbom", Usage: "Path to SBOM (CycloneDX or SPDX)"},
			&urfave.StringFlag{Name: "vex", Usage: "Path to VEX document (OpenVEX or CSAF)"},
			&urfave.StringSliceFlag{Name: "scan", Usage: "Path to scan results (Grype/Trivy/SARIF), repeatable"},
			&urfave.StringFlag{Name: "policy-report", Usage: "Path to cra-policykit report (JSON)"},
			&urfave.StringFlag{Name: "csaf", Usage: "Path to CSAF advisory"},
			&urfave.StringFlag{Name: "art14-report", Usage: "Path to Art. 14 notification (JSON)"},
			&urfave.StringFlag{Name: "risk-assessment", Usage: "Path to cybersecurity risk assessment document"},
			&urfave.StringFlag{Name: "architecture", Usage: "Path to design/development architecture document"},
			&urfave.StringFlag{Name: "production-process", Usage: "Path to production/monitoring process document"},
			&urfave.StringFlag{Name: "eu-declaration", Usage: "Path to EU declaration of conformity"},
			&urfave.StringFlag{Name: "cvd-policy", Usage: "Path to coordinated vulnerability disclosure policy"},
			&urfave.StringFlag{Name: "standards", Usage: "Path to harmonised standards document"},
			&urfave.StringFlag{Name: "product-config", Required: true, Usage: "Path to product configuration (YAML)"},
			&urfave.StringFlag{Name: "output-dir", Required: true, Usage: "Output directory for evidence bundle"},
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
				SigningKey:        cmd.String("signing-key"),
			}

			w, closer := OutputWriter(cmd)
			defer closer() //nolint:errcheck // CLI cleanup

			return evidence.Run(opts, w)
		},
	}
}
```

- [ ] **Step 3: Run `task build`**

Run: `task build`
Expected: BUILD SUCCESS

- [ ] **Step 4: Commit**

```bash
git add pkg/evidence/evidence.go internal/cli/evidence.go
git commit -m "feat(evidence): implement Run pipeline and CLI wiring"
```

---

### Task 11: Integration test fixtures and tests

**Files:**
- Create: `testdata/integration/evidence-full-bundle/` (fixture with all artifacts)
- Create: `testdata/integration/evidence-cross-validation-mismatch/` (fixture with product identity mismatch)
- Create: `testdata/integration/evidence-minimal/expected.json`
- Create: `testdata/integration/evidence-full-bundle/expected.json`
- Create: `testdata/integration/evidence-purl-mismatch/expected.json`
- Create: `testdata/integration/evidence-cross-validation-mismatch/expected.json`
- Create: `testdata/integration/evidence-multiple-scans/` (fixture)
- Create: `pkg/evidence/integration_test.go`

- [ ] **Step 1: Create evidence-minimal expected.json**

Create `testdata/integration/evidence-minimal/expected.json`:

```json
{
  "description": "Minimal bundle with SBOM + scan only — completeness report shows gaps",
  "assertions": {
    "artifact_count": 4,
    "min_completeness": 20.0,
    "max_completeness": 45.0,
    "covered_sections": ["1a", "1b", "1d", "2b-sbom", "2b-cvd", "4", "6", "8"],
    "missing_sections": ["2a", "2c", "3", "7"],
    "validation_passed": 2,
    "validation_failed": 0,
    "validation_warnings": 0,
    "failed_checks": [],
    "product_name": "cra-toolkit",
    "product_version": "1.0.0",
    "has_signature": false,
    "sbom_component_count": 2,
    "vex_assessed_cves": 0,
    "error": ""
  }
}
```

- [ ] **Step 2: Create evidence-full-bundle fixture**

Copy artifacts from existing fixtures to create a comprehensive fixture:

```bash
mkdir -p testdata/integration/evidence-full-bundle
cp testdata/integration/policykit-all-pass/sbom.cdx.json testdata/integration/evidence-full-bundle/
cp testdata/integration/policykit-all-pass/grype.json testdata/integration/evidence-full-bundle/
cp testdata/integration/policykit-all-pass/vex-results.json testdata/integration/evidence-full-bundle/
```

Create `testdata/integration/evidence-full-bundle/product-config.yaml`:

```yaml
product:
  name: "cra-toolkit"
  version: "1.0.0"
  manufacturer: "SUSE"
  member_state: "DE"
  support_end_date: "2031-12-31"

evidence:
  intended_purpose: "CLI toolkit for CRA compliance automation"
  product_class: "default"
  conformity_procedure: "module-A"
  security_contact: "security@suse.com"
  cvd_policy_url: "https://www.suse.com/support/security/"
  standards_applied:
    - "ISO/IEC 27001:2022"
```

Create `testdata/integration/evidence-full-bundle/risk-assessment.txt`:

```
SUSE CRA Toolkit — Cybersecurity Risk Assessment
This is a placeholder manufacturer-provided risk assessment document.
```

Create `testdata/integration/evidence-full-bundle/architecture.txt`:

```
SUSE CRA Toolkit — System Architecture
This is a placeholder manufacturer-provided architecture document.
```

Create `testdata/integration/evidence-full-bundle/eu-declaration.txt`:

```
EU Declaration of Conformity
Product: SUSE CRA Toolkit v1.0.0
This is a placeholder EU declaration of conformity.
```

Create `testdata/integration/evidence-full-bundle/cvd-policy.md`:

```markdown
# Coordinated Vulnerability Disclosure Policy
Contact: security@suse.com
```

Create `testdata/integration/evidence-full-bundle/standards.md`:

```markdown
# Standards Applied
- ISO/IEC 27001:2022
```

Create `testdata/integration/evidence-full-bundle/production-process.txt`:

```
Production and Monitoring Process Documentation
```

Generate a policy report by running:
```bash
cd /Users/ravan/suse/repo/github/ravan/cra-toolkit
task build
./bin/cra policykit --sbom testdata/integration/policykit-all-pass/sbom.cdx.json --scan testdata/integration/policykit-all-pass/grype.json --vex testdata/integration/policykit-all-pass/vex-results.json --provenance testdata/integration/policykit-all-pass/provenance.json --signature testdata/integration/policykit-all-pass/signature.json --product-config testdata/integration/policykit-all-pass/product-config.yaml --kev testdata/integration/policykit-all-pass/kev.json --format json > testdata/integration/evidence-full-bundle/policy-report.json
```

Create `testdata/integration/evidence-full-bundle/expected.json`:

```json
{
  "description": "Full bundle with all toolkit and manufacturer artifacts — complete coverage",
  "assertions": {
    "artifact_count": 12,
    "min_completeness": 85.0,
    "max_completeness": 100.0,
    "covered_sections": ["1a", "1b", "1d", "2a", "2b-sbom", "2b-cvd", "2c", "3", "4", "5", "6", "7", "8"],
    "missing_sections": [],
    "validation_passed": 8,
    "validation_failed": 0,
    "validation_warnings": 1,
    "failed_checks": [],
    "product_name": "cra-toolkit",
    "product_version": "1.0.0",
    "has_signature": false,
    "sbom_component_count": 2,
    "vex_assessed_cves": 1,
    "error": ""
  }
}
```

- [ ] **Step 3: Create evidence-purl-mismatch expected.json**

Create `testdata/integration/evidence-purl-mismatch/expected.json`:

```json
{
  "description": "VEX contains PURLs not in SBOM — CV-SBOM-VEX-PURL fails",
  "assertions": {
    "artifact_count": 3,
    "min_completeness": 20.0,
    "max_completeness": 60.0,
    "covered_sections": ["1a", "1b", "1d", "2b-sbom", "2b-cvd", "4", "6", "8"],
    "missing_sections": ["2a", "2c", "3", "7"],
    "validation_passed": 1,
    "validation_failed": 1,
    "validation_warnings": 0,
    "failed_checks": ["CV-SBOM-VEX-PURL"],
    "product_name": "cra-toolkit",
    "product_version": "1.0.0",
    "has_signature": false,
    "sbom_component_count": 2,
    "vex_assessed_cves": 1,
    "error": ""
  }
}
```

Also copy the product config and SBOM to the purl-mismatch fixture:

```bash
cp testdata/integration/evidence-minimal/product-config.yaml testdata/integration/evidence-purl-mismatch/
cp testdata/integration/evidence-minimal/sbom.cdx.json testdata/integration/evidence-purl-mismatch/
```

- [ ] **Step 4: Write integration test**

Create `pkg/evidence/integration_test.go`:

```go
package evidence_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/evidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type expectedEvidence struct {
	Description string `json:"description"`
	Assertions  struct {
		ArtifactCount      int      `json:"artifact_count"`
		MinCompleteness    float64  `json:"min_completeness"`
		MaxCompleteness    float64  `json:"max_completeness"`
		CoveredSections    []string `json:"covered_sections"`
		MissingSections    []string `json:"missing_sections"`
		ValidationPassed   int      `json:"validation_passed"`
		ValidationFailed   int      `json:"validation_failed"`
		ValidationWarnings int      `json:"validation_warnings"`
		FailedChecks       []string `json:"failed_checks"`
		ProductName        string   `json:"product_name"`
		ProductVersion     string   `json:"product_version"`
		HasSignature       bool     `json:"has_signature"`
		SBOMComponentCount int      `json:"sbom_component_count"`
		VEXAssessedCVEs    int      `json:"vex_assessed_cves"`
		Error              string   `json:"error"`
	} `json:"assertions"`
}

func TestIntegration_EvidenceMinimal(t *testing.T) {
	runEvidenceIntegration(t, "evidence-minimal", nil)
}

func TestIntegration_EvidenceFullBundle(t *testing.T) {
	runEvidenceIntegration(t, "evidence-full-bundle", func(opts *evidence.Options, dir string) {
		opts.VEXPath = filepath.Join(dir, "vex-results.json")
		opts.PolicyReport = filepath.Join(dir, "policy-report.json")
		opts.RiskAssessment = filepath.Join(dir, "risk-assessment.txt")
		opts.ArchitectureDocs = filepath.Join(dir, "architecture.txt")
		opts.EUDeclaration = filepath.Join(dir, "eu-declaration.txt")
		opts.CVDPolicy = filepath.Join(dir, "cvd-policy.md")
		opts.StandardsDoc = filepath.Join(dir, "standards.md")
		opts.ProductionProcess = filepath.Join(dir, "production-process.txt")
	})
}

func TestIntegration_EvidencePURLMismatch(t *testing.T) {
	runEvidenceIntegration(t, "evidence-purl-mismatch", func(opts *evidence.Options, dir string) {
		opts.VEXPath = filepath.Join(dir, "vex-mismatch.json")
	})
}

func runEvidenceIntegration(t *testing.T, scenario string, customize func(*evidence.Options, string)) {
	t.Helper()
	dir := filepath.Join(fixtureBase, scenario)

	expected := loadExpectedEvidence(t, dir)

	outputDir := t.TempDir()
	opts := &evidence.Options{
		SBOMPath:      filepath.Join(dir, "sbom.cdx.json"),
		ScanPaths:     []string{filepath.Join(dir, "grype.json")},
		ProductConfig: filepath.Join(dir, "product-config.yaml"),
		OutputDir:     outputDir,
		OutputFormat:  "json",
	}

	if customize != nil {
		customize(opts, dir)
	}

	var buf bytes.Buffer
	err := evidence.Run(opts, &buf)

	if expected.Assertions.Error != "" {
		require.Error(t, err)
		assert.Contains(t, err.Error(), expected.Assertions.Error)
		return
	}
	require.NoError(t, err)

	var bundle evidence.Bundle
	require.NoError(t, json.Unmarshal(buf.Bytes(), &bundle))

	// Product identity.
	assert.Equal(t, expected.Assertions.ProductName, bundle.Product.Name)
	assert.Equal(t, expected.Assertions.ProductVersion, bundle.Product.Version)

	// Artifact count.
	if expected.Assertions.ArtifactCount > 0 {
		assert.GreaterOrEqual(t, len(bundle.Artifacts), expected.Assertions.ArtifactCount-2, "artifact count too low")
	}

	// Completeness.
	assert.GreaterOrEqual(t, bundle.Completeness.Score, expected.Assertions.MinCompleteness)
	if expected.Assertions.MaxCompleteness > 0 {
		assert.LessOrEqual(t, bundle.Completeness.Score, expected.Assertions.MaxCompleteness)
	}

	// Covered sections.
	coveredIDs := make(map[string]bool)
	for _, s := range bundle.Completeness.Sections {
		if s.Covered {
			coveredIDs[s.ID] = true
		}
	}
	for _, id := range expected.Assertions.CoveredSections {
		assert.True(t, coveredIDs[id], "expected section %s to be covered", id)
	}

	// Missing sections.
	for _, id := range expected.Assertions.MissingSections {
		assert.False(t, coveredIDs[id], "expected section %s to be missing", id)
	}

	// Validation.
	if expected.Assertions.ValidationFailed >= 0 {
		assert.Equal(t, expected.Assertions.ValidationFailed, bundle.Validation.Failed, "validation failures")
	}

	// Failed checks.
	failedCheckIDs := make(map[string]bool)
	for _, c := range bundle.Validation.Checks {
		if c.Status == "fail" {
			failedCheckIDs[c.CheckID] = true
		}
	}
	for _, checkID := range expected.Assertions.FailedChecks {
		assert.True(t, failedCheckIDs[checkID], "expected check %s to fail", checkID)
	}

	// Signature.
	if expected.Assertions.HasSignature {
		require.NotNil(t, bundle.Signature)
		assert.NotEqual(t, "unsigned", bundle.Signature.Method)
	}

	// Summary stats.
	if expected.Assertions.SBOMComponentCount > 0 && bundle.Summary.SBOMStats != nil {
		assert.Equal(t, expected.Assertions.SBOMComponentCount, bundle.Summary.SBOMStats.ComponentCount)
	}
	if expected.Assertions.VEXAssessedCVEs > 0 && bundle.Summary.VulnHandlingStats != nil {
		assert.Equal(t, expected.Assertions.VEXAssessedCVEs, bundle.Summary.VulnHandlingStats.TotalAssessed)
	}

	// Verify output directory structure.
	assert.FileExists(t, filepath.Join(outputDir, "bundle.json"))
	assert.FileExists(t, filepath.Join(outputDir, "completeness.md"))
	assert.FileExists(t, filepath.Join(outputDir, "annex-vii-summary.md"))
	assert.FileExists(t, filepath.Join(outputDir, "manifest.sha256"))
}

func loadExpectedEvidence(t *testing.T, dir string) expectedEvidence {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	require.NoError(t, err)
	var expected expectedEvidence
	require.NoError(t, json.Unmarshal(data, &expected))
	return expected
}
```

- [ ] **Step 5: Run integration tests**

Run: `go test -run TestIntegration ./pkg/evidence/...`
Expected: PASS (all 3 scenarios)

- [ ] **Step 6: Run full quality gate**

Run: `task quality`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add testdata/integration/evidence-*/ pkg/evidence/integration_test.go
git commit -m "test(evidence): add integration test fixtures and 3 scenario tests"
```

---

### Task 12: LLM quality judge test

**Files:**
- Create: `pkg/evidence/llm_judge_test.go`

- [ ] **Step 1: Write LLM judge test**

Create `pkg/evidence/llm_judge_test.go`:

```go
//go:build llmjudge

package evidence_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/evidence"
)

type evidenceLLMScores struct {
	AnnexVIICoverage      int    `json:"annex_vii_coverage"`
	CrossValidationRigor  int    `json:"cross_validation_rigor"`
	CompletenessAccuracy  int    `json:"completeness_accuracy"`
	SummaryAccuracy       int    `json:"summary_accuracy"`
	RegulatoryHonesty     int    `json:"regulatory_honesty"`
	OverallQuality        int    `json:"overall_quality"`
	Reasoning             string `json:"reasoning"`
}

func TestLLMJudge_EvidenceFullBundle(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	dir := filepath.Join(fixtureBase, "evidence-full-bundle")
	outputDir := t.TempDir()

	opts := &evidence.Options{
		SBOMPath:          filepath.Join(dir, "sbom.cdx.json"),
		VEXPath:           filepath.Join(dir, "vex-results.json"),
		ScanPaths:         []string{filepath.Join(dir, "grype.json")},
		PolicyReport:      filepath.Join(dir, "policy-report.json"),
		RiskAssessment:    filepath.Join(dir, "risk-assessment.txt"),
		ArchitectureDocs:  filepath.Join(dir, "architecture.txt"),
		EUDeclaration:     filepath.Join(dir, "eu-declaration.txt"),
		CVDPolicy:         filepath.Join(dir, "cvd-policy.md"),
		StandardsDoc:      filepath.Join(dir, "standards.md"),
		ProductionProcess: filepath.Join(dir, "production-process.txt"),
		ProductConfig:     filepath.Join(dir, "product-config.yaml"),
		OutputDir:         outputDir,
		OutputFormat:      "json",
	}

	var buf bytes.Buffer
	if err := evidence.Run(opts, &buf); err != nil {
		t.Fatalf("evidence.Run() error: %v", err)
	}

	bundleFile, err := os.CreateTemp(".", "evidence-bundle-*.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(bundleFile.Name()) //nolint:errcheck // test cleanup
	if _, err := bundleFile.Write(buf.Bytes()); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	bundleFile.Close()

	completenessPath := filepath.Join(outputDir, "completeness.md")
	summaryPath := filepath.Join(outputDir, "annex-vii-summary.md")

	prompt := fmt.Sprintf(`You are a CRA (EU Cyber Resilience Act) Annex VII technical documentation quality judge.

CRA Annex VII requires technical documentation containing:
1. General description (purpose, versions, user info)
2. Design/development description (architecture, vulnerability handling incl. SBOM, CVD, updates, production)
3. Cybersecurity risk assessment
4. Support period information
5. Harmonised standards applied
6. Test/verification reports
7. EU declaration of conformity
8. SBOM (for market surveillance)

The tool is an evidence BUNDLER — it collects artifacts, cross-validates consistency, and generates
a completeness report. It should NOT fabricate data or overstate its role.

Read the GENERATED BUNDLE JSON from: %s
Read the COMPLETENESS REPORT from: %s
Read the ANNEX VII SUMMARY from: %s

Score on these dimensions (1-10 each):
1. annex_vii_coverage: Does the bundle structure correctly map to all 8 Annex VII sections?
2. cross_validation_rigor: Are cross-validation checks meaningful and correctly reported?
3. completeness_accuracy: Does the completeness report honestly reflect what is present vs missing?
4. summary_accuracy: Are Annex VII summary stats derived from real data, not fabricated?
5. regulatory_honesty: Does the output avoid overstating compliance or the tool's role?
6. overall_quality: Would a compliance officer trust this for conformity assessment preparation?

Respond ONLY with valid JSON, no other text:
{"annex_vii_coverage": N, "cross_validation_rigor": N, "completeness_accuracy": N, "summary_accuracy": N, "regulatory_honesty": N, "overall_quality": N, "reasoning": "brief explanation"}`,
		bundleFile.Name(), completenessPath, summaryPath)

	cmd := exec.Command(geminiPath, "--approval-mode", "plan", "-p", prompt) //nolint:gosec
	var geminiOut bytes.Buffer
	cmd.Stdout = &geminiOut
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gemini error: %v", err)
	}

	responseText := geminiOut.String()
	jsonStart := strings.Index(responseText, "{")
	jsonEnd := strings.LastIndex(responseText, "}")
	if jsonStart == -1 || jsonEnd == -1 {
		t.Fatalf("no JSON in response: %s", responseText)
	}

	var scores evidenceLLMScores
	if err := json.Unmarshal([]byte(responseText[jsonStart:jsonEnd+1]), &scores); err != nil {
		t.Fatalf("parse scores: %v\nresponse: %s", err, responseText)
	}

	t.Logf("LLM Scores: coverage=%d rigor=%d completeness=%d summary=%d honesty=%d overall=%d",
		scores.AnnexVIICoverage, scores.CrossValidationRigor, scores.CompletenessAccuracy,
		scores.SummaryAccuracy, scores.RegulatoryHonesty, scores.OverallQuality)
	t.Logf("Reasoning: %s", scores.Reasoning)

	threshold := 8
	dims := map[string]int{
		"annex_vii_coverage":     scores.AnnexVIICoverage,
		"cross_validation_rigor": scores.CrossValidationRigor,
		"completeness_accuracy":  scores.CompletenessAccuracy,
		"summary_accuracy":       scores.SummaryAccuracy,
		"regulatory_honesty":     scores.RegulatoryHonesty,
		"overall_quality":        scores.OverallQuality,
	}
	for dim, score := range dims {
		if score < threshold {
			t.Errorf("%s: score %d < threshold %d", dim, score, threshold)
		}
	}
}
```

- [ ] **Step 2: Run LLM judge test (optional)**

Run: `task test:evidence:llmjudge`
Expected: PASS (all dimensions >= 8/10)

- [ ] **Step 3: Commit**

```bash
git add pkg/evidence/llm_judge_test.go
git commit -m "test(evidence): add LLM quality judge test for Annex VII regulatory accuracy"
```

---

### Task 13: Final quality gate and cleanup

- [ ] **Step 1: Remove the old stub ErrNotImplemented**

The old `evidence.go` stub had `ErrNotImplemented`. Verify it's been removed by the Task 10 replacement. If any code still references it, remove the reference.

- [ ] **Step 2: Run full quality gate**

Run: `task quality`
Expected: ALL PASS

- [ ] **Step 3: Run all evidence tests**

Run: `go test -race -count=1 ./pkg/evidence/...`
Expected: ALL PASS

- [ ] **Step 4: Run integration tests for all packages to ensure no regressions**

Run: `task test`
Expected: ALL PASS

- [ ] **Step 5: Commit if any cleanup was needed**

```bash
git add -A
git commit -m "chore(evidence): final cleanup and quality gate pass"
```
