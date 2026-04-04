package evidence_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/evidence"
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

func runEvidenceIntegration(t *testing.T, scenario string, customize func(*evidence.Options, string)) { //nolint:gocognit,gocyclo // integration test helper has inherently many assertions
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

	// Validation counts.
	assert.Equal(t, expected.Assertions.ValidationPassed, bundle.Validation.Passed, "validation passed count")
	assert.Equal(t, expected.Assertions.ValidationFailed, bundle.Validation.Failed, "validation failures")
	assert.Equal(t, expected.Assertions.ValidationWarnings, bundle.Validation.Warnings, "validation warnings")

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
	path := filepath.Join(dir, "expected.json")
	data, err := os.ReadFile(path) //nolint:gosec // test fixture path, not user input
	require.NoError(t, err)
	var expected expectedEvidence
	require.NoError(t, json.Unmarshal(data, &expected))
	return expected
}
