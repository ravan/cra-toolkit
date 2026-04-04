package policykit_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixtureBase = "../../testdata/integration"

type expectedPolicykit struct {
	Description string `json:"description"`
	Assertions  struct {
		TotalResults     int               `json:"total_results"`
		Passed           *int              `json:"passed"`
		Failed           *int              `json:"failed"`
		Skipped          *int              `json:"skipped"`
		Human            *int              `json:"human"`
		ExpectedStatuses map[string]string `json:"expected_statuses"`
	} `json:"assertions"`
}

func TestIntegration_PolicykitAllPass(t *testing.T) {
	runPolicykitIntegration(t, "policykit-all-pass")
}

func TestIntegration_PolicykitKEVFail(t *testing.T) {
	runPolicykitIntegration(t, "policykit-kev-fail")
}

func TestIntegration_PolicykitVEXGap(t *testing.T) {
	runPolicykitIntegration(t, "policykit-vex-gap")
}

func TestIntegration_PolicykitMissingOptional(t *testing.T) {
	runPolicykitIntegration(t, "policykit-missing-optional")
}

func TestIntegration_PolicykitInvalidSBOM(t *testing.T) {
	runPolicykitIntegration(t, "policykit-invalid-sbom")
}

func TestIntegration_PolicykitMixed(t *testing.T) {
	runPolicykitIntegration(t, "policykit-mixed")
}

func runPolicykitIntegration(t *testing.T, scenario string) {
	t.Helper()
	dir := filepath.Join(fixtureBase, scenario)

	expected := loadExpectedPolicykit(t, dir)

	opts := &policykit.Options{
		SBOMPath:     filepath.Join(dir, "sbom.cdx.json"),
		ScanPaths:    []string{filepath.Join(dir, "grype.json")},
		VEXPath:      filepath.Join(dir, "vex-results.json"),
		KEVPath:      filepath.Join(dir, "kev.json"),
		OutputFormat: "json",
	}

	// Optional files
	if _, err := os.Stat(filepath.Join(dir, "provenance.json")); err == nil {
		opts.ProvenancePath = filepath.Join(dir, "provenance.json")
	}
	if _, err := os.Stat(filepath.Join(dir, "signature.json")); err == nil {
		opts.SignaturePaths = []string{filepath.Join(dir, "signature.json")}
	}
	if _, err := os.Stat(filepath.Join(dir, "product-config.yaml")); err == nil {
		opts.ProductConfig = filepath.Join(dir, "product-config.yaml")
	}

	var buf bytes.Buffer
	err := policykit.Run(opts, &buf)
	require.NoError(t, err, "policykit.Run() error")

	var report policykit.Report
	require.NoError(t, json.Unmarshal(buf.Bytes(), &report), "output is not valid JSON")

	// Validate summary counts
	if expected.Assertions.TotalResults > 0 {
		assert.Equal(t, expected.Assertions.TotalResults, report.Summary.Total, "total results count")
	}
	if expected.Assertions.Passed != nil {
		assert.Equal(t, *expected.Assertions.Passed, report.Summary.Passed, "passed count")
	}
	if expected.Assertions.Failed != nil {
		assert.Equal(t, *expected.Assertions.Failed, report.Summary.Failed, "failed count")
	}
	if expected.Assertions.Skipped != nil {
		assert.Equal(t, *expected.Assertions.Skipped, report.Summary.Skipped, "skipped count")
	}
	if expected.Assertions.Human != nil {
		assert.Equal(t, *expected.Assertions.Human, report.Summary.Human, "human count")
	}

	// Validate per-rule statuses
	resultMap := make(map[string]string)
	for _, r := range report.Results {
		resultMap[r.RuleID] = r.Status
	}
	for ruleID, expectedStatus := range expected.Assertions.ExpectedStatuses {
		actual, ok := resultMap[ruleID]
		if !ok {
			t.Errorf("expected rule %s not found in results", ruleID)
			continue
		}
		assert.Equal(t, expectedStatus, actual, "rule %s status", ruleID)
	}

	t.Logf("%s: %d results (P:%d F:%d S:%d H:%d), all assertions passed",
		scenario, report.Summary.Total, report.Summary.Passed, report.Summary.Failed,
		report.Summary.Skipped, report.Summary.Human)
}

func loadExpectedPolicykit(t *testing.T, dir string) expectedPolicykit {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "expected.json")) //nolint:gosec
	require.NoError(t, err, "read expected.json")
	var expected expectedPolicykit
	require.NoError(t, json.Unmarshal(data, &expected), "parse expected.json")
	return expected
}
