// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

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

	summary := evidence.BuildSummary(&pid, sbomPath, vexPath, scanPaths, "")
	assert.Equal(t, "Test product", summary.ProductDescription)
	assert.Equal(t, "2031-12-31", summary.SupportPeriod)
	assert.Equal(t, "module-A", summary.ConformityProcedure)
	assert.NotNil(t, summary.SBOMStats)
	assert.NotNil(t, summary.ScanStats)
	assert.NotNil(t, summary.VulnHandlingStats)
}
