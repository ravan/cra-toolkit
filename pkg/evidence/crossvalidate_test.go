// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package evidence_test

import (
	"path/filepath"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/evidence"
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
	// policykit-all-pass has sbom.cdx.json and vex-results.json.
	// VEX references pkg:golang/golang.org/x/text@v0.3.7 which is in the SBOM.
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

	var found bool
	for _, c := range checks {
		if c.CheckID == "CV-SBOM-VEX-PURL" {
			found = true
			assert.Equal(t, "pass", c.Status, "details: %s", c.Details)
		}
	}
	assert.True(t, found, "CV-SBOM-VEX-PURL check not found in results")
}

func TestCrossValidate_SkipsWhenMissing(t *testing.T) {
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
