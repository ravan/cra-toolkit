// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package evidence_test

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/evidence"
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

	pid := &evidence.ProductIdentity{
		IntendedPurpose:  "Test product",
		SupportPeriodEnd: "2031-12-31",
		SecurityContact:  "test@example.com",
		CVDPolicyURL:     "https://example.com/security",
	}

	report := evidence.ComputeCompleteness(arts, pid)
	assert.Equal(t, 100.0, report.Score)
	assert.Equal(t, report.TotalWeight, report.CoveredWeight)
}

func TestComputeCompleteness_MinimalSBOMOnly(t *testing.T) {
	arts := []evidence.ArtifactEntry{
		{AnnexVIIRef: "2b", Source: "toolkit", Description: "SBOM"},
	}

	pid := &evidence.ProductIdentity{
		IntendedPurpose: "Test product",
	}

	report := evidence.ComputeCompleteness(arts, pid)
	assert.Greater(t, report.Score, 0.0)
	assert.Less(t, report.Score, 50.0)

	var gaps []string
	for _, s := range report.Sections {
		if !s.Covered {
			gaps = append(gaps, s.ID)
		}
	}
	assert.Contains(t, gaps, "3") // Risk assessment missing
	assert.Contains(t, gaps, "7") // EU declaration missing
}

func TestComputeCompleteness_HardwareWeight(t *testing.T) {
	arts := []evidence.ArtifactEntry{}
	pid := &evidence.ProductIdentity{}

	report := evidence.ComputeCompleteness(arts, pid)

	for _, s := range report.Sections {
		if s.ID == "1c" {
			assert.Equal(t, 0, s.Weight)
		}
	}
}
