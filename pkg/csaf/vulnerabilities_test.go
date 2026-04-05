// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csaf

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapVulnerabilities_AffectedStatus(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7"},
	}
	vexResults := []formats.VEXResult{
		{CVE: "CVE-2022-32149", ComponentPURL: "pkg:golang/golang.org/x/text@v0.3.7", Status: formats.StatusAffected},
	}

	vulns := mapVulnerabilities(findings, vexResults)

	require.Len(t, vulns, 1)
	assert.Equal(t, "CVE-2022-32149", vulns[0].CVE)
	assert.Equal(t, []string{"pkg:golang/golang.org/x/text@v0.3.7"}, vulns[0].ProductStatus.KnownAffected)
}

func TestMapVulnerabilities_NotAffectedWithJustification(t *testing.T) {
	purl := "pkg:golang/golang.org/x/text@v0.3.7"
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", AffectedPURL: purl},
	}
	vexResults := []formats.VEXResult{
		{
			CVE:           "CVE-2022-32149",
			ComponentPURL: purl,
			Status:        formats.StatusNotAffected,
			Justification: formats.JustificationVulnerableCodeNotInExecutePath,
		},
	}

	vulns := mapVulnerabilities(findings, vexResults)

	require.Len(t, vulns, 1)
	assert.Equal(t, []string{purl}, vulns[0].ProductStatus.KnownNotAffected)
	require.Len(t, vulns[0].Flags, 1)
	assert.Equal(t, string(formats.JustificationVulnerableCodeNotInExecutePath), vulns[0].Flags[0].Label)
	assert.Equal(t, []string{purl}, vulns[0].Flags[0].ProductIDs)
}

func TestMapVulnerabilities_FixedStatus(t *testing.T) {
	purl := "pkg:golang/golang.org/x/text@v0.3.8"
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", AffectedPURL: purl},
	}
	vexResults := []formats.VEXResult{
		{CVE: "CVE-2022-32149", ComponentPURL: purl, Status: formats.StatusFixed},
	}

	vulns := mapVulnerabilities(findings, vexResults)

	require.Len(t, vulns, 1)
	assert.Equal(t, []string{purl}, vulns[0].ProductStatus.Fixed)
}

func TestMapVulnerabilities_FindingWithoutVEX_DefaultsToUnderInvestigation(t *testing.T) {
	purl := "pkg:golang/golang.org/x/text@v0.3.7"
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", AffectedPURL: purl},
	}
	var vexResults []formats.VEXResult

	vulns := mapVulnerabilities(findings, vexResults)

	require.Len(t, vulns, 1)
	assert.Equal(t, []string{purl}, vulns[0].ProductStatus.UnderInvestigation)
}

func TestMapVulnerabilities_MultipleCVEs_SeparateVulnerabilities(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7"},
		{CVE: "CVE-2023-45283", AffectedPURL: "pkg:golang/golang.org/x/net@v0.1.0"},
	}
	vexResults := []formats.VEXResult{
		{CVE: "CVE-2022-32149", ComponentPURL: "pkg:golang/golang.org/x/text@v0.3.7", Status: formats.StatusAffected},
		{CVE: "CVE-2023-45283", ComponentPURL: "pkg:golang/golang.org/x/net@v0.1.0", Status: formats.StatusFixed},
	}

	vulns := mapVulnerabilities(findings, vexResults)

	require.Len(t, vulns, 2)
	assert.Equal(t, "CVE-2022-32149", vulns[0].CVE)
	assert.Equal(t, "CVE-2023-45283", vulns[1].CVE)
}

func TestMapVulnerabilities_SameCVE_MultipleProducts(t *testing.T) {
	purl1 := "pkg:golang/golang.org/x/text@v0.3.7"
	purl2 := "pkg:golang/golang.org/x/text@v0.4.0"
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", AffectedPURL: purl1},
		{CVE: "CVE-2022-32149", AffectedPURL: purl2},
	}
	vexResults := []formats.VEXResult{
		{CVE: "CVE-2022-32149", ComponentPURL: purl1, Status: formats.StatusAffected},
		{CVE: "CVE-2022-32149", ComponentPURL: purl2, Status: formats.StatusNotAffected, Justification: formats.JustificationVulnerableCodeNotPresent},
	}

	vulns := mapVulnerabilities(findings, vexResults)

	require.Len(t, vulns, 1)
	assert.Equal(t, []string{purl1}, vulns[0].ProductStatus.KnownAffected)
	assert.Equal(t, []string{purl2}, vulns[0].ProductStatus.KnownNotAffected)
}
