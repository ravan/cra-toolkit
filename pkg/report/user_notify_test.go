// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildUserNotification(t *testing.T) {
	vulns := []ExploitedVuln{
		{
			CVE:      "CVE-2022-32149",
			Severity: "high",
			CVSS:     7.5,
			AffectedProducts: []AffectedProduct{
				{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"},
			},
			FixVersion: "0.3.8",
		},
	}

	un := BuildUserNotification(vulns, "CSAF-ADV-2026-001")
	require.NotNil(t, un)
	assert.Len(t, un.AffectedProducts, 1)
	assert.Equal(t, "high", un.Severity)
	assert.Equal(t, "CSAF-ADV-2026-001", un.CSAFAdvisoryRef)
	assert.NotEmpty(t, un.RecommendedActions)
}

func TestBuildUserNotification_NoRef(t *testing.T) {
	vulns := []ExploitedVuln{{CVE: "CVE-2022-32149", Severity: "high"}}
	un := BuildUserNotification(vulns, "")
	assert.Empty(t, un.CSAFAdvisoryRef)
}
