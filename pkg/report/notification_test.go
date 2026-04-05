// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildNotification(t *testing.T) {
	vulns := []ExploitedVuln{
		{
			CVE:         "CVE-2022-32149",
			Signals:     []ExploitationSignal{{Source: ExploitationKEV, Detail: "In KEV"}},
			Severity:    "high",
			CVSS:        7.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			Description: "DoS via crafted Accept-Language header",
			FixVersion:  "0.3.8",
			AffectedProducts: []AffectedProduct{
				{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"},
			},
		},
	}
	mfr := Manufacturer{Name: "SUSE LLC", MemberState: "DE", MemberStatesAvailable: []string{"DE"}}
	components := []formats.Component{
		{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"},
		{Name: "example.com/app", Version: "1.0.0", PURL: "pkg:golang/example.com/app@1.0.0"},
	}
	var vexResults []formats.VEXResult

	entries := BuildNotification(vulns, &mfr, components, vexResults)
	require.Len(t, entries, 1)

	e := entries[0]
	assert.Equal(t, "DoS via crafted Accept-Language header", e.Description)
	assert.NotEmpty(t, e.GeneralNature)
	assert.Contains(t, e.CorrectiveActions, "Update golang.org/x/text to version 0.3.8")
	assert.NotNil(t, e.EstimatedImpact)
	assert.Equal(t, 2, e.EstimatedImpact.AffectedComponentCount)
	assert.Equal(t, "high", e.InformationSensitivity)
	// 14d fields still empty
	assert.Empty(t, e.RootCause)
}
