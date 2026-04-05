// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildFinalReport_WithHumanInput(t *testing.T) {
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
	components := []formats.Component{{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"}}
	human := &HumanInput{
		Vulnerabilities: map[string]HumanVulnInput{
			"CVE-2022-32149": {
				CorrectiveMeasureDate: "2022-10-11",
				RootCause:             "Algorithmic complexity in ParseAcceptLanguage",
				ThreatActorInfo:       "No specific threat actor identified",
				SecurityUpdate:        "golang.org/x/text v0.3.8",
				PreventiveMeasures:    []string{"Input length limiting"},
			},
		},
	}

	entries := BuildFinalReport(vulns, &mfr, components, nil, human, "")
	require.Len(t, entries, 1)

	e := entries[0]
	assert.Equal(t, "2022-10-11", e.CorrectiveMeasureDate)
	assert.Equal(t, "Algorithmic complexity in ParseAcceptLanguage", e.RootCause)
	assert.Equal(t, "No specific threat actor identified", e.ThreatActorInfo)
	assert.Equal(t, "golang.org/x/text v0.3.8", e.SecurityUpdate)
	assert.Equal(t, []string{"Input length limiting"}, e.PreventiveMeasures)
}

func TestBuildFinalReport_WithoutHumanInput(t *testing.T) {
	vulns := []ExploitedVuln{
		{CVE: "CVE-2022-32149", Signals: []ExploitationSignal{{Source: ExploitationKEV, Detail: "In KEV"}}, Severity: "high", CVSS: 7.5, Description: "DoS"},
	}
	mfr := Manufacturer{Name: "SUSE LLC", MemberState: "DE"}

	entries := BuildFinalReport(vulns, &mfr, nil, nil, nil, "")
	require.Len(t, entries, 1)

	e := entries[0]
	assert.Equal(t, "[HUMAN INPUT REQUIRED]", e.RootCause)
	assert.Equal(t, "[HUMAN INPUT REQUIRED]", e.ThreatActorInfo)
}

func TestBuildFinalReport_CorrectiveMeasureDateFromFlag(t *testing.T) {
	vulns := []ExploitedVuln{
		{CVE: "CVE-2022-32149", Signals: []ExploitationSignal{{Source: ExploitationKEV, Detail: "In KEV"}}, Severity: "high"},
	}
	mfr := Manufacturer{Name: "SUSE LLC", MemberState: "DE"}

	entries := BuildFinalReport(vulns, &mfr, nil, nil, nil, "2022-10-15")
	require.Len(t, entries, 1)
	assert.Equal(t, "2022-10-15", entries[0].CorrectiveMeasureDate)
}
