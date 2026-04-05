// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeCompleteness_EarlyWarning(t *testing.T) {
	n := &Notification{
		Stage: StageEarlyWarning,
		Vulnerabilities: []VulnEntry{
			{
				CVE:                 "CVE-2022-32149",
				ExploitationSignals: []ExploitationSignal{{Source: ExploitationKEV}},
				Severity:            "high",
				CVSS:                7.5,
				AffectedProducts:    []AffectedProduct{{Name: "test"}},
				MemberStates:        []string{"DE"},
			},
		},
	}

	c := ComputeCompleteness(n)
	assert.InDelta(t, 1.0, c.Score, 0.01)
	assert.Empty(t, c.Pending)
	assert.Equal(t, CompletenessNote, c.Note)
}

func TestComputeCompleteness_FinalReportWithPlaceholders(t *testing.T) {
	n := &Notification{
		Stage: StageFinalReport,
		Vulnerabilities: []VulnEntry{
			{
				CVE:             "CVE-2022-32149",
				Severity:        "high",
				RootCause:       humanInputRequired,
				ThreatActorInfo: humanInputRequired,
				SecurityUpdate:  humanInputRequired,
			},
		},
	}

	c := ComputeCompleteness(n)
	assert.Less(t, c.Score, 1.0)
	assert.NotEmpty(t, c.Pending)
	assert.Equal(t, CompletenessNote, c.Note)
}
