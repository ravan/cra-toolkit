package report

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderMarkdown(t *testing.T) {
	n := &Notification{
		NotificationID:    "CRA-NOTIF-TEST",
		ToolkitVersion:    "0.1.0",
		Timestamp:         "2026-04-04T12:00:00Z",
		Stage:             StageEarlyWarning,
		CRAReference:      "Art. 14(2)(a)",
		SubmissionChannel: SubmissionChannelENISA,
		Manufacturer:      Manufacturer{Name: "SUSE LLC", MemberState: "DE"},
		CSIRTCoordinator:  CSIRTInfo{Name: "BSI (CERT-Bund)", Country: "DE", SubmissionChannel: SubmissionChannelENISA},
		Vulnerabilities: []VulnEntry{
			{
				CVE:                 "CVE-2022-32149",
				ExploitationSignals: []ExploitationSignal{{Source: ExploitationKEV, Detail: "In KEV catalog"}},
				Severity:            "high",
				CVSS:                7.5,
				AffectedProducts:    []AffectedProduct{{Name: "golang.org/x/text", Version: "v0.3.7"}},
			},
		},
		Completeness: Completeness{Score: 1.0, TotalFields: 4, FilledFields: 4, Note: CompletenessNote},
	}

	md := RenderMarkdown(n)
	assert.Contains(t, md, "CRA Article 14 Vulnerability Notification")
	assert.Contains(t, md, "CRA-NOTIF-TEST")
	assert.Contains(t, md, "Early Warning")
	assert.Contains(t, md, "Art. 14(2)(a)")
	assert.Contains(t, md, "ENISA Single Reporting Platform")
	assert.Contains(t, md, "BSI (CERT-Bund)")
	assert.Contains(t, md, "CVE-2022-32149")
	assert.Contains(t, md, "KEV")
	assert.Contains(t, md, "Toolkit quality metric")
	// Check the regulatory honesty notes are present
	assert.True(t, strings.Contains(md, "manufacturer") && strings.Contains(md, "determination"))
}
