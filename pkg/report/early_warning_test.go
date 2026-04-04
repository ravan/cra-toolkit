package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildEarlyWarning(t *testing.T) {
	vulns := []ExploitedVuln{
		{
			CVE:      "CVE-2022-32149",
			Signals:  []ExploitationSignal{{Source: ExploitationKEV, Detail: "In KEV catalog"}},
			Severity: "high",
			CVSS:     7.5,
			AffectedProducts: []AffectedProduct{
				{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"},
			},
		},
	}
	mfr := Manufacturer{
		Name:                  "SUSE LLC",
		MemberState:           "DE",
		MemberStatesAvailable: []string{"DE", "FR"},
	}

	entries := BuildEarlyWarning(vulns, &mfr)
	require.Len(t, entries, 1)
	assert.Equal(t, "CVE-2022-32149", entries[0].CVE)
	assert.Len(t, entries[0].ExploitationSignals, 1)
	assert.Equal(t, ExploitationKEV, entries[0].ExploitationSignals[0].Source)
	assert.Equal(t, "high", entries[0].Severity)
	assert.InDelta(t, 7.5, entries[0].CVSS, 0.01)
	assert.Len(t, entries[0].AffectedProducts, 1)
	assert.Equal(t, []string{"DE", "FR"}, entries[0].MemberStates)
	// 72h/14d fields should be empty
	assert.Empty(t, entries[0].Description)
	assert.Empty(t, entries[0].RootCause)
}
