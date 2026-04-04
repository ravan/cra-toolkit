package report

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAggregateSignals_KEVMatch(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7", Severity: "high", CVSS: 7.5, Description: "DoS via Accept-Language", FixVersion: "0.3.8"},
	}
	kev := &policykit.KEVCatalog{CVEs: map[string]bool{"CVE-2022-32149": true}}
	components := []formats.Component{{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"}}

	vulns := AggregateExploitationSignals(findings, kev, nil, nil, components, 0.7)
	require.Len(t, vulns, 1)
	assert.Equal(t, "CVE-2022-32149", vulns[0].CVE)
	require.Len(t, vulns[0].Signals, 1)
	assert.Equal(t, ExploitationKEV, vulns[0].Signals[0].Source)
}

func TestAggregateSignals_EPSSAboveThreshold(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", Severity: "high", CVSS: 7.5, AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7"},
	}
	epss := &EPSSData{Scores: map[string]float64{"CVE-2022-32149": 0.85}}
	components := []formats.Component{{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"}}

	vulns := AggregateExploitationSignals(findings, nil, epss, nil, components, 0.7)
	require.Len(t, vulns, 1)
	require.Len(t, vulns[0].Signals, 1)
	assert.Equal(t, ExploitationEPSS, vulns[0].Signals[0].Source)
	assert.Contains(t, vulns[0].Signals[0].Detail, "0.85")
}

func TestAggregateSignals_EPSSBelowThreshold(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", Severity: "high", CVSS: 7.5, AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7"},
	}
	epss := &EPSSData{Scores: map[string]float64{"CVE-2022-32149": 0.3}}
	components := []formats.Component{{PURL: "pkg:golang/golang.org/x/text@v0.3.7"}}

	vulns := AggregateExploitationSignals(findings, nil, epss, nil, components, 0.7)
	assert.Empty(t, vulns)
}

func TestAggregateSignals_ManualOverride(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", Severity: "high", CVSS: 7.5, AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7"},
	}
	overrides := []ExploitationOverride{
		{CVE: "CVE-2022-32149", Source: "manual", Reason: "Internal threat intel"},
	}
	components := []formats.Component{{Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"}}

	vulns := AggregateExploitationSignals(findings, nil, nil, overrides, components, 0.7)
	require.Len(t, vulns, 1)
	require.Len(t, vulns[0].Signals, 1)
	assert.Equal(t, ExploitationManual, vulns[0].Signals[0].Source)
	assert.Equal(t, "Internal threat intel", vulns[0].Signals[0].Detail)
}

func TestAggregateSignals_MultipleSignals(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", Severity: "high", CVSS: 7.5, AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7"},
	}
	kev := &policykit.KEVCatalog{CVEs: map[string]bool{"CVE-2022-32149": true}}
	epss := &EPSSData{Scores: map[string]float64{"CVE-2022-32149": 0.95}}
	components := []formats.Component{{PURL: "pkg:golang/golang.org/x/text@v0.3.7"}}

	vulns := AggregateExploitationSignals(findings, kev, epss, nil, components, 0.7)
	require.Len(t, vulns, 1)
	// Both KEV and EPSS signals should be recorded
	assert.Len(t, vulns[0].Signals, 2)
}

func TestAggregateSignals_NoSignals(t *testing.T) {
	findings := []formats.Finding{
		{CVE: "CVE-2022-32149", Severity: "high", CVSS: 7.5, AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7"},
	}
	components := []formats.Component{{PURL: "pkg:golang/golang.org/x/text@v0.3.7"}}

	vulns := AggregateExploitationSignals(findings, nil, nil, nil, components, 0.7)
	assert.Empty(t, vulns)
}
