package report

import (
	"fmt"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
)

// AggregateExploitationSignals collects exploitation signals from KEV, EPSS, and manual
// overrides for each finding. Returns only findings with at least one signal.
// This supports the manufacturer's determination per Art. 14(1) — it does NOT make
// the regulatory determination itself.
func AggregateExploitationSignals(
	findings []formats.Finding,
	kev *policykit.KEVCatalog,
	epss *EPSSData,
	overrides []ExploitationOverride,
	components []formats.Component,
	epssThreshold float64,
) []ExploitedVuln {
	manualLookup := buildManualLookup(overrides)
	componentByPURL := buildComponentLookup(components)

	seen := make(map[string]bool)
	result := make([]ExploitedVuln, 0, len(findings))

	for i := range findings {
		f := &findings[i]
		if seen[f.CVE] {
			continue
		}

		signals := collectSignals(f.CVE, kev, epss, manualLookup, epssThreshold)
		if len(signals) == 0 {
			continue
		}

		seen[f.CVE] = true
		result = append(result, buildExploitedVuln(f, signals, componentByPURL))
	}

	return result
}

func buildManualLookup(overrides []ExploitationOverride) map[string]ExploitationOverride {
	m := make(map[string]ExploitationOverride, len(overrides))
	for _, o := range overrides {
		m[o.CVE] = o
	}
	return m
}

func buildComponentLookup(components []formats.Component) map[string]formats.Component {
	m := make(map[string]formats.Component, len(components))
	for i := range components {
		if components[i].PURL != "" {
			m[components[i].PURL] = components[i]
		}
	}
	return m
}

func collectSignals(
	cve string,
	kev *policykit.KEVCatalog,
	epss *EPSSData,
	manualLookup map[string]ExploitationOverride,
	epssThreshold float64,
) []ExploitationSignal {
	var signals []ExploitationSignal

	if kev != nil && kev.Contains(cve) {
		signals = append(signals, ExploitationSignal{
			Source: ExploitationKEV,
			Detail: "Listed in CISA Known Exploited Vulnerabilities catalog",
		})
	}

	if o, ok := manualLookup[cve]; ok {
		signals = append(signals, ExploitationSignal{
			Source: ExploitationManual,
			Detail: o.Reason,
		})
	}

	if epss != nil {
		if score, ok := epss.Scores[cve]; ok && score >= epssThreshold {
			signals = append(signals, ExploitationSignal{
				Source: ExploitationEPSS,
				Detail: fmt.Sprintf("EPSS score %.4f (threshold %.2f)", score, epssThreshold),
			})
		}
	}

	return signals
}

func buildExploitedVuln(f *formats.Finding, signals []ExploitationSignal, componentByPURL map[string]formats.Component) ExploitedVuln {
	return ExploitedVuln{
		CVE:              f.CVE,
		Signals:          signals,
		AffectedProducts: resolveAffectedProducts(f, componentByPURL),
		Severity:         f.Severity,
		CVSS:             f.CVSS,
		CVSSVector:       f.CVSSVector,
		Description:      f.Description,
		FixVersion:       f.FixVersion,
	}
}

func resolveAffectedProducts(f *formats.Finding, componentByPURL map[string]formats.Component) []AffectedProduct {
	comp, ok := componentByPURL[f.AffectedPURL]
	if ok {
		return []AffectedProduct{{
			Name:    comp.Name,
			Version: comp.Version,
			PURL:    comp.PURL,
		}}
	}
	if f.AffectedPURL != "" {
		return []AffectedProduct{{
			Name: f.AffectedName,
			PURL: f.AffectedPURL,
		}}
	}
	return nil
}
