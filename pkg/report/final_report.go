// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package report

import "github.com/ravan/cra-toolkit/pkg/formats"

const humanInputRequired = "[HUMAN INPUT REQUIRED]"

// BuildFinalReport creates VulnEntry values for the 14-day final report stage.
// Per Art. 14(2)(c): everything from notification plus root cause, threat actor info,
// security update details, corrective measures, preventive measures.
// Human input is merged where available; missing fields get placeholders.
func BuildFinalReport(
	vulns []ExploitedVuln,
	mfr *Manufacturer,
	components []formats.Component,
	vexResults []formats.VEXResult,
	human *HumanInput,
	correctiveMeasureDate string,
) []VulnEntry {
	// Start with notification-level enrichment.
	entries := BuildNotification(vulns, mfr, components, vexResults)

	for i := range entries {
		mergeHumanInput(&entries[i], human, correctiveMeasureDate)
	}

	return entries
}

// mergeHumanInput applies human-authored fields to a VulnEntry, filling placeholders where absent.
func mergeHumanInput(e *VulnEntry, human *HumanInput, correctiveMeasureDate string) {
	var hi HumanVulnInput
	if human != nil {
		hi = human.Vulnerabilities[e.CVE]
	}

	// Corrective measure date: CLI flag overrides human input.
	e.CorrectiveMeasureDate = correctiveMeasureDate
	if e.CorrectiveMeasureDate == "" {
		e.CorrectiveMeasureDate = hi.CorrectiveMeasureDate
	}

	// Human-authored fields with placeholders.
	e.RootCause = hi.RootCause
	if e.RootCause == "" {
		e.RootCause = humanInputRequired
	}

	e.ThreatActorInfo = hi.ThreatActorInfo
	if e.ThreatActorInfo == "" {
		e.ThreatActorInfo = humanInputRequired
	}

	e.SecurityUpdate = resolveSecurityUpdate(&hi, e.CorrectiveActions)

	if len(hi.PreventiveMeasures) > 0 {
		e.PreventiveMeasures = hi.PreventiveMeasures
	}
}

// resolveSecurityUpdate picks the best available security update string.
func resolveSecurityUpdate(hi *HumanVulnInput, correctiveActions []string) string {
	switch {
	case hi.SecurityUpdate != "":
		return hi.SecurityUpdate
	case len(correctiveActions) > 0:
		return correctiveActions[0]
	default:
		return humanInputRequired
	}
}
