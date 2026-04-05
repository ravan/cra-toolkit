package report

import (
	"fmt"
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

// BuildNotification creates VulnEntry values for the 72h notification stage.
// Per Art. 14(2)(b): everything from early warning plus description, general nature,
// corrective actions, mitigating measures, estimated impact, sensitivity.
func BuildNotification(vulns []ExploitedVuln, mfr *Manufacturer, components []formats.Component, vexResults []formats.VEXResult) []VulnEntry {
	// Build VEX lookup for mitigating measures.
	vexByCV := make(map[string]formats.VEXResult, len(vexResults))
	for _, vr := range vexResults {
		vexByCV[vr.CVE] = vr
	}

	impact := &Impact{
		AffectedComponentCount: len(components),
		SeverityDistribution:   buildSeverityDistribution(vulns),
	}

	entries := make([]VulnEntry, 0, len(vulns))
	for i := range vulns {
		v := &vulns[i]
		e := VulnEntry{
			CVE:                    v.CVE,
			ExploitationSignals:    v.Signals,
			Severity:               v.Severity,
			CVSS:                   v.CVSS,
			AffectedProducts:       v.AffectedProducts,
			MemberStates:           mfr.MemberStatesAvailable,
			Description:            v.Description,
			GeneralNature:          buildGeneralNature(v.Description, v.CVSSVector),
			EstimatedImpact:        impact,
			InformationSensitivity: "high",
		}

		if v.FixVersion != "" {
			name := "affected component"
			if len(v.AffectedProducts) > 0 {
				name = v.AffectedProducts[0].Name
			}
			e.CorrectiveActions = []string{
				fmt.Sprintf("Update %s to version %s", name, v.FixVersion),
			}
		}

		if vr, ok := vexByCV[v.CVE]; ok {
			if detail := ReachabilityDetail(vr); detail != "" {
				e.MitigatingMeasures = []string{detail}
			} else if vr.Evidence != "" {
				e.MitigatingMeasures = []string{vr.Evidence}
			}
		}

		entries = append(entries, e)
	}
	return entries
}

// buildGeneralNature derives the general nature of the exploit from the CVE description
// and CVSS vector. The CVE description is the primary source per our design spec.
func buildGeneralNature(description, cvssVector string) string {
	if description == "" {
		return ""
	}

	// Start with the CVE description as the general nature.
	nature := description

	// Supplement with structured CVSS metadata if available.
	if cvssVector != "" {
		var supplements []string
		if strings.Contains(cvssVector, "AV:N") {
			supplements = append(supplements, "network-accessible")
		} else if strings.Contains(cvssVector, "AV:L") {
			supplements = append(supplements, "local access required")
		}
		if strings.Contains(cvssVector, "AC:L") {
			supplements = append(supplements, "low complexity")
		}
		if strings.Contains(cvssVector, "PR:N") {
			supplements = append(supplements, "no authentication required")
		}
		if len(supplements) > 0 {
			nature += " (" + strings.Join(supplements, ", ") + ")"
		}
	}

	return nature
}

func buildSeverityDistribution(vulns []ExploitedVuln) map[string]int {
	dist := make(map[string]int)
	for i := range vulns {
		if vulns[i].Severity != "" {
			dist[vulns[i].Severity]++
		}
	}
	return dist
}
