package csaf

import (
	"fmt"
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func buildDocumentNotes(findings []formats.Finding) []note {
	var cves []string
	seen := make(map[string]bool)
	for i := range findings {
		f := &findings[i]
		if !seen[f.CVE] {
			seen[f.CVE] = true
			cves = append(cves, f.CVE)
		}
	}
	return []note{{
		Category: "summary",
		Title:    "Advisory Summary",
		Text:     fmt.Sprintf("Security advisory addressing %d vulnerability(ies): %s.", len(cves), strings.Join(cves, ", ")),
	}}
}

func buildVulnNotes(finding *formats.Finding, vexResult *formats.VEXResult) []note {
	var notes []note
	if finding.Description != "" {
		notes = append(notes, note{Category: "description", Text: finding.Description})
	}
	if vexResult.Confidence >= formats.ConfidenceHigh && vexResult.Evidence != "" {
		notes = append(notes, note{Category: "details", Title: "VEX Assessment", Text: vexResult.Evidence})
	}
	return notes
}
