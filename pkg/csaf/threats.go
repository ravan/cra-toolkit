// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csaf

import (
	"strings"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

func addThreats(vulns []vulnerability, findings []formats.Finding) []vulnerability {
	severityLookup := make(map[string]string, len(findings))
	for i := range findings {
		f := &findings[i]
		if _, exists := severityLookup[f.CVE]; !exists {
			severityLookup[f.CVE] = f.Severity
		}
	}
	for i := range vulns {
		v := &vulns[i]
		sev, ok := severityLookup[v.CVE]
		if !ok || sev == "" {
			continue
		}
		v.Threats = append(v.Threats, threat{Category: "impact", Details: severityToThreatDetail(sev)})
	}
	return vulns
}

func severityToThreatDetail(severity string) string {
	if severity == "" {
		return "Unknown"
	}
	return strings.ToUpper(severity[:1]) + severity[1:]
}
