// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"fmt"
	"strings"
)

// RenderMarkdown produces a human-readable markdown notification document.
func RenderMarkdown(n *Notification) string { //nolint:gocognit,gocyclo // markdown rendering iterates multiple sections
	var b strings.Builder

	b.WriteString("# CRA Article 14 Vulnerability Notification\n\n")

	// Metadata.
	b.WriteString("## Metadata\n\n")
	b.WriteString("| Field | Value |\n| --- | --- |\n")
	b.WriteString(fmt.Sprintf("| Notification ID | %s |\n", n.NotificationID))
	b.WriteString(fmt.Sprintf("| Stage | %s — %s |\n", stageLabel(n.Stage), n.CRAReference))
	b.WriteString(fmt.Sprintf("| Generated | %s |\n", n.Timestamp))
	b.WriteString(fmt.Sprintf("| Submission Channel | %s |\n", n.SubmissionChannel))
	b.WriteString(fmt.Sprintf("| Toolkit Version | %s |\n", n.ToolkitVersion))
	b.WriteString("\n")

	// Manufacturer.
	b.WriteString("## Manufacturer\n\n")
	b.WriteString("| Field | Value |\n| --- | --- |\n")
	b.WriteString(fmt.Sprintf("| Name | %s |\n", n.Manufacturer.Name))
	b.WriteString(fmt.Sprintf("| Member State | %s |\n", n.Manufacturer.MemberState))
	if n.Manufacturer.ContactEmail != "" {
		b.WriteString(fmt.Sprintf("| Contact | %s |\n", n.Manufacturer.ContactEmail))
	}
	b.WriteString("\n")

	// CSIRT Coordinator.
	b.WriteString("## CSIRT Coordinator (Informational)\n\n")
	b.WriteString("| Field | Value |\n| --- | --- |\n")
	b.WriteString(fmt.Sprintf("| CSIRT | %s |\n", n.CSIRTCoordinator.Name))
	b.WriteString(fmt.Sprintf("| Country | %s |\n", n.CSIRTCoordinator.Country))
	b.WriteString("\n> **Note:** Per Art. 14(7), this notification is submitted via the ENISA Single\n")
	b.WriteString("> Reporting Platform, which routes to the CSIRT coordinator simultaneously with ENISA.\n\n")

	// Vulnerabilities.
	b.WriteString("## Vulnerabilities with Exploitation Signals\n\n")
	for i := range n.Vulnerabilities {
		v := &n.Vulnerabilities[i]
		b.WriteString(fmt.Sprintf("### %s\n\n", v.CVE))

		// Signals.
		var signalParts []string
		for _, s := range v.ExploitationSignals {
			signalParts = append(signalParts, fmt.Sprintf("%s (%s)", strings.ToUpper(string(s.Source)), s.Detail))
		}
		b.WriteString(fmt.Sprintf("- **Exploitation Signals:** %s\n", strings.Join(signalParts, "; ")))

		// Severity with manual title case to avoid deprecated strings.Title.
		severityTitle := titleCase(v.Severity)
		b.WriteString(fmt.Sprintf("- **Severity:** %s (CVSS %.1f)\n", severityTitle, v.CVSS))
		for _, p := range v.AffectedProducts {
			b.WriteString(fmt.Sprintf("- **Affected:** %s %s\n", p.Name, p.Version))
		}

		// Notification-level fields.
		if v.Description != "" {
			b.WriteString(fmt.Sprintf("- **Description:** %s\n", v.Description))
		}
		if len(v.CorrectiveActions) > 0 {
			b.WriteString(fmt.Sprintf("- **Corrective Actions:** %s\n", strings.Join(v.CorrectiveActions, "; ")))
		}
		if len(v.MitigatingMeasures) > 0 {
			b.WriteString("- **Mitigating Measures:**\n")
			for _, m := range v.MitigatingMeasures {
				b.WriteString(fmt.Sprintf("  ```\n%s  ```\n", m))
			}
		}

		// Final report fields.
		if v.CorrectiveMeasureDate != "" {
			b.WriteString(fmt.Sprintf("- **Corrective Measure Available:** %s\n", v.CorrectiveMeasureDate))
		}
		if v.RootCause != "" {
			b.WriteString(fmt.Sprintf("- **Root Cause:** %s\n", v.RootCause))
		}
		if v.ThreatActorInfo != "" {
			b.WriteString(fmt.Sprintf("- **Threat Actor Info:** %s\n", v.ThreatActorInfo))
		}
		if v.SecurityUpdate != "" {
			b.WriteString(fmt.Sprintf("- **Security Update:** %s\n", v.SecurityUpdate))
		}

		b.WriteString("\n")
	}

	b.WriteString("> **Note:** Exploitation signals are provided to support the manufacturer's\n")
	b.WriteString("> determination per Art. 14(1). The manufacturer is responsible for the\n")
	b.WriteString("> regulatory decision to notify.\n\n")

	// User notification.
	if n.UserNotification != nil {
		b.WriteString("## User Notification (Art. 14(8))\n\n")
		b.WriteString(fmt.Sprintf("- **Severity:** %s\n", n.UserNotification.Severity))
		if n.UserNotification.CSAFAdvisoryRef != "" {
			b.WriteString(fmt.Sprintf("- **CSAF Advisory:** %s\n", n.UserNotification.CSAFAdvisoryRef))
		}
		for _, a := range n.UserNotification.RecommendedActions {
			b.WriteString(fmt.Sprintf("- **Action:** %s\n", a))
		}
		b.WriteString("\n")
	}

	// Completeness.
	b.WriteString("## Completeness (Toolkit Quality Metric)\n\n")
	b.WriteString("| Metric | Value |\n| --- | --- |\n")
	b.WriteString(fmt.Sprintf("| Score | %.0f%% |\n", n.Completeness.Score*100))
	b.WriteString(fmt.Sprintf("| Machine Generated | %d |\n", n.Completeness.MachineGenerated))
	b.WriteString(fmt.Sprintf("| Human Provided | %d |\n", n.Completeness.HumanProvided))
	b.WriteString(fmt.Sprintf("| Pending | %d |\n", len(n.Completeness.Pending)))
	b.WriteString(fmt.Sprintf("\n> %s\n", CompletenessNote))

	return b.String()
}

func stageLabel(s Stage) string {
	switch s {
	case StageEarlyWarning:
		return "Early Warning (24h)"
	case StageNotification:
		return "Notification (72h)"
	case StageFinalReport:
		return "Final Report (14d)"
	default:
		return string(s)
	}
}

// titleCase converts the first character of s to uppercase.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
