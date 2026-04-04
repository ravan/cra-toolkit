package evidence

import (
	"fmt"
	"strings"
)

// RenderCompletenessMarkdown produces a human-readable completeness report.
func RenderCompletenessMarkdown(report CompletenessReport) string {
	var b strings.Builder

	b.WriteString("# CRA Annex VII Completeness Report\n\n")
	b.WriteString(fmt.Sprintf("> %s\n\n", report.Note))

	b.WriteString("## Score\n\n")
	b.WriteString(fmt.Sprintf("**%.0f%%** (%d / %d weight covered)\n\n", report.Score, report.CoveredWeight, report.TotalWeight))

	b.WriteString("## Sections\n\n")
	b.WriteString("| ID | Section | CRA Reference | Weight | Status |\n")
	b.WriteString("| --- | --- | --- | --- | --- |\n")

	for _, s := range report.Sections {
		status := "MISSING"
		if s.Weight == 0 {
			status = "N/A"
		} else if s.Covered {
			status = "COVERED"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %s |\n", s.ID, s.Title, s.CRARef, s.Weight, status))
	}
	b.WriteString("\n")

	// Gaps section.
	var gaps []AnnexVIISection
	for _, s := range report.Sections {
		if !s.Covered && s.Weight > 0 {
			gaps = append(gaps, s)
		}
	}
	if len(gaps) > 0 {
		b.WriteString("## Gaps\n\n")
		for _, g := range gaps {
			b.WriteString(fmt.Sprintf("- **%s** (%s): %s\n", g.ID, g.Title, g.Gap))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// RenderSummaryMarkdown produces a human-readable Annex VII summary.
func RenderSummaryMarkdown(summary AnnexVIISummary) string {
	var b strings.Builder

	b.WriteString("# CRA Annex VII Technical Documentation Summary\n\n")
	b.WriteString("> This summary is generated from real artifact data. No content is synthesized.\n\n")

	if summary.ProductDescription != "" {
		b.WriteString("## Product Description\n\n")
		b.WriteString(fmt.Sprintf("%s\n\n", summary.ProductDescription))
	}

	if summary.SBOMStats != nil {
		b.WriteString("## SBOM (Annex VII, point 2(b) and point 8)\n\n")
		b.WriteString("| Metric | Value |\n| --- | --- |\n")
		b.WriteString(fmt.Sprintf("| Format | %s |\n", summary.SBOMStats.Format))
		b.WriteString(fmt.Sprintf("| Component Count | %d |\n", summary.SBOMStats.ComponentCount))
		b.WriteString(fmt.Sprintf("| Product | %s %s |\n", summary.SBOMStats.ProductName, summary.SBOMStats.ProductVersion))
		b.WriteString("\n")
	}

	if summary.VulnHandlingStats != nil {
		b.WriteString("## Vulnerability Handling (Annex VII, point 2(b))\n\n")
		b.WriteString("| Metric | Value |\n| --- | --- |\n")
		b.WriteString(fmt.Sprintf("| Total Assessed | %d |\n", summary.VulnHandlingStats.TotalAssessed))
		for status, count := range summary.VulnHandlingStats.StatusDistribution {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", status, count))
		}
		b.WriteString("\n")
	}

	if summary.ScanStats != nil {
		b.WriteString("## Test Reports — Vulnerability Scans (Annex VII, point 6)\n\n")
		b.WriteString("| Metric | Value |\n| --- | --- |\n")
		b.WriteString(fmt.Sprintf("| Total Findings | %d |\n", summary.ScanStats.TotalFindings))
		b.WriteString(fmt.Sprintf("| Scanner Count | %d |\n", summary.ScanStats.ScannerCount))
		for sev, count := range summary.ScanStats.SeverityDistribution {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", sev, count))
		}
		b.WriteString("\n")
	}

	if summary.PolicyComplianceStats != nil {
		b.WriteString("## Test Reports — Policy Evaluation (Annex VII, point 6)\n\n")
		b.WriteString("| Metric | Value |\n| --- | --- |\n")
		b.WriteString(fmt.Sprintf("| Total Rules | %d |\n", summary.PolicyComplianceStats.Total))
		b.WriteString(fmt.Sprintf("| Passed | %d |\n", summary.PolicyComplianceStats.Passed))
		b.WriteString(fmt.Sprintf("| Failed | %d |\n", summary.PolicyComplianceStats.Failed))
		b.WriteString(fmt.Sprintf("| Human Review | %d |\n", summary.PolicyComplianceStats.Human))
		b.WriteString("\n")
	}

	if summary.SupportPeriod != "" {
		b.WriteString("## Support Period (Annex VII, point 4)\n\n")
		b.WriteString(fmt.Sprintf("Support period ends: %s\n\n", summary.SupportPeriod))
	}

	if summary.ConformityProcedure != "" {
		b.WriteString("## Conformity Procedure\n\n")
		b.WriteString(fmt.Sprintf("Procedure: %s\n\n", summary.ConformityProcedure))
	}

	return b.String()
}

// RenderValidationMarkdown renders cross-validation results.
func RenderValidationMarkdown(report ValidationReport) string {
	var b strings.Builder

	b.WriteString("## Cross-Validation Results\n\n")
	b.WriteString(fmt.Sprintf("Passed: %d | Failed: %d | Warnings: %d\n\n", report.Passed, report.Failed, report.Warnings))

	if len(report.Checks) > 0 {
		b.WriteString("| Check | Status | Details |\n| --- | --- | --- |\n")
		for _, c := range report.Checks {
			b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", c.CheckID, strings.ToUpper(c.Status), c.Details))
		}
		b.WriteString("\n")
	}

	return b.String()
}
