// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package policykit

import (
	"fmt"
	"strings"
)

// Report holds the complete result of a CRA policy evaluation run.
type Report struct {
	ReportID       string         `json:"report_id"`
	ToolkitVersion string         `json:"toolkit_version"`
	Timestamp      string         `json:"timestamp"`
	Summary        Summary        `json:"summary"`
	Results        []PolicyResult `json:"results"`
}

// Summary tallies the outcomes of all policy results in a report.
type Summary struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
	Human   int `json:"human"`
}

// PolicyResult captures the outcome of evaluating a single CRA policy rule.
type PolicyResult struct {
	RuleID       string         `json:"rule_id"`
	Name         string         `json:"name"`
	CRAReference string         `json:"cra_reference"`
	Status       string         `json:"status"`
	Severity     string         `json:"severity"`
	Evidence     map[string]any `json:"evidence,omitempty"`
	Guidance     string         `json:"guidance,omitempty"`
}

// RenderMarkdown produces a human-readable markdown compliance report for auditors.
func RenderMarkdown(r *Report) string { //nolint:gocognit,gocyclo // markdown rendering requires iterating over multiple status groups
	var b strings.Builder

	// Title
	b.WriteString("# CRA PolicyKit Compliance Report\n\n")

	// Metadata
	b.WriteString("## Metadata\n\n")
	b.WriteString("| Field | Value |\n")
	b.WriteString("| --- | --- |\n")
	b.WriteString(fmt.Sprintf("| Report ID | %s |\n", r.ReportID))
	b.WriteString(fmt.Sprintf("| Generated | %s |\n", r.Timestamp))
	b.WriteString(fmt.Sprintf("| Toolkit Version | %s |\n", r.ToolkitVersion))
	b.WriteString("\n")

	// Summary table
	b.WriteString("## Summary\n\n")
	b.WriteString("| Status | Count |\n")
	b.WriteString("| --- | --- |\n")
	b.WriteString(fmt.Sprintf("| PASS | %d |\n", r.Summary.Passed))
	b.WriteString(fmt.Sprintf("| FAIL | %d |\n", r.Summary.Failed))
	b.WriteString(fmt.Sprintf("| SKIP | %d |\n", r.Summary.Skipped))
	b.WriteString(fmt.Sprintf("| HUMAN | %d |\n", r.Summary.Human))
	b.WriteString(fmt.Sprintf("| **Total** | **%d** |\n", r.Summary.Total))
	b.WriteString("\n")

	// Machine-Checked Policies: grouped by status — FAIL first, then PASS, then SKIP
	b.WriteString("## Machine-Checked Policies\n\n")
	statusOrder := []string{"FAIL", "PASS", "SKIP"}
	for _, status := range statusOrder {
		for _, pr := range r.Results {
			if pr.Status != status {
				continue
			}
			severity := pr.Severity
			if severity != "" {
				severity = strings.ToUpper(severity[:1]) + severity[1:]
			}
			b.WriteString(fmt.Sprintf("### %s: %s — %s\n\n", pr.Status, pr.RuleID, pr.Name))
			b.WriteString(fmt.Sprintf("- **CRA Reference:** %s\n", pr.CRAReference))
			b.WriteString(fmt.Sprintf("- **Severity:** %s\n", severity))
			if len(pr.Evidence) > 0 {
				b.WriteString("- **Evidence:**\n")
				for k, v := range pr.Evidence {
					b.WriteString(fmt.Sprintf("  - %s: %v\n", k, v))
				}
			}
			b.WriteString("\n")
		}
	}

	// Requires Human Review section
	hasHuman := false
	for _, pr := range r.Results {
		if pr.Status != "HUMAN" {
			continue
		}
		if !hasHuman {
			b.WriteString("## Requires Human Review\n\n")
			hasHuman = true
		}
		severity := pr.Severity
		if severity != "" {
			severity = strings.ToUpper(severity[:1]) + severity[1:]
		}
		b.WriteString(fmt.Sprintf("### HUMAN: %s — %s\n\n", pr.RuleID, pr.Name))
		b.WriteString(fmt.Sprintf("- **CRA Reference:** %s\n", pr.CRAReference))
		b.WriteString(fmt.Sprintf("- **Severity:** %s\n", severity))
		if pr.Guidance != "" {
			b.WriteString(fmt.Sprintf("- **Guidance:** %s\n", pr.Guidance))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// ComputeSummary tallies PASS, FAIL, SKIP, and HUMAN counts from the given results.
func ComputeSummary(results []PolicyResult) Summary {
	var s Summary
	s.Total = len(results)
	for _, r := range results {
		switch r.Status {
		case "PASS":
			s.Passed++
		case "FAIL":
			s.Failed++
		case "SKIP":
			s.Skipped++
		case "HUMAN":
			s.Human++
		}
	}
	return s
}
