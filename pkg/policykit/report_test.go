package policykit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyResultJSONSerialization(t *testing.T) {
	pr := PolicyResult{
		RuleID:       "CRA-1.1",
		Name:         "SBOM completeness",
		CRAReference: "Annex I, Part II, §1",
		Status:       "PASS",
		Severity:     "high",
		Evidence:     map[string]any{"components": 42},
		Guidance:     "Ensure all components are listed",
	}

	data, err := json.Marshal(pr)
	require.NoError(t, err)

	var decoded PolicyResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, pr.RuleID, decoded.RuleID)
	assert.Equal(t, pr.Name, decoded.Name)
	assert.Equal(t, pr.CRAReference, decoded.CRAReference)
	assert.Equal(t, pr.Status, decoded.Status)
	assert.Equal(t, pr.Severity, decoded.Severity)
	assert.Equal(t, pr.Guidance, decoded.Guidance)
	// Evidence round-trips as float64 for numbers in JSON
	assert.Equal(t, float64(42), decoded.Evidence["components"])
}

func TestPolicyResultOmitsEmptyEvidence(t *testing.T) {
	pr := PolicyResult{
		RuleID:       "CRA-1.2",
		Name:         "Vulnerability disclosure",
		CRAReference: "Annex I, Part II, §2",
		Status:       "FAIL",
		Severity:     "critical",
	}

	data, err := json.Marshal(pr)
	require.NoError(t, err)

	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)
	assert.NotContains(t, raw, "evidence")
	assert.NotContains(t, raw, "guidance")
}

func TestReportJSONSerialization(t *testing.T) {
	report := Report{
		ReportID:       "rpt-001",
		ToolkitVersion: "0.1.0",
		Timestamp:      "2026-04-04T00:00:00Z",
		Summary: Summary{
			Total:   3,
			Passed:  1,
			Failed:  1,
			Skipped: 0,
			Human:   1,
		},
		Results: []PolicyResult{
			{RuleID: "CRA-1.1", Name: "test", CRAReference: "ref", Status: "PASS", Severity: "high"},
			{RuleID: "CRA-1.2", Name: "test2", CRAReference: "ref2", Status: "FAIL", Severity: "critical"},
			{RuleID: "CRA-1.3", Name: "test3", CRAReference: "ref3", Status: "HUMAN", Severity: "medium"},
		},
	}

	data, err := json.Marshal(report)
	require.NoError(t, err)

	var decoded Report
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, report.ReportID, decoded.ReportID)
	assert.Equal(t, report.ToolkitVersion, decoded.ToolkitVersion)
	assert.Equal(t, report.Summary.Total, decoded.Summary.Total)
	assert.Len(t, decoded.Results, 3)
}

func TestComputeSummary(t *testing.T) {
	results := []PolicyResult{
		{RuleID: "r1", Status: "PASS"},
		{RuleID: "r2", Status: "PASS"},
		{RuleID: "r3", Status: "FAIL"},
		{RuleID: "r4", Status: "SKIP"},
		{RuleID: "r5", Status: "HUMAN"},
		{RuleID: "r6", Status: "HUMAN"},
	}

	summary := ComputeSummary(results)

	assert.Equal(t, 6, summary.Total)
	assert.Equal(t, 2, summary.Passed)
	assert.Equal(t, 1, summary.Failed)
	assert.Equal(t, 1, summary.Skipped)
	assert.Equal(t, 2, summary.Human)
}

func TestRenderMarkdown(t *testing.T) {
	report := &Report{
		ReportID:       "rpt-test-001",
		ToolkitVersion: "0.2.0",
		Timestamp:      "2026-04-04T12:00:00Z",
		Summary: Summary{
			Total:   4,
			Passed:  1,
			Failed:  1,
			Skipped: 1,
			Human:   1,
		},
		Results: []PolicyResult{
			{
				RuleID:       "CRA-2.1",
				Name:         "Vulnerability handling process",
				CRAReference: "Annex I, Part II, §3",
				Status:       "FAIL",
				Severity:     "critical",
				Evidence:     map[string]any{"policy_found": false, "days_since_review": 400},
			},
			{
				RuleID:       "CRA-1.1",
				Name:         "SBOM completeness",
				CRAReference: "Annex I, Part II, §1",
				Status:       "PASS",
				Severity:     "high",
				Evidence:     map[string]any{"components": 42},
			},
			{
				RuleID:       "CRA-3.1",
				Name:         "Security update mechanism",
				CRAReference: "Annex I, Part I, §2",
				Status:       "SKIP",
				Severity:     "medium",
			},
			{
				RuleID:       "CRA-4.1",
				Name:         "Secure by default configuration",
				CRAReference: "Annex I, Part I, §1",
				Status:       "HUMAN",
				Severity:     "high",
				Guidance:     "Verify that default configuration disables unnecessary network services",
			},
		},
	}

	md := RenderMarkdown(report)

	// Title header
	assert.Contains(t, md, "# CRA PolicyKit Compliance Report")

	// Metadata
	assert.Contains(t, md, "rpt-test-001")
	assert.Contains(t, md, "2026-04-04T12:00:00Z")
	assert.Contains(t, md, "0.2.0")

	// Summary table with PASS/FAIL rows
	assert.Contains(t, md, "| PASS |")
	assert.Contains(t, md, "| FAIL |")

	// FAIL section appears before PASS section
	failIdx := strings.Index(md, "### FAIL: CRA-2.1")
	passIdx := strings.Index(md, "### PASS: CRA-1.1")
	assert.Greater(t, failIdx, -1, "FAIL section must exist")
	assert.Greater(t, passIdx, -1, "PASS section must exist")
	assert.Less(t, failIdx, passIdx, "FAIL section must appear before PASS section")

	// Human review section with guidance
	assert.Contains(t, md, "## Requires Human Review")
	assert.Contains(t, md, "CRA-4.1")
	assert.Contains(t, md, "Verify that default configuration disables unnecessary network services")

	// Rule IDs appear correctly
	assert.Contains(t, md, "CRA-2.1")
	assert.Contains(t, md, "CRA-1.1")
	assert.Contains(t, md, "CRA-3.1")
	assert.Contains(t, md, "CRA-4.1")
}

func TestComputeSummaryEmpty(t *testing.T) {
	summary := ComputeSummary(nil)

	assert.Equal(t, 0, summary.Total)
	assert.Equal(t, 0, summary.Passed)
	assert.Equal(t, 0, summary.Failed)
	assert.Equal(t, 0, summary.Skipped)
	assert.Equal(t, 0, summary.Human)
}
