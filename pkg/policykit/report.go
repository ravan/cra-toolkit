package policykit

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
