package cra.reach_method

import rego.v1

reach_not_affected := [s |
	some s in input.vex.statements
	s.status == "not_affected"
	s.resolved_by == "reachability_analysis"
]

pattern_match_cves := [s.cve |
	some s in reach_not_affected
	s.analysis_method == "pattern_match"
]

default result := {
	"rule_id": "CRA-REACH-3",
	"name": "Pattern-match reachability alone cannot justify not_affected",
	"cra_reference": "Annex I Part I.2(a)",
	"status": "FAIL",
	"severity": "medium",
	"evidence": {},
}

result := r if {
	count(pattern_match_cves) == 0
	r := {
		"rule_id": "CRA-REACH-3",
		"name": "Pattern-match reachability alone cannot justify not_affected",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "PASS",
		"severity": "medium",
		"evidence": {
			"pattern_match_not_affected_cves": [],
		},
	}
}

result := r if {
	count(pattern_match_cves) > 0
	r := {
		"rule_id": "CRA-REACH-3",
		"name": "Pattern-match reachability alone cannot justify not_affected",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "FAIL",
		"severity": "medium",
		"evidence": {
			"pattern_match_not_affected_cves": pattern_match_cves,
		},
	}
}
