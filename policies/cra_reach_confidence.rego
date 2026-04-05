# Copyright 2026 Ravan Naidoo
# SPDX-License-Identifier: GPL-3.0-only
package cra.reach_confidence

import rego.v1

reach_not_affected := [s |
	some s in input.vex.statements
	s.status == "not_affected"
	s.resolved_by == "reachability_analysis"
]

low_confidence_cves := [s.cve |
	some s in reach_not_affected
	s.confidence != "high"
]

default result := {
	"rule_id": "CRA-REACH-1",
	"name": "Reachability not_affected claims require high confidence",
	"cra_reference": "Annex I Part I.2(a)",
	"status": "FAIL",
	"severity": "high",
	"evidence": {},
}

result := r if {
	count(low_confidence_cves) == 0
	r := {
		"rule_id": "CRA-REACH-1",
		"name": "Reachability not_affected claims require high confidence",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "PASS",
		"severity": "high",
		"evidence": {
			"total_reachability_not_affected": count(reach_not_affected),
			"low_confidence_cves": [],
		},
	}
}

result := r if {
	count(low_confidence_cves) > 0
	r := {
		"rule_id": "CRA-REACH-1",
		"name": "Reachability not_affected claims require high confidence",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "FAIL",
		"severity": "high",
		"evidence": {
			"total_reachability_not_affected": count(reach_not_affected),
			"low_confidence_cves": low_confidence_cves,
		},
	}
}
