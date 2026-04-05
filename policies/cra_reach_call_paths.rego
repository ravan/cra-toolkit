# Copyright 2026 Ravan Naidoo
# SPDX-License-Identifier: GPL-3.0-only
package cra.reach_call_paths

import rego.v1

reach_affected := [s |
	some s in input.vex.statements
	s.status == "affected"
	s.resolved_by == "reachability_analysis"
]

missing_paths_cves := [s.cve |
	some s in reach_affected
	count(s.call_paths) == 0
]

default result := {
	"rule_id": "CRA-REACH-2",
	"name": "Reachability affected claims must have supporting call paths",
	"cra_reference": "Annex I Part I.2(a)",
	"status": "FAIL",
	"severity": "high",
	"evidence": {},
}

result := r if {
	count(missing_paths_cves) == 0
	r := {
		"rule_id": "CRA-REACH-2",
		"name": "Reachability affected claims must have supporting call paths",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "PASS",
		"severity": "high",
		"evidence": {
			"total_reachability_affected": count(reach_affected),
			"missing_call_paths_cves": [],
		},
	}
}

result := r if {
	count(missing_paths_cves) > 0
	r := {
		"rule_id": "CRA-REACH-2",
		"name": "Reachability affected claims must have supporting call paths",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "FAIL",
		"severity": "high",
		"evidence": {
			"total_reachability_affected": count(reach_affected),
			"missing_call_paths_cves": missing_paths_cves,
		},
	}
}
