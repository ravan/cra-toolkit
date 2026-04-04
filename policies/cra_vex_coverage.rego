package cra.vex_coverage

import rego.v1

critical_high_findings := [f | some f in input.scan.findings; f.cvss >= 7.0]
vex_lookup := {sprintf("%s|%s", [s.cve, s.purl]) | some s in input.vex.statements}
unassessed := [f.cve | some f in critical_high_findings; not sprintf("%s|%s", [f.cve, f.purl]) in vex_lookup]

default result := {
	"rule_id": "CRA-AI-2.2",
	"name": "All critical/high CVEs have VEX assessment",
	"cra_reference": "Annex I Part I.2(a)",
	"status": "FAIL",
	"severity": "high",
	"evidence": {},
}

result := r if {
	count(unassessed) == 0
	r := {
		"rule_id": "CRA-AI-2.2",
		"name": "All critical/high CVEs have VEX assessment",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "PASS",
		"severity": "high",
		"evidence": {
			"total_critical_high": count(critical_high_findings),
			"assessed": count(critical_high_findings),
			"unassessed": [],
		},
	}
}

result := r if {
	count(unassessed) > 0
	r := {
		"rule_id": "CRA-AI-2.2",
		"name": "All critical/high CVEs have VEX assessment",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "FAIL",
		"severity": "high",
		"evidence": {
			"total_critical_high": count(critical_high_findings),
			"assessed": count(critical_high_findings) - count(unassessed),
			"unassessed": unassessed,
		},
	}
}
