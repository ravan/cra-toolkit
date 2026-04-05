# Copyright 2026 Ravan Naidoo
# SPDX-License-Identifier: GPL-3.0-only
package cra.no_kev

import rego.v1

scan_cves := {f.cve | some f in input.scan.findings}
kev_set := {k | some k in input.kev.cves}
kev_matches := scan_cves & kev_set

default result := {
	"rule_id": "CRA-AI-2.1",
	"name": "No known exploited vulnerabilities",
	"cra_reference": "Annex I Part I.2(a)",
	"status": "PASS",
	"severity": "critical",
	"evidence": {},
}

result := r if {
	count(kev_matches) > 0
	r := {
		"rule_id": "CRA-AI-2.1",
		"name": "No known exploited vulnerabilities",
		"cra_reference": "Annex I Part I.2(a)",
		"status": "FAIL",
		"severity": "critical",
		"evidence": {
			"kev_matches": sort(kev_matches),
			"kev_catalog_date": input.kev.catalog_date,
			"total_cves_checked": count(scan_cves),
		},
	}
}
