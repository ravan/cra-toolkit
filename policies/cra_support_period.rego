package cra.support_period

import rego.v1

default result := {
	"rule_id": "CRA-AI-4.1",
	"name": "Support period declared and > 5 years",
	"cra_reference": "Annex I Part II",
	"status": "FAIL",
	"severity": "medium",
	"evidence": {},
}

result := r if {
	not input.product.exists
	r := {
		"rule_id": "CRA-AI-4.1",
		"name": "Support period declared and > 5 years",
		"cra_reference": "Annex I Part II",
		"status": "SKIP",
		"severity": "medium",
		"evidence": {"reason": "No product config provided (--product-config flag)"},
	}
}

result := r if {
	input.product.exists
	input.product.release_date != ""
	input.product.support_end_date != ""
	input.product.support_years >= 5
	r := {
		"rule_id": "CRA-AI-4.1",
		"name": "Support period declared and > 5 years",
		"cra_reference": "Annex I Part II",
		"status": "PASS",
		"severity": "medium",
		"evidence": {
			"release_date": input.product.release_date,
			"support_end_date": input.product.support_end_date,
			"support_years": input.product.support_years,
		},
	}
}
