# Copyright 2026 Ravan Naidoo
# SPDX-License-Identifier: GPL-3.0-only
package cra.update_mechanism

import rego.v1

valid_types := {"automatic", "manual", "hybrid"}

default result := {
	"rule_id": "CRA-AI-4.2",
	"name": "Secure update mechanism documented",
	"cra_reference": "Annex I Part II.7",
	"status": "FAIL",
	"severity": "medium",
	"evidence": {},
}

result := r if {
	not input.product.exists
	r := {
		"rule_id": "CRA-AI-4.2",
		"name": "Secure update mechanism documented",
		"cra_reference": "Annex I Part II.7",
		"status": "SKIP",
		"severity": "medium",
		"evidence": {"reason": "No product config provided (--product-config flag)"},
	}
}

result := r if {
	input.product.exists
	input.product.update_mechanism.type in valid_types
	input.product.update_mechanism.url != ""
	r := {
		"rule_id": "CRA-AI-4.2",
		"name": "Secure update mechanism documented",
		"cra_reference": "Annex I Part II.7",
		"status": "PASS",
		"severity": "medium",
		"evidence": {
			"mechanism_type": input.product.update_mechanism.type,
			"url_present": true,
			"auto_update_default": input.product.update_mechanism.auto_update_default,
			"security_updates_separate": input.product.update_mechanism.security_updates_separate,
		},
	}
}
