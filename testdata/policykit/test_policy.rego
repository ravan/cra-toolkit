package cra.test_policy

import rego.v1

default result := {
	"rule_id": "TEST-1",
	"name": "Test policy",
	"cra_reference": "Test",
	"status": "FAIL",
	"severity": "low",
	"evidence": {},
}

result := r if {
	input.test_value == true
	r := {
		"rule_id": "TEST-1",
		"name": "Test policy",
		"cra_reference": "Test",
		"status": "PASS",
		"severity": "low",
		"evidence": {"test_value": true},
	}
}
