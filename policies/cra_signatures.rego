# Copyright 2026 Ravan Naidoo
# SPDX-License-Identifier: GPL-3.0-only
package cra.signatures

import rego.v1

default result := {
	"rule_id": "CRA-AI-3.2",
	"name": "Artifacts cryptographically signed",
	"cra_reference": "Art. 13",
	"status": "FAIL",
	"severity": "high",
	"evidence": {},
}

result := r if {
	not input.signatures.exists
	r := {
		"rule_id": "CRA-AI-3.2",
		"name": "Artifacts cryptographically signed",
		"cra_reference": "Art. 13",
		"status": "SKIP",
		"severity": "high",
		"evidence": {"reason": "No signature files provided (--signature flag)"},
	}
}

result := r if {
	input.signatures.exists
	count(input.signatures.files) > 0
	formats_detected := {f.format | some f in input.signatures.files}
	r := {
		"rule_id": "CRA-AI-3.2",
		"name": "Artifacts cryptographically signed",
		"cra_reference": "Art. 13",
		"status": "PASS",
		"severity": "high",
		"evidence": {
			"signature_count": count(input.signatures.files),
			"formats_detected": sort(formats_detected),
		},
	}
}
