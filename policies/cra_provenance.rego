package cra.provenance

import rego.v1

default result := {
	"rule_id": "CRA-AI-3.1",
	"name": "Build provenance exists (SLSA L1+)",
	"cra_reference": "Art. 13",
	"status": "FAIL",
	"severity": "high",
	"evidence": {},
}

result := r if {
	not input.provenance.exists
	r := {
		"rule_id": "CRA-AI-3.1",
		"name": "Build provenance exists (SLSA L1+)",
		"cra_reference": "Art. 13",
		"status": "SKIP",
		"severity": "high",
		"evidence": {"reason": "No provenance attestation provided (--provenance flag)"},
	}
}

result := r if {
	input.provenance.exists
	input.provenance.builder_id != ""
	input.provenance.source_repo != ""
	input.provenance.build_type != ""
	r := {
		"rule_id": "CRA-AI-3.1",
		"name": "Build provenance exists (SLSA L1+)",
		"cra_reference": "Art. 13",
		"status": "PASS",
		"severity": "high",
		"evidence": {
			"builder_id": input.provenance.builder_id,
			"source_repo": input.provenance.source_repo,
			"build_type": input.provenance.build_type,
		},
	}
}
