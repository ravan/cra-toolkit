package cra.sbom_valid

import rego.v1

default result := {
	"rule_id": "CRA-AI-1.1",
	"name": "SBOM exists and is valid",
	"cra_reference": "Annex I Part II.1",
	"status": "FAIL",
	"severity": "critical",
	"evidence": {},
}

result := r if {
	input.sbom.format in {"cyclonedx", "spdx"}
	input.sbom.metadata.name != ""
	input.sbom.metadata.version != ""
	count(input.sbom.components) > 0
	purl_count := count([c | some c in input.sbom.components; c.purl != ""])
	r := {
		"rule_id": "CRA-AI-1.1",
		"name": "SBOM exists and is valid",
		"cra_reference": "Annex I Part II.1",
		"status": "PASS",
		"severity": "critical",
		"evidence": {
			"sbom_format": input.sbom.format,
			"sbom_version": input.sbom.version,
			"component_count": count(input.sbom.components),
			"components_with_purl": purl_count,
			"has_metadata": true,
			"has_supplier": input.sbom.metadata.supplier != "",
		},
	}
}
