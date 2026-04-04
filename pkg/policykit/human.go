package policykit

// HumanReviewItems returns the static list of CRA requirements that need human review.
func HumanReviewItems() []PolicyResult {
	return []PolicyResult{
		{RuleID: "CRA-HU-1.1", Name: "Appropriate cybersecurity level", CRAReference: "Annex I Part I.1", Status: "HUMAN", Severity: "high", Guidance: "Verify risk assessment performed and cybersecurity measures are proportionate to identified risks."},
		{RuleID: "CRA-HU-1.2", Name: "Secure by default configuration", CRAReference: "Annex I Part I.2(b)", Status: "HUMAN", Severity: "high", Guidance: "Verify product ships with secure defaults and users can reset to original state."},
		{RuleID: "CRA-HU-1.3", Name: "Access control mechanisms", CRAReference: "Annex I Part I.2(d)", Status: "HUMAN", Severity: "high", Guidance: "Verify authentication, identity, and access management systems protect against unauthorised access."},
		{RuleID: "CRA-HU-1.4", Name: "Data encryption at rest and in transit", CRAReference: "Annex I Part I.2(e)", Status: "HUMAN", Severity: "high", Guidance: "Verify confidentiality of stored, transmitted, and processed data using state of the art encryption."},
		{RuleID: "CRA-HU-1.5", Name: "Data integrity protection", CRAReference: "Annex I Part I.2(f)", Status: "HUMAN", Severity: "high", Guidance: "Verify integrity of stored, transmitted data, commands, programs, and configuration against unauthorised modification."},
		{RuleID: "CRA-HU-1.6", Name: "Data minimisation", CRAReference: "Annex I Part I.2(g)", Status: "HUMAN", Severity: "medium", Guidance: "Verify only adequate, relevant, and limited data is processed for the product's intended purpose."},
		{RuleID: "CRA-HU-1.7", Name: "Attack surface minimisation", CRAReference: "Annex I Part I.2(j)", Status: "HUMAN", Severity: "high", Guidance: "Verify product is designed to limit attack surfaces including external interfaces."},
		{RuleID: "CRA-HU-1.8", Name: "Risk assessment performed", CRAReference: "Art. 13(2)", Status: "HUMAN", Severity: "high", Guidance: "Verify cybersecurity risk assessment has been carried out and is documented."},
	}
}
