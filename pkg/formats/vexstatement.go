// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package formats

import "io"

// VEXStatus represents the VEX status of a vulnerability finding.
type VEXStatus string

const (
	StatusNotAffected        VEXStatus = "not_affected"
	StatusAffected           VEXStatus = "affected"
	StatusFixed              VEXStatus = "fixed"
	StatusUnderInvestigation VEXStatus = "under_investigation"
)

// Justification represents the VEX justification code.
type Justification string

const (
	JustificationComponentNotPresent            Justification = "component_not_present"
	JustificationVulnerableCodeNotPresent       Justification = "vulnerable_code_not_present"
	JustificationVulnerableCodeNotInExecutePath Justification = "vulnerable_code_not_in_execute_path"
	JustificationInlineMitigationsAlreadyExist  Justification = "inline_mitigations_already_exist"
)

// VEXStatement represents an upstream VEX statement for a vulnerability.
type VEXStatement struct {
	CVE           string        // CVE identifier
	ProductPURL   string        // PURL of the product
	Status        VEXStatus     // VEX status
	Justification Justification // justification code (required when status = not_affected)
	StatusNotes   string        // additional notes
}

// VEXParser parses upstream VEX documents and returns statements.
type VEXParser interface {
	Parse(r io.Reader) ([]VEXStatement, error)
}

// VEXWriter writes VEX results to an output format.
type VEXWriter interface {
	Write(w io.Writer, results []VEXResult) error
}

// VEXResult represents the result of VEX determination for a single finding.
type VEXResult struct {
	CVE           string        // CVE identifier
	ComponentPURL string        // PURL of the component in the SBOM
	Status        VEXStatus     // determined VEX status
	Justification Justification // justification code
	Confidence    Confidence    // confidence level of the determination
	ResolvedBy    string        // name of the filter that resolved this finding
	Evidence      string        // human-readable evidence chain

	// Reachability evidence — populated when ResolvedBy == "reachability_analysis"
	AnalysisMethod string     // "tree_sitter", "govulncheck", "pattern_match"; empty for non-reachability
	CallPaths      []CallPath // structured call chains; nil if not from reachability or pattern_match
	Symbols        []string   // vulnerable symbols confirmed reachable
	MaxCallDepth   int        // max(path.Depth()) across all paths; 0 if none
	EntryFiles     []string   // deduplicated entry-point files (Nodes[0].File)
}
