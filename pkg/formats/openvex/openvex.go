// Package openvex implements parsing and writing of OpenVEX documents.
package openvex

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

// OpenVEX context URL
const contextURL = "https://openvex.dev/ns/v0.2.0"

// Parser parses OpenVEX JSON documents.
type Parser struct{}

// Writer writes VEX results as OpenVEX JSON documents.
type Writer struct{}

// document is the top-level OpenVEX document structure.
type document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id,omitempty"`
	Author     string      `json:"author,omitempty"`
	Role       string      `json:"role,omitempty"`
	Timestamp  string      `json:"timestamp,omitempty"`
	Version    int         `json:"version,omitempty"`
	Statements []statement `json:"statements"`
}

// statement is an OpenVEX statement.
type statement struct {
	Vulnerability   vulnerability `json:"vulnerability"`
	Products        []product     `json:"products"`
	Status          string        `json:"status"`
	Justification   string        `json:"justification,omitempty"`
	ImpactStatement string        `json:"impact_statement,omitempty"`
}

// vulnerability holds CVE information.
type vulnerability struct {
	Name string `json:"name"`
}

// product identifies a product in an OpenVEX statement.
type product struct {
	ID            string         `json:"@id"`
	Subcomponents []subcomponent `json:"subcomponents,omitempty"`
}

// subcomponent identifies a subcomponent of a product.
type subcomponent struct {
	ID string `json:"@id"`
}

// Parse reads an OpenVEX JSON document and returns VEX statements.
func (p Parser) Parse(r io.Reader) ([]formats.VEXStatement, error) {
	var doc document
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("openvex: decode JSON: %w", err)
	}

	stmts := make([]formats.VEXStatement, 0, len(doc.Statements))
	for _, s := range doc.Statements {
		cve := s.Vulnerability.Name

		var productPURL string
		if len(s.Products) > 0 {
			productPURL = s.Products[0].ID
		}

		stmts = append(stmts, formats.VEXStatement{
			CVE:           cve,
			ProductPURL:   productPURL,
			Status:        mapStatus(s.Status),
			Justification: mapJustification(s.Justification),
			StatusNotes:   s.ImpactStatement,
		})
	}

	return stmts, nil
}

// Write serializes VEX results to OpenVEX JSON format.
func (w Writer) Write(out io.Writer, results []formats.VEXResult) error {
	stmts := make([]statement, 0, len(results))
	for i := range results {
		r := &results[i]
		s := statement{
			Vulnerability: vulnerability{Name: r.CVE},
			Products: []product{
				{ID: r.ComponentPURL},
			},
			Status:        statusToOpenVEX(r.Status),
			Justification: justificationToOpenVEX(r.Justification),
		}
		if r.ResolvedBy == "reachability_analysis" {
			s.ImpactStatement = buildReachabilityImpact(r)
		} else {
			s.ImpactStatement = r.Evidence
		}
		stmts = append(stmts, s)
	}

	doc := document{
		Context:    contextURL,
		ID:         "https://suse.com/vex/" + time.Now().UTC().Format("20060102T150405Z"),
		Author:     "SUSE CRA Toolkit",
		Role:       "Document Creator",
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Version:    1,
		Statements: stmts,
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("openvex: encode JSON: %w", err)
	}
	return nil
}

// mapStatus converts an OpenVEX status string to the internal VEXStatus type.
func mapStatus(s string) formats.VEXStatus {
	switch s {
	case "not_affected":
		return formats.StatusNotAffected
	case "affected":
		return formats.StatusAffected
	case "fixed":
		return formats.StatusFixed
	case "under_investigation":
		return formats.StatusUnderInvestigation
	default:
		return formats.VEXStatus(s)
	}
}

// mapJustification converts an OpenVEX justification string to the internal Justification type.
func mapJustification(j string) formats.Justification {
	switch j {
	case "component_not_present":
		return formats.JustificationComponentNotPresent
	case "vulnerable_code_not_present":
		return formats.JustificationVulnerableCodeNotPresent
	case "vulnerable_code_not_in_execute_path":
		return formats.JustificationVulnerableCodeNotInExecutePath
	case "inline_mitigations_already_exist":
		return formats.JustificationInlineMitigationsAlreadyExist
	default:
		return formats.Justification(j)
	}
}

// statusToOpenVEX converts an internal VEXStatus to an OpenVEX status string.
func statusToOpenVEX(s formats.VEXStatus) string {
	return string(s)
}

// justificationToOpenVEX converts an internal Justification to an OpenVEX justification string.
func justificationToOpenVEX(j formats.Justification) string {
	return string(j)
}

// buildReachabilityImpact encodes reachability evidence as a JSON string for use as an OpenVEX impact_statement.
func buildReachabilityImpact(r *formats.VEXResult) string {
	callPaths := make([][]map[string]any, len(r.CallPaths))
	for i, p := range r.CallPaths {
		nodes := make([]map[string]any, len(p.Nodes))
		for j, n := range p.Nodes {
			nodes[j] = map[string]any{
				"symbol": n.Symbol,
				"file":   n.File,
				"line":   n.Line,
			}
		}
		callPaths[i] = nodes
	}

	impact := map[string]any{
		"summary":         r.Evidence,
		"analysis_method": r.AnalysisMethod,
		"confidence":      r.Confidence.String(),
		"symbols":         r.Symbols,
		"max_call_depth":  r.MaxCallDepth,
		"entry_files":     r.EntryFiles,
		"call_paths":      callPaths,
	}

	b, _ := json.MarshalIndent(impact, "", "  ")
	return string(b)
}
