// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package evidence

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/formats/csafvex"
	"github.com/ravan/cra-toolkit/pkg/formats/cyclonedx"
	"github.com/ravan/cra-toolkit/pkg/formats/grype"
	"github.com/ravan/cra-toolkit/pkg/formats/openvex"
	"github.com/ravan/cra-toolkit/pkg/formats/sarif"
	"github.com/ravan/cra-toolkit/pkg/formats/spdx"
	"github.com/ravan/cra-toolkit/pkg/formats/trivy"
	"gopkg.in/yaml.v3"
)

// LoadEvidenceConfig reads and parses the product config YAML file.
func LoadEvidenceConfig(path string) (*EvidenceConfig, error) {
	data, err := os.ReadFile(path) //nolint:gosec // CLI flag
	if err != nil {
		return nil, fmt.Errorf("read product config: %w", err)
	}
	var cfg EvidenceConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse product config: %w", err)
	}
	return &cfg, nil
}

// BuildProductIdentity maps an EvidenceConfig to a ProductIdentity.
func BuildProductIdentity(cfg *EvidenceConfig) ProductIdentity {
	return ProductIdentity{
		Name:                cfg.Product.Name,
		Version:             cfg.Product.Version,
		Manufacturer:        cfg.Product.Manufacturer,
		IntendedPurpose:     cfg.Evidence.IntendedPurpose,
		ProductClass:        cfg.Evidence.ProductClass,
		SupportPeriodEnd:    cfg.Product.SupportPeriodEnd,
		ConformityProcedure: cfg.Evidence.ConformityProcedure,
		SecurityContact:     cfg.Evidence.SecurityContact,
		CVDPolicyURL:        cfg.Evidence.CVDPolicyURL,
	}
}

// ResolveArtifacts checks that all specified artifact paths exist and returns
// an artifactInput slice describing each artifact.
func ResolveArtifacts(opts *Options) ([]artifactInput, error) {
	type inputSpec struct {
		path        string
		annexRef    string
		source      string
		description string
	}

	singles := []inputSpec{
		{opts.SBOMPath, "2b", "toolkit", "Software bill of materials"},
		{opts.VEXPath, "6", "toolkit", "VEX assessment results"},
		{opts.PolicyReport, "6", "toolkit", "CRA Annex I policy evaluation report"},
		{opts.CSAFPath, "6", "toolkit", "CSAF 2.0 security advisory"},
		{opts.ReportPath, "6", "toolkit", "CRA Art. 14 vulnerability notification"},
		{opts.RiskAssessment, "3", "manufacturer", "Cybersecurity risk assessment"},
		{opts.ArchitectureDocs, "2a", "manufacturer", "Design and development architecture"},
		{opts.ProductionProcess, "2c", "manufacturer", "Production and monitoring processes"},
		{opts.EUDeclaration, "7", "manufacturer", "EU declaration of conformity"},
		{opts.CVDPolicy, "2b", "manufacturer", "Coordinated vulnerability disclosure policy"},
		{opts.StandardsDoc, "5", "manufacturer", "Harmonised standards applied"},
	}

	arts := make([]artifactInput, 0, len(singles)+len(opts.ScanPaths))

	for _, s := range singles {
		if s.path == "" {
			continue
		}
		if _, err := os.Stat(s.path); err != nil {
			return nil, fmt.Errorf("artifact %s (%s): %w", s.description, s.path, err)
		}
		format := detectFormatSafe(s.path)
		arts = append(arts, artifactInput{
			sourcePath:  s.path,
			format:      format,
			annexVIIRef: s.annexRef,
			source:      s.source,
			description: s.description,
		})
	}

	for _, path := range opts.ScanPaths {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("artifact scan (%s): %w", path, err)
		}
		format := detectFormatSafe(path)
		arts = append(arts, artifactInput{
			sourcePath:  path,
			format:      format,
			annexVIIRef: "6",
			source:      "toolkit",
			description: "Vulnerability scan results",
		})
	}

	return arts, nil
}

// detectFormatSafe detects the format of a file, returning "unknown" on failure.
func detectFormatSafe(path string) string {
	f, err := os.Open(path) //nolint:gosec // CLI flag
	if err != nil {
		return "unknown"
	}
	defer f.Close() //nolint:errcheck // read-only

	format, err := formats.DetectFormat(f)
	if err != nil {
		return "unknown"
	}
	return format.String()
}

// parseSBOMComponents parses SBOM components from a CycloneDX or SPDX file.
func parseSBOMComponents(path string) ([]componentInfo, error) { //nolint:unused // used in tasks 3-6
	format, f, err := openDetected(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only

	var components []formats.Component
	switch format {
	case formats.FormatCycloneDX:
		components, err = cyclonedx.Parser{}.Parse(f)
	case formats.FormatSPDX:
		components, err = spdx.Parser{}.Parse(f)
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}
	if err != nil {
		return nil, fmt.Errorf("parse SBOM: %w", err)
	}

	infos := make([]componentInfo, 0, len(components))
	for i := range components {
		c := components[i]
		infos = append(infos, componentInfo{
			Name:    c.Name,
			Version: c.Version,
			PURL:    c.PURL,
		})
	}
	return infos, nil
}

// parseScanFindings parses vulnerability findings from Grype, Trivy, or SARIF files.
func parseScanFindings(paths []string) ([]findingInfo, error) { //nolint:unused // used in tasks 3-6
	var all []findingInfo
	for _, path := range paths {
		findings, err := parseSingleScanFile(path)
		if err != nil {
			return nil, err
		}
		for i := range findings {
			fi := findings[i]
			all = append(all, findingInfo{
				CVE:          fi.CVE,
				AffectedPURL: fi.AffectedPURL,
				Severity:     fi.Severity,
			})
		}
	}
	return all, nil
}

// parseSingleScanFile parses vulnerability findings from a single scan file.
func parseSingleScanFile(path string) ([]formats.Finding, error) { //nolint:unused // used in tasks 3-6
	format, f, err := openDetected(path)
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only

	var findings []formats.Finding
	switch format {
	case formats.FormatGrype:
		findings, err = grype.Parser{}.Parse(f)
	case formats.FormatTrivy:
		findings, err = trivy.Parser{}.Parse(f)
	case formats.FormatSARIF:
		findings, err = sarif.Parser{}.Parse(f)
	default:
		return nil, fmt.Errorf("unsupported scan format: %s", format)
	}
	if err != nil {
		return nil, fmt.Errorf("parse scan %s: %w", path, err)
	}
	return findings, nil
}

// parseVEXData parses VEX statements from an OpenVEX or CSAF VEX file.
func parseVEXData(path string) ([]vexInfo, error) { //nolint:unused // used in tasks 3-6
	format, f, err := openDetected(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only

	var stmts []formats.VEXStatement
	switch format {
	case formats.FormatOpenVEX:
		stmts, err = openvex.Parser{}.Parse(f)
	case formats.FormatCSAF:
		stmts, err = csafvex.Parser{}.Parse(f)
	default:
		return nil, fmt.Errorf("unsupported VEX format: %s", format)
	}
	if err != nil {
		return nil, fmt.Errorf("parse VEX: %w", err)
	}

	infos := make([]vexInfo, 0, len(stmts))
	for _, s := range stmts {
		infos = append(infos, vexInfo{
			CVE:           s.CVE,
			ComponentPURL: s.ProductPURL,
			Status:        string(s.Status),
		})
	}
	return infos, nil
}

// parsePolicyReportData parses a policy report JSON file.
func parsePolicyReportData(path string) (*policyReportData, error) { //nolint:unused // used in tasks 3-6
	data, err := os.ReadFile(path) //nolint:gosec // CLI flag
	if err != nil {
		return nil, fmt.Errorf("read policy report: %w", err)
	}

	var raw struct {
		Summary struct {
			Total   int `json:"total"`
			Passed  int `json:"passed"`
			Failed  int `json:"failed"`
			Skipped int `json:"skipped"`
			Human   int `json:"human"`
		} `json:"summary"`
	}

	if err := jsonUnmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse policy report: %w", err)
	}

	return &policyReportData{
		Total:   raw.Summary.Total,
		Passed:  raw.Summary.Passed,
		Failed:  raw.Summary.Failed,
		Skipped: raw.Summary.Skipped,
		Human:   raw.Summary.Human,
	}, nil
}

// openDetected opens a file and detects its format, returning both.
// The caller is responsible for closing the returned file.
func openDetected(path string) (formats.Format, *os.File, error) { //nolint:unused // used in tasks 3-6
	df, err := os.Open(path) //nolint:gosec // CLI flag
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("open for detection: %w", err)
	}
	format, err := formats.DetectFormat(df)
	_ = df.Close()
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("detect format: %w", err)
	}
	pf, err := os.Open(path) //nolint:gosec // CLI flag
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("open for parsing: %w", err)
	}
	return format, pf, nil
}

var jsonUnmarshal = json.Unmarshal //nolint:unused // used in tasks 3-6

// buildVEXEvidence converts VEXResults to serializable evidence entries.
func buildVEXEvidence(results []formats.VEXResult) []VEXEvidence {
	evidence := make([]VEXEvidence, len(results))
	for i := range results {
		r := &results[i]
		var paths []CallPathEntry
		for pi := range r.CallPaths {
			p := &r.CallPaths[pi]
			nodes := make([]CallNodeEntry, len(p.Nodes))
			for j := range p.Nodes {
				nodes[j] = CallNodeEntry{
					Symbol: p.Nodes[j].Symbol,
					File:   p.Nodes[j].File,
					Line:   p.Nodes[j].Line,
				}
			}
			paths = append(paths, CallPathEntry{
				Nodes: nodes,
				Depth: p.Depth(),
			})
		}
		evidence[i] = VEXEvidence{
			CVE:           r.CVE,
			ComponentPURL: r.ComponentPURL,
			Status:        string(r.Status),
			Justification: string(r.Justification),
			Confidence:    r.Confidence.String(),
			ResolvedBy:    r.ResolvedBy,
			Evidence:      r.Evidence,
			Symbols:       r.Symbols,
			CallPaths:     paths,
			MaxCallDepth:  r.MaxCallDepth,
			EntryFiles:    r.EntryFiles,
		}
	}
	return evidence
}

// buildVulnHandlingStats computes handling statistics from VEX results.
func buildVulnHandlingStats(results []formats.VEXResult) VulnHandlingStats {
	stats := VulnHandlingStats{
		TotalAssessed:      len(results),
		StatusDistribution: make(map[string]int),
	}
	for i := range results {
		stats.StatusDistribution[string(results[i].Status)]++
		if results[i].ResolvedBy == "reachability_analysis" {
			stats.ReachabilityBased++
		}
	}
	return stats
}
