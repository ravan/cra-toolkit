// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package evidence

import (
	"fmt"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/formats/cyclonedx"
	"github.com/ravan/cra-toolkit/pkg/formats/spdx"
)

// ExtractSBOMStats parses a real SBOM and extracts component statistics.
func ExtractSBOMStats(path string) (*SBOMStats, error) {
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
		return nil, err
	}

	productName := ""
	productVersion := ""
	if len(components) > 0 {
		productName = components[0].Name
		productVersion = components[0].Version
	}

	return &SBOMStats{
		Format:         format.String(),
		ComponentCount: len(components),
		ProductName:    productName,
		ProductVersion: productVersion,
	}, nil
}

// ExtractScanStats parses real scan results and extracts severity distribution.
func ExtractScanStats(paths []string) (*ScanStats, error) {
	findings, err := parseScanFindings(paths)
	if err != nil {
		return nil, err
	}

	dist := make(map[string]int)
	for _, f := range findings {
		sev := f.Severity
		if sev == "" {
			sev = "unknown"
		}
		dist[sev]++
	}

	return &ScanStats{
		TotalFindings:        len(findings),
		SeverityDistribution: dist,
		ScannerCount:         len(paths),
	}, nil
}

// ExtractVulnHandlingStats parses a real VEX document and extracts status distribution.
func ExtractVulnHandlingStats(path string) (*VulnHandlingStats, error) {
	vex, err := parseVEXData(path)
	if err != nil {
		return nil, err
	}

	dist := make(map[string]int)
	for _, v := range vex {
		dist[v.Status]++
	}

	return &VulnHandlingStats{
		TotalAssessed:      len(vex),
		StatusDistribution: dist,
	}, nil
}

// ExtractPolicyStats extracts summary from a real policy report.
func ExtractPolicyStats(path string) (*PolicyStats, error) {
	data, err := parsePolicyReportData(path)
	if err != nil {
		return nil, err
	}

	return &PolicyStats{
		Total:   data.Total,
		Passed:  data.Passed,
		Failed:  data.Failed,
		Skipped: data.Skipped,
		Human:   data.Human,
	}, nil
}

// BuildSummary constructs the AnnexVIISummary from real artifact data.
// Errors in individual extractions are silently skipped.
func BuildSummary(product *ProductIdentity, sbomPath, vexPath string, scanPaths []string, policyPath string) AnnexVIISummary {
	summary := AnnexVIISummary{
		ProductDescription:  product.IntendedPurpose,
		SupportPeriod:       product.SupportPeriodEnd,
		ConformityProcedure: product.ConformityProcedure,
	}

	if sbomPath != "" {
		if stats, err := ExtractSBOMStats(sbomPath); err == nil {
			summary.SBOMStats = stats
		}
	}

	if vexPath != "" {
		if stats, err := ExtractVulnHandlingStats(vexPath); err == nil {
			summary.VulnHandlingStats = stats
		}
	}

	if len(scanPaths) > 0 {
		if stats, err := ExtractScanStats(scanPaths); err == nil {
			summary.ScanStats = stats
		}
	}

	if policyPath != "" {
		if stats, err := ExtractPolicyStats(policyPath); err == nil {
			summary.PolicyComplianceStats = stats
		}
	}

	return summary
}
