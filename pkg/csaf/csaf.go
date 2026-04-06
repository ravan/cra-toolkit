// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package csaf converts vulnerability scanner output and VEX assessments
// into CSAF 2.0 advisories for downstream user notification per CRA Art. 14(8).
package csaf

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/formats/csafvex"
	"github.com/ravan/cra-toolkit/pkg/formats/cyclonedx"
	"github.com/ravan/cra-toolkit/pkg/formats/grype"
	"github.com/ravan/cra-toolkit/pkg/formats/openvex"
	"github.com/ravan/cra-toolkit/pkg/formats/sarif"
	"github.com/ravan/cra-toolkit/pkg/formats/spdx"
	"github.com/ravan/cra-toolkit/pkg/formats/trivy"
)

// RunOption configures a Run() call with extensions.
type RunOption func(*runConfig)

type runConfig struct{}

// Options configures a CSAF advisory generation run.
type Options struct {
	SBOMPath           string
	ScanPaths          []string
	VEXPath            string
	PublisherName      string
	PublisherNamespace string
	TrackingID         string
	Title              string
}

// Run executes the CSAF advisory generation pipeline.
func Run(opts *Options, out io.Writer, _ ...RunOption) error { //nolint:gocognit,gocyclo // CSAF pipeline has many sequential stages
	// 1. Parse SBOM.
	components, err := parseSBOM(opts.SBOMPath)
	if err != nil {
		return fmt.Errorf("parse SBOM: %w", err)
	}

	// 2. Parse scan results.
	var findings []formats.Finding
	for _, path := range opts.ScanPaths {
		f, err := parseScan(path)
		if err != nil {
			return fmt.Errorf("parse scan %s: %w", path, err)
		}
		findings = append(findings, f...)
	}

	// 3. Parse VEX results (optional).
	var vexResults []formats.VEXResult
	if opts.VEXPath != "" {
		vr, err := parseVEXResults(opts.VEXPath, findings)
		if err != nil {
			return fmt.Errorf("parse VEX %s: %w", opts.VEXPath, err)
		}
		vexResults = vr
	}

	// 4. Build product tree.
	tree := buildProductTree(components, opts.PublisherName)

	// 5. Map vulnerabilities.
	vulns := mapVulnerabilities(findings, vexResults)

	// 6. Enrich stages.
	vulns = enrichScores(vulns, findings)
	vulns = addRemediations(vulns, findings)
	vulns = addThreats(vulns, findings)

	// Add per-vulnerability notes.
	vexLookup := make(map[string]formats.VEXResult, len(vexResults))
	for i := range vexResults {
		vr := &vexResults[i]
		vexLookup[vr.CVE+"|"+vr.ComponentPURL] = *vr
	}
	for i := range vulns {
		vulns[i].References = buildVulnReferences(vulns[i].CVE)
		for j := range findings {
			f := &findings[j]
			if f.CVE == vulns[i].CVE {
				vr := vexLookup[f.CVE+"|"+f.AffectedPURL]
				vulns[i].Notes = buildVulnNotes(f, &vr)
				break
			}
		}
	}

	// 7. Assemble document.
	now := time.Now().UTC().Format(time.RFC3339)
	trackingID := opts.TrackingID
	if trackingID == "" {
		trackingID = "CRA-CSAF-" + time.Now().UTC().Format("20060102T150405Z")
	}
	title := opts.Title
	if title == "" {
		title = generateTitle(findings)
	}

	doc := csafDocument{
		Document: documentMeta{
			Category:    "csaf_security_advisory",
			CSAFVersion: "2.0",
			Title:       title,
			Publisher: publisher{
				Category:  "vendor",
				Name:      opts.PublisherName,
				Namespace: opts.PublisherNamespace,
			},
			Tracking: tracking{
				ID:                 trackingID,
				Status:             "final",
				Version:            "1",
				InitialReleaseDate: now,
				CurrentReleaseDate: now,
				RevisionHistory: []revision{
					{Date: now, Number: "1", Summary: "Initial version"},
				},
				Generator: &generator{
					Date:   now,
					Engine: generatorEngine{Name: "SUSE CRA Toolkit", Version: "0.1.0"},
				},
			},
			Notes:             buildDocumentNotes(findings),
			References:        buildDocumentReferences(findings),
			AggregateSeverity: computeAggregateSeverity(findings),
		},
		ProductTree:     tree,
		Vulnerabilities: vulns,
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("csaf: encode JSON: %w", err)
	}
	return nil
}

func generateTitle(findings []formats.Finding) string {
	seen := make(map[string]bool)
	var cves []string
	for i := range findings {
		f := &findings[i]
		if !seen[f.CVE] {
			seen[f.CVE] = true
			cves = append(cves, f.CVE)
		}
	}
	if len(cves) == 1 {
		return fmt.Sprintf("Security Advisory for %s", cves[0])
	}
	return fmt.Sprintf("Security Advisory for %d vulnerabilities", len(cves))
}

func computeAggregateSeverity(findings []formats.Finding) *aggregateSeverity {
	var maxCVSS float64
	for i := range findings {
		f := &findings[i]
		if f.CVSS > maxCVSS {
			maxCVSS = f.CVSS
		}
	}
	if maxCVSS == 0 {
		return nil
	}
	return &aggregateSeverity{Text: cvssToSeverity(maxCVSS)}
}

func parseVEXResults(path string, _ []formats.Finding) ([]formats.VEXResult, error) {
	stmts, err := parseVEXStatements(path)
	if err != nil {
		return nil, err
	}
	results := make([]formats.VEXResult, 0, len(stmts))
	for _, s := range stmts {
		results = append(results, formats.VEXResult{
			CVE:           s.CVE,
			ComponentPURL: s.ProductPURL,
			Status:        s.Status,
			Justification: s.Justification,
			Confidence:    formats.ConfidenceHigh,
			ResolvedBy:    "upstream_vex",
			Evidence:      s.StatusNotes,
		})
	}
	return results, nil
}

// --- File parsing helpers (same pattern as pkg/vex/vex.go) ---

func openDetected(path string) (formats.Format, *os.File, error) {
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

func parseSBOM(path string) ([]formats.Component, error) {
	format, f, err := openDetected(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file
	switch format {
	case formats.FormatCycloneDX:
		return cyclonedx.Parser{}.Parse(f)
	case formats.FormatSPDX:
		return spdx.Parser{}.Parse(f)
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}
}

func parseScan(path string) ([]formats.Finding, error) {
	format, f, err := openDetected(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file
	switch format {
	case formats.FormatGrype:
		return grype.Parser{}.Parse(f)
	case formats.FormatTrivy:
		return trivy.Parser{}.Parse(f)
	case formats.FormatSARIF:
		return sarif.Parser{}.Parse(f)
	default:
		return nil, fmt.Errorf("unsupported scan format: %s", format)
	}
}

func parseVEXStatements(path string) ([]formats.VEXStatement, error) {
	format, f, err := openDetected(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file
	switch format {
	case formats.FormatOpenVEX:
		return openvex.Parser{}.Parse(f)
	case formats.FormatCSAF:
		return csafvex.Parser{}.Parse(f)
	default:
		return nil, fmt.Errorf("unsupported VEX format: %s", format)
	}
}
