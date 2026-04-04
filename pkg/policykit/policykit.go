// Package policykit implements CRA Annex I policy evaluation using embedded OPA/Rego policies.
// It evaluates SBOM, VEX, and provenance artifacts against machine-checkable CRA rules.
package policykit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/csafvex"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/cyclonedx"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/grype"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/openvex"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/sarif"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/spdx"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/trivy"
	"github.com/ravan/suse-cra-toolkit/policies"
)

// Options configures a CRA policy evaluation run.
type Options struct {
	SBOMPath       string
	ScanPaths      []string
	VEXPath        string
	ProvenancePath string
	SignaturePaths []string
	ProductConfig  string
	KEVPath        string
	PolicyDir      string
	OutputFormat   string // "json" or "markdown"
}

// Run executes the 5-stage CRA policy evaluation pipeline and writes the report to out.
func Run(opts *Options, out io.Writer) error { //nolint:gocognit,gocyclo // pipeline has many sequential stages
	// Stage 1: Parse artifacts.
	artifacts, err := parseArtifacts(opts)
	if err != nil {
		return fmt.Errorf("parse artifacts: %w", err)
	}

	// Stage 2: Fetch KEV.
	kev, err := LoadKEV(opts.KEVPath)
	if err != nil {
		return fmt.Errorf("load KEV: %w", err)
	}
	artifacts.KEV = kev

	// Stage 3: Build input.
	input := BuildInput(artifacts)

	// Stage 4: Evaluate policies.
	modules, err := loadEmbeddedPolicies()
	if err != nil {
		return fmt.Errorf("load embedded policies: %w", err)
	}

	engine, err := NewEngine(modules)
	if err != nil {
		return fmt.Errorf("create engine: %w", err)
	}

	if opts.PolicyDir != "" {
		custom, err := loadPoliciesFromDir(opts.PolicyDir)
		if err != nil {
			return fmt.Errorf("load custom policies: %w", err)
		}
		if err := engine.AddCustomPolicies(custom); err != nil {
			return fmt.Errorf("add custom policies: %w", err)
		}
	}

	machineResults, err := engine.Evaluate(context.Background(), input)
	if err != nil {
		return fmt.Errorf("evaluate policies: %w", err)
	}

	// Stage 5: Assemble report.
	allResults := append(machineResults, HumanReviewItems()...)
	summary := ComputeSummary(allResults)

	report := &Report{
		ReportID:       "CRA-RPT-" + time.Now().UTC().Format("20060102T150405Z"),
		ToolkitVersion: "0.1.0",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Summary:        summary,
		Results:        allResults,
	}

	if opts.OutputFormat == "markdown" {
		_, err := io.WriteString(out, RenderMarkdown(report))
		return err
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}

// parseArtifacts loads and parses all input artifacts from the given options.
func parseArtifacts(opts *Options) (*ParsedArtifacts, error) {
	a := &ParsedArtifacts{}

	// Parse SBOM.
	components, sbomFormat, meta, err := parseSBOMWithMeta(opts.SBOMPath)
	if err != nil {
		return nil, fmt.Errorf("parse SBOM: %w", err)
	}
	a.Components = components
	a.SBOMFormat = sbomFormat
	a.SBOMVersion = meta.specVersion
	a.SBOMName = meta.name
	a.SBOMVersionField = meta.version
	a.SBOMSupplier = meta.supplier

	// Parse scan results.
	for _, path := range opts.ScanPaths {
		findings, err := parseScan(path)
		if err != nil {
			return nil, fmt.Errorf("parse scan %s: %w", path, err)
		}
		a.Findings = append(a.Findings, findings...)
	}

	// Parse VEX (optional).
	if opts.VEXPath != "" {
		vr, err := parseVEXResults(opts.VEXPath)
		if err != nil {
			return nil, fmt.Errorf("parse VEX %s: %w", opts.VEXPath, err)
		}
		a.VEXResults = vr
	}

	// Parse provenance (optional).
	if opts.ProvenancePath != "" {
		f, err := os.Open(opts.ProvenancePath) //nolint:gosec // CLI flag
		if err != nil {
			return nil, fmt.Errorf("open provenance: %w", err)
		}
		prov, err := ParseProvenance(f)
		_ = f.Close() //nolint:errcheck // read-only file
		if err != nil {
			return nil, fmt.Errorf("parse provenance: %w", err)
		}
		a.Provenance = prov
	}

	// Parse signatures (optional).
	for _, path := range opts.SignaturePaths {
		f, err := os.Open(path) //nolint:gosec // CLI flag
		if err != nil {
			return nil, fmt.Errorf("open signature %s: %w", path, err)
		}
		sig, err := ParseSignature(f, filepath.Base(path))
		_ = f.Close() //nolint:errcheck // read-only file
		if err != nil {
			return nil, fmt.Errorf("parse signature %s: %w", path, err)
		}
		a.Signatures = append(a.Signatures, *sig)
	}

	// Parse product config (optional).
	if opts.ProductConfig != "" {
		pc, err := LoadProductConfig(opts.ProductConfig)
		if err != nil {
			return nil, fmt.Errorf("load product config: %w", err)
		}
		a.Product = pc
	}

	return a, nil
}

// sbomMeta holds SBOM-level metadata extracted from the document.
type sbomMeta struct {
	specVersion string
	name        string
	version     string
	supplier    string
}

// openDetected opens a file, detects its format, then re-opens it for parsing.
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

// parseSBOMWithMeta parses an SBOM and extracts document-level metadata.
func parseSBOMWithMeta(path string) ([]formats.Component, string, sbomMeta, error) {
	format, f, err := openDetected(path)
	if err != nil {
		return nil, "", sbomMeta{}, err
	}
	defer f.Close() //nolint:errcheck // read-only file

	var components []formats.Component
	var formatName string

	switch format {
	case formats.FormatCycloneDX:
		components, err = cyclonedx.Parser{}.Parse(f)
		formatName = "cyclonedx"
	case formats.FormatSPDX:
		components, err = spdx.Parser{}.Parse(f)
		formatName = "spdx"
	default:
		return nil, "", sbomMeta{}, fmt.Errorf("unsupported SBOM format: %s", format)
	}
	if err != nil {
		return nil, "", sbomMeta{}, fmt.Errorf("parse SBOM: %w", err)
	}

	// Extract metadata by re-reading the file as JSON.
	meta := extractSBOMMeta(path, format)

	return components, formatName, meta, nil
}

// extractSBOMMeta re-reads the SBOM file to extract document-level metadata fields.
func extractSBOMMeta(path string, format formats.Format) sbomMeta {
	var meta sbomMeta

	if format != formats.FormatCycloneDX {
		return meta
	}

	data, err := os.ReadFile(path) //nolint:gosec // CLI flag
	if err != nil {
		return meta
	}

	var doc struct {
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Component struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"component"`
			Supplier *struct {
				Name string `json:"name"`
			} `json:"supplier"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return meta
	}

	meta.specVersion = doc.SpecVersion
	meta.name = doc.Metadata.Component.Name
	meta.version = doc.Metadata.Component.Version
	if doc.Metadata.Supplier != nil {
		meta.supplier = doc.Metadata.Supplier.Name
	}

	return meta
}

// parseScan parses a vulnerability scan result file.
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

// parseVEXResults parses VEX statements and converts them to VEXResult values.
func parseVEXResults(path string) ([]formats.VEXResult, error) {
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

// parseVEXStatements parses VEX statements from a file.
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

// loadEmbeddedPolicies reads all .rego files from the embedded policies filesystem.
func loadEmbeddedPolicies() (map[string]string, error) {
	modules := make(map[string]string)
	err := fs.WalkDir(policies.Embedded, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}
		data, err := fs.ReadFile(policies.Embedded, path)
		if err != nil {
			return fmt.Errorf("read embedded policy %s: %w", path, err)
		}
		modules[path] = string(data)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk embedded policies: %w", err)
	}
	return modules, nil
}

// loadPoliciesFromDir reads all .rego files from the given directory.
func loadPoliciesFromDir(dir string) (map[string]string, error) {
	modules := make(map[string]string)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read policy dir %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rego") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path) //nolint:gosec // CLI flag
		if err != nil {
			return nil, fmt.Errorf("read policy %s: %w", path, err)
		}
		modules[e.Name()] = string(data)
	}
	return modules, nil
}
