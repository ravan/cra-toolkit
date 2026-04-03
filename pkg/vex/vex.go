// Package vex implements VEX status determination using deterministic filters.
// It takes an SBOM and vulnerability scan results and auto-determines VEX status
// for each CVE using component presence, version range, platform, patch checks,
// and reachability analysis.
package vex

import (
	"fmt"
	"io"
	"os"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/csafvex"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/cyclonedx"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/grype"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/openvex"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/sarif"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/spdx"
	"github.com/ravan/suse-cra-toolkit/pkg/formats/trivy"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/generic"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/golang"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/rust"
)

// Options configures a VEX pipeline run.
type Options struct {
	SBOMPath         string
	ScanPaths        []string
	UpstreamVEXPaths []string
	SourceDir        string
	OutputFormat     string // "openvex" or "csaf"
}

// Run executes the full VEX determination pipeline:
//  1. Parse SBOM (auto-detect format: cyclonedx or spdx)
//  2. Parse scan results (auto-detect: grype, trivy, or sarif) -- multiple files
//  3. Parse upstream VEX docs (auto-detect: openvex or csaf) -- optional
//  4. Build filter chain: upstream -> presence -> version -> platform -> patch -> reachability
//  5. Run each finding through the chain
//  6. Write output (openvex or csaf writer)
func Run(opts *Options, out io.Writer) error {
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

	// 3. Parse upstream VEX documents.
	var upstreamStatements []formats.VEXStatement
	for _, path := range opts.UpstreamVEXPaths {
		stmts, err := parseVEX(path)
		if err != nil {
			return fmt.Errorf("parse upstream VEX %s: %w", path, err)
		}
		upstreamStatements = append(upstreamStatements, stmts...)
	}

	// 4. Build filter chain.
	filters := buildFilterChain(upstreamStatements, opts.SourceDir)

	// 5. Run each finding through chain.
	results := make([]formats.VEXResult, 0, len(findings))
	for i := range findings {
		result := RunChain(filters, &findings[i], components)
		results = append(results, result)
	}

	// 6. Write output.
	writer := selectWriter(opts.OutputFormat)
	return writer.Write(out, results)
}

// openDetected opens a file, detects its format, and returns the format along
// with a fresh reader for parsing. The caller must close the returned file.
func openDetected(path string) (formats.Format, *os.File, error) {
	// First open for format detection.
	df, err := os.Open(path) //nolint:gosec // path is from CLI flag, user-controlled
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("open for detection: %w", err)
	}

	format, err := formats.DetectFormat(df)
	_ = df.Close()
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("detect format: %w", err)
	}

	// Re-open for parsing (DetectFormat consumes the reader).
	pf, err := os.Open(path) //nolint:gosec // path is from CLI flag, user-controlled
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("open for parsing: %w", err)
	}

	return format, pf, nil
}

// parseSBOM detects the SBOM format and parses it.
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

// parseScan detects the scan format and parses it.
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

// parseVEX detects the VEX format and parses it.
func parseVEX(path string) ([]formats.VEXStatement, error) {
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

// buildFilterChain creates the ordered filter chain.
func buildFilterChain(upstreamStatements []formats.VEXStatement, sourceDir string) []Filter {
	var filters []Filter

	// Upstream filter (only if there are upstream statements).
	if len(upstreamStatements) > 0 {
		filters = append(filters, NewUpstreamFilter(upstreamStatements))
	}

	// Deterministic filters.
	filters = append(filters,
		NewPresenceFilter(),
		NewVersionFilter(),
		NewPlatformFilter(),
		NewPatchFilter(),
	)

	// Reachability filter (only if source dir is provided).
	if sourceDir != "" {
		analyzers := buildAnalyzers(sourceDir)
		if len(analyzers) > 0 {
			filters = append(filters, NewReachabilityFilter(sourceDir, analyzers))
		}
	}

	return filters
}

// buildAnalyzers detects languages in the source directory and creates
// the appropriate reachability analyzers.
func buildAnalyzers(sourceDir string) map[string]reachability.Analyzer {
	analyzers := make(map[string]reachability.Analyzer)

	langs := reachability.DetectLanguages(sourceDir)
	for _, lang := range langs {
		switch lang {
		case "go":
			analyzers["go"] = golang.New()
		case "rust":
			analyzers["rust"] = rust.New()
		}
	}

	// Always add generic as fallback.
	analyzers["generic"] = generic.New("")

	return analyzers
}

// selectWriter returns the appropriate VEX writer for the given format.
func selectWriter(format string) formats.VEXWriter {
	switch format {
	case "csaf":
		return csafvex.Writer{}
	default:
		return openvex.Writer{}
	}
}
