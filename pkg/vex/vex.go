// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package vex implements VEX status determination using deterministic filters.
// It takes an SBOM and vulnerability scan results and auto-determines VEX status
// for each CVE using component presence, version range, platform, patch checks,
// and reachability analysis.
package vex

import (
	"fmt"
	"io"
	"os"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/formats/csafvex"
	"github.com/ravan/cra-toolkit/pkg/formats/cyclonedx"
	"github.com/ravan/cra-toolkit/pkg/formats/grype"
	"github.com/ravan/cra-toolkit/pkg/formats/openvex"
	"github.com/ravan/cra-toolkit/pkg/formats/sarif"
	"github.com/ravan/cra-toolkit/pkg/formats/spdx"
	"github.com/ravan/cra-toolkit/pkg/formats/trivy"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
	csharpanalyzer "github.com/ravan/cra-toolkit/pkg/vex/reachability/csharp"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/generic"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/golang"
	javaanalyzer "github.com/ravan/cra-toolkit/pkg/vex/reachability/java"
	jsanalyzer "github.com/ravan/cra-toolkit/pkg/vex/reachability/javascript"
	phpanalyzer "github.com/ravan/cra-toolkit/pkg/vex/reachability/php"
	pythonanalyzer "github.com/ravan/cra-toolkit/pkg/vex/reachability/python"
	rubyanalyzer "github.com/ravan/cra-toolkit/pkg/vex/reachability/ruby"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/rust"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive"
)

// Options configures a VEX pipeline run.
type Options struct {
	SBOMPath         string
	ScanPaths        []string
	UpstreamVEXPaths []string
	SourceDir        string
	OutputFormat     string // "openvex" or "csaf"
	// TransitiveEnabled, when false, disables transitive reachability
	// analysis and preserves direct-only behavior. Defaults to true.
	TransitiveEnabled bool
	// TransitiveCacheDir overrides the default cache location for fetched
	// package tarballs. Empty means use the default.
	TransitiveCacheDir string
}

// RunConfig holds extension registrations passed via RunOption.
type RunConfig struct {
	ExtraFilters     []Filter
	ExtraAnalyzers   map[string]reachability.Analyzer
	ExtraScanParsers map[formats.Format]formats.ScanParser
	ExtraSBOMParsers map[formats.Format]formats.SBOMParser
	ExtraVEXWriters  map[string]formats.VEXWriter
	ExtraProbes      []formats.FormatProbe
}

// RunOption configures a Run() call with extensions.
type RunOption func(*RunConfig)

// WithExtraFilters adds extra filters to the VEX determination chain.
func WithExtraFilters(filters []Filter) RunOption {
	return func(c *RunConfig) { c.ExtraFilters = append(c.ExtraFilters, filters...) }
}

// WithExtraAnalyzers adds extra reachability analyzers.
func WithExtraAnalyzers(analyzers map[string]reachability.Analyzer) RunOption {
	return func(c *RunConfig) {
		if c.ExtraAnalyzers == nil {
			c.ExtraAnalyzers = make(map[string]reachability.Analyzer)
		}
		for k, v := range analyzers {
			c.ExtraAnalyzers[k] = v
		}
	}
}

// WithExtraScanParsers adds extra scan result parsers.
func WithExtraScanParsers(parsers map[formats.Format]formats.ScanParser) RunOption {
	return func(c *RunConfig) {
		if c.ExtraScanParsers == nil {
			c.ExtraScanParsers = make(map[formats.Format]formats.ScanParser)
		}
		for k, v := range parsers {
			c.ExtraScanParsers[k] = v
		}
	}
}

// WithExtraSBOMParsers adds extra SBOM parsers.
func WithExtraSBOMParsers(parsers map[formats.Format]formats.SBOMParser) RunOption {
	return func(c *RunConfig) {
		if c.ExtraSBOMParsers == nil {
			c.ExtraSBOMParsers = make(map[formats.Format]formats.SBOMParser)
		}
		for k, v := range parsers {
			c.ExtraSBOMParsers[k] = v
		}
	}
}

// WithExtraVEXWriters adds extra VEX output writers.
func WithExtraVEXWriters(writers map[string]formats.VEXWriter) RunOption {
	return func(c *RunConfig) {
		if c.ExtraVEXWriters == nil {
			c.ExtraVEXWriters = make(map[string]formats.VEXWriter)
		}
		for k, v := range writers {
			c.ExtraVEXWriters[k] = v
		}
	}
}

// WithExtraFormatProbes adds extra format detection probes.
func WithExtraFormatProbes(probes []formats.FormatProbe) RunOption {
	return func(c *RunConfig) { c.ExtraProbes = append(c.ExtraProbes, probes...) }
}

// Run executes the full VEX determination pipeline:
//  1. Parse SBOM (auto-detect format: cyclonedx or spdx)
//  2. Parse scan results (auto-detect: grype, trivy, or sarif) -- multiple files
//  3. Parse upstream VEX docs (auto-detect: openvex or csaf) -- optional
//  4. Build filter chain: upstream -> presence -> version -> platform -> patch -> reachability
//  5. Run each finding through the chain
//  6. Write output (openvex or csaf writer)
func Run(opts *Options, out io.Writer, runOpts ...RunOption) error {
	var cfg RunConfig
	for _, o := range runOpts {
		o(&cfg)
	}

	// 1. Parse SBOM.
	components, err := parseSBOM(opts.SBOMPath, cfg.ExtraProbes, cfg.ExtraSBOMParsers)
	if err != nil {
		return fmt.Errorf("parse SBOM: %w", err)
	}

	// 2. Parse scan results.
	var findings []formats.Finding
	for _, path := range opts.ScanPaths {
		f, err := parseScan(path, cfg.ExtraProbes, cfg.ExtraScanParsers)
		if err != nil {
			return fmt.Errorf("parse scan %s: %w", path, err)
		}
		findings = append(findings, f...)
	}

	// 3. Parse upstream VEX documents.
	var upstreamStatements []formats.VEXStatement
	for _, path := range opts.UpstreamVEXPaths {
		stmts, err := parseVEX(path, cfg.ExtraProbes)
		if err != nil {
			return fmt.Errorf("parse upstream VEX %s: %w", path, err)
		}
		upstreamStatements = append(upstreamStatements, stmts...)
	}

	// 4. Build filter chain.
	directDeps := cyclonedx.ParseDirectDeps(opts.SBOMPath)
	transitiveCfg := resolveTransitiveConfig(opts, nil)
	filters := buildFilterChain(upstreamStatements, opts.SourceDir, components, directDeps, transitiveCfg, cfg.ExtraFilters, cfg.ExtraAnalyzers)

	// 5. Run each finding through chain.
	results := make([]formats.VEXResult, 0, len(findings))
	for i := range findings {
		result := RunChain(filters, &findings[i], components)
		results = append(results, result)
	}

	// 6. Write output.
	writer := selectWriter(opts.OutputFormat, cfg.ExtraVEXWriters)
	return writer.Write(out, results)
}

// openDetected opens a file, detects its format, and returns the format along
// with a fresh reader for parsing. The caller must close the returned file.
func openDetected(path string, extraProbes []formats.FormatProbe) (formats.Format, *os.File, error) {
	// First open for format detection.
	df, err := os.Open(path) //nolint:gosec // path is from CLI flag, user-controlled
	if err != nil {
		return formats.FormatUnknown, nil, fmt.Errorf("open for detection: %w", err)
	}

	format, err := formats.DetectFormat(df, extraProbes...)
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
func parseSBOM(path string, extraProbes []formats.FormatProbe, extra map[formats.Format]formats.SBOMParser) ([]formats.Component, error) {
	format, f, err := openDetected(path, extraProbes)
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
		if p, ok := extra[format]; ok {
			return p.Parse(f)
		}
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}
}

// parseScan detects the scan format and parses it.
func parseScan(path string, extraProbes []formats.FormatProbe, extra map[formats.Format]formats.ScanParser) ([]formats.Finding, error) {
	format, f, err := openDetected(path, extraProbes)
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
		if p, ok := extra[format]; ok {
			return p.Parse(f)
		}
		return nil, fmt.Errorf("unsupported scan format: %s", format)
	}
}

// parseVEX detects the VEX format and parses it.
func parseVEX(path string, extraProbes []formats.FormatProbe) ([]formats.VEXStatement, error) {
	format, f, err := openDetected(path, extraProbes)
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
func buildFilterChain(upstreamStatements []formats.VEXStatement, sourceDir string, components []formats.Component, directDeps []string, transitiveCfg transitive.Config, extraFilters []Filter, extraAnalyzers map[string]reachability.Analyzer) []Filter {
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
		analyzers := buildAnalyzers(sourceDir, components, directDeps, transitiveCfg, extraAnalyzers)
		if len(analyzers) > 0 {
			filters = append(filters, NewReachabilityFilter(sourceDir, analyzers))
		}
	}

	// Extension filters (appended after all built-in filters).
	filters = append(filters, extraFilters...)

	return filters
}

// buildAnalyzers detects languages in the source directory and creates
// the appropriate reachability analyzers.
//
//nolint:gocyclo // language-analyzer mapping is inherently branchy
func buildAnalyzers(sourceDir string, components []formats.Component, directDeps []string, transitiveCfg transitive.Config, extra map[string]reachability.Analyzer) map[string]reachability.Analyzer {
	analyzers := make(map[string]reachability.Analyzer)

	langs := reachability.DetectLanguages(sourceDir)
	for _, lang := range langs {
		switch lang {
		case "go":
			analyzers["go"] = golang.New()
		case "rust":
			analyzers["rust"] = rust.New()
		case "python":
			a := pythonanalyzer.New()
			if ta := buildTransitiveAnalyzer(transitiveCfg, "python"); ta != nil {
				a.Transitive = ta
				a.SBOMSummary = buildTransitiveSummary(components, directDeps, "pypi")
			}
			analyzers["python"] = a
		case "javascript":
			a := jsanalyzer.New()
			if ta := buildTransitiveAnalyzer(transitiveCfg, "javascript"); ta != nil {
				a.Transitive = ta
				a.SBOMSummary = buildTransitiveSummary(components, directDeps, "npm")
			}
			analyzers["javascript"] = a
		case "java":
			analyzers["java"] = javaanalyzer.New()
		case "csharp":
			analyzers["csharp"] = csharpanalyzer.New()
		case "php":
			analyzers["php"] = phpanalyzer.New()
		case "ruby":
			analyzers["ruby"] = rubyanalyzer.New()
		}
	}

	// Always add generic as fallback.
	analyzers["generic"] = generic.New("")

	// Merge extra analyzers (can override built-in or add new languages).
	for k, v := range extra {
		analyzers[k] = v
	}

	return analyzers
}

// selectWriter returns the appropriate VEX writer for the given format.
func selectWriter(format string, extra map[string]formats.VEXWriter) formats.VEXWriter {
	switch format {
	case "csaf":
		return csafvex.Writer{}
	case "openvex", "":
		return openvex.Writer{}
	default:
		if w, ok := extra[format]; ok {
			return w
		}
		return openvex.Writer{}
	}
}
