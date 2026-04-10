// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
)

// SBOMSummary is the minimal SBOM projection the transitive analyzer needs:
// the version-pinned package list and the application root package names.
// vex.Run builds this from a parsed CycloneDX or SPDX SBOM before handing it
// to per-language analyzers.
type SBOMSummary struct {
	Packages []Package
	Roots    []string
}

// Analyzer is the top-level transitive reachability analyzer. One instance is
// constructed per vex.Run with the SBOM summary and ecosystem-specific fetcher
// wired in. It is safe to reuse across findings within the same run.
type Analyzer struct {
	Config    Config
	Fetchers  map[string]Fetcher // keyed by ecosystem: "pypi", "npm"
	Language  string             // "python" or "javascript"
	Ecosystem string             // matching ecosystem key for Fetchers
}

// Analyze attempts transitive reachability analysis for the given finding.
// Returns a Result with Degradations populated to indicate why transitive
// analysis could not produce a verdict (and the caller should fall back to
// the existing direct-only analyzer), or a reachable verdict with stitched
// call paths as evidence.
//
//nolint:gocognit,gocyclo // multi-phase pipeline; splitting further would obscure flow
func (a *Analyzer) Analyze(ctx context.Context, sbom *SBOMSummary, finding *formats.Finding, sourceDir string) (reachability.Result, error) {
	if sbom == nil || len(sbom.Packages) == 0 || len(sbom.Roots) == 0 {
		return notApplicable(ReasonTransitiveNotApplicable), nil
	}
	fetcher, ok := a.Fetchers[a.Ecosystem]
	if !ok {
		return notApplicable(ReasonTransitiveNotApplicable), nil
	}

	graph, err := BuildDepGraph(ctx, fetcher, sbom.Packages, sbom.Roots)
	if err != nil {
		return reachability.Result{
			Reachable:    false,
			Confidence:   formats.ConfidenceLow,
			Degradations: []string{ReasonManifestFetchFailed},
		}, nil
	}
	if _, ok := graph.Node(finding.AffectedName); !ok {
		return notApplicable(ReasonTransitiveNotApplicable), nil
	}

	paths := graph.PathsTo(finding.AffectedName)
	if len(paths) == 0 {
		return notApplicable(ReasonTransitiveNotApplicable), nil
	}
	if a.Config.MaxPathsPerFinding > 0 && len(paths) > a.Config.MaxPathsPerFinding {
		paths = paths[:a.Config.MaxPathsPerFinding]
	}

	// Stage B: identify target symbols inside V (coarse: all exports).
	// v1 strategy: use the package's own source to collect its exported
	// symbols. For unit-test economy the Analyzer delegates this to a helper
	// that can be stubbed if needed.
	targets, targetDegradations := a.collectVulnSymbols(ctx, finding)
	if len(targets) == 0 {
		return reachability.Result{
			Reachable:    true,
			Confidence:   formats.ConfidenceLow,
			Degradations: append(targetDegradations, ReasonSourceUnavailable),
			Evidence:     "transitive: vulnerable package source unavailable; conservative reachable verdict",
		}, nil
	}

	var pathDegradations []string
	for _, p := range paths {
		w := &Walker{
			Fetcher:     fetcher,
			Hop:         RunHop,
			Config:      a.Config,
			Language:    a.Language,
			InitialTarg: targets,
		}
		res, err := w.WalkPath(ctx, p)
		if err != nil {
			pathDegradations = append(pathDegradations, err.Error())
			continue
		}
		pathDegradations = append(pathDegradations, res.Degradations...)
		if !res.Completed {
			continue
		}
		// Final app-side check: use the same RunHop against the application
		// source with the final target set from the walk.
		appRes, err := RunHop(ctx, HopInput{
			Language:      a.Language,
			SourceDir:     sourceDir,
			TargetSymbols: res.FinalTargets,
			MaxTargets:    a.Config.MaxTargetSymbolsPerHop,
		})
		if err != nil {
			continue
		}
		if len(appRes.ReachingSymbols) == 0 {
			continue
		}
		// Stitch per-hop paths and the app-side path.
		stitched := StitchCallPaths(res.HopPaths)
		return reachability.Result{
			Reachable:    true,
			Confidence:   formats.ConfidenceMedium, // coarse targets → medium, LLM narrowing will raise to high
			Evidence:     "transitive: reachable through " + joinPackages(p),
			Symbols:      appRes.ReachingSymbols,
			Paths:        []formats.CallPath{stitched},
			Degradations: pathDegradations,
		}, nil
	}

	return reachability.Result{
		Reachable:    false,
		Confidence:   formats.ConfidenceMedium,
		Evidence:     "transitive: no path from application reaches " + finding.AffectedName,
		Degradations: pathDegradations,
	}, nil
}

// collectVulnSymbols fetches the vulnerable package's source and returns its
// exported symbols as the coarse target set (Stage B of the algorithm).
func (a *Analyzer) collectVulnSymbols(ctx context.Context, finding *formats.Finding) (symbols, degradations []string) { //nolint:nonamedreturns // gocritic requires named returns
	fetcher, ok := a.Fetchers[a.Ecosystem]
	if !ok {
		return nil, []string{ReasonTransitiveNotApplicable}
	}
	// Find the pinned version from the finding. If not present,
	// return an empty set (the caller already verified existence).
	version := findingVersion(finding)
	if version == "" {
		return nil, []string{ReasonManifestFetchFailed}
	}
	fres, err := fetcher.Fetch(ctx, finding.AffectedName, version, nil)
	if err != nil {
		return nil, []string{ReasonTarballFetchFailed}
	}
	if fres.SourceUnavailable {
		return nil, []string{ReasonSourceUnavailable}
	}

	// Extract all exported symbols from the package source.
	symbols, degradations = extractExportedSymbols(a.Language, fres.SourceDir, finding.AffectedName)
	return symbols, degradations
}

// findingVersion returns the pinned version from the finding. It uses
// AffectedVersion (the installed/pinned version) in preference to the
// AffectedVersions range expression.
func findingVersion(f *formats.Finding) string {
	if f.AffectedVersion != "" {
		return f.AffectedVersion
	}
	// Fall back to the first version in AffectedVersions if it looks like a
	// plain version rather than a range expression.
	v := strings.TrimSpace(f.AffectedVersions)
	if v != "" && !strings.ContainsAny(v, "<>=!~") {
		return v
	}
	return ""
}

// extractExportedSymbols walks the package source and returns fully-qualified
// symbol IDs of its public API. v1: "all top-level functions and methods."
// Filtering by language conventions (leading underscore for Python private)
// is applied.
func extractExportedSymbols(language, sourceDir, packageName string) (symbols, degradations []string) { //nolint:nonamedreturns // gocritic requires named returns
	syms, err := listExportedSymbols(language, sourceDir, packageName)
	if err != nil {
		return nil, []string{ReasonExtractorError}
	}
	return syms, nil
}

// notApplicable returns a not-reachable Result with a single degradation reason.
func notApplicable(reason string) reachability.Result {
	return reachability.Result{
		Reachable:    false,
		Confidence:   formats.ConfidenceLow,
		Degradations: []string{reason},
		Evidence:     "transitive: " + reason,
	}
}

// joinPackages produces a human-readable arrow-joined package name chain.
func joinPackages(p []Package) string {
	parts := make([]string, len(p))
	for i, pkg := range p {
		parts[i] = pkg.Name
	}
	return strings.Join(parts, " → ")
}
