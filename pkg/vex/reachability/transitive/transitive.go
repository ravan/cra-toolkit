// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"errors"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/rust"
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
	Config   Config
	Fetchers map[string]Fetcher // keyed by ecosystem: "pypi", "npm"
	Language LanguageSupport    // per-language plug-in; selects fetcher via Ecosystem()
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
	if a.Language == nil {
		return notApplicable(ReasonTransitiveNotApplicable), nil
	}
	fetcher, ok := a.Fetchers[a.Language.Ecosystem()]
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
		// source. Transform FinalTargets from internal module-qualified names
		// (e.g., "api.get") to package-level names the app actually calls
		// (e.g., "requests.get") using the path root package name.
		appTargets := transformToPackageTargets(res.FinalTargets, p[0].Name)
		appRes, err := RunHop(ctx, HopInput{
			Language:      a.Language,
			SourceDir:     sourceDir,
			TargetSymbols: appTargets,
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
	if a.Language == nil {
		return nil, []string{ReasonTransitiveNotApplicable}
	}
	fetcher, ok := a.Fetchers[a.Language.Ecosystem()]
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
func extractExportedSymbols(lang LanguageSupport, sourceDir, packageName string) (symbols, degradations []string) { //nolint:nonamedreturns // gocritic requires named returns
	syms, err := listExportedSymbols(lang, sourceDir, packageName)
	if err != nil {
		if errors.Is(err, rust.ErrNoLibraryAPI) {
			return nil, []string{ReasonNoLibraryAPI}
		}
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

// transformToPackageTargets converts internal module-qualified targets from a
// walker's FinalTargets into the package-level names the application actually
// calls. For each target like "api.get" and root package "requests" it emits:
//   - "requests.get"     — short form, matching re-exports from __init__
//   - "requests.api.get" — full form, matching qualified access paths
//
// For targets that use "::" scope resolution (e.g. Ruby's
// "nokogiri.nokogiri.html.Nokogiri::HTML"), it additionally emits a scope-flat
// form where the last "::" component becomes the method name:
//   - "nokogiri.HTML"    — scope-flat form, matching Nokogiri::HTML → nokogiri.HTML
//
// Scope-flat forms are emitted first because they are most likely to match
// app-level calls, especially for languages like Ruby where the app-side
// extractor resolves Nokogiri::HTML(args) to nokogiri.HTML via scope aliasing.
// This ordering ensures they are not dropped by the MaxTargetSymbolsPerHop cap.
//
// Duplicates are suppressed.
func transformToPackageTargets(finalTargets []string, rootPkgName string) []string {
	seen := make(map[string]struct{}, len(finalTargets)*3)
	result := make([]string, 0, len(finalTargets)*3)
	add := func(s string) {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}

	// Pass 1: scope-flat forms first (highest priority for Ruby/PHP/C++ namespaces).
	// For "nokogiri.nokogiri.html.Nokogiri::HTML" this produces "nokogiri.HTML".
	for _, t := range finalTargets {
		if idx := strings.LastIndex(t, "::"); idx >= 0 {
			add(rootPkgName + "." + t[idx+2:])
		}
	}

	// Pass 2: short forms (strip the leading module component).
	// For "requests.api.get" this produces "requests.get".
	for _, t := range finalTargets {
		if dot := strings.Index(t, "."); dot >= 0 {
			add(rootPkgName + "." + t[dot+1:])
		}
	}

	// Pass 3: full paths (least likely to match app-level calls, but included
	// for completeness and for cases where the app uses fully-qualified access).
	for _, t := range finalTargets {
		add(rootPkgName + "." + t)
	}

	return result
}

// joinPackages produces a human-readable arrow-joined package name chain.
func joinPackages(p []Package) string {
	parts := make([]string, len(p))
	for i, pkg := range p {
		parts[i] = pkg.Name
	}
	return strings.Join(parts, " → ")
}
