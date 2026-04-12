// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"fmt"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

// HopRunner is the per-hop primitive. walker_test uses a stub; production
// wires this to RunHop.
type HopRunner func(ctx context.Context, in HopInput) (HopResult, error)

// Walker orchestrates a pairwise reverse walk over a single SBOM dependency
// path. It does not aggregate across multiple paths — that is the Analyzer's job.
type Walker struct {
	Fetcher     Fetcher
	Hop         HopRunner
	Config      Config
	Language    LanguageSupport
	InitialTarg []string // target symbols at the vulnerable package
}

// WalkResult is the outcome of walking one dependency path from V backwards.
type WalkResult struct {
	// Completed is true if the walker reached the root of the path (the
	// package immediately downstream of the application) without short-
	// circuiting or hitting a bound.
	Completed bool

	// FinalTargets is the set of symbols in the path root that are tainted
	// exports — the targets the application-side forward analyzer should check.
	FinalTargets []string

	// BrokenAt names the package where the walk short-circuited because no
	// caller was found. Empty if Completed is true.
	BrokenAt string

	// BoundExceeded names the bound that was hit, if any ("max_hops").
	BoundExceeded string

	// HopPaths is the ordered list of per-hop call paths, from application
	// end toward V. Used by the Analyzer to stitch evidence.
	HopPaths []formats.CallPath

	// Degradations records structured reasons for degraded analysis.
	Degradations []string
}

// hopOutcome is the result of a single package hop during the walk.
type hopOutcome struct {
	reaching    []string
	paths       []formats.CallPath // exemplar call paths from this hop
	degradation string             // non-empty means the hop was degraded; walk continues
	brokenAt    string             // non-empty means no callers found; walk should stop
}

// runHop fetches the source for pkg and queries for callers of targetSet.
// It returns a hopOutcome describing what to do next.
func (w *Walker) runHop(ctx context.Context, pkg Package, targetSet []string) (hopOutcome, error) {
	hopCtx := ctx
	if w.Config.HopTimeout > 0 {
		var cancel context.CancelFunc
		hopCtx, cancel = context.WithTimeout(ctx, w.Config.HopTimeout)
		defer cancel()
	}

	fres, err := w.Fetcher.Fetch(hopCtx, pkg.Name, pkg.Version, nil)
	if err != nil {
		return hopOutcome{degradation: ReasonTarballFetchFailed + ":" + pkg.Name}, nil
	}
	if fres.SourceUnavailable {
		return hopOutcome{degradation: ReasonSourceUnavailable + ":" + pkg.Name}, nil
	}

	res, err := w.Hop(hopCtx, HopInput{
		Language:      w.Language,
		SourceDir:     fres.SourceDir,
		TargetSymbols: targetSet,
		MaxTargets:    w.Config.MaxTargetSymbolsPerHop,
	})
	if err != nil {
		return hopOutcome{degradation: ReasonExtractorError + ":" + pkg.Name + ":" + err.Error()}, nil
	}
	if len(res.ReachingSymbols) == 0 {
		return hopOutcome{brokenAt: pkg.Name}, nil
	}
	return hopOutcome{reaching: res.ReachingSymbols, paths: res.Paths}, nil
}

// WalkPath walks a single dependency path in reverse order. The path must be
// ordered from application-side roots to the vulnerable package; the walker
// iterates it in reverse.
//
// path layout: path[0]=D1 (direct dep), path[len-1]=V (vulnerable package).
// Walker skips path[len-1] itself (the vuln package whose exports were already
// identified by the caller) and starts at path[len-2].
func (w *Walker) WalkPath(ctx context.Context, path []Package) (WalkResult, error) {
	if len(path) < 2 {
		return WalkResult{Completed: true, FinalTargets: w.InitialTarg}, nil
	}

	// Detect the bound before starting — avoids wasting hops on an over-long path.
	hopsNeeded := len(path) - 1
	if w.Config.MaxHopsPerPath > 0 && hopsNeeded > w.Config.MaxHopsPerPath {
		return WalkResult{
			BoundExceeded: "max_hops",
			Degradations:  []string{ReasonBoundExceeded},
		}, nil
	}

	targetSet := w.InitialTarg
	var hopPaths []formats.CallPath
	var degradations []string

	// Iterate in reverse starting at the package immediately upstream of V
	// (path[len-2]) and ending at path[0] (the direct dep).
	for i := len(path) - 2; i >= 0; i-- {
		out, err := w.runHop(ctx, path[i], targetSet)
		if err != nil {
			return WalkResult{}, err
		}
		if out.degradation != "" {
			degradations = append(degradations, out.degradation)
			continue
		}
		if out.brokenAt != "" {
			return WalkResult{
				BrokenAt:     out.brokenAt,
				Degradations: append(degradations, fmt.Sprintf("%s:%s", ReasonPathBroken, out.brokenAt)),
				HopPaths:     hopPaths,
			}, nil
		}
		hopPaths = append(hopPaths, out.paths...)
		targetSet = out.reaching
	}

	return WalkResult{
		Completed:    true,
		FinalTargets: targetSet,
		HopPaths:     hopPaths,
		Degradations: degradations,
	}, nil
}
