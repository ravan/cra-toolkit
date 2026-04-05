package vex

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability"
)

// reachabilityFilter bridges reachability analyzers into the Filter interface.
type reachabilityFilter struct {
	sourceDir string
	analyzers map[string]reachability.Analyzer
}

// NewReachabilityFilter returns a Filter that uses reachability analyzers to
// determine whether vulnerable code is actually called. If no analyzer matches
// the finding's language, the "generic" analyzer is used as a fallback.
func NewReachabilityFilter(sourceDir string, analyzers map[string]reachability.Analyzer) Filter {
	return &reachabilityFilter{
		sourceDir: sourceDir,
		analyzers: analyzers,
	}
}

func (f *reachabilityFilter) Name() string { return "reachability" }

func (f *reachabilityFilter) Evaluate(finding *formats.Finding, components []formats.Component) (Result, bool) {
	analyzer, ok := f.analyzers[finding.Language]
	if !ok {
		// Fall back to "generic" analyzer.
		analyzer, ok = f.analyzers["generic"]
		if !ok {
			// No analyzer available; cannot resolve.
			return Result{}, false
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := analyzer.Analyze(ctx, f.sourceDir, finding)
	if err != nil {
		// Analysis failed; cannot resolve.
		return Result{}, false
	}

	if result.Reachable {
		evidence := result.Evidence
		// Append structured path info if available.
		if len(result.Paths) > 0 {
			var pathStrs []string
			for _, p := range result.Paths {
				pathStrs = append(pathStrs, p.String())
			}
			evidence = fmt.Sprintf("%s\nCall paths:\n  %s", evidence, strings.Join(pathStrs, "\n  "))
		}
		return Result{
			CVE:           finding.CVE,
			ComponentPURL: finding.AffectedPURL,
			Status:        formats.StatusAffected,
			Confidence:    result.Confidence,
			ResolvedBy:    "reachability_analysis",
			Evidence:      evidence,
		}, true
	}

	return Result{
		CVE:           finding.CVE,
		ComponentPURL: finding.AffectedPURL,
		Status:        formats.StatusNotAffected,
		Justification: formats.JustificationVulnerableCodeNotInExecutePath,
		Confidence:    result.Confidence,
		ResolvedBy:    "reachability_analysis",
		Evidence:      fmt.Sprintf("Reachability analysis: %s", result.Evidence),
	}, true
}
