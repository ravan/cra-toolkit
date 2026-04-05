package report

import (
	"strings"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func TestReachabilityDetail_WithPaths(t *testing.T) {
	v := formats.VEXResult{
		ResolvedBy:     "reachability_analysis",
		AnalysisMethod: "tree_sitter",
		Confidence:     formats.ConfidenceHigh,
		Symbols:        []string{"yaml.load"},
		CallPaths: []formats.CallPath{
			{
				Nodes: []formats.CallNode{
					{Symbol: "app.main", File: "src/app.py", Line: 10},
					{Symbol: "app.process", File: "src/app.py", Line: 25},
					{Symbol: "yaml.load", File: "yaml/__init__.py", Line: 100},
				},
			},
		},
		MaxCallDepth: 3,
	}

	got := ReachabilityDetail(v)

	if !strings.Contains(got, "Symbols: yaml.load") {
		t.Errorf("expected 'Symbols: yaml.load', got:\n%s", got)
	}
	if !strings.Contains(got, "Call paths (1):") {
		t.Errorf("expected 'Call paths (1):', got:\n%s", got)
	}
	if !strings.Contains(got, "Path 1 (depth 3):") {
		t.Errorf("expected 'Path 1 (depth 3):', got:\n%s", got)
	}
	if !strings.Contains(got, "app.main") {
		t.Errorf("expected 'app.main' in output, got:\n%s", got)
	}
	if !strings.Contains(got, "[src/app.py:10]") {
		t.Errorf("expected '[src/app.py:10]' in output, got:\n%s", got)
	}
	// Verify indentation uses → for non-first nodes.
	if !strings.Contains(got, "→ app.process") {
		t.Errorf("expected '→ app.process' indented, got:\n%s", got)
	}
}

func TestReachabilityDetail_NoPaths(t *testing.T) {
	v := formats.VEXResult{
		ResolvedBy:     "reachability_analysis",
		AnalysisMethod: "tree_sitter",
		Confidence:     formats.ConfidenceHigh,
		Status:         formats.StatusNotAffected,
		Symbols:        []string{"yaml.load"},
	}

	got := ReachabilityDetail(v)

	if !strings.Contains(got, "No call path found") {
		t.Errorf("expected 'No call path found', got:\n%s", got)
	}
	if !strings.Contains(got, "Symbols checked: yaml.load") {
		t.Errorf("expected 'Symbols checked: yaml.load', got:\n%s", got)
	}
	if !strings.Contains(got, "Confidence: high") {
		t.Errorf("expected 'Confidence: high', got:\n%s", got)
	}
}

func TestReachabilityDetail_NotReachability(t *testing.T) {
	v := formats.VEXResult{
		ResolvedBy: "version",
		Evidence:   "version not in affected range",
	}

	got := ReachabilityDetail(v)

	if got != "" {
		t.Errorf("expected empty string for non-reachability result, got: %q", got)
	}
}
