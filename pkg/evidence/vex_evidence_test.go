// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package evidence

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

func vexResultFixtures() []formats.VEXResult {
	return []formats.VEXResult{
		{
			CVE:            "CVE-2020-1747",
			ComponentPURL:  "pkg:pypi/pyyaml@5.3",
			Status:         formats.StatusAffected,
			Justification:  "",
			Confidence:     formats.ConfidenceHigh,
			ResolvedBy:     "reachability_analysis",
			AnalysisMethod: "tree_sitter",
			Evidence:       "yaml.load is called",
			Symbols:        []string{"yaml.load"},
			MaxCallDepth:   2,
			EntryFiles:     []string{"src/app.py"},
			CallPaths: []formats.CallPath{
				{
					Nodes: []formats.CallNode{
						{Symbol: "app.main", File: "src/app.py", Line: 10},
						{Symbol: "yaml.load", File: "yaml/__init__.py", Line: 100},
					},
				},
			},
		},
		{
			CVE:           "CVE-2023-9999",
			ComponentPURL: "pkg:golang/example.com/lib@v1.0.0",
			Status:        formats.StatusNotAffected,
			Justification: formats.JustificationVulnerableCodeNotPresent,
			ResolvedBy:    "version",
			Evidence:      "version not in affected range",
		},
	}
}

func TestBuildVEXEvidence_Count(t *testing.T) {
	evidence := buildVEXEvidence(vexResultFixtures())
	if len(evidence) != 2 {
		t.Fatalf("expected 2 evidence entries, got %d", len(evidence))
	}
}

func TestBuildVEXEvidence_ReachabilityEntry(t *testing.T) {
	evidence := buildVEXEvidence(vexResultFixtures())
	e1 := evidence[0]

	if e1.CVE != "CVE-2020-1747" {
		t.Errorf("e1.CVE = %q, want CVE-2020-1747", e1.CVE)
	}
	if e1.ResolvedBy != "reachability_analysis" {
		t.Errorf("e1.ResolvedBy = %q, want reachability_analysis", e1.ResolvedBy)
	}
	if e1.MaxCallDepth != 2 {
		t.Errorf("e1.MaxCallDepth = %d, want 2", e1.MaxCallDepth)
	}
}

func TestBuildVEXEvidence_CallPaths(t *testing.T) {
	evidence := buildVEXEvidence(vexResultFixtures())
	e1 := evidence[0]

	if len(e1.CallPaths) != 1 {
		t.Fatalf("e1.CallPaths count = %d, want 1", len(e1.CallPaths))
	}
	if e1.CallPaths[0].Depth != 2 {
		t.Errorf("e1.CallPaths[0].Depth = %d, want 2", e1.CallPaths[0].Depth)
	}
	if len(e1.CallPaths[0].Nodes) != 2 {
		t.Fatalf("e1.CallPaths[0].Nodes count = %d, want 2", len(e1.CallPaths[0].Nodes))
	}
	if e1.CallPaths[0].Nodes[0].Symbol != "app.main" {
		t.Errorf("node[0].Symbol = %q, want app.main", e1.CallPaths[0].Nodes[0].Symbol)
	}
}

func TestBuildVEXEvidence_NonReachabilityEntry(t *testing.T) {
	evidence := buildVEXEvidence(vexResultFixtures())
	e2 := evidence[1]

	if e2.CVE != "CVE-2023-9999" {
		t.Errorf("e2.CVE = %q, want CVE-2023-9999", e2.CVE)
	}
	if len(e2.CallPaths) != 0 {
		t.Errorf("e2.CallPaths should be empty, got %d", len(e2.CallPaths))
	}
}

func TestBuildVulnHandlingStats_ReachabilityBased(t *testing.T) {
	results := []formats.VEXResult{
		{CVE: "CVE-1", Status: formats.StatusAffected, ResolvedBy: "reachability_analysis"},
		{CVE: "CVE-2", Status: formats.StatusNotAffected, ResolvedBy: "version"},
		{CVE: "CVE-3", Status: formats.StatusNotAffected, ResolvedBy: "reachability_analysis"},
	}

	stats := buildVulnHandlingStats(results)

	if stats.TotalAssessed != 3 {
		t.Errorf("TotalAssessed = %d, want 3", stats.TotalAssessed)
	}
	if stats.ReachabilityBased != 2 {
		t.Errorf("ReachabilityBased = %d, want 2", stats.ReachabilityBased)
	}
	if stats.StatusDistribution["affected"] != 1 {
		t.Errorf("StatusDistribution[affected] = %d, want 1", stats.StatusDistribution["affected"])
	}
	if stats.StatusDistribution["not_affected"] != 2 {
		t.Errorf("StatusDistribution[not_affected] = %d, want 2", stats.StatusDistribution["not_affected"])
	}
}
