// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package reachability_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
)

func TestCallPath_String(t *testing.T) {
	path := reachability.CallPath{
		Nodes: []reachability.CallNode{
			{Symbol: "main", File: "main.py", Line: 1},
			{Symbol: "handler", File: "handler.py", Line: 10},
			{Symbol: "yaml.load", File: "yaml/__init__.py", Line: 55},
		},
	}

	s := path.String()
	if s == "" {
		t.Error("expected non-empty string representation")
	}
	const want = "main (main.py:1) -> handler (handler.py:10) -> yaml.load (yaml/__init__.py:55)"
	if s != want {
		t.Errorf("String() = %q, want %q", s, want)
	}
	if len(path.Nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(path.Nodes))
	}
}

func TestResult_WithPaths(t *testing.T) {
	result := reachability.Result{
		Reachable: true,
		Symbols:   []string{"yaml.load"},
		Paths: []reachability.CallPath{
			{
				Nodes: []reachability.CallNode{
					{Symbol: "main", File: "main.py", Line: 1},
					{Symbol: "yaml.load", File: "", Line: 0},
				},
			},
		},
	}

	if len(result.Paths) != 1 {
		t.Errorf("expected 1 path, got %d", len(result.Paths))
	}
	if len(result.Paths[0].Nodes) != 2 {
		t.Errorf("expected 2 nodes in path, got %d", len(result.Paths[0].Nodes))
	}
}

func TestResult_Degradations(t *testing.T) {
	r := reachability.Result{
		Reachable:  true,
		Confidence: formats.ConfidenceLow,
		Degradations: []string{
			"source_unavailable",
			"bound_exceeded",
		},
	}
	if len(r.Degradations) != 2 {
		t.Fatalf("expected 2 degradations, got %d", len(r.Degradations))
	}
	if r.Degradations[0] != "source_unavailable" {
		t.Errorf("unexpected first degradation: %q", r.Degradations[0])
	}
}
