package reachability_test

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability"
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
