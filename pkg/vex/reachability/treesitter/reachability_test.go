package treesitter_test

import (
	"fmt"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
)

func buildLinearGraph() *treesitter.Graph {
	g := treesitter.NewGraph()
	g.AddSymbol(&treesitter.Symbol{ID: "entry", Name: "entry", IsEntryPoint: true})
	g.AddSymbol(&treesitter.Symbol{ID: "middle", Name: "middle"})
	g.AddSymbol(&treesitter.Symbol{ID: "target", Name: "target", IsExternal: true})
	g.AddEdge(treesitter.Edge{From: "entry", To: "middle", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	g.AddEdge(treesitter.Edge{From: "middle", To: "target", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	return g
}

func TestFindReachablePaths_DirectPath(t *testing.T) {
	g := buildLinearGraph()
	cfg := treesitter.ReachabilityConfig{MaxDepth: 50, MaxPaths: 5}
	paths := treesitter.FindReachablePaths(g, g.EntryPoints(), "target", cfg)
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	if len(paths[0].Nodes) != 3 {
		t.Errorf("expected 3 nodes in path, got %d", len(paths[0].Nodes))
	}
	if paths[0].Nodes[0].Symbol != "entry" {
		t.Errorf("expected first node 'entry', got %q", paths[0].Nodes[0].Symbol)
	}
	if paths[0].Nodes[2].Symbol != "target" {
		t.Errorf("expected last node 'target', got %q", paths[0].Nodes[2].Symbol)
	}
}

func TestFindReachablePaths_NoPath(t *testing.T) {
	g := treesitter.NewGraph()
	g.AddSymbol(&treesitter.Symbol{ID: "entry", Name: "entry", IsEntryPoint: true})
	g.AddSymbol(&treesitter.Symbol{ID: "isolated", Name: "isolated"})
	cfg := treesitter.ReachabilityConfig{MaxDepth: 50, MaxPaths: 5}
	paths := treesitter.FindReachablePaths(g, g.EntryPoints(), "isolated", cfg)
	if len(paths) != 0 {
		t.Errorf("expected 0 paths, got %d", len(paths))
	}
}

func TestFindReachablePaths_CycleDetection(t *testing.T) {
	g := treesitter.NewGraph()
	g.AddSymbol(&treesitter.Symbol{ID: "a", Name: "a", IsEntryPoint: true})
	g.AddSymbol(&treesitter.Symbol{ID: "b", Name: "b"})
	g.AddSymbol(&treesitter.Symbol{ID: "c", Name: "c"})
	g.AddEdge(treesitter.Edge{From: "a", To: "b", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	g.AddEdge(treesitter.Edge{From: "b", To: "a", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	g.AddEdge(treesitter.Edge{From: "b", To: "c", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	cfg := treesitter.ReachabilityConfig{MaxDepth: 50, MaxPaths: 5}
	paths := treesitter.FindReachablePaths(g, g.EntryPoints(), "c", cfg)
	if len(paths) != 1 {
		t.Fatalf("expected 1 path despite cycle, got %d", len(paths))
	}
	if len(paths[0].Nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(paths[0].Nodes))
	}
}

func TestFindReachablePaths_MaxDepth(t *testing.T) {
	g := treesitter.NewGraph()
	for i := 0; i <= 10; i++ {
		id := treesitter.SymbolID(fmt.Sprintf("n%d", i))
		g.AddSymbol(&treesitter.Symbol{ID: id, Name: string(id), IsEntryPoint: i == 0})
		if i > 0 {
			prev := treesitter.SymbolID(fmt.Sprintf("n%d", i-1))
			g.AddEdge(treesitter.Edge{From: prev, To: id, Kind: treesitter.EdgeDirect, Confidence: 1.0})
		}
	}
	cfg := treesitter.ReachabilityConfig{MaxDepth: 5, MaxPaths: 5}
	paths := treesitter.FindReachablePaths(g, g.EntryPoints(), "n10", cfg)
	if len(paths) != 0 {
		t.Errorf("expected 0 paths with MaxDepth=5, got %d", len(paths))
	}
	cfg.MaxDepth = 15
	paths = treesitter.FindReachablePaths(g, g.EntryPoints(), "n10", cfg)
	if len(paths) != 1 {
		t.Errorf("expected 1 path with MaxDepth=15, got %d", len(paths))
	}
}

func TestFindReachablePaths_MaxPaths(t *testing.T) {
	g := treesitter.NewGraph()
	g.AddSymbol(&treesitter.Symbol{ID: "entry", Name: "entry", IsEntryPoint: true})
	g.AddSymbol(&treesitter.Symbol{ID: "a", Name: "a"})
	g.AddSymbol(&treesitter.Symbol{ID: "b", Name: "b"})
	g.AddSymbol(&treesitter.Symbol{ID: "target", Name: "target"})
	g.AddEdge(treesitter.Edge{From: "entry", To: "a", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	g.AddEdge(treesitter.Edge{From: "entry", To: "b", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	g.AddEdge(treesitter.Edge{From: "a", To: "target", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	g.AddEdge(treesitter.Edge{From: "b", To: "target", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	cfg := treesitter.ReachabilityConfig{MaxDepth: 50, MaxPaths: 1}
	paths := treesitter.FindReachablePaths(g, g.EntryPoints(), "target", cfg)
	if len(paths) != 1 {
		t.Errorf("expected exactly 1 path with MaxPaths=1, got %d", len(paths))
	}
}

func TestPathConfidence(t *testing.T) {
	g := treesitter.NewGraph()
	g.AddSymbol(&treesitter.Symbol{ID: "entry", Name: "entry", IsEntryPoint: true})
	g.AddSymbol(&treesitter.Symbol{ID: "dispatch", Name: "dispatch"})
	g.AddSymbol(&treesitter.Symbol{ID: "target", Name: "target"})
	g.AddEdge(treesitter.Edge{From: "entry", To: "dispatch", Kind: treesitter.EdgeDirect, Confidence: 1.0})
	g.AddEdge(treesitter.Edge{From: "dispatch", To: "target", Kind: treesitter.EdgeDispatch, Confidence: 0.5})
	cfg := treesitter.ReachabilityConfig{MaxDepth: 50, MaxPaths: 5}
	paths := treesitter.FindReachablePaths(g, g.EntryPoints(), "target", cfg)
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	conf := treesitter.PathConfidence(g, paths[0])
	if conf < 0.49 || conf > 0.51 {
		t.Errorf("expected confidence ~0.5, got %f", conf)
	}
}

func TestMapConfidence(t *testing.T) {
	tests := []struct {
		pathConf float64
		want     string
	}{
		{1.0, "high"},
		{0.8, "high"},
		{0.5, "medium"},
		{0.4, "medium"},
		{0.3, "low"},
		{0.1, "low"},
	}
	for _, tt := range tests {
		got := treesitter.MapConfidence(tt.pathConf)
		if got.String() != tt.want {
			t.Errorf("MapConfidence(%f) = %q, want %q", tt.pathConf, got.String(), tt.want)
		}
	}
}
