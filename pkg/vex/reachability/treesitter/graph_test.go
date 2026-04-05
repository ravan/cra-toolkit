// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package treesitter_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestGraph_AddSymbol(t *testing.T) {
	g := treesitter.NewGraph()
	sym := &treesitter.Symbol{ID: "main.main", Name: "main", QualifiedName: "main.main", Kind: treesitter.SymbolFunction, File: "main.py", StartLine: 1}
	g.AddSymbol(sym)
	got := g.GetSymbol("main.main")
	if got == nil {
		t.Fatal("expected to find symbol main.main")
		return
	}
	if got.Name != "main" {
		t.Errorf("expected name 'main', got %q", got.Name)
	}
}

func TestGraph_AddEdge(t *testing.T) {
	g := treesitter.NewGraph()
	g.AddSymbol(&treesitter.Symbol{ID: "a", Name: "a"})
	g.AddSymbol(&treesitter.Symbol{ID: "b", Name: "b"})
	g.AddEdge(treesitter.Edge{From: "a", To: "b", Kind: treesitter.EdgeDirect, Confidence: 1.0})

	forward := g.ForwardEdges("a")
	if len(forward) != 1 {
		t.Fatalf("expected 1 forward edge from a, got %d", len(forward))
	}
	if forward[0].To != "b" {
		t.Errorf("expected edge to b, got %q", forward[0].To)
	}

	reverse := g.ReverseEdges("b")
	if len(reverse) != 1 {
		t.Fatalf("expected 1 reverse edge to b, got %d", len(reverse))
	}
	if reverse[0].From != "a" {
		t.Errorf("expected edge from a, got %q", reverse[0].From)
	}
}

func TestGraph_EntryPoints(t *testing.T) {
	g := treesitter.NewGraph()
	g.AddSymbol(&treesitter.Symbol{ID: "main", Name: "main", IsEntryPoint: true})
	g.AddSymbol(&treesitter.Symbol{ID: "helper", Name: "helper", IsEntryPoint: false})
	g.AddSymbol(&treesitter.Symbol{ID: "route", Name: "route", IsEntryPoint: true})
	eps := g.EntryPoints()
	if len(eps) != 2 {
		t.Errorf("expected 2 entry points, got %d", len(eps))
	}
}

func TestGraph_SymbolCount(t *testing.T) {
	g := treesitter.NewGraph()
	if g.SymbolCount() != 0 {
		t.Errorf("expected 0 symbols, got %d", g.SymbolCount())
	}
	g.AddSymbol(&treesitter.Symbol{ID: "a", Name: "a"})
	g.AddSymbol(&treesitter.Symbol{ID: "b", Name: "b"})
	if g.SymbolCount() != 2 {
		t.Errorf("expected 2 symbols, got %d", g.SymbolCount())
	}
}
