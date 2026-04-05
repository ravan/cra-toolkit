// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package treesitter_test

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestSymbolID(t *testing.T) {
	id := treesitter.NewSymbolID("myapp", "handler", "process")
	if id == "" {
		t.Error("expected non-empty SymbolID")
	}
	expected := treesitter.SymbolID("myapp.handler.process")
	if id != expected {
		t.Errorf("expected %q, got %q", expected, id)
	}
}

func TestSymbolKind_String(t *testing.T) {
	tests := []struct {
		kind treesitter.SymbolKind
		want string
	}{
		{treesitter.SymbolFunction, "function"},
		{treesitter.SymbolMethod, "method"},
		{treesitter.SymbolClass, "class"},
		{treesitter.SymbolModule, "module"},
	}
	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.want {
			t.Errorf("SymbolKind(%d).String() = %q, want %q", tt.kind, got, tt.want)
		}
	}
}

func TestEdgeKind_String(t *testing.T) {
	tests := []struct {
		kind treesitter.EdgeKind
		want string
	}{
		{treesitter.EdgeDirect, "direct"},
		{treesitter.EdgeDispatch, "dispatch"},
		{treesitter.EdgeImport, "import"},
	}
	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.want {
			t.Errorf("EdgeKind(%d).String() = %q, want %q", tt.kind, got, tt.want)
		}
	}
}

func TestEdge_DefaultConfidence(t *testing.T) {
	edge := treesitter.Edge{From: "a", To: "b", Kind: treesitter.EdgeDirect, Confidence: 1.0}
	if edge.Confidence != 1.0 {
		t.Errorf("expected confidence 1.0, got %f", edge.Confidence)
	}
	dispatchEdge := treesitter.Edge{From: "a", To: "b", Kind: treesitter.EdgeDispatch, Confidence: 0.5}
	if dispatchEdge.Confidence != 0.5 {
		t.Errorf("expected confidence 0.5, got %f", dispatchEdge.Confidence)
	}
}
