// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/rust"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestLanguage_Identity(t *testing.T) {
	lang := rust.New()
	if lang.Name() != "rust" {
		t.Errorf("Name() = %q, want %q", lang.Name(), "rust")
	}
	if lang.Ecosystem() != "crates.io" {
		t.Errorf("Ecosystem() = %q, want %q", lang.Ecosystem(), "crates.io")
	}
	exts := lang.FileExtensions()
	if len(exts) != 1 || exts[0] != ".rs" {
		t.Errorf("FileExtensions() = %v, want [\".rs\"]", exts)
	}
	if lang.Grammar() == nil {
		t.Error("Grammar() returned nil")
	}
	if lang.Extractor() == nil {
		t.Error("Extractor() returned nil")
	}
}

func TestLanguage_IsExportedSymbol(t *testing.T) {
	lang := rust.New()
	cases := []struct {
		name string
		sym  *treesitter.Symbol
		want bool
	}{
		{"nil", nil, false},
		{"public function", &treesitter.Symbol{Kind: treesitter.SymbolFunction, IsPublic: true}, true},
		{"private function", &treesitter.Symbol{Kind: treesitter.SymbolFunction, IsPublic: false}, false},
		{"public method", &treesitter.Symbol{Kind: treesitter.SymbolMethod, IsPublic: true}, true},
		{"private method", &treesitter.Symbol{Kind: treesitter.SymbolMethod, IsPublic: false}, false},
		{"public struct", &treesitter.Symbol{Kind: treesitter.SymbolClass, IsPublic: true}, true},
		{"private struct", &treesitter.Symbol{Kind: treesitter.SymbolClass, IsPublic: false}, false},
		{"public module", &treesitter.Symbol{Kind: treesitter.SymbolModule, IsPublic: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := lang.IsExportedSymbol(tc.sym)
			if got != tc.want {
				t.Errorf("IsExportedSymbol(%+v) = %v, want %v", tc.sym, got, tc.want)
			}
		})
	}
}
