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

func TestLanguage_ModulePath(t *testing.T) {
	lang := rust.New()
	cases := []struct {
		name      string
		file      string
		sourceDir string
		pkg       string
		want      string
	}{
		{
			name:      "lib.rs at crate root",
			file:      "/tmp/hyper-0.14.10/src/lib.rs",
			sourceDir: "/tmp/hyper-0.14.10",
			pkg:       "hyper",
			want:      "hyper",
		},
		{
			name:      "submodule file",
			file:      "/tmp/hyper-0.14.10/src/client.rs",
			sourceDir: "/tmp/hyper-0.14.10",
			pkg:       "hyper",
			want:      "hyper.client",
		},
		{
			name:      "nested mod.rs",
			file:      "/tmp/hyper-0.14.10/src/client/connect/mod.rs",
			sourceDir: "/tmp/hyper-0.14.10",
			pkg:       "hyper",
			want:      "hyper.client.connect",
		},
		{
			name:      "nested leaf file",
			file:      "/tmp/hyper-0.14.10/src/client/connect/http.rs",
			sourceDir: "/tmp/hyper-0.14.10",
			pkg:       "hyper",
			want:      "hyper.client.connect.http",
		},
		{
			name:      "out-of-src test file is rejected",
			file:      "/tmp/hyper-0.14.10/tests/integration.rs",
			sourceDir: "/tmp/hyper-0.14.10",
			pkg:       "hyper",
			want:      "tests",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := lang.ModulePath(tc.file, tc.sourceDir, tc.pkg)
			if got != tc.want {
				t.Errorf("ModulePath = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLanguage_SymbolKey(t *testing.T) {
	lang := rust.New()
	if got := lang.SymbolKey("hyper.client", "Request"); got != "hyper.client.Request" {
		t.Errorf("SymbolKey = %q, want %q", got, "hyper.client.Request")
	}
	if got := lang.SymbolKey("hyper", "spawn"); got != "hyper.spawn" {
		t.Errorf("SymbolKey = %q, want %q", got, "hyper.spawn")
	}
}

func TestLanguage_ResolveDottedTarget(t *testing.T) {
	lang := rust.New()
	scope := treesitter.NewScope(nil)
	scope.DefineImport("Deserialize", "serde.Deserialize", nil)
	scope.DefineImport("tokio", "tokio", nil)

	got, ok := lang.ResolveDottedTarget("Deserialize", "deserialize", scope)
	if !ok {
		t.Fatal("ResolveDottedTarget(Deserialize) returned !ok, want ok")
	}
	if got != "serde.Deserialize.deserialize" {
		t.Errorf("got %q, want %q", got, "serde.Deserialize.deserialize")
	}

	got, ok = lang.ResolveDottedTarget("tokio", "spawn", scope)
	if !ok {
		t.Fatal("ResolveDottedTarget(tokio) returned !ok, want ok")
	}
	if got != "tokio.spawn" {
		t.Errorf("got %q, want %q", got, "tokio.spawn")
	}

	_, ok = lang.ResolveDottedTarget("unknown", "fn", scope)
	if ok {
		t.Error("ResolveDottedTarget(unknown) returned ok, want !ok")
	}
}

func TestLanguage_NormalizeImports(t *testing.T) {
	lang := rust.New()
	in := []treesitter.Import{
		{Module: "std::collections::HashMap", Alias: "HashMap"},
		{Module: "serde::Serialize", Alias: "Ser"},
		{Module: "tokio", Alias: "tokio"},
		{Module: "crate::internal::helpers", Alias: "helpers"},
	}
	out := lang.NormalizeImports(in)
	if len(out) != len(in) {
		t.Fatalf("len(out) = %d, want %d", len(out), len(in))
	}
	want := []treesitter.Import{
		{Module: "std.collections.HashMap", Alias: "HashMap"},
		{Module: "serde.Serialize", Alias: "Ser"},
		{Module: "tokio", Alias: "tokio"},
		{Module: "crate.internal.helpers", Alias: "helpers"},
	}
	for i, w := range want {
		if out[i].Module != w.Module {
			t.Errorf("[%d].Module = %q, want %q", i, out[i].Module, w.Module)
		}
		if out[i].Alias != w.Alias {
			t.Errorf("[%d].Alias = %q, want %q", i, out[i].Alias, w.Alias)
		}
	}
}
