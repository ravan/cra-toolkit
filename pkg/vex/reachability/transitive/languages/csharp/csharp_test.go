// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csharp_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/csharp"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestCSharp_Identity(t *testing.T) {
	lang := csharp.New()
	if lang.Name() != "csharp" {
		t.Errorf("Name() = %q, want %q", lang.Name(), "csharp")
	}
	if lang.Ecosystem() != "nuget" {
		t.Errorf("Ecosystem() = %q, want %q", lang.Ecosystem(), "nuget")
	}
	exts := lang.FileExtensions()
	if len(exts) != 1 || exts[0] != ".cs" {
		t.Errorf("FileExtensions() = %v, want [\".cs\"]", exts)
	}
	if lang.Grammar() == nil {
		t.Error("Grammar() returned nil")
	}
	if lang.Extractor() == nil {
		t.Error("Extractor() returned nil")
	}
}

func TestCSharp_IsExportedSymbol(t *testing.T) {
	lang := csharp.New()
	tests := []struct {
		name string
		sym  *treesitter.Symbol
		want bool
	}{
		{"nil", nil, false},
		{"public method", &treesitter.Symbol{Name: "DeserializeObject", Kind: treesitter.SymbolMethod, IsPublic: true}, true},
		{"public function", &treesitter.Symbol{Name: "Parse", Kind: treesitter.SymbolFunction, IsPublic: true}, true},
		{"public class", &treesitter.Symbol{Name: "JsonConvert", Kind: treesitter.SymbolClass, IsPublic: true}, true},
		{"non-public method", &treesitter.Symbol{Name: "Internal", Kind: treesitter.SymbolMethod, IsPublic: false}, false},
		{"module kind", &treesitter.Symbol{Name: "Config", Kind: treesitter.SymbolModule, IsPublic: true}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lang.IsExportedSymbol(tc.sym); got != tc.want {
				t.Errorf("IsExportedSymbol(%+v) = %v, want %v", tc.sym, got, tc.want)
			}
		})
	}
}

func TestCSharp_ModulePath(t *testing.T) {
	lang := csharp.New()
	tests := []struct {
		name        string
		file        string
		sourceDir   string
		packageName string
		want        string
	}{
		{
			name:        "src layout",
			file:        "/tmp/json/src/Newtonsoft.Json/JsonConvert.cs",
			sourceDir:   "/tmp/json",
			packageName: "Newtonsoft.Json",
			want:        "Newtonsoft.Json.Newtonsoft.Json.JsonConvert",
		},
		{
			name:        "root layout",
			file:        "/tmp/lib/Service.cs",
			sourceDir:   "/tmp/lib",
			packageName: "MyLib",
			want:        "MyLib.Service",
		},
		{
			name:        "file outside sourceDir",
			file:        "/tmp/other/Foo.cs",
			sourceDir:   "/tmp/pkg",
			packageName: "MyPkg",
			want:        "MyPkg",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lang.ModulePath(tc.file, tc.sourceDir, tc.packageName); got != tc.want {
				t.Errorf("ModulePath(%q, %q, %q) = %q, want %q",
					tc.file, tc.sourceDir, tc.packageName, got, tc.want)
			}
		})
	}
}

func TestCSharp_SymbolKey(t *testing.T) {
	lang := csharp.New()
	got := lang.SymbolKey("Newtonsoft.Json.Newtonsoft.Json.JsonConvert", "DeserializeObject")
	want := "Newtonsoft.Json.Newtonsoft.Json.JsonConvert.DeserializeObject"
	if got != want {
		t.Errorf("SymbolKey = %q, want %q", got, want)
	}
}

func TestCSharp_NormalizeImports(t *testing.T) {
	lang := csharp.New()
	raw := []treesitter.Import{
		{Module: "System.Text.Json", Alias: "Json"},
		{Module: "Newtonsoft.Json", Alias: "Json"},
	}
	got := lang.NormalizeImports(raw)
	if len(got) != 2 {
		t.Fatalf("NormalizeImports returned %d imports, want 2", len(got))
	}
	if got[0].Module != "System.Text.Json" {
		t.Errorf("got[0].Module = %q, want %q", got[0].Module, "System.Text.Json")
	}
}

func TestCSharp_ResolveDottedTarget(t *testing.T) {
	lang := csharp.New()
	scope := treesitter.NewScope(nil)
	scope.DefineImport("JsonConvert", "Newtonsoft.Json.JsonConvert", nil)

	t.Run("alias found", func(t *testing.T) {
		got, ok := lang.ResolveDottedTarget("JsonConvert", "DeserializeObject", scope)
		if !ok {
			t.Fatal("expected ok=true")
		}
		want := treesitter.SymbolID("Newtonsoft.Json.JsonConvert.DeserializeObject")
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("alias not found", func(t *testing.T) {
		_, ok := lang.ResolveDottedTarget("Unknown", "method", scope)
		if ok {
			t.Error("expected ok=false")
		}
	})
}

func TestCSharp_ResolveSelfCall(t *testing.T) {
	lang := csharp.New()
	tests := []struct {
		name string
		to   treesitter.SymbolID
		from treesitter.SymbolID
		want treesitter.SymbolID
	}{
		{
			name: "this call in class method",
			to:   "this.Validate",
			from: "MyApp.Controllers.UserController.Index",
			want: "MyApp.Controllers.UserController.Validate",
		},
		{
			name: "short from — unchanged",
			to:   "this.Helper",
			from: "Mod.Func",
			want: "this.Helper",
		},
		{
			name: "non-this — unchanged",
			to:   "JsonConvert.DeserializeObject",
			from: "MyApp.Service.Run",
			want: "JsonConvert.DeserializeObject",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := lang.ResolveSelfCall(tc.to, tc.from)
			if got != tc.want {
				t.Errorf("ResolveSelfCall(%q, %q) = %q, want %q", tc.to, tc.from, got, tc.want)
			}
		})
	}
}
