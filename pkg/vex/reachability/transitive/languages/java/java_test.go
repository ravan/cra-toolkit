// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package java_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/java"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestJava_Identity(t *testing.T) {
	lang := java.New()
	if lang.Name() != "java" {
		t.Errorf("Name() = %q, want %q", lang.Name(), "java")
	}
	if lang.Ecosystem() != "maven" {
		t.Errorf("Ecosystem() = %q, want %q", lang.Ecosystem(), "maven")
	}
	exts := lang.FileExtensions()
	if len(exts) != 1 || exts[0] != ".java" {
		t.Errorf("FileExtensions() = %v, want [\".java\"]", exts)
	}
	if lang.Grammar() == nil {
		t.Error("Grammar() returned nil")
	}
	if lang.Extractor() == nil {
		t.Error("Extractor() returned nil")
	}
}

func TestJava_IsExportedSymbol(t *testing.T) {
	lang := java.New()
	tests := []struct {
		name string
		sym  *treesitter.Symbol
		want bool
	}{
		{"nil", nil, false},
		{"public method", &treesitter.Symbol{Name: "fromJson", Kind: treesitter.SymbolMethod, IsPublic: true}, true},
		{"public function", &treesitter.Symbol{Name: "parse", Kind: treesitter.SymbolFunction, IsPublic: true}, true},
		{"public class", &treesitter.Symbol{Name: "Gson", Kind: treesitter.SymbolClass, IsPublic: true}, true},
		{"non-public method", &treesitter.Symbol{Name: "internal", Kind: treesitter.SymbolMethod, IsPublic: false}, false},
		{"module kind", &treesitter.Symbol{Name: "config", Kind: treesitter.SymbolModule, IsPublic: true}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lang.IsExportedSymbol(tc.sym); got != tc.want {
				t.Errorf("IsExportedSymbol(%+v) = %v, want %v", tc.sym, got, tc.want)
			}
		})
	}
}

func TestJava_ModulePath(t *testing.T) {
	lang := java.New()
	tests := []struct {
		name        string
		file        string
		sourceDir   string
		packageName string
		want        string
	}{
		{
			name:        "standard Maven src/main/java layout",
			file:        "/tmp/gson/src/main/java/com/google/gson/Gson.java",
			sourceDir:   "/tmp/gson",
			packageName: "com.google.code.gson:gson",
			want:        "com.google.code.gson:gson.com.google.gson.Gson",
		},
		{
			name:        "flat source layout",
			file:        "/tmp/lib/com/example/Service.java",
			sourceDir:   "/tmp/lib",
			packageName: "com.example:lib",
			want:        "com.example:lib.com.example.Service",
		},
		{
			name:        "file outside sourceDir",
			file:        "/tmp/other/Foo.java",
			sourceDir:   "/tmp/pkg",
			packageName: "com.example:pkg",
			want:        "com.example:pkg",
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

func TestJava_SymbolKey(t *testing.T) {
	lang := java.New()
	got := lang.SymbolKey("com.google.code.gson:gson.com.google.gson.Gson", "fromJson")
	want := "com.google.code.gson:gson.com.google.gson.Gson.fromJson"
	if got != want {
		t.Errorf("SymbolKey = %q, want %q", got, want)
	}
}

func TestJava_NormalizeImports(t *testing.T) {
	lang := java.New()
	raw := []treesitter.Import{
		{Module: "org.apache.logging.log4j.Logger", Alias: "Logger"},
		{Module: "com.google.gson.Gson", Alias: "Gson"},
	}
	got := lang.NormalizeImports(raw)
	if len(got) != 2 {
		t.Fatalf("NormalizeImports returned %d imports, want 2", len(got))
	}
	if got[0].Module != "org.apache.logging.log4j.Logger" {
		t.Errorf("got[0].Module = %q, want %q", got[0].Module, "org.apache.logging.log4j.Logger")
	}
	if got[1].Alias != "Gson" {
		t.Errorf("got[1].Alias = %q, want %q", got[1].Alias, "Gson")
	}
}

func TestJava_ResolveDottedTarget(t *testing.T) {
	lang := java.New()
	scope := treesitter.NewScope(nil)
	scope.DefineImport("Logger", "org.apache.logging.log4j.Logger", nil)

	t.Run("alias found", func(t *testing.T) {
		got, ok := lang.ResolveDottedTarget("Logger", "getLogger", scope)
		if !ok {
			t.Fatal("expected ok=true")
		}
		want := treesitter.SymbolID("org.apache.logging.log4j.Logger.getLogger")
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

func TestJava_ResolveSelfCall(t *testing.T) {
	lang := java.New()
	tests := []struct {
		name string
		to   treesitter.SymbolID
		from treesitter.SymbolID
		want treesitter.SymbolID
	}{
		{
			name: "this call in class method",
			to:   "this.validate",
			from: "com.example.Service.handle",
			want: "com.example.Service.validate",
		},
		{
			name: "short from — unchanged",
			to:   "this.helper",
			from: "mod.func",
			want: "this.helper",
		},
		{
			name: "non-this — unchanged",
			to:   "Logger.getLogger",
			from: "com.example.App.main",
			want: "Logger.getLogger",
		},
		{
			name: "minimum valid from (3 dot-parts)",
			to:   "this.run",
			from: "com.example.App.handle",
			want: "com.example.App.run",
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
