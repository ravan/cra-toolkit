// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package ruby_test

import (
	"reflect"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/ruby"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestRuby_Identity(t *testing.T) {
	lang := ruby.New()
	if lang.Name() != "ruby" {
		t.Errorf("Name() = %q, want %q", lang.Name(), "ruby")
	}
	if lang.Ecosystem() != "rubygems" {
		t.Errorf("Ecosystem() = %q, want %q", lang.Ecosystem(), "rubygems")
	}
	exts := lang.FileExtensions()
	if len(exts) != 1 || exts[0] != ".rb" {
		t.Errorf("FileExtensions() = %v, want [\".rb\"]", exts)
	}
	if lang.Grammar() == nil {
		t.Error("Grammar() returned nil")
	}
	if lang.Extractor() == nil {
		t.Error("Extractor() returned nil")
	}
}

func TestRuby_IsExportedSymbol(t *testing.T) {
	lang := ruby.New()
	tests := []struct {
		name string
		sym  *treesitter.Symbol
		want bool
	}{
		{"nil", nil, false},
		{"public method", &treesitter.Symbol{Name: "create", Kind: treesitter.SymbolMethod, IsPublic: true}, true},
		{"public function", &treesitter.Symbol{Name: "run", Kind: treesitter.SymbolFunction, IsPublic: true}, true},
		{"public class", &treesitter.Symbol{Name: "User", Kind: treesitter.SymbolClass, IsPublic: true}, true},
		{"public module", &treesitter.Symbol{Name: "Admin", Kind: treesitter.SymbolModule, IsPublic: true}, true},
		{"private method", &treesitter.Symbol{Name: "secret", Kind: treesitter.SymbolMethod, IsPublic: false}, false},
		{"underscore method", &treesitter.Symbol{Name: "_internal", Kind: treesitter.SymbolMethod, IsPublic: true}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lang.IsExportedSymbol(tc.sym); got != tc.want {
				t.Errorf("IsExportedSymbol(%+v) = %v, want %v", tc.sym, got, tc.want)
			}
		})
	}
}

func TestRuby_ModulePath(t *testing.T) {
	lang := ruby.New()
	tests := []struct {
		name        string
		file        string
		sourceDir   string
		packageName string
		want        string
	}{
		{
			name:        "lib entry file",
			file:        "/tmp/nokogiri-1.15.0/lib/nokogiri.rb",
			sourceDir:   "/tmp/nokogiri-1.15.0",
			packageName: "nokogiri",
			want:        "nokogiri.nokogiri",
		},
		{
			name:        "nested lib file",
			file:        "/tmp/nokogiri-1.15.0/lib/nokogiri/html/document.rb",
			sourceDir:   "/tmp/nokogiri-1.15.0",
			packageName: "nokogiri",
			want:        "nokogiri.nokogiri.html.document",
		},
		{
			name:        "spec file excluded",
			file:        "/tmp/nokogiri-1.15.0/spec/html_spec.rb",
			sourceDir:   "/tmp/nokogiri-1.15.0",
			packageName: "nokogiri",
			want:        "nokogiri.spec.html_spec",
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

func TestRuby_SymbolKey(t *testing.T) {
	lang := ruby.New()
	got := lang.SymbolKey("nokogiri.nokogiri.html", "Document")
	want := "nokogiri.nokogiri.html.Document"
	if got != want {
		t.Errorf("SymbolKey = %q, want %q", got, want)
	}
}

func TestRuby_NormalizeImports(t *testing.T) {
	lang := ruby.New()
	raw := []treesitter.Import{
		{Module: "nokogiri", Alias: "nokogiri"},
		{Module: "active_support", Alias: "active_support"},
	}
	got := lang.NormalizeImports(raw)

	// nokogiri should get CamelCase alias from gem map
	if got[0].Alias != "Nokogiri" {
		t.Errorf("nokogiri alias = %q, want %q", got[0].Alias, "Nokogiri")
	}
	// active_support should get heuristic CamelCase alias
	if got[1].Alias != "ActiveSupport" {
		t.Errorf("active_support alias = %q, want %q", got[1].Alias, "ActiveSupport")
	}
}

func TestRuby_NormalizeImports_ReplacesColons(t *testing.T) {
	lang := ruby.New()
	raw := []treesitter.Import{
		{Module: "Foo::Bar", Alias: "Foo::Bar"},
	}
	got := lang.NormalizeImports(raw)
	if got[0].Module != "Foo.Bar" {
		t.Errorf("Module = %q, want %q", got[0].Module, "Foo.Bar")
	}
	if got[0].Alias != "Foo.Bar" {
		t.Errorf("Alias = %q, want %q", got[0].Alias, "Foo.Bar")
	}
}

func TestRuby_ResolveDottedTarget(t *testing.T) {
	lang := ruby.New()
	scope := treesitter.NewScope(nil)
	scope.DefineImport("Nokogiri", "nokogiri.Nokogiri", nil)

	t.Run("alias found", func(t *testing.T) {
		got, ok := lang.ResolveDottedTarget("Nokogiri", "HTML", scope)
		if !ok {
			t.Fatal("expected ok=true")
		}
		want := treesitter.SymbolID("nokogiri.Nokogiri.HTML")
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

func TestRuby_ResolveSelfCall(t *testing.T) {
	lang := ruby.New()
	tests := []struct {
		name string
		to   treesitter.SymbolID
		from treesitter.SymbolID
		want treesitter.SymbolID
	}{
		{
			name: "self call in class method",
			to:   "self.validate",
			from: "nokogiri.User.create",
			want: "nokogiri.User.validate",
		},
		{
			name: "short from — unchanged",
			to:   "self.helper",
			from: "mod.func",
			want: "self.helper",
		},
		{
			name: "non-self — unchanged",
			to:   "Nokogiri.HTML",
			from: "app.Parser.parse",
			want: "Nokogiri.HTML",
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

// Suppress unused import warning
var _ = reflect.DeepEqual
