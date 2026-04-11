// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package javascript_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/javascript"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestJavaScript_Identity(t *testing.T) {
	lang := javascript.New()
	if lang.Name() != "javascript" {
		t.Errorf("Name() = %q, want %q", lang.Name(), "javascript")
	}
	if lang.Ecosystem() != "npm" {
		t.Errorf("Ecosystem() = %q, want %q", lang.Ecosystem(), "npm")
	}
	exts := lang.FileExtensions()
	wantExts := map[string]bool{".js": true, ".mjs": true, ".cjs": true}
	if len(exts) != len(wantExts) {
		t.Errorf("FileExtensions() len = %d, want %d", len(exts), len(wantExts))
	}
	for _, e := range exts {
		if !wantExts[e] {
			t.Errorf("FileExtensions() contains unexpected %q", e)
		}
	}
	if lang.Grammar() == nil {
		t.Error("Grammar() returned nil")
	}
	if lang.Extractor() == nil {
		t.Error("Extractor() returned nil")
	}
}

func TestJavaScript_IsExportedSymbol(t *testing.T) {
	lang := javascript.New()
	tests := []struct {
		name string
		sym  *treesitter.Symbol
		want bool
	}{
		{"public function", &treesitter.Symbol{Name: "parse", Kind: treesitter.SymbolFunction}, true},
		{"public class", &treesitter.Symbol{Name: "BodyParser", Kind: treesitter.SymbolClass}, true},
		{"public method", &treesitter.Symbol{Name: "send", Kind: treesitter.SymbolMethod}, true},
		{"underscore function still public in JS", &treesitter.Symbol{Name: "_helper", Kind: treesitter.SymbolFunction}, true},
		{"module kind rejected", &treesitter.Symbol{Name: "index", Kind: treesitter.SymbolModule}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lang.IsExportedSymbol(tc.sym); got != tc.want {
				t.Errorf("IsExportedSymbol(%+v) = %v, want %v", tc.sym, got, tc.want)
			}
		})
	}
}

func TestJavaScript_ModulePath(t *testing.T) {
	lang := javascript.New()
	tests := []struct {
		name        string
		file        string
		sourceDir   string
		packageName string
		want        string
	}{
		{
			name:        "top-level file in package",
			file:        "/tmp/qs/index.js",
			sourceDir:   "/tmp",
			packageName: "qs",
			want:        "qs",
		},
		{
			name:        "nested file in package",
			file:        "/tmp/qs/lib/parse.js",
			sourceDir:   "/tmp",
			packageName: "qs",
			want:        "qs",
		},
		{
			name:        "deeply nested file in package",
			file:        "/tmp/body-parser/lib/types/urlencoded.js",
			sourceDir:   "/tmp",
			packageName: "body-parser",
			want:        "body-parser",
		},
		{
			// Regression: out-of-package files must not be lumped under
			// packageName. Return the first path component so that the
			// shared package-name prefix filter in listExportedSymbols
			// rejects them.
			name:        "neighbor directory not in package",
			file:        "/tmp/other-package/index.js",
			sourceDir:   "/tmp",
			packageName: "qs",
			want:        "other-package",
		},
		{
			name:        "sibling file at source root",
			file:        "/tmp/README.js",
			sourceDir:   "/tmp",
			packageName: "qs",
			want:        "README",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := lang.ModulePath(tc.file, tc.sourceDir, tc.packageName)
			if got != tc.want {
				t.Errorf("ModulePath(%q, %q, %q) = %q, want %q",
					tc.file, tc.sourceDir, tc.packageName, got, tc.want)
			}
		})
	}
}

func TestJavaScript_SymbolKey(t *testing.T) {
	lang := javascript.New()
	got := lang.SymbolKey("body-parser", "urlencoded")
	want := "body-parser.urlencoded"
	if got != want {
		t.Errorf("SymbolKey = %q, want %q", got, want)
	}
}

func TestJavaScript_NormalizeImports_Identity(t *testing.T) {
	lang := javascript.New()
	raw := []treesitter.Import{
		{Module: "qs", Alias: "mod", Symbols: []string{}},
		{Module: "express", Symbols: []string{"Router"}},
	}
	got := lang.NormalizeImports(raw)
	if len(got) != len(raw) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(raw))
	}
	for i := range raw {
		if got[i].Module != raw[i].Module || got[i].Alias != raw[i].Alias {
			t.Errorf("got[%d] = %+v, want %+v", i, got[i], raw[i])
		}
	}
}

func TestJavaScript_ResolveDottedTarget(t *testing.T) {
	lang := javascript.New()
	scope := treesitter.NewScope(nil)
	scope.DefineImport("mod", "qs", []string{})

	t.Run("alias found", func(t *testing.T) {
		got, ok := lang.ResolveDottedTarget("mod", "parse", scope)
		if !ok {
			t.Fatalf("expected ok=true for known alias")
		}
		if got != treesitter.SymbolID("qs.parse") {
			t.Errorf("ResolveDottedTarget = %q, want %q", got, "qs.parse")
		}
	})

	t.Run("alias not found", func(t *testing.T) {
		_, ok := lang.ResolveDottedTarget("nope", "parse", scope)
		if ok {
			t.Errorf("expected ok=false for unknown alias")
		}
	})
}

func TestJavaScript_ResolveSelfCall_IsIdentity(t *testing.T) {
	lang := javascript.New()
	tests := []struct {
		to   treesitter.SymbolID
		from treesitter.SymbolID
	}{
		{"self.helper", "adapters.HTTPAdapter.__init__"},
		{"this.render", "component.Foo.render"},
		{"urllib3.PoolManager", "app.main"},
	}
	for _, tc := range tests {
		t.Run(string(tc.to), func(t *testing.T) {
			got := lang.ResolveSelfCall(tc.to, tc.from)
			if got != tc.to {
				t.Errorf("ResolveSelfCall(%q, %q) = %q, want identity %q",
					tc.to, tc.from, got, tc.to)
			}
		})
	}
}
