// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package python_test

import (
	"reflect"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/python"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestPython_Identity(t *testing.T) {
	lang := python.New()
	if lang.Name() != "python" {
		t.Errorf("Name() = %q, want %q", lang.Name(), "python")
	}
	if lang.Ecosystem() != "pypi" {
		t.Errorf("Ecosystem() = %q, want %q", lang.Ecosystem(), "pypi")
	}
	exts := lang.FileExtensions()
	if len(exts) != 1 || exts[0] != ".py" {
		t.Errorf("FileExtensions() = %v, want [\".py\"]", exts)
	}
	if lang.Grammar() == nil {
		t.Error("Grammar() returned nil")
	}
	if lang.Extractor() == nil {
		t.Error("Extractor() returned nil")
	}
}

func TestPython_IsExportedSymbol(t *testing.T) {
	lang := python.New()
	tests := []struct {
		name string
		sym  *treesitter.Symbol
		want bool
	}{
		{"public function", &treesitter.Symbol{Name: "get", Kind: treesitter.SymbolFunction}, true},
		{"public class", &treesitter.Symbol{Name: "PoolManager", Kind: treesitter.SymbolClass}, true},
		{"public method", &treesitter.Symbol{Name: "send", Kind: treesitter.SymbolMethod}, true},
		{"underscore function is private", &treesitter.Symbol{Name: "_helper", Kind: treesitter.SymbolFunction}, false},
		{"underscore class is private", &treesitter.Symbol{Name: "_Internal", Kind: treesitter.SymbolClass}, false},
		{"dunder function is private", &treesitter.Symbol{Name: "__init__", Kind: treesitter.SymbolFunction}, false},
		{"module kind rejected", &treesitter.Symbol{Name: "adapters", Kind: treesitter.SymbolModule}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lang.IsExportedSymbol(tc.sym); got != tc.want {
				t.Errorf("IsExportedSymbol(%+v) = %v, want %v", tc.sym, got, tc.want)
			}
		})
	}
}

func TestPython_ModulePath(t *testing.T) {
	lang := python.New()
	tests := []struct {
		name        string
		file        string
		sourceDir   string
		packageName string
		want        string
	}{
		{
			name:        "flat layout",
			file:        "/tmp/urllib3-1.26/urllib3/poolmanager.py",
			sourceDir:   "/tmp",
			packageName: "urllib3",
			want:        "urllib3.poolmanager",
		},
		{
			name:        "src layout",
			file:        "/tmp/urllib3-2.0.5/src/urllib3/util/retry.py",
			sourceDir:   "/tmp",
			packageName: "urllib3",
			want:        "urllib3.util.retry",
		},
		{
			name:        "package init stripped",
			file:        "/tmp/urllib3-2.0/urllib3/__init__.py",
			sourceDir:   "/tmp",
			packageName: "urllib3",
			want:        "urllib3",
		},
		{
			name:        "package main stripped",
			file:        "/tmp/urllib3-2.0/urllib3/__main__.py",
			sourceDir:   "/tmp",
			packageName: "urllib3",
			want:        "urllib3",
		},
		{
			name:        "submodule init stripped",
			file:        "/tmp/urllib3-2.0/urllib3/util/__init__.py",
			sourceDir:   "/tmp",
			packageName: "urllib3",
			want:        "urllib3.util",
		},
		{
			name:        "fallback when package name absent",
			file:        "/tmp/urllib3-2.0/tests/test_retry.py",
			sourceDir:   "/tmp",
			packageName: "urllib3",
			want:        "urllib3-2.0.tests.test_retry",
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

func TestPython_SymbolKey(t *testing.T) {
	lang := python.New()
	got := lang.SymbolKey("urllib3.poolmanager", "PoolManager")
	want := "urllib3.poolmanager.PoolManager"
	if got != want {
		t.Errorf("SymbolKey = %q, want %q", got, want)
	}
}

func TestPython_NormalizeImports_Identity(t *testing.T) {
	lang := python.New()
	raw := []treesitter.Import{
		{Module: "urllib3", Symbols: []string{"PoolManager"}, Alias: ""},
		{Module: "json", Alias: "j"},
	}
	got := lang.NormalizeImports(raw)
	if len(got) != len(raw) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(raw))
	}
	for i := range raw {
		if !reflect.DeepEqual(got[i], raw[i]) {
			t.Errorf("got[%d] = %+v, want %+v", i, got[i], raw[i])
		}
	}
}

func TestPython_ResolveDottedTarget(t *testing.T) {
	lang := python.New()
	scope := treesitter.NewScope(nil)
	scope.DefineImport("mod", "qs", []string{})

	t.Run("alias found", func(t *testing.T) {
		got, ok := lang.ResolveDottedTarget("mod", "parse", scope)
		if !ok {
			t.Fatalf("expected ok=true for known alias")
		}
		want := treesitter.SymbolID("qs.parse")
		if got != want {
			t.Errorf("ResolveDottedTarget = %q, want %q", got, want)
		}
	})

	t.Run("alias not found", func(t *testing.T) {
		_, ok := lang.ResolveDottedTarget("nope", "parse", scope)
		if ok {
			t.Errorf("expected ok=false for unknown alias")
		}
	})
}

func TestPython_ResolveSelfCall(t *testing.T) {
	lang := python.New()
	tests := []struct {
		name string
		to   treesitter.SymbolID
		from treesitter.SymbolID
		want treesitter.SymbolID
	}{
		{
			name: "self call inside class method",
			to:   "self.init_poolmanager",
			from: "adapters.HTTPAdapter.__init__",
			want: "adapters.HTTPAdapter.init_poolmanager",
		},
		{
			name: "free function — from has only two parts",
			to:   "self.helper",
			from: "api.get",
			want: "self.helper",
		},
		{
			name: "non-self prefix — unchanged",
			to:   "urllib3.PoolManager",
			from: "adapters.HTTPAdapter.send",
			want: "urllib3.PoolManager",
		},
		{
			name: "empty from — unchanged",
			to:   "self.helper",
			from: "",
			want: "self.helper",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := lang.ResolveSelfCall(tc.to, tc.from)
			if got != tc.want {
				t.Errorf("ResolveSelfCall(%q, %q) = %q, want %q",
					tc.to, tc.from, got, tc.want)
			}
		})
	}
}
