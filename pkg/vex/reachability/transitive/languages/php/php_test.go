// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package php_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/php"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestPHP_IsExportedSymbol(t *testing.T) {
	lang := php.New()
	tests := []struct {
		name string
		sym  *treesitter.Symbol
		want bool
	}{
		{"nil", nil, false},
		{"public method", &treesitter.Symbol{Name: "index", Kind: treesitter.SymbolMethod, IsPublic: true}, true},
		{"public function", &treesitter.Symbol{Name: "helper", Kind: treesitter.SymbolFunction, IsPublic: true}, true},
		{"public class", &treesitter.Symbol{Name: "UserController", Kind: treesitter.SymbolClass, IsPublic: true}, true},
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

func TestPHP_ModulePath(t *testing.T) {
	lang := php.New()
	tests := []struct {
		name        string
		file        string
		sourceDir   string
		packageName string
		want        string
	}{
		{
			name:        "src layout PSR-4",
			file:        "/tmp/guzzlehttp-psr7/src/Psr7/Utils.php",
			sourceDir:   "/tmp/guzzlehttp-psr7",
			packageName: "guzzlehttp/psr7",
			want:        "guzzlehttp/psr7.Psr7.Utils",
		},
		{
			name:        "lib layout",
			file:        "/tmp/monolog/lib/Logger.php",
			sourceDir:   "/tmp/monolog",
			packageName: "monolog/monolog",
			want:        "monolog/monolog.Logger",
		},
		{
			name:        "no conventional prefix",
			file:        "/tmp/pkg/Handler/RequestHandler.php",
			sourceDir:   "/tmp/pkg",
			packageName: "vendor/pkg",
			want:        "vendor/pkg.Handler.RequestHandler",
		},
		{
			name:        "root file",
			file:        "/tmp/pkg/index.php",
			sourceDir:   "/tmp/pkg",
			packageName: "vendor/pkg",
			want:        "vendor/pkg.index",
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

func TestPHP_SymbolKey(t *testing.T) {
	lang := php.New()
	got := lang.SymbolKey("guzzlehttp/psr7.Psr7.Utils", "readLine")
	want := "guzzlehttp/psr7.Psr7.Utils.readLine"
	if got != want {
		t.Errorf("SymbolKey = %q, want %q", got, want)
	}
}

func TestPHP_Identity(t *testing.T) {
	lang := php.New()
	if lang.Name() != "php" {
		t.Errorf("Name() = %q, want %q", lang.Name(), "php")
	}
	if lang.Ecosystem() != "packagist" {
		t.Errorf("Ecosystem() = %q, want %q", lang.Ecosystem(), "packagist")
	}
	exts := lang.FileExtensions()
	if len(exts) != 1 || exts[0] != ".php" {
		t.Errorf("FileExtensions() = %v, want [\".php\"]", exts)
	}
	if lang.Grammar() == nil {
		t.Error("Grammar() returned nil")
	}
	if lang.Extractor() == nil {
		t.Error("Extractor() returned nil")
	}
}
