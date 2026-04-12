// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package php_test

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/php"
)

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
