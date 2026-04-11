// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/python"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestRunHop_Python_FindsCaller(t *testing.T) {
	src, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "testdata", "transitive", "hop", "python-caller"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := RunHop(context.Background(), HopInput{
		Language:      python.New(),
		SourceDir:     src,
		TargetSymbols: []string{"urllib3.PoolManager"},
		MaxTargets:    100,
	})
	if err != nil {
		t.Fatalf("RunHop: %v", err)
	}
	if len(res.ReachingSymbols) == 0 {
		t.Fatalf("expected at least one reaching symbol")
	}
	found := false
	for _, s := range res.ReachingSymbols {
		if s == "caller.outer_func" || s == "outer_func" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected outer_func in reaching symbols, got %v", res.ReachingSymbols)
	}
}

// TestBuildCrossFileScope_AliasOnlyImport verifies that an import with an alias
// but no named symbols (e.g. `const mod = require('qs')`) registers the alias
// in the scope so that dotted calls like `mod.parse` can be resolved.
//
// Regression: buildCrossFileScope previously skipped imports where Symbols == []
// causing the mod → qs mapping to never be registered.
func TestBuildCrossFileScope_AliasOnlyImport(t *testing.T) {
	// Simulate: const mod = require('qs')  →  Import{Module:"qs", Alias:"mod", Symbols:[]}
	imports := []treesitter.Import{
		{Module: "qs", Alias: "mod", Symbols: []string{}},
	}
	moduleSymbols := map[string][]*treesitter.Symbol{}
	baseScope := treesitter.NewScope(nil)

	augScope := buildCrossFileScope(imports, moduleSymbols, baseScope, python.New())

	// The alias "mod" must resolve to module "qs".
	modName, ok := augScope.LookupImport("mod")
	if !ok {
		t.Fatalf("buildCrossFileScope: alias %q not registered in scope; want module %q", "mod", "qs")
	}
	if modName != "qs" {
		t.Errorf("buildCrossFileScope: alias %q resolved to %q, want %q", "mod", modName, "qs")
	}
}

// TestResolveTarget_DottedAliasCall verifies that a dotted call like `mod.parse`
// is resolved via the scope alias map to `qs.parse` when `mod → qs` is registered.
//
// Regression: resolveTarget previously returned the dotted callee unchanged when
// it contained a dot, bypassing the alias scope lookup entirely.
func TestResolveTarget_DottedAliasCall(t *testing.T) {
	scope := treesitter.NewScope(nil)
	scope.DefineImport("mod", "qs", []string{})

	got := resolveTarget(treesitter.SymbolID("mod.parse"), scope, "urlencoded", python.New())

	want := treesitter.SymbolID("qs.parse")
	if got != want {
		t.Errorf("resolveTarget(%q): got %q, want %q", "mod.parse", got, want)
	}
}

func TestRunHop_Python_NoCaller(t *testing.T) {
	src, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "testdata", "transitive", "hop", "python-caller"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := RunHop(context.Background(), HopInput{
		Language:      python.New(),
		SourceDir:     src,
		TargetSymbols: []string{"somepkg.does_not_exist"},
		MaxTargets:    100,
	})
	if err != nil {
		t.Fatalf("RunHop: %v", err)
	}
	if len(res.ReachingSymbols) != 0 {
		t.Errorf("expected no reaching symbols, got %v", res.ReachingSymbols)
	}
}
