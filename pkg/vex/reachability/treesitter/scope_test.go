// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package treesitter_test

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestScope_DefineAndLookup(t *testing.T) {
	scope := treesitter.NewScope(nil)
	scope.Define("foo", "module.foo")
	resolved, ok := scope.Lookup("foo")
	if !ok {
		t.Fatal("expected to find 'foo' in scope")
	}
	if resolved != "module.foo" {
		t.Errorf("expected 'module.foo', got %q", resolved)
	}
}

func TestScope_ParentLookup(t *testing.T) {
	parent := treesitter.NewScope(nil)
	parent.Define("bar", "module.bar")
	child := treesitter.NewScope(parent)
	resolved, ok := child.Lookup("bar")
	if !ok {
		t.Fatal("expected to find 'bar' via parent scope")
	}
	if resolved != "module.bar" {
		t.Errorf("expected 'module.bar', got %q", resolved)
	}
}

func TestScope_ChildShadowsParent(t *testing.T) {
	parent := treesitter.NewScope(nil)
	parent.Define("x", "parent.x")
	child := treesitter.NewScope(parent)
	child.Define("x", "child.x")
	resolved, ok := child.Lookup("x")
	if !ok {
		t.Fatal("expected to find 'x'")
	}
	if resolved != "child.x" {
		t.Errorf("expected 'child.x', got %q", resolved)
	}
}

func TestScope_NotFound(t *testing.T) {
	scope := treesitter.NewScope(nil)
	_, ok := scope.Lookup("nonexistent")
	if ok {
		t.Error("expected lookup to fail for nonexistent name")
	}
}

func TestScope_ImportAlias(t *testing.T) {
	scope := treesitter.NewScope(nil)
	scope.DefineImport("yaml", "PyYAML", []string{})
	scope.DefineImport("np", "numpy", []string{})
	mod, ok := scope.LookupImport("yaml")
	if !ok {
		t.Fatal("expected to find import 'yaml'")
	}
	if mod != "PyYAML" {
		t.Errorf("expected 'PyYAML', got %q", mod)
	}
}
