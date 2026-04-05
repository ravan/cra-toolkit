// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

// LanguageExtractor defines the interface for extracting symbols, imports,
// and call edges from a parsed AST for a specific programming language.
type LanguageExtractor interface {
	// ExtractSymbols extracts all function/method/class definitions from a file.
	// Returns symbols with their qualified names, kinds, and source locations.
	ExtractSymbols(file string, source []byte, tree *tree_sitter.Tree) ([]*Symbol, error)

	// ResolveImports extracts and resolves all import statements from a file.
	// projectRoot is used for resolving relative imports.
	ResolveImports(file string, source []byte, tree *tree_sitter.Tree, projectRoot string) ([]Import, error)

	// ExtractCalls extracts all call edges from a file, resolving callee IDs
	// using the provided symbol scope.
	ExtractCalls(file string, source []byte, tree *tree_sitter.Tree, scope *Scope) ([]Edge, error)

	// FindEntryPoints identifies entry point symbols from the given symbol set.
	// Entry points are functions reachable from outside the application
	// (HTTP handlers, CLI commands, task workers, main functions, etc.)
	FindEntryPoints(symbols []*Symbol, projectRoot string) []SymbolID
}
