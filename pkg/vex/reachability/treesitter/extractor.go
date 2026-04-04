package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

// LanguageExtractor defines the interface for extracting symbols, imports,
// and call edges from a parsed AST for a specific programming language.
type LanguageExtractor interface {
	// ExtractSymbols extracts all function/method/class definitions from a file.
	ExtractSymbols(node *tree_sitter.Node, source []byte, file string) ([]*Symbol, error)

	// ExtractImports extracts all import statements from a file.
	ExtractImports(node *tree_sitter.Node, source []byte, file string) ([]Import, error)

	// ExtractCalls extracts all call edges from a file, resolving callee IDs
	// using the provided symbol scope.
	ExtractCalls(node *tree_sitter.Node, source []byte, file string, scope *Scope) ([]Edge, error)
}
