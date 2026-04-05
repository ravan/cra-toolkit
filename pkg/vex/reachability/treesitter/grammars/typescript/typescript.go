// Package typescript provides the tree-sitter TypeScript grammar.
package typescript

import (
	"unsafe"

	tree_sitter_typescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
)

// Language returns the tree-sitter TypeScript language pointer.
func Language() unsafe.Pointer {
	return tree_sitter_typescript.LanguageTypescript()
}

// LanguageTSX returns the tree-sitter TSX language pointer for .tsx files.
func LanguageTSX() unsafe.Pointer {
	return tree_sitter_typescript.LanguageTSX()
}
