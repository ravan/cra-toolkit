// Package javascript provides the tree-sitter JavaScript grammar.
package javascript

import (
	"unsafe"

	tree_sitter_javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
)

// Language returns the tree-sitter JavaScript language pointer.
func Language() unsafe.Pointer {
	return tree_sitter_javascript.Language()
}
