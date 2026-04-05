// Package python provides the tree-sitter Python grammar.
package python

import (
	"unsafe"

	tree_sitter_python "github.com/tree-sitter/tree-sitter-python/bindings/go"
)

// Language returns the tree-sitter Python language pointer.
func Language() unsafe.Pointer {
	return tree_sitter_python.Language()
}
