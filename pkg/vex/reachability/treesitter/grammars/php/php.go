// Package php provides the tree-sitter PHP grammar.
package php

import (
	"unsafe"

	tree_sitter_php "github.com/tree-sitter/tree-sitter-php/bindings/go"
)

// Language returns the tree-sitter PHP language pointer.
func Language() unsafe.Pointer {
	return tree_sitter_php.LanguagePHP()
}
