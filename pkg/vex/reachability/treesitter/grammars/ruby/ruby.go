// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package ruby provides the tree-sitter Ruby grammar.
package ruby

import (
	"unsafe"

	tree_sitter_ruby "github.com/tree-sitter/tree-sitter-ruby/bindings/go"
)

// Language returns the tree-sitter Ruby language pointer.
func Language() unsafe.Pointer {
	return tree_sitter_ruby.Language()
}
