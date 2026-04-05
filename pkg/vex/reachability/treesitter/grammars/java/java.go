// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package java provides the tree-sitter Java grammar.
package java

import (
	"unsafe"

	tree_sitter_java "github.com/tree-sitter/tree-sitter-java/bindings/go"
)

// Language returns the tree-sitter Java language pointer.
func Language() unsafe.Pointer {
	return tree_sitter_java.Language()
}
