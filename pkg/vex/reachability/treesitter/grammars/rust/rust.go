// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package rust provides the tree-sitter Rust grammar.
package rust

import (
	"unsafe"

	tree_sitter_rust "github.com/tree-sitter/tree-sitter-rust/bindings/go"
)

// Language returns the tree-sitter Rust language pointer.
func Language() unsafe.Pointer {
	return tree_sitter_rust.Language()
}
