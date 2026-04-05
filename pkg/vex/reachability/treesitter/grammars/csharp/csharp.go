// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package csharp provides the tree-sitter C# grammar.
package csharp

import (
	"unsafe"

	tree_sitter_csharp "github.com/tree-sitter/tree-sitter-c-sharp/bindings/go"
)

// Language returns the tree-sitter C# language pointer.
func Language() unsafe.Pointer {
	return tree_sitter_csharp.Language()
}
