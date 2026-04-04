// Package grammars is a blank-import anchor that prevents go mod tidy from
// stripping tree-sitter grammar dependencies that are loaded dynamically at
// runtime via unsafe CGo bindings.
package grammars

import (
	_ "github.com/tree-sitter/go-tree-sitter"
	_ "github.com/tree-sitter/tree-sitter-c-sharp/bindings/go"
	_ "github.com/tree-sitter/tree-sitter-java/bindings/go"
	_ "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	_ "github.com/tree-sitter/tree-sitter-php/bindings/go"
	_ "github.com/tree-sitter/tree-sitter-python/bindings/go"
	_ "github.com/tree-sitter/tree-sitter-ruby/bindings/go"
	_ "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
)
