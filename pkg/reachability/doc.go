// Package reachability provides tree-sitter-based static analysis for
// determining whether vulnerable code paths in dependencies are reachable
// from application entry points.
package reachability

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
