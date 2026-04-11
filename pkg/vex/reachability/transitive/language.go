// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/javascript"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/python"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/rust"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

// LanguageSupport is the per-language plug-in contract for transitive
// cross-package reachability analysis. Each supported language provides
// one implementation, constructed via LanguageFor.
//
// Implementations live in pkg/vex/reachability/transitive/languages/<lang>/
// and are registered in LanguageFor.
type LanguageSupport interface {
	// --- Identity ---

	// Name returns the canonical language name, e.g. "python", "javascript".
	Name() string

	// Ecosystem returns the fetcher ecosystem key, e.g. "pypi", "npm".
	// Used by Analyzer to select a Fetcher from its fetcher map.
	Ecosystem() string

	// FileExtensions returns the source file extensions this language
	// recognizes, e.g. [".py"] or [".js", ".mjs", ".cjs"].
	FileExtensions() []string

	// --- Tree-sitter plumbing ---

	// Grammar returns the tree-sitter grammar language pointer used by
	// treesitter.ParseFiles.
	Grammar() unsafe.Pointer

	// Extractor returns the language-specific tree-sitter extractor
	// that produces symbols, imports, and call edges.
	Extractor() treesitter.LanguageExtractor

	// --- Export enumeration ---

	// IsExportedSymbol reports whether a symbol is part of the package's
	// public API.
	IsExportedSymbol(sym *treesitter.Symbol) bool

	// ModulePath derives the dotted module path for a file given the
	// source-directory root and the package name.
	ModulePath(file, sourceDir, packageName string) string

	// SymbolKey composes a fully-qualified symbol key from a module path
	// and a symbol name.
	SymbolKey(modulePath, symbolName string) string

	// --- Scope resolution ---

	// NormalizeImports transforms the raw imports emitted by the extractor
	// into the canonical form consumed by the shared scope builder.
	NormalizeImports(raw []treesitter.Import) []treesitter.Import

	// ResolveDottedTarget attempts to resolve a dotted call target whose
	// prefix is an import alias. Returns (zero, false) when the prefix is
	// not a known alias in scope.
	ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool)

	// ResolveSelfCall rewrites a self-reference call target into a
	// class-qualified form based on the caller's symbol ID. Languages
	// where this rewrite does not apply return `to` unchanged.
	ResolveSelfCall(to, from treesitter.SymbolID) treesitter.SymbolID
}

// ExportLister is an optional capability some languages implement in addition
// to LanguageSupport. When a LanguageSupport also satisfies ExportLister, the
// generic listExportedSymbols walker in exports.go delegates the entire
// enumeration to ListExports — useful for languages whose public API
// enumeration cannot be expressed by the IsExportedSymbol + ModulePath +
// SymbolKey triple. Rust implements this to walk the `pub mod` tree from
// lib.rs and resolve `pub use` re-exports.
type ExportLister interface {
	ListExports(sourceDir, packageName string) ([]string, error)
}

// CrossFileStateExtractor is an optional capability for language extractors
// that accumulate state across files — notably Rust's trait-impl map for
// &dyn Trait dispatch. RunHop type-asserts its active extractor against this
// interface and, when supported, snapshots state after each per-file symbol
// extraction and replays the full snapshot list before call extraction. This
// ensures cross-file trait dispatch is resolved even though ExtractSymbols
// resets internal state at the start of every call.
//
// RestoreState must be idempotent and additive: calling it multiple times
// with different snapshots merges (not overwrites) the contained state.
type CrossFileStateExtractor interface {
	SnapshotState() any
	RestoreState(any)
}

// LanguageFor returns the LanguageSupport implementation for the given
// language name. Returns an error for unknown languages so callers can
// surface a clear message rather than a nil dereference.
//
// Task 1 leaves this as a stub returning errors for every input; Tasks 2
// and 3 add the Python and JavaScript cases.
func LanguageFor(name string) (LanguageSupport, error) {
	switch strings.ToLower(name) {
	case "python":
		return python.New(), nil
	case "javascript", "js":
		return javascript.New(), nil
	case "rust":
		return rust.New(), nil
	}
	return nil, fmt.Errorf("unsupported language %q", name)
}
