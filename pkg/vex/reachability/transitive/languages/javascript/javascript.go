// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package javascript provides the JavaScript LanguageSupport implementation
// for the transitive cross-package reachability analyzer. It is imported only
// by the transitive package's LanguageFor factory.
package javascript

import (
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarjs "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/javascript"
	jsextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/javascript"
)

// Language is the JavaScript LanguageSupport implementation. Callers use
// New to construct a value; the zero value is not valid.
type Language struct {
	extractor treesitter.LanguageExtractor
}

// New returns a fresh JavaScript Language. The extractor is constructed
// once per call; callers that run many analyses should cache the result.
func New() *Language {
	return &Language{extractor: jsextractor.New()}
}

func (l *Language) Name() string                            { return "javascript" }
func (l *Language) Ecosystem() string                      { return "npm" }
func (l *Language) FileExtensions() []string               { return []string{".js", ".mjs", ".cjs"} }
func (l *Language) Grammar() unsafe.Pointer                { return grammarjs.Language() }
func (l *Language) Extractor() treesitter.LanguageExtractor { return l.extractor }

// IsExportedSymbol reports whether a symbol is part of the JavaScript
// package's public API. Unlike Python, JS has no underscore convention for
// privacy, so any function, method, or class is considered part of the
// public surface.
func (l *Language) IsExportedSymbol(sym *treesitter.Symbol) bool {
	if sym == nil {
		return false
	}
	switch sym.Kind {
	case treesitter.SymbolFunction, treesitter.SymbolMethod, treesitter.SymbolClass:
		return true
	}
	return false
}

// ModulePath collapses every in-package file to packageName (the flat
// key scheme: callers reference npm package APIs as "pkg.symbol" rather
// than "pkg.subdir.file.symbol"). Out-of-package files return their first
// relative path component so that listExportedSymbols's shared package-
// name prefix filter rejects them, matching the pre-refactor behavior of
// listExportedJavaScript which used modulePrefix for filtering and
// packageName for key composition.
func (l *Language) ModulePath(file, sourceDir, packageName string) string {
	rel, err := filepath.Rel(sourceDir, file)
	if err != nil {
		return packageName
	}
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	parts := strings.Split(rel, string(filepath.Separator))
	for _, part := range parts {
		if part == packageName {
			return packageName
		}
	}
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// SymbolKey composes the flat key: "<modulePath>.<symbolName>". Because
// ModulePath always returns packageName, the resulting key is always
// "<packageName>.<symbolName>".
func (l *Language) SymbolKey(modulePath, symbolName string) string {
	return modulePath + "." + symbolName
}

// NormalizeImports is the identity function for JavaScript. The JavaScript
// extractor already handles alias-only imports, assignment-expression
// require(), and dotted-alias registrations at extraction time, so no
// further normalization is required.
func (l *Language) NormalizeImports(raw []treesitter.Import) []treesitter.Import {
	return raw
}

// ResolveDottedTarget resolves a dotted call target whose prefix is an
// import alias. Implementation is identical to Python's today; future
// languages with different path separators (e.g., Ruby ::, Rust ::) will
// override this.
func (l *Language) ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool) {
	resolved, ok := scope.LookupImport(prefix)
	if !ok {
		return "", false
	}
	return treesitter.SymbolID(resolved + "." + suffix), true
}

// ResolveSelfCall is the identity function for JavaScript. JS uses `this.X`
// which is already handled by the tree-sitter extractor directly; there is
// no `self.X` construct to rewrite post-hoc.
func (l *Language) ResolveSelfCall(to, from treesitter.SymbolID) treesitter.SymbolID {
	return to
}
