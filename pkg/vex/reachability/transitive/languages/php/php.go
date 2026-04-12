// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package php provides the PHP LanguageSupport implementation for the
// transitive cross-package reachability analyzer. It is imported only
// by the transitive package's LanguageFor factory.
package php

import (
	"path/filepath"
	"strings"
	"unsafe"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarphp "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/php"
	phpextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/php"
)

// Language is the PHP LanguageSupport implementation. Callers use New
// to construct a value; the zero value is not valid.
type Language struct {
	extractor treesitter.LanguageExtractor
}

// New returns a fresh PHP Language. The extractor wraps the raw PHP
// extractor with separator normalization (\ and :: → .). The extractor
// is constructed once per call; callers that run many analyses should
// cache the result.
func New() *Language {
	return &Language{extractor: &normalizedExtractor{inner: phpextractor.New()}}
}

func (l *Language) Name() string                            { return "php" }
func (l *Language) Ecosystem() string                       { return "packagist" }
func (l *Language) FileExtensions() []string                { return []string{".php"} }
func (l *Language) Grammar() unsafe.Pointer                 { return grammarphp.Language() }
func (l *Language) Extractor() treesitter.LanguageExtractor { return l.extractor }

// IsExportedSymbol reports whether a symbol is part of the PHP package's
// public API. PHP has no underscore-prefix convention; visibility is
// determined by the extractor's IsPublic flag and callable symbol kinds.
func (l *Language) IsExportedSymbol(sym *treesitter.Symbol) bool {
	if sym == nil {
		return false
	}
	if !sym.IsPublic {
		return false
	}
	switch sym.Kind {
	case treesitter.SymbolFunction, treesitter.SymbolMethod, treesitter.SymbolClass:
		return true
	}
	return false
}

// ModulePath derives a dotted module path for a PHP source file relative
// to sourceDir. The conventional src/ or lib/ prefix is stripped:
//
//	src/Psr7/Utils.php  → "guzzlehttp/psr7.Psr7.Utils"
//	lib/Logger.php      → "monolog/monolog.Logger"
//	Handler/Request.php → "vendor/pkg.Handler.Request"
func (l *Language) ModulePath(file, sourceDir, packageName string) string {
	rel, err := filepath.Rel(sourceDir, file)
	if err != nil || strings.HasPrefix(rel, "..") {
		return packageName
	}
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	parts := strings.Split(rel, string(filepath.Separator))
	// Strip conventional src/ or lib/ prefix.
	if len(parts) > 0 && (parts[0] == "src" || parts[0] == "lib") {
		parts = parts[1:]
	}
	if len(parts) == 0 {
		return packageName
	}
	mod := strings.Join(parts, ".")
	return packageName + "." + mod
}

// SymbolKey composes a dotted symbol key: "<modulePath>.<symbolName>".
func (l *Language) SymbolKey(modulePath, symbolName string) string {
	return modulePath + "." + symbolName
}

// NormalizeImports is the identity function for PHP. The normalizedExtractor
// wrapper already converts \ and :: to . in import module paths and aliases.
func (l *Language) NormalizeImports(raw []treesitter.Import) []treesitter.Import {
	return raw
}

// ResolveDottedTarget resolves a dotted call target whose prefix is an
// import alias. For example, given "Utils" and a scope where "Utils" maps
// to "GuzzleHttp.Psr7.Utils", returns "GuzzleHttp.Psr7.Utils.readLine"
// for suffix="readLine".
func (l *Language) ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool) {
	resolved, ok := scope.LookupImport(prefix)
	if !ok {
		return "", false
	}
	return treesitter.SymbolID(resolved + "." + suffix), true
}

// ResolveSelfCall rewrites "self.X" and "this.X" call targets to the
// class-qualified form "ClassName.X". The raw PHP extractor emits
// self::method and $this->method as self::method and this::method; the
// normalizedExtractor converts :: to ., producing self.X and this.X.
func (l *Language) ResolveSelfCall(to, from treesitter.SymbolID) treesitter.SymbolID {
	toStr := string(to)
	var methodName string
	switch {
	case strings.HasPrefix(toStr, "self."):
		methodName = toStr[len("self."):]
	case strings.HasPrefix(toStr, "this."):
		methodName = toStr[len("this."):]
	default:
		return to
	}
	fromParts := strings.Split(string(from), ".")
	if len(fromParts) < 3 {
		return to
	}
	classQual := strings.Join(fromParts[:len(fromParts)-1], ".")
	return treesitter.SymbolID(classQual + "." + methodName)
}

// normalizeSep converts PHP's \ (namespace) and :: (method dispatch)
// separators to . for the shared graph machinery. A leading backslash
// in a global-namespace-qualified PHP name (e.g. \Foo\Bar) becomes a
// leading dot after ReplaceAll; TrimLeft removes it.
func normalizeSep(s string) string {
	s = strings.ReplaceAll(s, `\`, ".")
	s = strings.ReplaceAll(s, "::", ".")
	return strings.TrimLeft(s, ".")
}

// normalizedExtractor wraps the raw PHP treesitter extractor and
// converts all \ and :: separators to . in its output. The raw
// extractor remains unchanged for single-language analysis.
type normalizedExtractor struct {
	inner treesitter.LanguageExtractor
}

func (e *normalizedExtractor) ExtractSymbols(file string, source []byte, tree *tree_sitter.Tree) ([]*treesitter.Symbol, error) {
	syms, err := e.inner.ExtractSymbols(file, source, tree)
	if err != nil {
		return nil, err
	}
	for _, s := range syms {
		s.ID = treesitter.SymbolID(normalizeSep(string(s.ID)))
		s.QualifiedName = normalizeSep(s.QualifiedName)
		s.Package = normalizeSep(s.Package)
	}
	return syms, nil
}

func (e *normalizedExtractor) ResolveImports(file string, source []byte, tree *tree_sitter.Tree, projectRoot string) ([]treesitter.Import, error) {
	imports, err := e.inner.ResolveImports(file, source, tree, projectRoot)
	if err != nil {
		return nil, err
	}
	for i := range imports {
		imports[i].Module = normalizeSep(imports[i].Module)
		imports[i].Alias = normalizeSep(imports[i].Alias)
	}
	return imports, nil
}

func (e *normalizedExtractor) ExtractCalls(file string, source []byte, tree *tree_sitter.Tree, scope *treesitter.Scope) ([]treesitter.Edge, error) {
	edges, err := e.inner.ExtractCalls(file, source, tree, scope)
	if err != nil {
		return nil, err
	}
	for i := range edges {
		edges[i].From = treesitter.SymbolID(normalizeSep(string(edges[i].From)))
		edges[i].To = treesitter.SymbolID(normalizeSep(string(edges[i].To)))
	}
	return edges, nil
}

func (e *normalizedExtractor) FindEntryPoints(symbols []*treesitter.Symbol, projectRoot string) []treesitter.SymbolID {
	eps := e.inner.FindEntryPoints(symbols, projectRoot)
	for i := range eps {
		eps[i] = treesitter.SymbolID(normalizeSep(string(eps[i])))
	}
	return eps
}
