// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package php provides the PHP LanguageSupport implementation for the
// transitive cross-package reachability analyzer. It is imported only
// by the transitive package's LanguageFor factory.
package php

import (
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
// extractor with separator normalization (\ and :: → .).
func New() *Language {
	return &Language{extractor: &normalizedExtractor{inner: phpextractor.New()}}
}

func (l *Language) Name() string                            { return "php" }
func (l *Language) Ecosystem() string                       { return "packagist" }
func (l *Language) FileExtensions() []string                { return []string{".php"} }
func (l *Language) Grammar() unsafe.Pointer                 { return grammarphp.Language() }
func (l *Language) Extractor() treesitter.LanguageExtractor { return l.extractor }

// normalizeSep converts PHP's \ (namespace) and :: (method dispatch)
// separators to . for the shared graph machinery.
func normalizeSep(s string) string {
	s = strings.ReplaceAll(s, `\`, ".")
	s = strings.ReplaceAll(s, "::", ".")
	return s
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
