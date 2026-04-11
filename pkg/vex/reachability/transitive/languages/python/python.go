// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package python provides the Python LanguageSupport implementation for
// the transitive cross-package reachability analyzer. It is imported only
// by the transitive package's LanguageFor factory.
package python

import (
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarpython "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/python"
	pyextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/python"
)

// Language is the Python LanguageSupport implementation. Callers use New
// to construct a value; the zero value is not valid.
type Language struct {
	extractor treesitter.LanguageExtractor
}

// New returns a fresh Python Language. The extractor is constructed once
// per call; callers that run many analyses should cache the result.
func New() *Language {
	return &Language{extractor: pyextractor.New()}
}

func (l *Language) Name() string                            { return "python" }
func (l *Language) Ecosystem() string                       { return "pypi" }
func (l *Language) FileExtensions() []string                { return []string{".py"} }
func (l *Language) Grammar() unsafe.Pointer                 { return grammarpython.Language() }
func (l *Language) Extractor() treesitter.LanguageExtractor { return l.extractor }

// IsExportedSymbol reports whether a symbol is part of the Python package's
// public API. Python convention: underscore-prefixed names are private, and
// only functions, methods, and classes are part of the callable API surface.
func (l *Language) IsExportedSymbol(sym *treesitter.Symbol) bool {
	if sym == nil {
		return false
	}
	if strings.HasPrefix(sym.Name, "_") {
		return false
	}
	switch sym.Kind {
	case treesitter.SymbolFunction, treesitter.SymbolMethod, treesitter.SymbolClass:
		return true
	}
	return false
}

// ModulePath derives the dotted module path for a Python source file
// relative to sourceDir. It searches for the first path component that
// exactly matches packageName, then uses everything from that component
// onward. This correctly handles both flat and src-layout tarballs:
//
//	Flat:       "urllib3-1.26/urllib3/poolmanager.py"    → "urllib3.poolmanager"
//	Src layout: "urllib3-2.0.5/src/urllib3/util/retry.py" → "urllib3.util.retry"
//
// __init__ and __main__ suffixes are stripped. If no component matches
// packageName, the full relative path is joined (noise paths from tests/
// or docs/ fall into this branch).
func (l *Language) ModulePath(file, sourceDir, packageName string) string {
	rel, err := filepath.Rel(sourceDir, file)
	if err != nil {
		return packageName
	}
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		if part == packageName {
			mod := strings.Join(parts[i:], ".")
			mod = strings.TrimSuffix(mod, ".__init__")
			mod = strings.TrimSuffix(mod, ".__main__")
			return mod
		}
	}
	mod := strings.Join(parts, ".")
	mod = strings.TrimSuffix(mod, ".__init__")
	mod = strings.TrimSuffix(mod, ".__main__")
	return mod
}

// SymbolKey composes a dotted symbol key: "<modulePath>.<symbolName>".
// Python uses deep dotted keys so that submodule symbols are distinguishable
// from top-level package symbols.
func (l *Language) SymbolKey(modulePath, symbolName string) string {
	return modulePath + "." + symbolName
}

// NormalizeImports is the identity function for Python. The Python extractor
// produces imports in canonical form already; no rewriting is required.
func (l *Language) NormalizeImports(raw []treesitter.Import) []treesitter.Import {
	return raw
}

// ResolveDottedTarget resolves a dotted call target whose prefix is an
// import alias. For example, given "mod" and a scope where "mod" is an
// alias for "qs", this returns "qs.parse" given suffix="parse".
func (l *Language) ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool) {
	resolved, ok := scope.LookupImport(prefix)
	if !ok {
		return "", false
	}
	return treesitter.SymbolID(resolved + "." + suffix), true
}

// ResolveSelfCall rewrites "self.X" call targets to the class-qualified
// form "Module.ClassName.X" by extracting the class context from the
// caller's symbol ID. Only applies when `from` has at least three dot-
// separated components (module.class.method). Free functions are left
// unchanged.
func (l *Language) ResolveSelfCall(to, from treesitter.SymbolID) treesitter.SymbolID {
	toStr := string(to)
	if !strings.HasPrefix(toStr, "self.") {
		return to
	}
	methodName := toStr[len("self."):]
	fromParts := strings.Split(string(from), ".")
	if len(fromParts) < 3 {
		return to
	}
	classQual := strings.Join(fromParts[:len(fromParts)-1], ".")
	return treesitter.SymbolID(classQual + "." + methodName)
}
