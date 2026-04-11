// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package rust provides the Rust LanguageSupport implementation for the
// transitive cross-package reachability analyzer. It is imported only by
// the transitive package's LanguageFor factory.
package rust

import (
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarrust "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/rust"
	rustextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/rust"
)

// Language is the Rust LanguageSupport implementation. Callers use New to
// construct a value; the zero value is not valid.
type Language struct {
	extractor treesitter.LanguageExtractor
}

// New returns a fresh Rust Language. The extractor is constructed once per
// call; callers that run many analyses should cache the result.
func New() *Language {
	return &Language{extractor: rustextractor.New()}
}

func (l *Language) Name() string                            { return "rust" }
func (l *Language) Ecosystem() string                       { return "crates.io" }
func (l *Language) FileExtensions() []string                { return []string{".rs"} }
func (l *Language) Grammar() unsafe.Pointer                 { return grammarrust.Language() }
func (l *Language) Extractor() treesitter.LanguageExtractor { return l.extractor }

// IsExportedSymbol reports whether a symbol is part of the Rust crate's
// public API. It is a fallback used only if the ExportLister hook is not
// consulted (the primary path uses Language.ListExports, defined in
// exports.go). A symbol is considered exported when it is flagged public
// by the extractor AND its kind is a callable or type container.
func (l *Language) IsExportedSymbol(sym *treesitter.Symbol) bool {
	if sym == nil || !sym.IsPublic {
		return false
	}
	switch sym.Kind {
	case treesitter.SymbolFunction, treesitter.SymbolMethod, treesitter.SymbolClass:
		return true
	}
	return false
}

// ModulePath derives the crate-relative module path for a Rust source file.
func (l *Language) ModulePath(file, sourceDir, packageName string) string {
	rel, err := filepath.Rel(sourceDir, file)
	if err != nil {
		return packageName
	}
	parts := strings.Split(rel, string(filepath.Separator))
	srcIdx := -1
	for i, p := range parts {
		if p == "src" {
			srcIdx = i
			break
		}
	}
	if srcIdx < 0 {
		if len(parts) == 0 {
			return ""
		}
		return parts[0]
	}
	tail := parts[srcIdx+1:]
	if len(tail) == 0 {
		return packageName
	}
	last := tail[len(tail)-1]
	last = strings.TrimSuffix(last, ".rs")
	tail[len(tail)-1] = last

	switch last {
	case "lib", "main":
		if len(tail) == 1 {
			return packageName
		}
		tail = tail[:len(tail)-1]
	case "mod":
		tail = tail[:len(tail)-1]
	}
	if len(tail) == 0 {
		return packageName
	}
	return packageName + "." + strings.Join(tail, ".")
}

// SymbolKey composes a fully-qualified symbol key from a module path and a
// symbol name.
func (l *Language) SymbolKey(modulePath, symbolName string) string {
	return modulePath + "." + symbolName
}

// NormalizeImports transforms raw imports emitted by the extractor into the
// canonical form consumed by the shared scope builder. It converts Rust's
// "::" path separators to "." so all downstream logic uses a uniform format.
func (l *Language) NormalizeImports(raw []treesitter.Import) []treesitter.Import {
	out := make([]treesitter.Import, len(raw))
	for i, imp := range raw {
		imp.Module = strings.ReplaceAll(imp.Module, "::", ".")
		imp.Alias = strings.ReplaceAll(imp.Alias, "::", ".")
		out[i] = imp
	}
	return out
}

// ResolveDottedTarget attempts to resolve a dotted call target whose prefix
// is an import alias. It looks up the prefix in the scope's import table and
// appends the suffix to form a fully-qualified symbol ID.
func (l *Language) ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool) {
	resolved, ok := scope.LookupImport(prefix)
	if !ok {
		return "", false
	}
	return treesitter.SymbolID(resolved + "." + suffix), true
}

// ResolveSelfCall rewrites a self-reference call target into a class-qualified
// form based on the caller's symbol ID. Stub implementation — filled in by
// Task 12.
func (l *Language) ResolveSelfCall(to, from treesitter.SymbolID) treesitter.SymbolID {
	return to
}
