// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package csharp provides the C# LanguageSupport implementation for the
// transitive cross-package reachability analyzer. It is imported only
// by the transitive package's LanguageFor factory.
package csharp

import (
	"path/filepath"
	"strings"
	"unsafe"

	csharpextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/csharp"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarcsharp "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/csharp"
)

// Language is the C# LanguageSupport implementation. Callers use New
// to construct a value; the zero value is not valid.
type Language struct {
	extractor treesitter.LanguageExtractor
}

// New returns a fresh C# Language.
func New() *Language {
	return &Language{extractor: csharpextractor.New()}
}

func (l *Language) Name() string                            { return "csharp" }
func (l *Language) Ecosystem() string                       { return "nuget" }
func (l *Language) FileExtensions() []string                { return []string{".cs"} }
func (l *Language) Grammar() unsafe.Pointer                 { return grammarcsharp.Language() }
func (l *Language) Extractor() treesitter.LanguageExtractor { return l.extractor }

// IsExportedSymbol reports whether a symbol is part of the C# package's
// public API. C#'s public modifier is explicit.
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

// ModulePath derives a dotted module path for a C# source file relative
// to sourceDir. Strips the conventional src/ prefix when present:
//
//	src/Newtonsoft.Json/JsonConvert.cs → "Newtonsoft.Json.Newtonsoft.Json.JsonConvert"
//	Service.cs                        → "MyLib.Service"
func (l *Language) ModulePath(file, sourceDir, packageName string) string {
	rel, err := filepath.Rel(sourceDir, file)
	if err != nil || strings.HasPrefix(rel, "..") {
		return packageName
	}
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	parts := strings.Split(rel, string(filepath.Separator))
	// Strip conventional src/ prefix.
	if len(parts) > 0 && parts[0] == "src" {
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

// NormalizeImports is the identity function for C#. Using directives
// are already dotted paths. No rewriting is required.
func (l *Language) NormalizeImports(raw []treesitter.Import) []treesitter.Import {
	return raw
}

// ResolveDottedTarget resolves a dotted call target whose prefix is an
// import alias.
func (l *Language) ResolveDottedTarget(prefix, suffix string, scope *treesitter.Scope) (treesitter.SymbolID, bool) {
	resolved, ok := scope.LookupImport(prefix)
	if !ok {
		return "", false
	}
	return treesitter.SymbolID(resolved + "." + suffix), true
}

// ResolveSelfCall rewrites "this.X" call targets to the class-qualified
// form "ClassName.X".
func (l *Language) ResolveSelfCall(to, from treesitter.SymbolID) treesitter.SymbolID {
	toStr := string(to)
	if !strings.HasPrefix(toStr, "this.") {
		return to
	}
	methodName := toStr[len("this."):]
	fromParts := strings.Split(string(from), ".")
	if len(fromParts) < 3 {
		return to
	}
	classQual := strings.Join(fromParts[:len(fromParts)-1], ".")
	return treesitter.SymbolID(classQual + "." + methodName)
}
