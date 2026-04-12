// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package ruby provides the Ruby LanguageSupport implementation for
// the transitive cross-package reachability analyzer. It is imported only
// by the transitive package's LanguageFor factory.
package ruby

import (
	"path/filepath"
	"strings"
	"unicode"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarruby "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/ruby"
	rubyextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/ruby"
)

// gemModuleMap maps well-known RubyGem names to their primary module constant.
// Entries here take precedence over the generic toCamelCase heuristic.
var gemModuleMap = map[string]string{
	"nokogiri":      "Nokogiri",
	"rails":         "Rails",
	"activesupport": "ActiveSupport",
	"activerecord":  "ActiveRecord",
	"actionpack":    "ActionPack",
	"faraday":       "Faraday",
	"httparty":      "HTTParty",
	"rest-client":   "RestClient",
	"sidekiq":       "Sidekiq",
	"devise":        "Devise",
	"omniauth":      "OmniAuth",
	"rack":          "Rack",
	"sinatra":       "Sinatra",
	"puma":          "Puma",
	"json":          "JSON",
	"yaml":          "YAML",
	"net-http":      "Net",
	"uri":           "URI",
	"openssl":       "OpenSSL",
	"loofah":        "Loofah",
	"sanitize":      "Sanitize",
}

// Language is the Ruby LanguageSupport implementation. Callers use New
// to construct a value; the zero value is not valid.
type Language struct {
	extractor treesitter.LanguageExtractor
}

// New returns a fresh Ruby Language. The extractor is constructed once
// per call; callers that run many analyses should cache the result.
func New() *Language {
	return &Language{extractor: rubyextractor.New()}
}

func (l *Language) Name() string                            { return "ruby" }
func (l *Language) Ecosystem() string                       { return "rubygems" }
func (l *Language) FileExtensions() []string                { return []string{".rb"} }
func (l *Language) Grammar() unsafe.Pointer                 { return grammarruby.Language() }
func (l *Language) Extractor() treesitter.LanguageExtractor { return l.extractor }

// IsExportedSymbol reports whether a symbol is part of the Ruby package's
// public API. Ruby convention: underscore-prefixed names are private-by-
// convention; methods/functions/classes/modules must have IsPublic set
// (i.e. not declared private/protected in the extractor).
func (l *Language) IsExportedSymbol(sym *treesitter.Symbol) bool {
	if sym == nil {
		return false
	}
	if strings.HasPrefix(sym.Name, "_") {
		return false
	}
	if !sym.IsPublic {
		return false
	}
	switch sym.Kind {
	case treesitter.SymbolFunction, treesitter.SymbolMethod,
		treesitter.SymbolClass, treesitter.SymbolModule:
		return true
	}
	return false
}

// ModulePath derives the dotted module path for a Ruby source file relative
// to sourceDir. The "lib/" top-level directory is stripped when present,
// matching the standard RubyGems layout:
//
//	lib/nokogiri.rb                  → nokogiri.nokogiri
//	lib/nokogiri/html/document.rb    → nokogiri.nokogiri.html.document
//	spec/html_spec.rb                → nokogiri.spec.html_spec  (no lib/)
func (l *Language) ModulePath(file, sourceDir, packageName string) string {
	rel, err := filepath.Rel(sourceDir, file)
	if err != nil {
		return packageName
	}
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	parts := strings.Split(rel, string(filepath.Separator))
	// Strip the conventional "lib/" prefix when present.
	if len(parts) > 0 && parts[0] == "lib" {
		parts = parts[1:]
	}
	mod := strings.Join(parts, ".")
	return packageName + "." + mod
}

// SymbolKey composes a dotted symbol key: "<modulePath>.<symbolName>".
func (l *Language) SymbolKey(modulePath, symbolName string) string {
	return modulePath + "." + symbolName
}

// NormalizeImports rewrites raw imports to canonical form:
//   - "::" namespace separators are replaced with "."
//   - Aliases are set to the gem's primary module constant (from gemModuleMap)
//     or to the heuristic CamelCase form of the gem name.
func (l *Language) NormalizeImports(raw []treesitter.Import) []treesitter.Import {
	out := make([]treesitter.Import, len(raw))
	for i, imp := range raw {
		origModule := raw[i].Module
		imp.Module = strings.ReplaceAll(imp.Module, "::", ".")
		// Resolve alias: gem map takes priority over heuristic.
		if camel, ok := gemModuleMap[origModule]; ok {
			imp.Alias = camel
		} else {
			imp.Alias = toCamelCase(origModule)
		}
		imp.Alias = strings.ReplaceAll(imp.Alias, "::", ".")
		out[i] = imp
	}
	return out
}

// ResolveDottedTarget resolves a dotted call target whose prefix is an
// import alias. For example, given prefix="Nokogiri" and a scope where
// "Nokogiri" maps to "nokogiri.Nokogiri", it returns "nokogiri.Nokogiri.HTML"
// for suffix="HTML".
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

// toCamelCase converts a snake_case or kebab-case gem name to CamelCase.
// Examples: "active_support" → "ActiveSupport", "rest-client" → "RestClient".
func toCamelCase(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-'
	})
	var b strings.Builder
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		runes := []rune(part)
		runes[0] = unicode.ToUpper(runes[0])
		b.WriteString(string(runes))
	}
	if b.Len() == 0 {
		return s
	}
	return b.String()
}
