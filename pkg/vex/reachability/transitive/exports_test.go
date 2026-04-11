// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"os"
	"path/filepath"
	"testing"
)

// TestListExportedJavaScript_FlatSymbolKeys verifies that listExportedJavaScript
// emits symbols as "<packageName>.<symbolName>" (flat) rather than the deep
// file-path-qualified form "<packageName>.<subdir>.<file>.<symbolName>".
//
// Callers reference the npm package API as "qs.parse", not "qs.lib.parse.parse",
// so the flat form is required for correct transitive reachability analysis.
func TestListExportedJavaScript_FlatSymbolKeys(t *testing.T) {
	tmp := t.TempDir()

	// Create a minimal npm-style package layout mirroring what NPMFetcher produces:
	//   tmp/qs/lib/parse.js  — exports a `parse` function
	//
	// NPMFetcher unpacks the tarball to tmp/ and renames the inner "package/"
	// directory to "<name>/" (i.e. tmp/qs/). It then returns SourceDir = tmp,
	// so listExportedJavaScript is called with sourceDir=tmp and packageName="qs".
	libDir := filepath.Join(tmp, "qs", "lib")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	parseJS := `function parse(str, opts) { return {}; }
module.exports = { parse };
`
	if err := os.WriteFile(filepath.Join(libDir, "parse.js"), []byte(parseJS), 0o644); err != nil {
		t.Fatal(err)
	}

	// Optional but realistic package.json at the package root.
	pkgJSON := `{"name":"qs","version":"6.11.0","main":"lib/stringify.js"}`
	if err := os.WriteFile(filepath.Join(tmp, "qs", "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	// sourceDir is the parent tmp dir (not tmp/qs/), matching real NPMFetcher output.
	syms, err := listExportedJavaScript(tmp, "qs")
	if err != nil {
		t.Fatalf("listExportedJavaScript: %v", err)
	}

	// Must contain the flat form "qs.parse".
	wantFlat := "qs.parse"
	wantDeep := "qs.lib.parse.parse"

	foundFlat := false
	foundDeep := false
	for _, s := range syms {
		if s == wantFlat {
			foundFlat = true
		}
		if s == wantDeep {
			foundDeep = true
		}
	}

	if !foundFlat {
		t.Errorf("expected symbol %q in result %v", wantFlat, syms)
	}
	if foundDeep {
		t.Errorf("unexpected deep symbol %q found in result %v; symbols should use flat packageName prefix", wantDeep, syms)
	}
}

// TestListExportedJavaScript_ModuleExportsFunctionExpression verifies that
// `var x = module.exports = function name(str, opts) {...}` emits the function
// name as a symbol. This is the pattern used by qs/lib/parse.js.
func TestListExportedJavaScript_ModuleExportsFunctionExpression(t *testing.T) {
	tmp := t.TempDir()

	libDir := filepath.Join(tmp, "qs", "lib")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// qs/lib/parse.js pattern: var parse = module.exports = function parse(str, opts) {...}
	parseJS := `var parse = module.exports = function parse(str, opts) {
    return {};
};
`
	if err := os.WriteFile(filepath.Join(libDir, "parse.js"), []byte(parseJS), 0o644); err != nil {
		t.Fatal(err)
	}

	syms, err := listExportedJavaScript(tmp, "qs")
	if err != nil {
		t.Fatalf("listExportedJavaScript: %v", err)
	}

	wantFlat := "qs.parse"
	var foundFlat bool
	for _, s := range syms {
		if s == wantFlat {
			foundFlat = true
		}
	}

	if !foundFlat {
		t.Errorf("expected symbol %q in result %v (module.exports = function parse pattern missed)", wantFlat, syms)
	}
}

// TestListExportedJavaScript_ModuleExportsObjectKeys verifies that
// `module.exports = { parse: require('./lib/parse'), stringify: ... }` emits
// the object keys as symbols. This is the pattern used by qs/index.js.
func TestListExportedJavaScript_ModuleExportsObjectKeys(t *testing.T) {
	tmp := t.TempDir()

	pkgDir := filepath.Join(tmp, "qs")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// qs/index.js pattern: module.exports = { parse: require('./lib/parse'), ... }
	indexJS := `module.exports = {
    formats: require('./lib/formats'),
    parse:   require('./lib/parse'),
    stringify: require('./lib/stringify'),
};
`
	if err := os.WriteFile(filepath.Join(pkgDir, "index.js"), []byte(indexJS), 0o644); err != nil {
		t.Fatal(err)
	}

	syms, err := listExportedJavaScript(tmp, "qs")
	if err != nil {
		t.Fatalf("listExportedJavaScript: %v", err)
	}

	wantSymbols := []string{"qs.parse", "qs.stringify", "qs.formats"}
	symSet := make(map[string]bool, len(syms))
	for _, s := range syms {
		symSet[s] = true
	}

	for _, want := range wantSymbols {
		if !symSet[want] {
			t.Errorf("expected symbol %q in result %v (module.exports object key missed)", want, syms)
		}
	}
}
