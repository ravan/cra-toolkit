// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust_test

import (
	"testing"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	rustgrammar "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/rust"
	rustextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/rust"
)

// parseRustSource parses Rust source bytes and returns the tree and the source slice.
func parseRustSource(t *testing.T, source string) (*tree_sitter.Tree, []byte) { //nolint:gocritic // two return values are self-documenting in context
	t.Helper()
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(rustgrammar.Language())); err != nil {
		t.Fatalf("set language: %v", err)
	}
	src := []byte(source)
	tree := parser.Parse(src, nil)
	if tree == nil {
		t.Fatal("tree-sitter returned nil tree")
	}
	return tree, src
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractSymbols
// ─────────────────────────────────────────────────────────────────────────────

// TestExtractSymbols_Functions verifies that top-level functions are extracted.
//
//nolint:gocognit,gocyclo // test validates multiple function symbol assertions
func TestExtractSymbols_Functions(t *testing.T) {
	source := `fn main() {
    println!("hello");
}

fn helper(x: i32) -> i32 {
    x + 1
}
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	symbols, err := ext.ExtractSymbols("src/main.rs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	if len(symbols) < 2 {
		t.Fatalf("expected at least 2 symbols, got %d", len(symbols))
	}

	var foundMain, foundHelper bool
	for _, s := range symbols {
		switch s.Name {
		case "main":
			foundMain = true
			if s.Kind != treesitter.SymbolFunction {
				t.Errorf("expected main to be SymbolFunction, got %s", s.Kind)
			}
			if s.Language != "rust" {
				t.Errorf("expected language 'rust', got %q", s.Language)
			}
		case "helper":
			foundHelper = true
			if s.Kind != treesitter.SymbolFunction {
				t.Errorf("expected helper to be SymbolFunction, got %s", s.Kind)
			}
		}
	}

	if !foundMain {
		t.Error("expected to find function 'main'")
	}
	if !foundHelper {
		t.Error("expected to find function 'helper'")
	}
}

// TestExtractSymbols_StructAndEnum verifies that struct and enum definitions are extracted.
func TestExtractSymbols_StructAndEnum(t *testing.T) {
	source := `struct Server {
    port: u16,
}

enum Status {
    Ok,
    Error(String),
}
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	symbols, err := ext.ExtractSymbols("src/server.rs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	var foundStruct, foundEnum bool
	for _, s := range symbols {
		switch s.Name {
		case "Server":
			foundStruct = true
			if s.Kind != treesitter.SymbolClass {
				t.Errorf("expected Server to be SymbolClass, got %s", s.Kind)
			}
		case "Status":
			foundEnum = true
			if s.Kind != treesitter.SymbolClass {
				t.Errorf("expected Status to be SymbolClass, got %s", s.Kind)
			}
		}
	}

	if !foundStruct {
		t.Error("expected to find struct 'Server'")
	}
	if !foundEnum {
		t.Error("expected to find enum 'Status'")
	}
}

// TestExtractSymbols_Trait verifies that trait definitions and their method signatures are extracted.
//
//nolint:gocognit,gocyclo // test validates multiple symbol kinds from trait definition
func TestExtractSymbols_Trait(t *testing.T) {
	source := `trait Handler {
    fn handle(&self, input: &str) -> String;
    fn process(&self);
}
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	symbols, err := ext.ExtractSymbols("src/handler.rs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	var foundTrait, foundHandle, foundProcess bool
	for _, s := range symbols {
		switch s.Name {
		case "Handler":
			foundTrait = true
			if s.Kind != treesitter.SymbolClass {
				t.Errorf("expected Handler trait to be SymbolClass, got %s", s.Kind)
			}
		case "handle":
			foundHandle = true
			if s.Kind != treesitter.SymbolMethod {
				t.Errorf("expected handle to be SymbolMethod, got %s", s.Kind)
			}
		case "process":
			foundProcess = true
			if s.Kind != treesitter.SymbolMethod {
				t.Errorf("expected process to be SymbolMethod, got %s", s.Kind)
			}
		}
	}

	if !foundTrait {
		t.Error("expected to find trait 'Handler'")
	}
	if !foundHandle {
		t.Error("expected to find trait method 'handle'")
	}
	if !foundProcess {
		t.Error("expected to find trait method 'process'")
	}
}

// TestExtractSymbols_ImplBlock verifies that methods in impl blocks are extracted as SymbolMethod.
//
//nolint:gocognit // test validates multiple impl method assertions
func TestExtractSymbols_ImplBlock(t *testing.T) {
	source := `struct Server {
    port: u16,
}

impl Server {
    fn new(port: u16) -> Self {
        Server { port }
    }

    pub fn start(&self) {
        println!("Starting");
    }
}
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	symbols, err := ext.ExtractSymbols("src/server.rs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	var foundNew, foundStart bool
	for _, s := range symbols {
		switch s.Name {
		case "new":
			foundNew = true
			if s.Kind != treesitter.SymbolMethod {
				t.Errorf("expected new to be SymbolMethod, got %s", s.Kind)
			}
			if s.QualifiedName != "server.Server.new" {
				t.Errorf("expected qualified name 'server.Server.new', got %q", s.QualifiedName)
			}
		case "start":
			foundStart = true
			if s.Kind != treesitter.SymbolMethod {
				t.Errorf("expected start to be SymbolMethod, got %s", s.Kind)
			}
		}
	}

	if !foundNew {
		t.Error("expected to find method 'new'")
	}
	if !foundStart {
		t.Error("expected to find method 'start'")
	}
}

// TestExtractSymbols_TraitImpl verifies that impl Trait for Type builds the trait-impl map.
//
//nolint:gocognit,gocyclo // test validates trait-impl map population with multiple assertions
func TestExtractSymbols_TraitImpl(t *testing.T) {
	source := `trait Handler {
    fn handle(&self, input: &str) -> String;
}

struct LogHandler;
struct FileHandler;

impl Handler for LogHandler {
    fn handle(&self, input: &str) -> String {
        input.to_string()
    }
}

impl Handler for FileHandler {
    fn handle(&self, input: &str) -> String {
        input.to_string()
    }
}
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	symbols, err := ext.ExtractSymbols("src/handlers.rs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	// Should have trait, two structs, trait method signature, and two impl methods
	if len(symbols) < 5 {
		t.Errorf("expected at least 5 symbols, got %d", len(symbols))
		for _, s := range symbols {
			t.Logf("  %s (%s) %q", s.Name, s.Kind, s.QualifiedName)
		}
	}

	// Verify impl methods are extracted with correct qualified names
	var foundLogHandle, foundFileHandle bool
	for _, s := range symbols {
		if s.Name == "handle" && s.Kind == treesitter.SymbolMethod {
			switch s.QualifiedName {
			case "handlers.LogHandler.handle":
				foundLogHandle = true
			case "handlers.FileHandler.handle":
				foundFileHandle = true
			}
		}
	}

	if !foundLogHandle {
		t.Error("expected to find method 'handlers.LogHandler.handle'")
	}
	if !foundFileHandle {
		t.Error("expected to find method 'handlers.FileHandler.handle'")
	}
}

// TestExtractSymbols_ModuleFromFile verifies module name derivation from file paths.
func TestExtractSymbols_ModuleFromFile(t *testing.T) {
	source := `fn helper() {}`

	tests := []struct {
		file    string
		wantPkg string
	}{
		{"src/main.rs", "src"},
		{"src/lib.rs", "src"},
		{"src/handler/mod.rs", "handler"},
		{"src/server.rs", "server"},
		{"src/utils/helpers.rs", "helpers"},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			tree, src := parseRustSource(t, source)
			defer tree.Close()

			ext := rustextractor.New()
			symbols, err := ext.ExtractSymbols(tt.file, src, tree)
			if err != nil {
				t.Fatalf("ExtractSymbols failed: %v", err)
			}

			if len(symbols) == 0 {
				t.Fatal("expected at least 1 symbol")
			}

			if symbols[0].Package != tt.wantPkg {
				t.Errorf("expected package %q, got %q", tt.wantPkg, symbols[0].Package)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolveImports
// ─────────────────────────────────────────────────────────────────────────────

// TestResolveImports_Simple verifies simple use declarations.
//
//nolint:dupl // similar structure to other import tests is intentional — different use forms
func TestResolveImports_Simple(t *testing.T) {
	source := `use std::collections::HashMap;
use std::io::Read;
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	imports, err := ext.ResolveImports("src/main.rs", src, tree, "/project")
	if err != nil {
		t.Fatalf("ResolveImports failed: %v", err)
	}

	if len(imports) != 2 {
		t.Fatalf("expected 2 imports, got %d", len(imports))
	}

	var foundHashMap, foundRead bool
	for _, imp := range imports {
		switch imp.Alias {
		case "HashMap":
			foundHashMap = true
			if imp.Module != "std::collections::HashMap" {
				t.Errorf("expected module 'std::collections::HashMap', got %q", imp.Module)
			}
		case "Read":
			foundRead = true
			if imp.Module != "std::io::Read" {
				t.Errorf("expected module 'std::io::Read', got %q", imp.Module)
			}
		}
	}

	if !foundHashMap {
		t.Error("expected to find import 'HashMap'")
	}
	if !foundRead {
		t.Error("expected to find import 'Read'")
	}
}

// TestResolveImports_Grouped verifies grouped use declarations like use hyper::{Body, Request}.
func TestResolveImports_Grouped(t *testing.T) {
	source := `use hyper::{Body, Request, Response};
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	imports, err := ext.ResolveImports("src/main.rs", src, tree, "/project")
	if err != nil {
		t.Fatalf("ResolveImports failed: %v", err)
	}

	if len(imports) != 3 {
		t.Fatalf("expected 3 imports, got %d", len(imports))
		for _, imp := range imports {
			t.Logf("  %s (alias: %q)", imp.Module, imp.Alias)
		}
	}

	expected := map[string]string{
		"Body":     "hyper::Body",
		"Request":  "hyper::Request",
		"Response": "hyper::Response",
	}

	for _, imp := range imports {
		wantModule, ok := expected[imp.Alias]
		if !ok {
			t.Errorf("unexpected import alias %q", imp.Alias)
			continue
		}
		if imp.Module != wantModule {
			t.Errorf("import %q: expected module %q, got %q", imp.Alias, wantModule, imp.Module)
		}
	}
}

// TestResolveImports_Aliased verifies use ... as ... declarations.
//
//nolint:dupl // similar structure to other import tests is intentional — different use forms
func TestResolveImports_Aliased(t *testing.T) {
	source := `use serde::Serialize as Ser;
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	imports, err := ext.ResolveImports("src/main.rs", src, tree, "/project")
	if err != nil {
		t.Fatalf("ResolveImports failed: %v", err)
	}

	if len(imports) != 1 {
		t.Fatalf("expected 1 import, got %d", len(imports))
	}

	if imports[0].Module != "serde::Serialize" {
		t.Errorf("expected module 'serde::Serialize', got %q", imports[0].Module)
	}
	if imports[0].Alias != "Ser" {
		t.Errorf("expected alias 'Ser', got %q", imports[0].Alias)
	}
}

// TestResolveImports_ExternCrate verifies extern crate declarations.
//
//nolint:dupl // similar structure to other import tests is intentional — different use forms
func TestResolveImports_ExternCrate(t *testing.T) {
	source := `extern crate serde;
extern crate tokio;
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	imports, err := ext.ResolveImports("src/main.rs", src, tree, "/project")
	if err != nil {
		t.Fatalf("ResolveImports failed: %v", err)
	}

	if len(imports) != 2 {
		t.Fatalf("expected 2 imports, got %d", len(imports))
	}

	var foundSerde, foundTokio bool
	for _, imp := range imports {
		switch imp.Alias {
		case "serde":
			foundSerde = true
			if imp.Module != "serde" {
				t.Errorf("expected module 'serde', got %q", imp.Module)
			}
		case "tokio":
			foundTokio = true
			if imp.Module != "tokio" {
				t.Errorf("expected module 'tokio', got %q", imp.Module)
			}
		}
	}

	if !foundSerde {
		t.Error("expected to find extern crate 'serde'")
	}
	if !foundTokio {
		t.Error("expected to find extern crate 'tokio'")
	}
}

// TestResolveImports_Wildcard verifies glob imports like use std::io::*.
//
//nolint:dupl // similar structure to other import tests is intentional — different use forms
func TestResolveImports_Wildcard(t *testing.T) {
	source := `use std::io::*;
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	imports, err := ext.ResolveImports("src/main.rs", src, tree, "/project")
	if err != nil {
		t.Fatalf("ResolveImports failed: %v", err)
	}

	if len(imports) != 1 {
		t.Fatalf("expected 1 import, got %d", len(imports))
	}

	if imports[0].Module != "std::io" {
		t.Errorf("expected module 'std::io', got %q", imports[0].Module)
	}
	if imports[0].Alias != "std::io" {
		t.Errorf("expected alias 'std::io' for wildcard import, got %q", imports[0].Alias)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractCalls
// ─────────────────────────────────────────────────────────────────────────────

// TestExtractCalls_DirectFunction verifies direct function call extraction.
//
//nolint:dupl,gocognit // similar structure to other call tests is intentional — different call forms
func TestExtractCalls_DirectFunction(t *testing.T) {
	source := `fn main() {
    helper(42);
}

fn helper(x: i32) -> i32 {
    x + 1
}
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	if _, err := ext.ExtractSymbols("src/main.rs", src, tree); err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("src/main.rs", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	var foundHelper bool
	for _, e := range edges {
		if e.To == "helper" || e.To == "src.helper" {
			foundHelper = true
			if e.Kind != treesitter.EdgeDirect {
				t.Errorf("expected EdgeDirect, got %s", e.Kind)
			}
			if e.Confidence != 1.0 {
				t.Errorf("expected confidence 1.0, got %.1f", e.Confidence)
			}
		}
	}

	if !foundHelper {
		t.Error("expected to find direct call to 'helper'")
		for _, e := range edges {
			t.Logf("  %s -> %s (%s, conf=%.1f)", e.From, e.To, e.Kind, e.Confidence)
		}
	}
}

// TestExtractCalls_StaticMethod verifies static method call extraction (Type::method).
//
//nolint:dupl,gocognit // similar structure to other call tests is intentional — different call forms
func TestExtractCalls_StaticMethod(t *testing.T) {
	source := `struct Server {
    port: u16,
}

impl Server {
    fn new(port: u16) -> Self {
        Server { port }
    }
}

fn main() {
    let s = Server::new(8080);
}
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	if _, err := ext.ExtractSymbols("src/main.rs", src, tree); err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("src/main.rs", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	var foundStaticCall bool
	for _, e := range edges {
		// Server::new should be normalized to Server.new
		if e.To == "Server.new" || e.To == "src.Server.new" {
			foundStaticCall = true
			if e.Kind != treesitter.EdgeDirect {
				t.Errorf("expected EdgeDirect, got %s", e.Kind)
			}
			if e.Confidence != 1.0 {
				t.Errorf("expected confidence 1.0, got %.1f", e.Confidence)
			}
		}
	}

	if !foundStaticCall {
		t.Error("expected to find static call to 'Server.new'")
		for _, e := range edges {
			t.Logf("  %s -> %s (%s, conf=%.1f)", e.From, e.To, e.Kind, e.Confidence)
		}
	}
}

// TestExtractCalls_MethodCall verifies regular method calls (obj.method()).
//
//nolint:gocognit // test validates method call edge properties
func TestExtractCalls_MethodCall(t *testing.T) {
	source := `struct Server {
    port: u16,
}

impl Server {
    pub fn start(&self) {}
}

fn main() {
    let s = Server { port: 8080 };
    s.start();
}
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	if _, err := ext.ExtractSymbols("src/main.rs", src, tree); err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("src/main.rs", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	var foundMethodCall bool
	for _, e := range edges {
		if e.To == "s.start" {
			foundMethodCall = true
			if e.Kind != treesitter.EdgeDirect {
				t.Errorf("expected EdgeDirect, got %s", e.Kind)
			}
			if e.Confidence != 0.8 {
				t.Errorf("expected confidence 0.8, got %.1f", e.Confidence)
			}
		}
	}

	if !foundMethodCall {
		t.Error("expected to find method call to 's.start'")
		for _, e := range edges {
			t.Logf("  %s -> %s (%s, conf=%.1f)", e.From, e.To, e.Kind, e.Confidence)
		}
	}
}

// TestExtractCalls_TraitDispatch verifies that calls on &dyn Trait parameters produce EdgeDispatch edges.
//
//nolint:gocognit // test validates trait dispatch with multiple implementors
func TestExtractCalls_TraitDispatch(t *testing.T) {
	source := `trait Handler {
    fn handle(&self, input: &str) -> String;
}

struct LogHandler;
struct FileHandler;

impl Handler for LogHandler {
    fn handle(&self, input: &str) -> String {
        input.to_string()
    }
}

impl Handler for FileHandler {
    fn handle(&self, input: &str) -> String {
        input.to_string()
    }
}

fn process(handler: &dyn Handler) {
    handler.handle("test");
}
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	if _, err := ext.ExtractSymbols("src/handlers.rs", src, tree); err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("src/handlers.rs", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	// Should emit EdgeDispatch to both LogHandler.handle and FileHandler.handle
	dispatchCount := 0
	for _, e := range edges {
		if e.Kind == treesitter.EdgeDispatch && e.Confidence == 0.5 {
			dispatchCount++
			t.Logf("dispatch edge: %s -> %s (conf=%.1f)", e.From, e.To, e.Confidence)
		}
	}

	if dispatchCount < 2 {
		t.Errorf("expected at least 2 dispatch edges, got %d", dispatchCount)
		for _, e := range edges {
			t.Logf("  %s -> %s (%s, conf=%.1f)", e.From, e.To, e.Kind, e.Confidence)
		}
	}
}

// TestTraitImplSnapshot verifies SnapshotTraitImpls/RestoreTraitImpls for cross-file analysis.
//
//nolint:gocognit // test validates cross-file trait dispatch
func TestTraitImplSnapshot(t *testing.T) {
	sourceA := `trait Handler {
    fn handle(&self, input: &str) -> String;
}
`
	sourceB := `struct LogHandler;

impl Handler for LogHandler {
    fn handle(&self, input: &str) -> String {
        input.to_string()
    }
}

fn process(handler: &dyn Handler) {
    handler.handle("test");
}
`
	treeA, srcA := parseRustSource(t, sourceA)
	defer treeA.Close()
	treeB, srcB := parseRustSource(t, sourceB)
	defer treeB.Close()

	ext := rustextractor.New()

	// Phase 1: extract symbols from both files
	if _, err := ext.ExtractSymbols("src/trait_def.rs", srcA, treeA); err != nil {
		t.Fatalf("ExtractSymbols file_a: %v", err)
	}
	if _, err := ext.ExtractSymbols("src/impl.rs", srcB, treeB); err != nil {
		t.Fatalf("ExtractSymbols file_b: %v", err)
	}

	// Snapshot the accumulated cross-file trait-impl state
	snap := ext.SnapshotTraitImpls()

	// Phase 2: re-extract symbols from file_b (resets state), then restore snapshot
	if _, err := ext.ExtractSymbols("src/impl.rs", srcB, treeB); err != nil {
		t.Fatalf("re-ExtractSymbols file_b: %v", err)
	}
	ext.RestoreTraitImpls(snap)

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("src/impl.rs", srcB, treeB, scope)
	if err != nil {
		t.Fatalf("ExtractCalls: %v", err)
	}

	var foundDispatch bool
	for _, e := range edges {
		if e.Kind == treesitter.EdgeDispatch && e.Confidence == 0.5 {
			foundDispatch = true
			t.Logf("cross-file dispatch: %s -> %s", e.From, e.To)
		}
	}

	if !foundDispatch {
		t.Error("expected cross-file CHA to produce at least one EdgeDispatch")
		for _, e := range edges {
			t.Logf("  %s -> %s (%s, conf=%.1f)", e.From, e.To, e.Kind, e.Confidence)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// FindEntryPoints
// ─────────────────────────────────────────────────────────────────────────────

// TestFindEntryPoints_Main verifies that fn main() is detected as an entry point.
func TestFindEntryPoints_Main(t *testing.T) {
	source := `fn main() {
    println!("hello");
}

fn helper() {}
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	symbols, err := ext.ExtractSymbols("src/main.rs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")

	var foundMain bool
	for _, ep := range eps {
		if ep == "src.main" {
			foundMain = true
		}
	}

	if !foundMain {
		t.Error("expected fn main() to be an entry point")
		t.Logf("entry points: %v", eps)
	}
}

// TestFindEntryPoints_MainRsFunctions verifies that all functions in main.rs are entry points.
func TestFindEntryPoints_MainRsFunctions(t *testing.T) {
	source := `fn run() {
    println!("running");
}

fn setup() {
    println!("setup");
}
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	symbols, err := ext.ExtractSymbols("src/main.rs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")

	if len(eps) < 2 {
		t.Errorf("expected at least 2 entry points for functions in main.rs, got %d", len(eps))
		t.Logf("entry points: %v", eps)
	}
}

// TestFindEntryPoints_TestFunctions verifies that test_ prefixed functions are entry points.
func TestFindEntryPoints_TestFunctions(t *testing.T) {
	source := `fn test_something() {
    assert!(true);
}

fn test_another() {
    assert!(true);
}

fn helper() {}
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	symbols, err := ext.ExtractSymbols("src/lib.rs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")

	testEPs := 0
	for _, ep := range eps {
		t.Logf("entry point: %s", ep)
		if string(ep) == "src.test_something" || string(ep) == "src.test_another" {
			testEPs++
		}
	}

	if testEPs < 2 {
		t.Errorf("expected at least 2 test entry points, got %d", testEPs)
	}
}

func TestExtractSymbols_PublicVisibility(t *testing.T) {
	source := `pub fn public_fn() {}
fn private_fn() {}
pub(crate) fn crate_fn() {}
pub(super) fn super_fn() {}

pub struct PublicStruct;
struct PrivateStruct;

pub trait PublicTrait {
    fn required(&self);
}

pub struct Server;

impl Server {
    pub fn serve(&self) {}
    fn internal(&self) {}
}

impl PublicTrait for Server {
    fn required(&self) {}
}
`
	tree, src := parseRustSource(t, source)
	defer tree.Close()

	ext := rustextractor.New()
	symbols, err := ext.ExtractSymbols("src/lib.rs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}

	got := make(map[string]bool, len(symbols))
	for _, s := range symbols {
		got[s.Name] = s.IsPublic
	}

	expected := map[string]bool{
		"public_fn":     true,
		"private_fn":    false,
		"crate_fn":      false,
		"super_fn":      false,
		"PublicStruct":  true,
		"PrivateStruct": false,
		"PublicTrait":   true,
		"Server":        true,
		"serve":         true,
		"internal":      false,
		// Trait-impl method: inherits visibility from the impl block unconditionally.
		"required": true,
	}

	for name, want := range expected {
		pub, found := got[name]
		if !found {
			t.Errorf("symbol %q not emitted", name)
			continue
		}
		if pub != want {
			t.Errorf("symbol %q IsPublic = %v, want %v", name, pub, want)
		}
	}
}
