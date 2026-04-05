// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package php_test

import (
	"strings"
	"testing"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	phpgrammar "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/grammars/php"
	phpextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/php"
)

// parseSource parses PHP source bytes and returns the tree and the source slice.
func parseSource(t *testing.T, source string) (*tree_sitter.Tree, []byte) { //nolint:gocritic // two return values are self-documenting
	t.Helper()
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(phpgrammar.Language())); err != nil {
		t.Fatalf("set language: %v", err)
	}
	src := []byte(source)
	tree := parser.Parse(src, nil)
	if tree == nil {
		t.Fatal("tree-sitter returned nil tree")
	}
	return tree, src
}

// TestExtractSymbols_BasicClass verifies that a simple PHP class and its methods are extracted.
//
//nolint:gocognit,gocyclo // test validates multiple symbol kinds with individual assertions
func TestExtractSymbols_BasicClass(t *testing.T) {
	source := `<?php
namespace App;

class Greeter
{
    public function greet(string $name): string
    {
        return "Hello, " . $name;
    }

    public function printGreeting(string $name): void
    {
        echo $this->greet($name);
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := phpextractor.New()
	symbols, err := ext.ExtractSymbols("Greeter.php", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	// Expect: class Greeter + 2 methods = 3 symbols
	if len(symbols) != 3 {
		t.Errorf("expected exactly 3 symbols (class + 2 methods), got %d", len(symbols))
		for _, s := range symbols {
			t.Logf("  %s (%s) at line %d", s.QualifiedName, s.Kind, s.StartLine)
		}
	}

	var foundClass, foundGreet, foundPrint bool
	for _, s := range symbols {
		switch {
		case s.Name == "Greeter" && s.Kind == treesitter.SymbolClass:
			foundClass = true
			if s.Package != "App" {
				t.Errorf("expected package 'App', got %q", s.Package)
			}
		case s.Name == "greet" && s.Kind == treesitter.SymbolMethod:
			foundGreet = true
			if s.QualifiedName != `App\Greeter::greet` {
				t.Errorf("expected qualified name 'App\\Greeter::greet', got %q", s.QualifiedName)
			}
		case s.Name == "printGreeting" && s.Kind == treesitter.SymbolMethod:
			foundPrint = true
		}
	}

	if !foundClass {
		t.Error("expected to find class 'Greeter'")
	}
	if !foundGreet {
		t.Error("expected to find method 'greet'")
	}
	if !foundPrint {
		t.Error("expected to find method 'printGreeting'")
	}
}

// TestExtractSymbols_Namespace verifies that namespace is correctly extracted.
func TestExtractSymbols_Namespace(t *testing.T) {
	source := `<?php
namespace App\Controllers;

class UserController
{
    public function index(): string
    {
        return "users";
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := phpextractor.New()
	symbols, err := ext.ExtractSymbols("UserController.php", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	var foundClass bool
	for _, s := range symbols {
		if s.Name == "UserController" && s.Kind == treesitter.SymbolClass {
			foundClass = true
			if s.Package != `App\Controllers` {
				t.Errorf("expected package 'App\\Controllers', got %q", s.Package)
			}
			if s.QualifiedName != `App\Controllers\UserController` {
				t.Errorf("expected qualified name 'App\\Controllers\\UserController', got %q", s.QualifiedName)
			}
		}
	}

	if !foundClass {
		t.Error("expected to find class 'UserController' with namespace 'App\\Controllers'")
	}
}

// TestResolveImports_PHP verifies that namespace use declarations are extracted as imports.
//
//nolint:gocyclo // test validates multiple import forms with individual assertions
func TestResolveImports_PHP(t *testing.T) {
	source := `<?php
namespace App;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Psr\Http\Message\ResponseInterface;

class MyClass
{
    public function run(): void {}
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := phpextractor.New()
	imports, err := ext.ResolveImports("MyClass.php", src, tree, "/project")
	if err != nil {
		t.Fatalf("ResolveImports failed: %v", err)
	}

	if len(imports) < 3 {
		t.Errorf("expected at least 3 imports, got %d", len(imports))
		for _, imp := range imports {
			t.Logf("  %s (alias: %q)", imp.Module, imp.Alias)
		}
	}

	var foundGuzzle, foundException, foundPsr bool
	for _, imp := range imports {
		switch imp.Module {
		case `GuzzleHttp\Client`:
			foundGuzzle = true
			if imp.Alias != "Client" {
				t.Errorf("expected alias 'Client', got %q", imp.Alias)
			}
		case `GuzzleHttp\Exception\RequestException`:
			foundException = true
		case `Psr\Http\Message\ResponseInterface`:
			foundPsr = true
		}
	}

	if !foundGuzzle {
		t.Errorf("expected to find import 'GuzzleHttp\\Client'")
	}
	if !foundException {
		t.Errorf("expected to find import 'GuzzleHttp\\Exception\\RequestException'")
	}
	if !foundPsr {
		t.Errorf("expected to find import 'Psr\\Http\\Message\\ResponseInterface'")
	}
}

// TestExtractCalls_MemberCall verifies that method calls via member_call_expression are extracted.
//
//nolint:gocognit,gocyclo // test validates multiple call forms
func TestExtractCalls_MemberCall(t *testing.T) {
	source := `<?php
namespace App;

use GuzzleHttp\Client;

class UserController
{
    public function proxy(string $url): string
    {
        $client = new Client(['cookies' => true]);
        $response = $client->get($url);
        return (string) $response->getBody();
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := phpextractor.New()
	if _, err := ext.ExtractSymbols("UserController.php", src, tree); err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("UserController.php", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	if len(edges) == 0 {
		t.Fatal("expected at least one call edge, got none")
	}

	// The extractor emits member calls using the variable name ($client → "client::get")
	// or the resolved type name ("Client::get") if type inference is available.
	// Either form is acceptable.
	var foundGet bool
	for _, e := range edges {
		t.Logf("  edge: %s -> %s (conf=%.1f)", e.From, e.To, e.Confidence)
		toStr := string(e.To)
		if toStr == "Client::get" || toStr == `GuzzleHttp\Client::get` || toStr == "client::get" {
			foundGet = true
		}
	}
	if !foundGet {
		t.Error("expected to find edge to 'client::get', 'Client::get', or 'GuzzleHttp\\Client::get'")
	}

	// All edges must have a From and positive confidence
	for _, e := range edges {
		if e.From == "" {
			t.Errorf("edge has empty From field: %+v", e)
		}
		if e.Confidence <= 0 {
			t.Errorf("edge has non-positive confidence: %+v", e)
		}
	}
}

// TestExtractCalls_ObjectCreation verifies that new T() calls are extracted as edges.
func TestExtractCalls_ObjectCreation(t *testing.T) {
	source := `<?php
namespace App;

use GuzzleHttp\Client;

class Builder
{
    public function createClient(): Client
    {
        $client = new Client(['timeout' => 10]);
        return $client;
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := phpextractor.New()
	if _, err := ext.ExtractSymbols("Builder.php", src, tree); err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("Builder.php", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	var foundObjectCreation bool
	for _, e := range edges {
		if string(e.To) == "Client.<init>" || string(e.To) == `GuzzleHttp\Client.<init>` {
			foundObjectCreation = true
		}
	}
	if !foundObjectCreation {
		t.Error("expected to find 'new Client()' as edge to 'Client.<init>'")
		for _, e := range edges {
			t.Logf("  edge: %s -> %s", e.From, e.To)
		}
	}
}

// TestExtractCalls_StaticCall verifies that static method calls are extracted.
func TestExtractCalls_StaticCall(t *testing.T) {
	source := `<?php
use App\UserController;

Route::get('/users', [UserController::class, 'index']);
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := phpextractor.New()
	if _, err := ext.ExtractSymbols("routes.php", src, tree); err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("routes.php", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	var foundRouteGet bool
	for _, e := range edges {
		if string(e.To) == "Route::get" {
			foundRouteGet = true
		}
	}
	if !foundRouteGet {
		t.Error("expected to find edge to 'Route::get'")
		for _, e := range edges {
			t.Logf("  edge: %s -> %s", e.From, e.To)
		}
	}
}

// TestExtractSymbols_TopLevelFunction verifies that top-level (global) PHP functions are extracted
// as SymbolFunction kind symbols.
//
//nolint:gocognit,gocyclo // test validates multiple symbol kinds with individual assertions
func TestExtractSymbols_TopLevelFunction(t *testing.T) {
	source := `<?php
function sendRequest(string $url): string {
    $client = new \GuzzleHttp\Client();
    return $client->get($url)->getBody();
}

function helperFunc(): void {
    echo "helper";
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := phpextractor.New()
	symbols, err := ext.ExtractSymbols("helpers.php", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	if len(symbols) != 2 {
		t.Errorf("expected exactly 2 symbols (2 top-level functions), got %d", len(symbols))
		for _, s := range symbols {
			t.Logf("  %s (%s) at line %d", s.QualifiedName, s.Kind, s.StartLine)
		}
	}

	var foundSend, foundHelper bool
	for _, s := range symbols {
		switch s.Name {
		case "sendRequest":
			foundSend = true
			if s.Kind != treesitter.SymbolFunction {
				t.Errorf("expected sendRequest to be SymbolFunction, got %s", s.Kind)
			}
			if s.QualifiedName != "sendRequest" {
				t.Errorf("expected qualified name 'sendRequest', got %q", s.QualifiedName)
			}
		case "helperFunc":
			foundHelper = true
			if s.Kind != treesitter.SymbolFunction {
				t.Errorf("expected helperFunc to be SymbolFunction, got %s", s.Kind)
			}
		}
	}

	if !foundSend {
		t.Error("expected to find top-level function 'sendRequest'")
	}
	if !foundHelper {
		t.Error("expected to find top-level function 'helperFunc'")
	}
}

// TestExtractSymbols_TopLevelFunction_WithNamespace verifies that top-level functions in a
// namespaced file use the namespace as qualifier.
//
//nolint:gocognit // test validates qualified names, package, and kind in one function
func TestExtractSymbols_TopLevelFunction_WithNamespace(t *testing.T) {
	source := `<?php
namespace App\Helpers;

function formatDate(string $date): string {
    return date('Y-m-d', strtotime($date));
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := phpextractor.New()
	symbols, err := ext.ExtractSymbols("helpers.php", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	var found bool
	for _, s := range symbols {
		if s.Name != "formatDate" {
			continue
		}
		found = true
		if s.Kind != treesitter.SymbolFunction {
			t.Errorf("expected SymbolFunction, got %s", s.Kind)
		}
		expected := `App\Helpers\formatDate`
		if s.QualifiedName != expected {
			t.Errorf("expected qualified name %q, got %q", expected, s.QualifiedName)
		}
		if s.Package != `App\Helpers` {
			t.Errorf("expected package 'App\\Helpers', got %q", s.Package)
		}
	}
	if !found {
		t.Error("expected to find top-level function 'formatDate'")
	}
}

// TestExtractCalls_TopLevelFunction verifies that call edges from within a top-level function
// are extracted with the function as the caller.
//
//nolint:gocognit,gocyclo // test validates edge origins, object creation, and confidence with individual assertions
func TestExtractCalls_TopLevelFunction(t *testing.T) {
	source := `<?php
function sendRequest(string $url): string {
    $client = new \GuzzleHttp\Client();
    return $client->get($url)->getBody();
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := phpextractor.New()
	if _, err := ext.ExtractSymbols("helpers.php", src, tree); err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("helpers.php", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	if len(edges) == 0 {
		t.Fatal("expected at least one call edge from top-level function, got none")
	}

	// All edges should originate from "sendRequest" (the top-level function)
	var foundFromFunc bool
	var foundObjectCreation bool
	for _, e := range edges {
		t.Logf("  edge: %s -> %s (conf=%.1f)", e.From, e.To, e.Confidence)
		if string(e.From) == "sendRequest" {
			foundFromFunc = true
		}
		if string(e.To) == `\GuzzleHttp\Client.<init>` || string(e.To) == `GuzzleHttp\Client.<init>` || string(e.To) == `\GuzzleHttp\Client` {
			foundObjectCreation = true
		}
	}

	if !foundFromFunc {
		t.Error("expected edges from 'sendRequest' (top-level function), none found")
		for _, e := range edges {
			t.Logf("  from=%s to=%s", e.From, e.To)
		}
	}
	if !foundObjectCreation {
		// Also accept "\\GuzzleHttp\\Client.<init>" format
		for _, e := range edges {
			if strings.Contains(string(e.To), "Client") {
				foundObjectCreation = true
				break
			}
		}
		if !foundObjectCreation {
			t.Error("expected to find 'new \\GuzzleHttp\\Client()' as an edge (object creation)")
		}
	}

	// All edges must have positive confidence
	for _, e := range edges {
		if e.Confidence <= 0 {
			t.Errorf("edge has non-positive confidence: %+v", e)
		}
	}
}

// TestExtractSymbols_Attributes verifies that PHP attributes (#[Route]) are collected.
func TestExtractSymbols_Attributes(t *testing.T) {
	source := `<?php
namespace App;

class UserController
{
    #[Route('/api/proxy', methods: ['GET'])]
    public function proxy(string $url): string
    {
        return "ok";
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := phpextractor.New()
	symbols, err := ext.ExtractSymbols("UserController.php", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	var proxySym *treesitter.Symbol
	for _, s := range symbols {
		if s.Name == "proxy" && s.Kind == treesitter.SymbolMethod {
			proxySym = s
			break
		}
	}

	if proxySym == nil {
		t.Fatal("expected to find method 'proxy'")
	}

	// Verify entry points include the #[Route] decorated method
	eps := ext.FindEntryPoints(symbols, "/project")
	var foundProxy bool
	for _, ep := range eps {
		if ep == proxySym.ID {
			foundProxy = true
		}
	}
	if !foundProxy {
		t.Errorf("expected 'proxy' to be an entry point (has #[Route]), entry points: %v", eps)
	}
}
