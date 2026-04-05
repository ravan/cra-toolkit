package csharp_test

import (
	"testing"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	csharpextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/csharp"
	csharpgrammar "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/grammars/csharp"
)

// parseSource parses C# source bytes and returns the tree and the source slice.
func parseSource(t *testing.T, source string) (*tree_sitter.Tree, []byte) { //nolint:gocritic // two return values are self-documenting
	t.Helper()
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(csharpgrammar.Language())); err != nil {
		t.Fatalf("set language: %v", err)
	}
	src := []byte(source)
	tree := parser.Parse(src, nil)
	if tree == nil {
		t.Fatal("tree-sitter returned nil tree")
	}
	return tree, src
}

// TestExtractSymbols_BasicClass verifies that a simple C# class and its methods are extracted.
//
//nolint:gocognit,gocyclo // test validates multiple symbol kinds with individual assertions
func TestExtractSymbols_BasicClass(t *testing.T) {
	source := `using System;

namespace TestApp;

public class Greeter
{
    public string Greet(string name)
    {
        return "Hello, " + name;
    }

    public void PrintGreeting(string name)
    {
        Console.WriteLine(Greet(name));
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := csharpextractor.New()
	symbols, err := ext.ExtractSymbols("Greeter.cs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	if len(symbols) < 3 {
		t.Errorf("expected at least 3 symbols (class + 2 methods), got %d", len(symbols))
		for _, s := range symbols {
			t.Logf("  %s (%s) at line %d", s.QualifiedName, s.Kind, s.StartLine)
		}
	}

	var foundClass, foundGreet, foundPrint bool
	for _, s := range symbols {
		switch {
		case s.Name == "Greeter" && s.Kind == treesitter.SymbolClass:
			foundClass = true
			if s.Package != "TestApp" {
				t.Errorf("expected package 'TestApp', got %q", s.Package)
			}
		case s.Name == "Greet" && s.Kind == treesitter.SymbolMethod:
			foundGreet = true
			if s.QualifiedName != "TestApp.Greeter.Greet" {
				t.Errorf("expected qualified name 'TestApp.Greeter.Greet', got %q", s.QualifiedName)
			}
		case s.Name == "PrintGreeting" && s.Kind == treesitter.SymbolMethod:
			foundPrint = true
		}
	}

	if !foundClass {
		t.Error("expected to find class 'Greeter'")
	}
	if !foundGreet {
		t.Error("expected to find method 'Greet'")
	}
	if !foundPrint {
		t.Error("expected to find method 'PrintGreeting'")
	}
}

// TestExtractSymbols_Constructor verifies that constructors are extracted as methods.
func TestExtractSymbols_Constructor(t *testing.T) {
	source := `namespace TestApp;

public class Service
{
    private readonly string _name;

    public Service(string name)
    {
        _name = name;
    }

    public string GetName() => _name;
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := csharpextractor.New()
	symbols, err := ext.ExtractSymbols("Service.cs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	var foundConstructor, foundGetName bool
	for _, s := range symbols {
		switch {
		case s.Name == "Service" && s.Kind == treesitter.SymbolMethod:
			foundConstructor = true
		case s.Name == "GetName" && s.Kind == treesitter.SymbolMethod:
			foundGetName = true
		}
	}

	if !foundConstructor {
		t.Error("expected to find constructor 'Service'")
	}
	if !foundGetName {
		t.Error("expected to find method 'GetName'")
	}
}

// TestExtractSymbols_FileScopedNamespace verifies that file-scoped namespaces (C# 10+) are parsed.
func TestExtractSymbols_FileScopedNamespace(t *testing.T) {
	source := `namespace MyApp.Controllers;

public class HomeController
{
    public string Index() => "home";
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := csharpextractor.New()
	symbols, err := ext.ExtractSymbols("HomeController.cs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	var foundClass bool
	for _, s := range symbols {
		if s.Name == "HomeController" && s.Kind == treesitter.SymbolClass {
			foundClass = true
			if s.Package != "MyApp.Controllers" {
				t.Errorf("expected package 'MyApp.Controllers', got %q", s.Package)
			}
			if s.QualifiedName != "MyApp.Controllers.HomeController" {
				t.Errorf("expected qualified name 'MyApp.Controllers.HomeController', got %q", s.QualifiedName)
			}
		}
	}

	if !foundClass {
		t.Error("expected to find class 'HomeController' with file-scoped namespace")
	}
}

// TestResolveImports_CSharp verifies that using directives are extracted as imports.
//
//nolint:gocyclo // test validates multiple import forms with individual assertions
func TestResolveImports_CSharp(t *testing.T) {
	source := `using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace TestApp;

public class DataController
{
    public void Run() {}
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := csharpextractor.New()
	imports, err := ext.ResolveImports("DataController.cs", src, tree, "/project")
	if err != nil {
		t.Fatalf("ResolveImports failed: %v", err)
	}

	if len(imports) < 4 {
		t.Errorf("expected at least 4 imports, got %d", len(imports))
		for _, imp := range imports {
			t.Logf("  %s (alias: %q)", imp.Module, imp.Alias)
		}
	}

	var foundSystem, foundAspNet, foundNewtonsoft bool
	for _, imp := range imports {
		switch imp.Module {
		case "System":
			foundSystem = true
		case "Microsoft.AspNetCore.Mvc":
			foundAspNet = true
		case "Newtonsoft.Json":
			foundNewtonsoft = true
		}
	}

	if !foundSystem {
		t.Error("expected to find import 'System'")
	}
	if !foundAspNet {
		t.Error("expected to find import 'Microsoft.AspNetCore.Mvc'")
	}
	if !foundNewtonsoft {
		t.Error("expected to find import 'Newtonsoft.Json'")
	}
}

// TestExtractCalls_InvocationExpression verifies that method calls are extracted as edges.
//
//nolint:gocognit,gocyclo // test validates multiple call forms
func TestExtractCalls_InvocationExpression(t *testing.T) {
	source := `using Newtonsoft.Json;

namespace TestApp;

public class DataController
{
    public object Deserialize(string payload)
    {
        var obj = JsonConvert.DeserializeObject(payload);
        return obj;
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := csharpextractor.New()
	// ExtractSymbols must be called before ExtractCalls
	if _, err := ext.ExtractSymbols("DataController.cs", src, tree); err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("DataController.cs", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	if len(edges) == 0 {
		t.Fatal("expected at least one call edge, got none")
	}

	var foundDeserialize bool
	for _, e := range edges {
		if string(e.To) == "JsonConvert.DeserializeObject" {
			foundDeserialize = true
		}
	}
	if !foundDeserialize {
		t.Error("expected to find edge to 'JsonConvert.DeserializeObject'")
		for _, e := range edges {
			t.Logf("  edge: %s -> %s (%s, conf=%.1f)", e.From, e.To, e.Kind, e.Confidence)
		}
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
	source := `using Newtonsoft.Json;

namespace TestApp;

public class Builder
{
    public JsonSerializerSettings CreateSettings()
    {
        var settings = new JsonSerializerSettings();
        return settings;
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := csharpextractor.New()
	if _, err := ext.ExtractSymbols("Builder.cs", src, tree); err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	scope := treesitter.NewScope(nil)
	edges, err := ext.ExtractCalls("Builder.cs", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	var foundObjectCreation bool
	for _, e := range edges {
		if string(e.To) == "JsonSerializerSettings.<init>" {
			foundObjectCreation = true
		}
	}
	if !foundObjectCreation {
		t.Error("expected to find 'new JsonSerializerSettings()' as edge to 'JsonSerializerSettings.<init>'")
		for _, e := range edges {
			t.Logf("  edge: %s -> %s", e.From, e.To)
		}
	}
}

// TestExtractSymbols_Attributes verifies that C# attributes are collected for entry point detection.
func TestExtractSymbols_Attributes(t *testing.T) {
	source := `using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace TestApp;

[ApiController]
[Route("[controller]")]
public class DataController : ControllerBase
{
    [HttpPost("deserialize")]
    public IActionResult Deserialize([FromBody] string payload)
    {
        var obj = JsonConvert.DeserializeObject(payload);
        return Ok(obj);
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := csharpextractor.New()
	symbols, err := ext.ExtractSymbols("DataController.cs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	// Find the Deserialize method
	var deserializeSym *treesitter.Symbol
	for _, s := range symbols {
		if s.Name == "Deserialize" && s.Kind == treesitter.SymbolMethod {
			deserializeSym = s
			break
		}
	}

	if deserializeSym == nil {
		t.Fatal("expected to find method 'Deserialize'")
	}

	// Verify entry points include the [HttpPost] decorated method
	eps := ext.FindEntryPoints(symbols, "/project")
	var foundDeserialize bool
	for _, ep := range eps {
		if ep == deserializeSym.ID {
			foundDeserialize = true
		}
	}
	if !foundDeserialize {
		t.Errorf("expected 'Deserialize' to be an entry point (has [HttpPost]), entry points: %v", eps)
	}
}

// TestModuleFromFile verifies the C# namespace-from-file helper.
func TestModuleFromFile(t *testing.T) {
	cases := []struct {
		file string
		want string
	}{
		{"Program.cs", "Program"},
		{"DataController.cs", "DataController"},
		{"/path/to/Service.cs", "Service"},
	}
	for _, tc := range cases {
		got := csharpextractor.ModuleFromFile(tc.file)
		if got != tc.want {
			t.Errorf("ModuleFromFile(%q) = %q, want %q", tc.file, got, tc.want)
		}
	}
}
