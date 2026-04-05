// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package javascript_test

import (
	"testing"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	jsgrammar "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/grammars/javascript"
	tsgrammar "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/grammars/typescript"
	jsextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/javascript"
)

// parseJS parses JavaScript source with the JS grammar.
func parseJS(t *testing.T, source string) (*tree_sitter.Tree, []byte) { //nolint:gocritic // two return values are self-documenting
	t.Helper()
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(jsgrammar.Language())); err != nil {
		t.Fatalf("set JS language: %v", err)
	}
	src := []byte(source)
	tree := parser.Parse(src, nil)
	if tree == nil {
		t.Fatal("tree-sitter returned nil tree for JS source")
	}
	return tree, src
}

// parseTS parses TypeScript source with the TS grammar.
func parseTS(t *testing.T, source string) (*tree_sitter.Tree, []byte) { //nolint:gocritic // two return values are self-documenting
	t.Helper()
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(tsgrammar.Language())); err != nil {
		t.Fatalf("set TS language: %v", err)
	}
	src := []byte(source)
	tree := parser.Parse(src, nil)
	if tree == nil {
		t.Fatal("tree-sitter returned nil tree for TS source")
	}
	return tree, src
}

//nolint:gocognit,gocyclo // test validates multiple symbol kinds with individual assertions
func TestExtractSymbols_JavaScript(t *testing.T) {
	source := `const _ = require('lodash');
const express = require('express');

function handleRequest(req, res) {
    const template = _.template(req.body.input);
    res.send(template({ user: req.user }));
}

class UserController {
    getUser(req, res) {
        return res.json({ name: "test" });
    }
}

module.exports = { handleRequest, UserController };
`
	tree, src := parseJS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	symbols, err := ext.ExtractSymbols("handler.js", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	// Should find: handleRequest (function), UserController (class), getUser (method)
	if len(symbols) < 3 {
		t.Errorf("expected at least 3 symbols, got %d", len(symbols))
		for _, s := range symbols {
			t.Logf("  %s (%s) at line %d", s.QualifiedName, s.Kind, s.StartLine)
		}
	}

	var foundHandleRequest, foundUserController, foundGetUser bool
	for _, s := range symbols {
		switch {
		case s.Name == "handleRequest" && s.Kind == treesitter.SymbolFunction:
			foundHandleRequest = true
			if s.File != "handler.js" {
				t.Errorf("handleRequest.File = %q, want handler.js", s.File)
			}
		case s.Name == "UserController" && s.Kind == treesitter.SymbolClass:
			foundUserController = true
		case s.Name == "getUser" && s.Kind == treesitter.SymbolMethod:
			foundGetUser = true
		}
	}

	if !foundHandleRequest {
		t.Error("expected to find function 'handleRequest'")
	}
	if !foundUserController {
		t.Error("expected to find class 'UserController'")
	}
	if !foundGetUser {
		t.Error("expected to find method 'getUser'")
	}
}

func TestExtractSymbols_ArrowFunctions(t *testing.T) {
	source := `const greet = (name) => {
    return 'Hello, ' + name;
};

const add = (a, b) => a + b;
`
	tree, src := parseJS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	symbols, err := ext.ExtractSymbols("utils.js", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	// Arrow functions assigned to const are extracted
	var foundGreet bool
	for _, s := range symbols {
		if s.Name == "greet" {
			foundGreet = true
		}
	}
	if !foundGreet {
		t.Error("expected to find arrow function 'greet'")
	}
}

//nolint:gocognit,gocyclo // test validates multiple symbol kinds with individual assertions
func TestExtractSymbols_TypeScript(t *testing.T) {
	source := `import { Injectable } from '@angular/core';

@Injectable()
export class UserService {
    getUser(id: string): Promise<User> {
        return Promise.resolve({ id });
    }
}

export function validateInput(input: string): boolean {
    return input.length > 0;
}

export const transform = (data: unknown): string => JSON.stringify(data);
`
	tree, src := parseTS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	symbols, err := ext.ExtractSymbols("user.service.ts", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	if len(symbols) < 3 {
		t.Errorf("expected at least 3 symbols, got %d", len(symbols))
		for _, s := range symbols {
			t.Logf("  %s (%s) at line %d", s.QualifiedName, s.Kind, s.StartLine)
		}
	}

	var foundClass, foundMethod, foundFunction bool
	for _, s := range symbols {
		switch {
		case s.Name == "UserService" && s.Kind == treesitter.SymbolClass:
			foundClass = true
		case s.Name == "getUser" && s.Kind == treesitter.SymbolMethod:
			foundMethod = true
		case s.Name == "validateInput" && s.Kind == treesitter.SymbolFunction:
			foundFunction = true
		}
	}

	if !foundClass {
		t.Error("expected to find class 'UserService'")
	}
	if !foundMethod {
		t.Error("expected to find method 'getUser'")
	}
	if !foundFunction {
		t.Error("expected to find function 'validateInput'")
	}
}

//nolint:gocognit,gocyclo // test validates multiple import forms with individual assertions
func TestResolveImports_ESM(t *testing.T) {
	source := `import express from 'express';
import { readFile, writeFile } from 'fs/promises';
import * as path from 'path';
`
	tree, src := parseJS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	imports, err := ext.ResolveImports("app.js", src, tree, "/project")
	if err != nil {
		t.Fatalf("ResolveImports failed: %v", err)
	}

	if len(imports) < 3 {
		t.Errorf("expected at least 3 imports, got %d", len(imports))
		for _, imp := range imports {
			t.Logf("  %s (symbols: %v, alias: %q)", imp.Module, imp.Symbols, imp.Alias)
		}
	}

	var foundExpress, foundFs, foundPath bool
	for _, imp := range imports {
		switch imp.Module {
		case "express":
			foundExpress = true
			if imp.Alias != "express" {
				t.Errorf("express alias = %q, want 'express'", imp.Alias)
			}
		case "fs/promises":
			foundFs = true
			if len(imp.Symbols) != 2 {
				t.Errorf("fs/promises symbols = %d, want 2", len(imp.Symbols))
			}
		case "path":
			foundPath = true
		}
	}

	if !foundExpress {
		t.Error("expected to find 'import express from 'express''")
	}
	if !foundFs {
		t.Error("expected to find 'import { readFile, writeFile } from 'fs/promises''")
	}
	if !foundPath {
		t.Error("expected to find 'import * as path from 'path''")
	}
}

//nolint:gocognit,gocyclo // test validates require() patterns with individual assertions
func TestResolveImports_CommonJS(t *testing.T) {
	source := `const _ = require('lodash');
const express = require('express');
const { readFileSync } = require('fs');
`
	tree, src := parseJS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	imports, err := ext.ResolveImports("app.js", src, tree, "/project")
	if err != nil {
		t.Fatalf("ResolveImports failed: %v", err)
	}

	if len(imports) < 3 {
		t.Errorf("expected at least 3 imports, got %d", len(imports))
		for _, imp := range imports {
			t.Logf("  %s (symbols: %v, alias: %q)", imp.Module, imp.Symbols, imp.Alias)
		}
	}

	var foundLodash, foundExpress, foundFs bool
	for _, imp := range imports {
		switch imp.Module {
		case "lodash":
			foundLodash = true
			if imp.Alias != "_" {
				t.Errorf("lodash alias = %q, want '_'", imp.Alias)
			}
		case "express":
			foundExpress = true
		case "fs":
			foundFs = true
		}
	}

	if !foundLodash {
		t.Error("expected to find require('lodash') with alias '_'")
	}
	if !foundExpress {
		t.Error("expected to find require('express')")
	}
	if !foundFs {
		t.Error("expected to find require('fs')")
	}
}

//nolint:gocognit,gocyclo // test validates multiple call types with individual assertions
func TestExtractCalls_JavaScript(t *testing.T) {
	source := `const _ = require('lodash');
const express = require('express');

function handleRequest(req, res) {
    const template = _.template(req.body.input);
    res.send(template({ user: req.user }));
}

class UserController {
    getUser(req, res) {
        return res.json({ name: "test" });
    }
}

module.exports = { handleRequest, UserController };
`
	tree, src := parseJS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	scope := treesitter.NewScope(nil)
	scope.DefineImport("_", "lodash", []string{})
	scope.DefineImport("express", "express", []string{})

	edges, err := ext.ExtractCalls("handler.js", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	// Should find calls: _.template, res.send, res.json (at minimum)
	if len(edges) < 3 {
		t.Errorf("expected at least 3 call edges, got %d", len(edges))
		for _, e := range edges {
			t.Logf("  %s -> %s (%s)", e.From, e.To, e.Kind)
		}
	}

	var foundTemplate, foundSend, foundJson bool
	for _, e := range edges {
		switch string(e.To) {
		case "lodash.template":
			// _ is a known import alias for lodash; resolved correctly.
			foundTemplate = true
			if e.Kind != treesitter.EdgeDirect {
				t.Errorf("lodash.template: expected EdgeDirect, got %s", e.Kind)
			}
		case "res.send":
			foundSend = true
		case "res.json":
			foundJson = true
		}
	}

	if !foundTemplate {
		t.Error("expected to find call to lodash.template (resolved from _.template via import alias)")
	}
	if !foundSend {
		t.Error("expected to find call to res.send")
	}
	if !foundJson {
		t.Error("expected to find call to res.json")
	}
}

func TestExtractCalls_ImportAliasResolution(t *testing.T) {
	source := `const _ = require('lodash');
const express = require('express');

function handleRequest(req, res) {
    const compiled = _.template(req.body.input);
    res.send(compiled());
}
`
	tree, src := parseJS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	scope := treesitter.NewScope(nil)
	// Populate scope with import aliases as the analyzer would do.
	scope.DefineImport("_", "lodash", []string{})
	scope.DefineImport("express", "express", []string{})

	edges, err := ext.ExtractCalls("handler.js", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	// _.template should resolve to lodash.template via import alias in scope.
	// res.send should stay as res.send (res is not a known import alias).
	var foundLodashTemplate, foundResSend bool
	var foundUnresolvedTemplate bool
	for _, e := range edges {
		switch string(e.To) {
		case "lodash.template":
			foundLodashTemplate = true
		case "_.template":
			foundUnresolvedTemplate = true
		case "res.send":
			foundResSend = true
		}
	}

	if !foundLodashTemplate {
		t.Error("expected _.template to be resolved to lodash.template via import alias")
		for _, e := range edges {
			t.Logf("  %s -> %s", e.From, e.To)
		}
	}
	if foundUnresolvedTemplate {
		t.Error("unresolved _.template edge should not appear; alias resolution failed")
	}
	if !foundResSend {
		t.Error("expected res.send to remain as res.send (res is not an import alias)")
	}
}

func TestExtractCalls_ChainedAndNew(t *testing.T) {
	source := `const http = require('http');

function start() {
    const server = new http.Server();
    http.createServer().listen(3000);
}
`
	tree, src := parseJS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	scope := treesitter.NewScope(nil)

	edges, err := ext.ExtractCalls("server.js", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	// Should find: new http.Server, http.createServer, .listen
	if len(edges) < 2 {
		t.Errorf("expected at least 2 call edges, got %d", len(edges))
		for _, e := range edges {
			t.Logf("  %s -> %s", e.From, e.To)
		}
	}
}

func TestExtractSymbols_LineNumbers(t *testing.T) {
	source := `function first() {
    return 1;
}

function second() {
    return 2;
}
`
	tree, src := parseJS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	symbols, err := ext.ExtractSymbols("nums.js", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}

	for _, s := range symbols {
		if s.StartLine < 1 {
			t.Errorf("symbol %s has StartLine %d, want >= 1", s.Name, s.StartLine)
		}
		if s.EndLine < s.StartLine {
			t.Errorf("symbol %s has EndLine %d < StartLine %d", s.Name, s.EndLine, s.StartLine)
		}
	}
}

func TestModuleExports_ExportMarking(t *testing.T) {
	source := `const _ = require('lodash');
const express = require('express');

function handleRequest(req, res) {
    const template = _.template(req.body.input);
    res.send(template({ user: req.user }));
}

class UserController {
    getUser(req, res) {
        return res.json({ name: "test" });
    }
}

module.exports = { handleRequest, UserController };
`
	tree, src := parseJS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	symbols, err := ext.ExtractSymbols("handler.js", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")

	// handleRequest is marked exported via module.exports and its name matches
	// isLikelyRouteHandler (contains "handler"), so it becomes an entry point.
	// UserController is a class (SymbolClass), so FindEntryPoints skips it by design
	// (only SymbolFunction and SymbolMethod qualify); the export marking is still applied.
	var foundHandleRequest bool
	for _, ep := range eps {
		epStr := string(ep)
		if len(epStr) >= len("handleRequest") && epStr[len(epStr)-len("handleRequest"):] == "handleRequest" {
			foundHandleRequest = true
		}
	}

	if !foundHandleRequest {
		t.Error("expected handleRequest to be marked exported via module.exports and be an entry point")
		for _, ep := range eps {
			t.Logf("  entry point: %s", ep)
		}
	}

	// Verify UserController is found as a symbol (export marking succeeded — it was not silently lost).
	var foundUserController bool
	for _, sym := range symbols {
		if sym.Name == "UserController" {
			foundUserController = true
		}
	}
	if !foundUserController {
		t.Error("expected to find symbol UserController")
	}
}

func TestExtractCalls_TypedConfidence(t *testing.T) {
	source := `import { Request, Response } from 'express';

function handleRequest(req: Request, res: Response) {
    res.send('hello');
    req.body.toString();
}

function untypedHandler(req, res) {
    res.json({ ok: true });
}
`
	tree, src := parseTS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	scope := treesitter.NewScope(nil)

	edges, err := ext.ExtractCalls("handler.ts", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	// res and req in handleRequest have type annotations → calls on them get confidence 1.0
	// res and req in untypedHandler have NO type annotations → calls get confidence 0.8
	var typedSendConf, untypedJsonConf float64
	for _, e := range edges {
		switch string(e.To) {
		case "res.send":
			typedSendConf = e.Confidence
		case "res.json":
			untypedJsonConf = e.Confidence
		}
	}

	if typedSendConf != 1.0 {
		t.Errorf("res.send in typed handler: expected confidence 1.0, got %f", typedSendConf)
	}
	if untypedJsonConf != 0.8 {
		t.Errorf("res.json in untyped handler: expected confidence 0.8, got %f", untypedJsonConf)
	}
}
