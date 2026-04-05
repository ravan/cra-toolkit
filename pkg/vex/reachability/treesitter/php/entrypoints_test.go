// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package php_test

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	phpextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/php"
)

// TestFindEntryPoints_SymfonyRoute verifies that #[Route] attributes are detected as entry points.
//
//nolint:dupl // similar structure to TestFindEntryPoints_ControllerPublicMethods but tests different detection strategy
func TestFindEntryPoints_SymfonyRoute(t *testing.T) {
	source := `<?php
namespace App\Controller;

class UserController
{
    #[Route('/api/users', methods: ['GET'])]
    public function list(): string
    {
        return "[]";
    }

    #[Route('/api/users', methods: ['POST'])]
    public function create(): string
    {
        return "created";
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

	eps := ext.FindEntryPoints(symbols, "/project")
	if len(eps) < 2 {
		t.Errorf("expected at least 2 entry points (#[Route] methods), got %d: %v", len(eps), eps)
	}

	epSet := make(map[treesitter.SymbolID]bool, len(eps))
	for _, ep := range eps {
		epSet[ep] = true
	}

	for _, name := range []string{"list", "create"} {
		id := treesitter.SymbolID(`App\Controller\UserController::` + name)
		if !epSet[id] {
			t.Errorf("expected method %q to be an entry point", name)
		}
	}
}

// TestFindEntryPoints_ControllerPublicMethods verifies that public methods in Controller classes are entry points.
//
//nolint:dupl // similar structure to TestFindEntryPoints_SymfonyRoute but tests different detection strategy
func TestFindEntryPoints_ControllerPublicMethods(t *testing.T) {
	source := `<?php
namespace App;

class ProductController
{
    public function index(): string
    {
        return "products";
    }

    public function show(int $id): string
    {
        return "product";
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := phpextractor.New()
	symbols, err := ext.ExtractSymbols("ProductController.php", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")
	if len(eps) < 2 {
		t.Errorf("expected at least 2 entry points (public controller methods), got %d: %v", len(eps), eps)
	}

	epSet := make(map[treesitter.SymbolID]bool, len(eps))
	for _, ep := range eps {
		epSet[ep] = true
	}

	for _, name := range []string{"index", "show"} {
		id := treesitter.SymbolID(`App\ProductController::` + name)
		if !epSet[id] {
			t.Errorf("expected public method %q in *Controller class to be an entry point", name)
		}
	}
}

// TestFindEntryPoints_LaravelRoute verifies that a public method in a *Controller class is detected
// as an entry point even when it is referenced as a Laravel route callback.
// Full route callback resolution is not implemented; detection relies on the Controller heuristic.
//
//nolint:dupl // similar structure intentional — tests Laravel detection vs generic controller detection
func TestFindEntryPoints_LaravelRoute(t *testing.T) {
	source := `<?php
namespace App\Http\Controllers;

class ProductController
{
    public function index(): string
    {
        return "products";
    }

    public function show(int $id): string
    {
        return "product";
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := phpextractor.New()
	symbols, err := ext.ExtractSymbols("ProductController.php", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	// Laravel routes reference controller methods (e.g. Route::get('/products', [ProductController::class, 'index'])).
	// The Controller heuristic detects public methods in *Controller classes as entry points.
	eps := ext.FindEntryPoints(symbols, "/project")
	if len(eps) < 2 {
		t.Errorf("expected at least 2 entry points (public controller methods), got %d: %v", len(eps), eps)
	}

	epSet := make(map[treesitter.SymbolID]bool, len(eps))
	for _, ep := range eps {
		epSet[ep] = true
	}

	for _, name := range []string{"index", "show"} {
		id := treesitter.SymbolID(`App\Http\Controllers\ProductController::` + name)
		if !epSet[id] {
			t.Errorf("expected Laravel route handler method %q to be detected as entry point via Controller heuristic", name)
		}
	}
}

// TestFindEntryPoints_IndexPHP_NoPanic verifies that FindEntryPoints does not panic for index.php
// files that contain no function/method definitions (only top-level statements).
func TestFindEntryPoints_IndexPHP_NoPanic(t *testing.T) {
	source := `<?php
require_once 'vendor/autoload.php';

$app = new App();
$app->run();
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := phpextractor.New()
	symbols, err := ext.ExtractSymbols("index.php", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	// index.php with no function definitions produces no symbols.
	// FindEntryPoints must not panic and must return a non-nil (possibly empty) slice.
	eps := ext.FindEntryPoints(symbols, "/project")
	if eps == nil {
		// dedup always returns a non-nil slice; if symbols is empty the result should be empty
		t.Error("expected non-nil entry points slice, got nil")
	}
	// No symbols were defined, so no entry points should be detected.
	if len(eps) != 0 {
		t.Errorf("expected 0 entry points for index.php with no function defs, got %d: %v", len(eps), eps)
	}
}
