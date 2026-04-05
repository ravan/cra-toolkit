// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package javascript_test

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	jsextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/javascript"
)

func TestFindEntryPoints_Express(t *testing.T) {
	source := `const express = require('express');
const app = express();

app.get('/health', (req, res) => {
    res.send('ok');
});

app.post('/api/data', handleData);

function handleData(req, res) {
    res.json(process(req.body));
}

function process(data) {
    return data;
}
`
	tree, src := parseJS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	symbols, err := ext.ExtractSymbols("server.js", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}
	eps := ext.FindEntryPoints(symbols, "/project")

	// handleData and the arrow function should be entry points; process should NOT
	if len(eps) < 1 {
		t.Errorf("expected at least 1 entry point for Express routes, got %d", len(eps))
		for _, ep := range eps {
			t.Logf("  entry point: %s", ep)
		}
	}

	// 'process' should not be an entry point
	for _, ep := range eps {
		if string(ep) == "server.process" {
			t.Errorf("'process' should not be an entry point — it is not a route handler")
		}
	}
}

func TestFindEntryPoints_Nuxt(t *testing.T) {
	source := `export default defineEventHandler((event) => {
    return { status: 'ok' };
});
`
	tree, src := parseJS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	symbols, err := ext.ExtractSymbols("server/api/status.js", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}
	eps := ext.FindEntryPoints(symbols, "/project")

	// defineEventHandler export is an entry point
	if len(eps) < 1 {
		t.Errorf("expected at least 1 entry point for Nuxt defineEventHandler, got %d", len(eps))
		for _, ep := range eps {
			t.Logf("  entry point: %s", ep)
		}
	}
}

//nolint:gocognit,gocyclo // test validates multiple entry points with individual assertions
func TestFindEntryPoints_SvelteKit(t *testing.T) {
	source := `export async function GET({ params }) {
    return json({ id: params.id });
}

export async function POST({ request }) {
    const body = await request.json();
    return json(body);
}

function internalHelper() {
    return 'not exported';
}
`
	tree, src := parseJS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	symbols, err := ext.ExtractSymbols("+server.js", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}
	eps := ext.FindEntryPoints(symbols, "/project")

	// GET and POST are entry points (SvelteKit +server.ts convention)
	if len(eps) < 2 {
		t.Errorf("expected at least 2 entry points (GET, POST), got %d", len(eps))
		for _, ep := range eps {
			t.Logf("  entry point: %s", ep)
		}
	}

	var foundGET, foundPOST bool
	for _, ep := range eps {
		epStr := string(ep)
		if len(epStr) >= 3 && epStr[len(epStr)-3:] == "GET" {
			foundGET = true
		}
		if len(epStr) >= 4 && epStr[len(epStr)-4:] == "POST" {
			foundPOST = true
		}
	}
	if !foundGET {
		t.Error("expected GET to be an entry point")
	}
	if !foundPOST {
		t.Error("expected POST to be an entry point")
	}

	// internalHelper should NOT be an entry point
	for _, ep := range eps {
		epStr := string(ep)
		if len(epStr) >= 14 && epStr[len(epStr)-14:] == "internalHelper" {
			t.Error("'internalHelper' should not be an entry point")
		}
	}
}

func TestFindEntryPoints_NextJS(t *testing.T) {
	source := `export default function Page({ params }) {
    return <div>{params.id}</div>;
}

export async function getServerSideProps(context) {
    return { props: {} };
}
`
	tree, src := parseJS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	symbols, err := ext.ExtractSymbols("pages/index.js", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}
	eps := ext.FindEntryPoints(symbols, "/project")

	// getServerSideProps is a Next.js entry point
	if len(eps) < 1 {
		t.Errorf("expected at least 1 entry point (Next.js lifecycle), got %d", len(eps))
		for _, ep := range eps {
			t.Logf("  entry point: %s", ep)
		}
	}
}

func TestFindEntryPoints_Hono(t *testing.T) {
	source := `import { Hono } from 'hono';

const app = new Hono();

app.get('/api/items', (c) => {
    return c.json([]);
});

app.post('/api/items', async (c) => {
    const body = await c.req.json();
    return c.json(body);
});

export default app;
`
	tree, src := parseJS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	symbols, err := ext.ExtractSymbols("routes.js", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}
	eps := ext.FindEntryPoints(symbols, "/project")

	// Hono route handlers should be entry points
	if len(eps) < 1 {
		t.Errorf("expected at least 1 entry point for Hono routes, got %d", len(eps))
		for _, ep := range eps {
			t.Logf("  entry point: %s", ep)
		}
	}
}

func TestFindEntryPoints_RemixLoaderAction(t *testing.T) {
	source := `export async function loader({ request }) {
    return json({ items: [] });
}

export async function action({ request }) {
    const body = await request.formData();
    return redirect('/');
}

export default function IndexRoute() {
    return <div>Hello</div>;
}
`
	tree, src := parseJS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	symbols, err := ext.ExtractSymbols("app/routes/index.jsx", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}
	eps := ext.FindEntryPoints(symbols, "/project")

	// loader and action are Remix entry points
	if len(eps) < 2 {
		t.Errorf("expected at least 2 entry points (loader, action), got %d", len(eps))
		for _, ep := range eps {
			t.Logf("  entry point: %s", ep)
		}
	}
}

func TestFindEntryPoints_NestJS(t *testing.T) {
	source := `import { Controller, Get, Post } from '@nestjs/common';

@Controller('cats')
class CatsController {
    @Get()
    findAll() {
        return [];
    }

    @Post()
    create(body) {
        return body;
    }
}
`
	tree, src := parseTS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	symbols, err := ext.ExtractSymbols("cats.controller.ts", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}
	eps := ext.FindEntryPoints(symbols, "/project")

	// NestJS @Get/@Post decorated methods are entry points
	if len(eps) < 2 {
		t.Errorf("expected at least 2 entry points (NestJS @Get, @Post), got %d", len(eps))
		for _, ep := range eps {
			t.Logf("  entry point: %s", ep)
		}
	}
}

func TestFindEntryPoints_ExportsMain(t *testing.T) {
	symbols := []*treesitter.Symbol{
		{ID: "cli.main", Name: "main", Kind: treesitter.SymbolFunction, File: "cli.js", StartLine: 1},
		{ID: "cli.helper", Name: "helper", Kind: treesitter.SymbolFunction, File: "cli.js", StartLine: 10},
	}

	ext := jsextractor.New()
	eps := ext.FindEntryPoints(symbols, "/project")

	if len(eps) < 1 {
		t.Errorf("expected at least 1 entry point for function named 'main', got %d", len(eps))
	}
}

//nolint:gocognit,gocyclo // test validates multiple Astro entry points with individual assertions
func TestFindEntryPoints_Astro(t *testing.T) {
	source := `export const GET = async ({ request }) => {
    return new Response(JSON.stringify({ status: 'ok' }));
};

export const POST = async ({ request }) => {
    const data = await request.json();
    return new Response(JSON.stringify(data));
};

const internalHelper = () => {
    return 'not exported';
};
`
	tree, src := parseJS(t, source)
	defer tree.Close()

	ext := jsextractor.New()
	// File must be in src/pages/ for Astro detection
	symbols, err := ext.ExtractSymbols("src/pages/api/status.js", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}
	eps := ext.FindEntryPoints(symbols, "/project")

	if len(eps) < 2 {
		t.Errorf("expected at least 2 entry points (GET, POST) for Astro API route, got %d", len(eps))
		for _, ep := range eps {
			t.Logf("  entry point: %s", ep)
		}
	}

	var foundGET, foundPOST bool
	for _, ep := range eps {
		epStr := string(ep)
		switch {
		case len(epStr) >= 3 && epStr[len(epStr)-3:] == "GET":
			foundGET = true
		case len(epStr) >= 4 && epStr[len(epStr)-4:] == "POST":
			foundPOST = true
		}
	}
	if !foundGET {
		t.Error("expected GET to be an Astro entry point")
	}
	if !foundPOST {
		t.Error("expected POST to be an Astro entry point")
	}

	// internalHelper should NOT be an entry point
	for _, ep := range eps {
		epStr := string(ep)
		if len(epStr) >= len("internalHelper") && epStr[len(epStr)-len("internalHelper"):] == "internalHelper" {
			t.Error("'internalHelper' should not be an entry point")
		}
	}
}
