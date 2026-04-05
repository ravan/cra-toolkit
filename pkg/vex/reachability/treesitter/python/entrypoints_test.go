package python_test

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	pyextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/python"
)

func TestFindEntryPoints_MainBlock(t *testing.T) {
	symbols := []*treesitter.Symbol{
		{ID: "app.main", Name: "main", Kind: treesitter.SymbolFunction, File: "app.py", StartLine: 10},
		{ID: "app.helper", Name: "helper", Kind: treesitter.SymbolFunction, File: "app.py", StartLine: 1},
	}

	ext := pyextractor.New()
	eps := ext.FindEntryPoints(symbols, "/project")

	// "main"-named functions are treated as entry points by convention.
	// We assert at least 1 entry point (the "main" function) is found.
	if len(eps) < 1 {
		t.Errorf("expected at least 1 entry point for function named 'main', got %d", len(eps))
	}
	t.Logf("Found %d entry points", len(eps))
}

func TestFindEntryPoints_FlaskRoute(t *testing.T) {
	source := `from flask import Flask

app = Flask(__name__)

@app.route("/health")
def health():
    return "ok"

@app.route("/api/data", methods=["POST"])
def handle_data():
    return process()

def process():
    pass
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := pyextractor.New()
	symbols, err := ext.ExtractSymbols("app.py", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")

	if len(eps) < 2 {
		t.Errorf("expected at least 2 entry points (Flask routes), got %d", len(eps))
		for _, ep := range eps {
			t.Logf("  entry point: %s", ep)
		}
	}
}

func TestFindEntryPoints_FastAPIRoute(t *testing.T) {
	source := `from fastapi import FastAPI

app = FastAPI()

@app.get("/items")
def list_items():
    return []

@app.post("/items")
async def create_item(item: dict):
    return item
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := pyextractor.New()
	symbols, err := ext.ExtractSymbols("main.py", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")

	if len(eps) < 2 {
		t.Errorf("expected at least 2 entry points (FastAPI routes), got %d", len(eps))
	}
}
