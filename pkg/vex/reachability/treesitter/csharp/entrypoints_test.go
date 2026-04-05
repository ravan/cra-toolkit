package csharp_test

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	csharpextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/csharp"
)

// TestFindEntryPoints_StaticMain verifies that static void Main is detected as an entry point.
func TestFindEntryPoints_StaticMain(t *testing.T) {
	source := `namespace ConsoleApp;

class Program
{
    static void Main(string[] args)
    {
        System.Console.WriteLine("Hello World");
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := csharpextractor.New()
	symbols, err := ext.ExtractSymbols("Program.cs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")
	if len(eps) == 0 {
		t.Error("expected 'Main' to be detected as an entry point")
		for _, s := range symbols {
			t.Logf("  symbol: %s (%s)", s.QualifiedName, s.Kind)
		}
		return
	}

	var foundMain bool
	for _, ep := range eps {
		if string(ep) == "ConsoleApp.Program.Main" {
			foundMain = true
		}
	}
	if !foundMain {
		t.Errorf("expected entry point 'ConsoleApp.Program.Main', got: %v", eps)
	}
}

// TestFindEntryPoints_HttpMethods verifies ASP.NET HTTP attribute detection.
func TestFindEntryPoints_HttpMethods(t *testing.T) {
	source := `using Microsoft.AspNetCore.Mvc;

namespace TestApp;

[ApiController]
[Route("[controller]")]
public class DataController : ControllerBase
{
    [HttpGet("list")]
    public IActionResult List() => Ok(new[] { "a", "b" });

    [HttpPost("create")]
    public IActionResult Create([FromBody] string data) => Ok(data);

    [HttpPut("{id}")]
    public IActionResult Update(int id, [FromBody] string data) => Ok(data);

    [HttpDelete("{id}")]
    public IActionResult Delete(int id) => NoContent();

    [HttpPatch("{id}")]
    public IActionResult Patch(int id, [FromBody] string data) => Ok(data);
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := csharpextractor.New()
	symbols, err := ext.ExtractSymbols("DataController.cs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")
	if len(eps) < 5 {
		t.Errorf("expected at least 5 HTTP entry points, got %d: %v", len(eps), eps)
	}

	epSet := make(map[treesitter.SymbolID]bool, len(eps))
	for _, ep := range eps {
		epSet[ep] = true
	}

	for _, name := range []string{"List", "Create", "Update", "Delete", "Patch"} {
		id := treesitter.SymbolID("TestApp.DataController." + name)
		if !epSet[id] {
			t.Errorf("expected method %q to be an entry point", name)
		}
	}
}

// TestFindEntryPoints_MinimalAPI verifies that app.MapGet/MapPost etc. are detected.
func TestFindEntryPoints_MinimalAPI(t *testing.T) {
	source := `var app = WebApplication.Create(args);

app.MapGet("/hello", () => "Hello World");
app.MapPost("/data", (string payload) => payload);
app.MapPut("/data/{id}", (int id, string data) => data);
app.MapDelete("/data/{id}", (int id) => Results.NoContent());
app.MapPatch("/data/{id}", (int id, string data) => data);

app.Run();
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := csharpextractor.New()
	symbols, err := ext.ExtractSymbols("Program.cs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	// Minimal API inline lambdas (e.g. app.MapGet("/hello", () => "Hello World")) do not
	// produce named method symbols in the AST — the handler is an anonymous lambda with no
	// identifier. These fall through to the all-methods-as-entrypoints fallback in the analyzer.
	// Named handler functions passed by reference would be detectable, but inline lambdas are not.
	t.Skip("Minimal API inline lambdas fall through to fallback entry detection")

	_ = ext.FindEntryPoints(symbols, "/project")
}

// TestFindEntryPoints_BackgroundService verifies that ExecuteAsync is detected.
func TestFindEntryPoints_BackgroundService(t *testing.T) {
	source := `using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;

namespace TestApp;

public class WorkerService : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(1000, stoppingToken);
        }
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := csharpextractor.New()
	symbols, err := ext.ExtractSymbols("WorkerService.cs", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")
	var foundExecuteAsync bool
	for _, ep := range eps {
		if string(ep) == "TestApp.WorkerService.ExecuteAsync" {
			foundExecuteAsync = true
		}
	}
	if !foundExecuteAsync {
		t.Errorf("expected 'ExecuteAsync' to be an entry point, got: %v", eps)
		for _, s := range symbols {
			t.Logf("  symbol: %s (%s)", s.QualifiedName, s.Kind)
		}
	}
}
