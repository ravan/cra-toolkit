package csharp_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/csharp"
)

func TestAnalyzer_Language(t *testing.T) {
	a := csharp.New()
	if lang := a.Language(); lang != "csharp" {
		t.Fatalf("expected 'csharp', got %q", lang)
	}
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestAnalyze_CSharpReachable(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "DataController.cs"), []byte(`using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace TestApp;

[ApiController]
[Route("[controller]")]
public class DataController : ControllerBase
{
    [HttpPost("deserialize")]
    public IActionResult Deserialize([FromBody] string payload)
    {
        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.Auto
        };
        var obj = JsonConvert.DeserializeObject(payload, settings);
        return Ok(obj);
    }
}
`))

	analyzer := csharp.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2024-21907",
		AffectedPURL: "pkg:nuget/Newtonsoft.Json@13.0.1",
		AffectedName: "Newtonsoft.Json",
		Symbols:      []string{"JsonConvert.DeserializeObject"},
		Language:     "csharp",
	}

	result, err := analyzer.Analyze(ctx, dir, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Reachable {
		t.Errorf("expected Reachable=true, got false; evidence: %s", result.Evidence)
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", result.Confidence)
	}
	if len(result.Symbols) == 0 {
		t.Error("expected at least one symbol in result")
	}
	if len(result.Paths) == 0 {
		t.Error("expected at least one call path in result")
	}
	if result.Evidence == "" {
		t.Error("expected non-empty evidence")
	}
	t.Logf("Evidence: %s", result.Evidence)
	for i, p := range result.Paths {
		t.Logf("Path %d: %s", i, p)
	}
}

func TestAnalyze_CSharpNotReachable(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "DataController.cs"), []byte(`using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace TestApp;

[ApiController]
[Route("[controller]")]
public class DataController : ControllerBase
{
    [HttpGet("serialize")]
    public IActionResult Serialize([FromQuery] string name)
    {
        var data = new { Name = name };
        var json = JsonConvert.SerializeObject(data);
        return Content(json, "application/json");
    }
}
`))

	analyzer := csharp.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2024-21907",
		AffectedPURL: "pkg:nuget/Newtonsoft.Json@13.0.1",
		AffectedName: "Newtonsoft.Json",
		Symbols:      []string{"JsonConvert.DeserializeObject"},
		Language:     "csharp",
	}

	result, err := analyzer.Analyze(ctx, dir, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Reachable {
		t.Errorf("expected Reachable=false, got true; evidence: %s", result.Evidence)
	}
	if len(result.Paths) != 0 {
		t.Errorf("expected 0 paths, got %d", len(result.Paths))
	}
}

func TestAnalyze_NoSourceFiles(t *testing.T) {
	dir := t.TempDir()

	analyzer := csharp.New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2024-21907",
		AffectedPURL: "pkg:nuget/Newtonsoft.Json@13.0.1",
		AffectedName: "Newtonsoft.Json",
		Symbols:      []string{"JsonConvert.DeserializeObject"},
		Language:     "csharp",
	}

	result, err := analyzer.Analyze(ctx, dir, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Reachable {
		t.Error("expected Reachable=false for empty directory")
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", result.Confidence)
	}
}

func TestIntegration_CSharpTreesitterReachable(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	sourceDir := filepath.Join(fixtureBase, "csharp-treesitter-reachable", "source")
	analyzer := csharp.New()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2024-21907",
		AffectedPURL: "pkg:nuget/Newtonsoft.Json@13.0.1",
		AffectedName: "Newtonsoft.Json",
		Symbols:      []string{"JsonConvert.DeserializeObject"},
		Language:     "csharp",
	}

	result, err := analyzer.Analyze(ctx, sourceDir, &finding)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if !result.Reachable {
		t.Errorf("expected Reachable=true; evidence: %s", result.Evidence)
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", result.Confidence)
	}
	if len(result.Paths) == 0 {
		t.Error("expected at least one call path")
	}
	if len(result.Symbols) == 0 {
		t.Error("expected at least one reached symbol")
	}

	t.Logf("Evidence: %s", result.Evidence)
	for i, p := range result.Paths {
		t.Logf("Path %d: %s", i, p)
	}
}

func TestIntegration_CSharpTreesitterNotReachable(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	sourceDir := filepath.Join(fixtureBase, "csharp-treesitter-not-reachable", "source")
	analyzer := csharp.New()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2024-21907",
		AffectedPURL: "pkg:nuget/Newtonsoft.Json@13.0.1",
		AffectedName: "Newtonsoft.Json",
		Symbols:      []string{"JsonConvert.DeserializeObject"},
		Language:     "csharp",
	}

	result, err := analyzer.Analyze(ctx, sourceDir, &finding)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if result.Reachable {
		t.Errorf("expected Reachable=false; evidence: %s", result.Evidence)
	}
	if len(result.Paths) != 0 {
		t.Errorf("expected 0 paths, got %d", len(result.Paths))
	}
}
