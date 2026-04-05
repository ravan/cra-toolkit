package php_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/php"
)

func TestAnalyzer_Language(t *testing.T) {
	a := php.New()
	if lang := a.Language(); lang != "php" {
		t.Fatalf("expected 'php', got %q", lang)
	}
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestAnalyze_PHPReachable(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "UserController.php"), []byte(`<?php
namespace App;

use GuzzleHttp\Client;

class UserController
{
    #[Route('/api/proxy', methods: ['GET'])]
    public function proxy(string $url): string
    {
        $client = new Client(['cookies' => true]);
        $response = $client->get($url);
        return (string) $response->getBody();
    }
}
`))

	analyzer := php.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2022-29248",
		AffectedPURL: "pkg:composer/guzzlehttp/guzzle@7.4.3",
		AffectedName: "guzzlehttp/guzzle",
		Symbols:      []string{"GuzzleHttp\\Client::get"},
		Language:     "php",
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

func TestAnalyze_PHPNotReachable(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "UserController.php"), []byte(`<?php
namespace App;

use GuzzleHttp\Client;

class UserController
{
    #[Route('/api/data', methods: ['GET'])]
    public function getData(): string
    {
        $ch = curl_init('https://api.example.com/data');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        return (string) curl_exec($ch);
    }
}
`))

	analyzer := php.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2022-29248",
		AffectedPURL: "pkg:composer/guzzlehttp/guzzle@7.4.3",
		AffectedName: "guzzlehttp/guzzle",
		Symbols:      []string{"GuzzleHttp\\Client::get"},
		Language:     "php",
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

	analyzer := php.New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2022-29248",
		AffectedPURL: "pkg:composer/guzzlehttp/guzzle@7.4.3",
		AffectedName: "guzzlehttp/guzzle",
		Symbols:      []string{"GuzzleHttp\\Client::get"},
		Language:     "php",
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

func TestIntegration_PHPTreesitterReachable(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	sourceDir := filepath.Join(fixtureBase, "php-treesitter-reachable", "source")
	analyzer := php.New()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2022-29248",
		AffectedPURL: "pkg:composer/guzzlehttp/guzzle@7.4.3",
		AffectedName: "guzzlehttp/guzzle",
		Symbols:      []string{"GuzzleHttp\\Client::get"},
		Language:     "php",
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

func TestIntegration_PHPTreesitterNotReachable(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	sourceDir := filepath.Join(fixtureBase, "php-treesitter-not-reachable", "source")
	analyzer := php.New()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2022-29248",
		AffectedPURL: "pkg:composer/guzzlehttp/guzzle@7.4.3",
		AffectedName: "guzzlehttp/guzzle",
		Symbols:      []string{"GuzzleHttp\\Client::get"},
		Language:     "php",
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
