package java_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/java"
)

func TestAnalyzer_Language(t *testing.T) {
	a := java.New()
	if lang := a.Language(); lang != "java" {
		t.Fatalf("expected 'java', got %q", lang)
	}
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestAnalyze_JavaReachable(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "App.java"), []byte(`package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main(String[] args) {
        String input = args[0];
        logger.info("Input: {}", input);
    }
}
`))

	analyzer := java.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2021-44228",
		AffectedPURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		AffectedName: "log4j-core",
		Symbols:      []string{"logger.info"},
		Language:     "java",
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

func TestAnalyze_JavaNotReachable(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "App.java"), []byte(`package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main(String[] args) {
        // Only uses System.out, never logger.info
        System.out.println("Processing: " + args[0]);
    }
}
`))

	analyzer := java.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2021-44228",
		AffectedPURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		AffectedName: "log4j-core",
		Symbols:      []string{"logger.info"},
		Language:     "java",
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

	analyzer := java.New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2021-44228",
		AffectedPURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		AffectedName: "log4j-core",
		Symbols:      []string{"logger.info"},
		Language:     "java",
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

func TestIntegration_JavaTreesitterReachable(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	sourceDir := filepath.Join(fixtureBase, "java-treesitter-reachable", "source")
	analyzer := java.New()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2021-44228",
		AffectedPURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		AffectedName: "log4j-core",
		Symbols:      []string{"logger.info"},
		Language:     "java",
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

func TestIntegration_JavaTreesitterNotReachable(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	sourceDir := filepath.Join(fixtureBase, "java-treesitter-not-reachable", "source")
	analyzer := java.New()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2021-44228",
		AffectedPURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		AffectedName: "log4j-core",
		Symbols:      []string{"logger.info"},
		Language:     "java",
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
