// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package javascript_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/javascript"
)

func TestAnalyzer_Language(t *testing.T) {
	a := javascript.New()
	if lang := a.Language(); lang != "javascript" {
		t.Fatalf("expected 'javascript', got %q", lang)
	}
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestAnalyze_JavaScriptReachable(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "app.js"), []byte(`const _ = require('lodash');
const express = require('express');
const app = express();

app.post('/render', (req, res) => {
    const compiled = _.template(req.body.template);
    res.send(compiled({ data: req.body.data }));
});

app.listen(3000);
`))

	analyzer := javascript.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2021-23337",
		AffectedPURL: "pkg:npm/lodash@4.17.20",
		AffectedName: "lodash",
		Symbols:      []string{"template"},
		Language:     "javascript",
	}

	result, err := analyzer.Analyze(ctx, dir, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Reachable {
		t.Error("expected Reachable=true, got false")
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

func TestAnalyze_JavaScriptNotReachable(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "app.js"), []byte(`const _ = require('lodash');
const express = require('express');
const app = express();

app.get('/users', (req, res) => {
    const users = [{ name: 'Alice' }, { name: 'Bob' }];
    const names = _.map(users, 'name');
    res.json(names);
});

app.listen(3000);
`))

	analyzer := javascript.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2021-23337",
		AffectedPURL: "pkg:npm/lodash@4.17.20",
		AffectedName: "lodash",
		Symbols:      []string{"template"},
		Language:     "javascript",
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

func TestAnalyze_TypeScriptReachable(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "app.ts"), []byte(`import * as _ from 'lodash';
import express from 'express';

const app = express();

app.post('/render', (req: any, res: any) => {
    const compiled = _.template(req.body.template);
    res.send(compiled({ data: req.body.data }));
});

app.listen(3000);
`))

	analyzer := javascript.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2021-23337",
		AffectedPURL: "pkg:npm/lodash@4.17.20",
		AffectedName: "lodash",
		Symbols:      []string{"template"},
		Language:     "javascript",
	}

	result, err := analyzer.Analyze(ctx, dir, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Reachable {
		t.Errorf("expected Reachable=true for TypeScript; evidence: %s", result.Evidence)
	}
	t.Logf("TypeScript Evidence: %s", result.Evidence)
}

func TestAnalyze_NoSourceFiles(t *testing.T) {
	dir := t.TempDir()

	analyzer := javascript.New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2021-23337",
		AffectedPURL: "pkg:npm/lodash@4.17.20",
		AffectedName: "lodash",
		Symbols:      []string{"template"},
		Language:     "javascript",
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

func TestIntegration_JavaScriptTreesitterReachable(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	sourceDir := filepath.Join(fixtureBase, "javascript-treesitter-reachable", "source")
	analyzer := javascript.New()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2021-23337",
		AffectedPURL: "pkg:npm/lodash@4.17.20",
		AffectedName: "lodash",
		Symbols:      []string{"template"},
		Language:     "javascript",
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

func TestIntegration_JavaScriptTreesitterNotReachable(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	sourceDir := filepath.Join(fixtureBase, "javascript-treesitter-not-reachable", "source")
	analyzer := javascript.New()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2021-23337",
		AffectedPURL: "pkg:npm/lodash@4.17.20",
		AffectedName: "lodash",
		Symbols:      []string{"template"},
		Language:     "javascript",
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
