# Java & C# Transitive LLM Judge Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add transitive LLM judge tests for Java and C# to match the coverage already present for Python, JavaScript, Rust, Ruby, and PHP.

**Architecture:** Append a `TestLLMJudge_*TransitiveReachability` function and a `parseSBOMFor*Judge` helper to each language's existing `llm_judge_test.go`. Each test instantiates the transitive `Analyzer` with the real fetcher (MavenFetcher / NuGetFetcher), runs it against the `realworld-cross-package` and `realworld-cross-package-safe` fixtures, and sends the analysis output to the `gemini` CLI for scoring across 6 dimensions at threshold 6/10.

**Tech Stack:** Go test (`//go:build llmjudge`), `transitive` package (`Analyzer`, `MavenFetcher`, `NuGetFetcher`, `Cache`, `LanguageFor`), `gemini` CLI, CycloneDX SBOM fixtures.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `pkg/vex/reachability/java/llm_judge_test.go` | Modify (append) | Add `TestLLMJudge_JavaTransitiveReachability` + `parseSBOMForJavaJudge` |
| `pkg/vex/reachability/csharp/llm_judge_test.go` | Modify (append) | Add `TestLLMJudge_CSharpTransitiveReachability` + `parseSBOMForCSharpJudge` |
| `Taskfile.yml` | Modify (line 123) | Add Java/C# entries to `test:reachability:transitive:llmjudge` |

---

### Task 1: Add Java transitive LLM judge test

**Files:**
- Modify: `pkg/vex/reachability/java/llm_judge_test.go` (append after line 181)

- [ ] **Step 1: Add the transitive import**

The file already imports `"github.com/ravan/cra-toolkit/pkg/formats"` and `"github.com/ravan/cra-toolkit/pkg/vex/reachability/java"`. Add the `transitive` import:

```go
"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive"
```

- [ ] **Step 2: Add `TestLLMJudge_JavaTransitiveReachability` and `parseSBOMForJavaJudge`**

Append the following after the `writeSourceFiles` function (after line 181):

```go
func TestLLMJudge_JavaTransitiveReachability(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	reachableDir := filepath.Join(fixtureBase, "java-realworld-cross-package")
	notReachableDir := filepath.Join(fixtureBase, "java-realworld-cross-package-safe")

	summary := parseSBOMForJavaJudge(t, reachableDir)

	cache := transitive.NewCache(t.TempDir())
	fetcher := &transitive.MavenFetcher{Cache: cache}
	lang, langErr := transitive.LanguageFor("java")
	if langErr != nil {
		t.Fatalf("LanguageFor(java): %v", langErr)
	}
	ta := &transitive.Analyzer{
		Config:   transitive.DefaultConfig(),
		Language: lang,
		Fetchers: map[string]transitive.Fetcher{"maven": fetcher},
	}

	finding := &formats.Finding{
		AffectedName:    "com.google.code.gson:gson",
		AffectedVersion: "2.8.6",
	}

	reachableResult, err := ta.Analyze(ctx, summary, finding, filepath.Join(reachableDir, "source"))
	if err != nil {
		t.Fatalf("Analyze reachable: %v", err)
	}

	notReachableResult, err := ta.Analyze(ctx, summary, finding, filepath.Join(notReachableDir, "source"))
	if err != nil {
		t.Fatalf("Analyze not-reachable: %v", err)
	}

	var pathStrs []string
	for _, p := range reachableResult.Paths {
		pathStrs = append(pathStrs, p.String())
	}

	prompt := fmt.Sprintf(`You are a security engineering judge evaluating a transitive dependency reachability analyzer for CRA (Cyber Resilience Act) compliance. The analyzer uses tree-sitter AST parsing for Java source code.

VULNERABILITY: CVE-2022-25647 in com.google.code.gson:gson@2.8.6.
VULNERABLE PACKAGE: com.google.code.gson:gson@2.8.6 (direct dependency)
EXPECTED REACHABLE CHAIN: App.main() → GsonWrapper.deserialize() → Gson.fromJson()
EXPECTED SAFE CHAIN: App.main() → System.out.println() [does NOT call Gson — no gson usage at all]

REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%%v, Confidence=%%s, Degradations=%%v
Call paths found: %s
Evidence: %s

NOT-REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%%v, Confidence=%%s, Degradations=%%v
Evidence: %s

Score the transitive Java analyzer (1-10 each):
1. path_accuracy: Are the reported cross-package call paths real and correctly tracing through GsonWrapper to Gson.fromJson?
2. confidence_calibration: Does the confidence level correctly reflect the certainty of transitive Java analysis?
3. evidence_quality: Is the stitched call path evidence sufficient for a VEX determination under CRA Article 14?
4. false_positive_rate: Is the not-reachable case (no gson usage) correctly identified as not-affected?
5. symbol_resolution: Are the cross-package symbols correctly resolved (GsonWrapper.deserialize → Gson.fromJson)?
6. overall_quality: Would this analysis pass a CRA market surveillance authority's review?

Respond ONLY with valid JSON:
{"path_accuracy": N, "confidence_calibration": N, "evidence_quality": N, "false_positive_rate": N, "symbol_resolution": N, "overall_quality": N, "reasoning": "brief explanation"}`,
		filepath.Join(reachableDir, "source"),
		strings.Join(pathStrs, "; "),
		reachableResult.Evidence,
		filepath.Join(notReachableDir, "source"),
		notReachableResult.Evidence,
	)

	prompt = fmt.Sprintf(prompt,
		reachableResult.Reachable, reachableResult.Confidence, reachableResult.Degradations,
		notReachableResult.Reachable, notReachableResult.Confidence, notReachableResult.Degradations,
	)

	cmd := exec.Command(geminiPath, "--yolo", "-p", prompt) //nolint:gosec
	var geminiOut bytes.Buffer
	cmd.Stdout = &geminiOut
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gemini CLI error: %v", err)
	}

	responseText := geminiOut.String()
	jsonStart := strings.Index(responseText, "{")
	jsonEnd := strings.LastIndex(responseText, "}")
	if jsonStart == -1 || jsonEnd == -1 {
		t.Fatalf("no JSON in gemini response: %s", responseText)
	}

	var scores reachabilityScores
	if err := json.Unmarshal([]byte(responseText[jsonStart:jsonEnd+1]), &scores); err != nil {
		t.Fatalf("parse scores: %v\nresponse: %s", err, responseText)
	}

	t.Logf("Java Transitive LLM Scores: path=%d, confidence=%d, evidence=%d, fp=%d, symbol=%d, overall=%d",
		scores.PathAccuracy, scores.ConfidenceCalibration, scores.EvidenceQuality,
		scores.FalsePositiveRate, scores.SymbolResolution, scores.OverallQuality)
	t.Logf("Reasoning: %s", scores.Reasoning)

	threshold := 6 // lower threshold for transitive (harder problem)
	dimensions := map[string]int{
		"path_accuracy":          scores.PathAccuracy,
		"confidence_calibration": scores.ConfidenceCalibration,
		"evidence_quality":       scores.EvidenceQuality,
		"false_positive_rate":    scores.FalsePositiveRate,
		"symbol_resolution":      scores.SymbolResolution,
		"overall_quality":        scores.OverallQuality,
	}
	for dim, score := range dimensions {
		if score < threshold {
			t.Errorf("%s: score %d < threshold %d", dim, score, threshold)
		}
	}
}

// parseSBOMForJavaJudge builds a minimal SBOMSummary from the fixture's SBOM file.
func parseSBOMForJavaJudge(t *testing.T, fixtureDir string) *transitive.SBOMSummary {
	t.Helper()
	sbomPath := filepath.Join(fixtureDir, "sbom.cdx.json")
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}

	var doc struct {
		Metadata struct {
			Component struct {
				BOMRef string `json:"bom-ref"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			BOMRef  string `json:"bom-ref"`
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse sbom: %v", err)
	}

	prefix := "pkg:maven/"
	var pkgs []transitive.Package
	for _, c := range doc.Components {
		if !strings.HasPrefix(c.PURL, prefix) {
			continue
		}
		pkgs = append(pkgs, transitive.Package{Name: c.Name, Version: c.Version})
	}

	var roots []string
	for _, p := range pkgs {
		roots = append(roots, p.Name)
	}

	return &transitive.SBOMSummary{Packages: pkgs, Roots: roots}
}
```

- [ ] **Step 3: Verify the file compiles**

Run: `go build -tags llmjudge ./pkg/vex/reachability/java/...`
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add pkg/vex/reachability/java/llm_judge_test.go
git commit -m "test(transitive): add Java transitive LLM judge test"
```

---

### Task 2: Add C# transitive LLM judge test

**Files:**
- Modify: `pkg/vex/reachability/csharp/llm_judge_test.go` (append after line 181)

- [ ] **Step 1: Add the transitive import**

The file already imports `"github.com/ravan/cra-toolkit/pkg/formats"` and `"github.com/ravan/cra-toolkit/pkg/vex/reachability/csharp"`. Add the `transitive` import:

```go
"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive"
```

- [ ] **Step 2: Add `TestLLMJudge_CSharpTransitiveReachability` and `parseSBOMForCSharpJudge`**

Append the following after the `writeSourceFiles` function (after line 181):

```go
func TestLLMJudge_CSharpTransitiveReachability(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	reachableDir := filepath.Join(fixtureBase, "csharp-realworld-cross-package")
	notReachableDir := filepath.Join(fixtureBase, "csharp-realworld-cross-package-safe")

	summary := parseSBOMForCSharpJudge(t, reachableDir)

	cache := transitive.NewCache(t.TempDir())
	fetcher := &transitive.NuGetFetcher{Cache: cache}
	lang, langErr := transitive.LanguageFor("csharp")
	if langErr != nil {
		t.Fatalf("LanguageFor(csharp): %v", langErr)
	}
	ta := &transitive.Analyzer{
		Config:   transitive.DefaultConfig(),
		Language: lang,
		Fetchers: map[string]transitive.Fetcher{"nuget": fetcher},
	}

	finding := &formats.Finding{
		AffectedName:    "Newtonsoft.Json",
		AffectedVersion: "13.0.1",
	}

	reachableResult, err := ta.Analyze(ctx, summary, finding, filepath.Join(reachableDir, "source"))
	if err != nil {
		t.Fatalf("Analyze reachable: %v", err)
	}

	notReachableResult, err := ta.Analyze(ctx, summary, finding, filepath.Join(notReachableDir, "source"))
	if err != nil {
		t.Fatalf("Analyze not-reachable: %v", err)
	}

	var pathStrs []string
	for _, p := range reachableResult.Paths {
		pathStrs = append(pathStrs, p.String())
	}

	prompt := fmt.Sprintf(`You are a security engineering judge evaluating a transitive dependency reachability analyzer for CRA (Cyber Resilience Act) compliance. The analyzer uses tree-sitter AST parsing for C# source code.

VULNERABILITY: CVE-2024-21907 in Newtonsoft.Json@13.0.1.
VULNERABLE PACKAGE: Newtonsoft.Json@13.0.1 (direct dependency)
EXPECTED REACHABLE CHAIN: App.Main() → JsonConvert.DeserializeObject()
EXPECTED SAFE CHAIN: App.Main() → Console.WriteLine() [does NOT call Newtonsoft.Json — no JSON library usage at all]

REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%%v, Confidence=%%s, Degradations=%%v
Call paths found: %s
Evidence: %s

NOT-REACHABLE PROJECT (source: %s):
Analysis result: Reachable=%%v, Confidence=%%s, Degradations=%%v
Evidence: %s

Score the transitive C# analyzer (1-10 each):
1. path_accuracy: Are the reported cross-package call paths real and correctly tracing through to JsonConvert.DeserializeObject?
2. confidence_calibration: Does the confidence level correctly reflect the certainty of transitive C# analysis?
3. evidence_quality: Is the stitched call path evidence sufficient for a VEX determination under CRA Article 14?
4. false_positive_rate: Is the not-reachable case (no JSON usage) correctly identified as not-affected?
5. symbol_resolution: Are the cross-package symbols correctly resolved (JsonConvert.DeserializeObject)?
6. overall_quality: Would this analysis pass a CRA market surveillance authority's review?

Respond ONLY with valid JSON:
{"path_accuracy": N, "confidence_calibration": N, "evidence_quality": N, "false_positive_rate": N, "symbol_resolution": N, "overall_quality": N, "reasoning": "brief explanation"}`,
		filepath.Join(reachableDir, "source"),
		strings.Join(pathStrs, "; "),
		reachableResult.Evidence,
		filepath.Join(notReachableDir, "source"),
		notReachableResult.Evidence,
	)

	prompt = fmt.Sprintf(prompt,
		reachableResult.Reachable, reachableResult.Confidence, reachableResult.Degradations,
		notReachableResult.Reachable, notReachableResult.Confidence, notReachableResult.Degradations,
	)

	cmd := exec.Command(geminiPath, "--yolo", "-p", prompt) //nolint:gosec
	var geminiOut bytes.Buffer
	cmd.Stdout = &geminiOut
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gemini CLI error: %v", err)
	}

	responseText := geminiOut.String()
	jsonStart := strings.Index(responseText, "{")
	jsonEnd := strings.LastIndex(responseText, "}")
	if jsonStart == -1 || jsonEnd == -1 {
		t.Fatalf("no JSON in gemini response: %s", responseText)
	}

	var scores reachabilityScores
	if err := json.Unmarshal([]byte(responseText[jsonStart:jsonEnd+1]), &scores); err != nil {
		t.Fatalf("parse scores: %v\nresponse: %s", err, responseText)
	}

	t.Logf("C# Transitive LLM Scores: path=%d, confidence=%d, evidence=%d, fp=%d, symbol=%d, overall=%d",
		scores.PathAccuracy, scores.ConfidenceCalibration, scores.EvidenceQuality,
		scores.FalsePositiveRate, scores.SymbolResolution, scores.OverallQuality)
	t.Logf("Reasoning: %s", scores.Reasoning)

	threshold := 6 // lower threshold for transitive (harder problem)
	dimensions := map[string]int{
		"path_accuracy":          scores.PathAccuracy,
		"confidence_calibration": scores.ConfidenceCalibration,
		"evidence_quality":       scores.EvidenceQuality,
		"false_positive_rate":    scores.FalsePositiveRate,
		"symbol_resolution":      scores.SymbolResolution,
		"overall_quality":        scores.OverallQuality,
	}
	for dim, score := range dimensions {
		if score < threshold {
			t.Errorf("%s: score %d < threshold %d", dim, score, threshold)
		}
	}
}

// parseSBOMForCSharpJudge builds a minimal SBOMSummary from the fixture's SBOM file.
func parseSBOMForCSharpJudge(t *testing.T, fixtureDir string) *transitive.SBOMSummary {
	t.Helper()
	sbomPath := filepath.Join(fixtureDir, "sbom.cdx.json")
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}

	var doc struct {
		Metadata struct {
			Component struct {
				BOMRef string `json:"bom-ref"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			BOMRef  string `json:"bom-ref"`
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse sbom: %v", err)
	}

	prefix := "pkg:nuget/"
	var pkgs []transitive.Package
	for _, c := range doc.Components {
		if !strings.HasPrefix(c.PURL, prefix) {
			continue
		}
		pkgs = append(pkgs, transitive.Package{Name: c.Name, Version: c.Version})
	}

	var roots []string
	for _, p := range pkgs {
		roots = append(roots, p.Name)
	}

	return &transitive.SBOMSummary{Packages: pkgs, Roots: roots}
}
```

- [ ] **Step 3: Verify the file compiles**

Run: `go build -tags llmjudge ./pkg/vex/reachability/csharp/...`
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add pkg/vex/reachability/csharp/llm_judge_test.go
git commit -m "test(transitive): add C# transitive LLM judge test"
```

---

### Task 3: Wire Java and C# into Taskfile

**Files:**
- Modify: `Taskfile.yml` (line 123, after the PHP entry in `test:reachability:transitive:llmjudge`)

- [ ] **Step 1: Add Java and C# entries**

After line 123 (`- go test ... PHPTransitiveReachability ...`), add:

```yaml
      - go test -race -count=1 -tags llmjudge -run TestLLMJudge_JavaTransitiveReachability -v ./pkg/vex/reachability/java/...
      - go test -race -count=1 -tags llmjudge -run TestLLMJudge_CSharpTransitiveReachability -v ./pkg/vex/reachability/csharp/...
```

- [ ] **Step 2: Verify Taskfile syntax**

Run: `task --list | grep transitive:llmjudge`
Expected: `test:reachability:transitive:llmjudge` appears in the list

- [ ] **Step 3: Commit**

```bash
git add Taskfile.yml
git commit -m "chore: add Java/C# transitive LLM judge tests to Taskfile"
```
