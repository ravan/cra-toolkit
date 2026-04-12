# Java & C# Transitive LLM Judge Tests

## Problem

Java and C# transitive reachability analysis was delivered with integration tests but without LLM judgment tests. All other languages (Python, JavaScript, Rust, Ruby, PHP) have transitive LLM judge tests. This gap means we have no quality signal on whether the transitive analysis output for Java/C# is convincing enough for CRA compliance review.

## Design

Add `TestLLMJudge_JavaTransitiveReachability` and `TestLLMJudge_CSharpTransitiveReachability` following the established pattern from Rust/PHP/Ruby transitive LLM judge tests.

### Java Transitive LLM Judge Test

**Location:** `pkg/vex/reachability/java/llm_judge_test.go` (append to existing file)

**Test function:** `TestLLMJudge_JavaTransitiveReachability`

- Fixtures: `java-realworld-cross-package` (reachable) / `java-realworld-cross-package-safe` (safe)
- Fetcher: `transitive.MavenFetcher`
- Ecosystem key: `maven`
- Finding: `com.google.code.gson:gson@2.8.6`
- SBOM parser: `parseSBOMForJavaJudge` using `pkg:maven/` PURL prefix
- Prompt: generic transitive style — describes the vulnerable package, expected reachable chain (app → GsonWrapper.deserialize → Gson.fromJson), expected safe chain (no gson usage), asks LLM to score the 6 standard dimensions
- Threshold: 6/10 (consistent with all other transitive tests)
- Timeout: 5 minutes (consistent with other transitive tests that fetch real sources)

**SBOM parser:** `parseSBOMForJavaJudge(t, fixtureDir)` — parses `sbom.cdx.json`, filters components by `pkg:maven/` prefix, derives roots from metadata component's dependsOn, falls back to all maven packages as roots.

### C# Transitive LLM Judge Test

**Location:** `pkg/vex/reachability/csharp/llm_judge_test.go` (append to existing file)

**Test function:** `TestLLMJudge_CSharpTransitiveReachability`

- Fixtures: `csharp-realworld-cross-package` (reachable) / `csharp-realworld-cross-package-safe` (safe)
- Fetcher: `transitive.NuGetFetcher`
- Ecosystem key: `nuget`
- Finding: `Newtonsoft.Json@13.0.1`
- SBOM parser: `parseSBOMForCSharpJudge` using `pkg:nuget/` PURL prefix
- Prompt: generic transitive style — describes the vulnerable package, expected reachable chain (app → JsonConvert.DeserializeObject), expected safe chain (no JSON library usage), asks LLM to score the 6 standard dimensions
- Threshold: 6/10
- Timeout: 5 minutes

**SBOM parser:** `parseSBOMForCSharpJudge(t, fixtureDir)` — same pattern as Java, filters by `pkg:nuget/` prefix.

### Taskfile Update

Add two entries to `test:reachability:transitive:llmjudge`:
- `go test -race -count=1 -tags llmjudge -run TestLLMJudge_JavaTransitiveReachability -v ./pkg/vex/reachability/java/...`
- `go test -race -count=1 -tags llmjudge -run TestLLMJudge_CSharpTransitiveReachability -v ./pkg/vex/reachability/csharp/...`

### Scoring Dimensions (unchanged from existing tests)

All 6 dimensions scored 1-10:
1. `path_accuracy` — cross-package call paths real and correctly traced
2. `confidence_calibration` — confidence level reflects certainty of transitive analysis
3. `evidence_quality` — stitched call path evidence sufficient for CRA Article 14 VEX determination
4. `false_positive_rate` — safe case correctly identified as not-affected
5. `symbol_resolution` — cross-package symbols correctly resolved
6. `overall_quality` — would pass CRA market surveillance authority review

### Dependencies

- Existing imports: `transitive` package for `Analyzer`, `MavenFetcher`/`NuGetFetcher`, `Cache`, `LanguageFor`, `SBOMSummary`, `Package`
- Existing fixtures: `java-realworld-cross-package[-safe]`, `csharp-realworld-cross-package[-safe]`
- External: `gemini` CLI (test skipped if unavailable)

## Files Changed

| File | Change |
|------|--------|
| `pkg/vex/reachability/java/llm_judge_test.go` | Add `TestLLMJudge_JavaTransitiveReachability` + `parseSBOMForJavaJudge` |
| `pkg/vex/reachability/csharp/llm_judge_test.go` | Add `TestLLMJudge_CSharpTransitiveReachability` + `parseSBOMForCSharpJudge` |
| `Taskfile.yml` | Add Java/C# to `test:reachability:transitive:llmjudge` task |
