# Reachability Evidence Propagation

**Date:** 2026-04-05  
**Status:** Approved

## Problem

The tree-sitter reachability analyzers produce rich, structured call-chain data:

- `Paths []CallPath` — full call chains with `{Symbol, File, Line}` per node
- `Symbols []string` — vulnerable symbols confirmed reachable
- `Confidence` — High / Medium / Low
- `Evidence string` — human-readable summary

Today this data is serialized into a plain-text `Evidence` string inside the reachability filter. Every downstream consumer (PolicyKit, CSAF, Report, Evidence bundle) either ignores that string or cannot use it programmatically. Structured call-chain information never reaches any consumer in machine-usable form.

## Goal

Propagate structured call-chain evidence through the full pipeline so that:

1. **PolicyKit** can write OPA policies that enforce real reachability quality gates (confidence, depth, symbol, entry point)
2. **CSAF** advisory output carries structured call-path notes in CSAF-compliant form
3. **Art. 14 Report** renders a human-readable, auditor-facing evidence section per vulnerability
4. **Evidence bundle** captures complete per-vulnerability reasoning in a signed `vex_evidence.json` artifact

## Approach

Promote `CallPath` / `CallNode` to `pkg/formats/`, add first-class fields to `formats.VEXResult`, and update all four consumers to use the structured data.

## Data Model

### `pkg/formats/callpath.go` (new)

```go
type CallNode struct {
    Symbol string // qualified name, e.g. "com.example.App.process"
    File   string // repo-relative file path
    Line   int    // 1-based; 0 if unknown
}

type CallPath struct {
    Nodes []CallNode
}

func (p CallPath) String() string     // "A (f:10) -> B (f:20) -> C (f:30)"
func (p CallPath) Depth() int         // len(p.Nodes)
func (p CallPath) EntryPoint() CallNode // p.Nodes[0]
```

These replace the identically-named types in `pkg/vex/reachability/result.go`. The reachability package imports `formats` — no circular dependency is introduced.

### `formats.VEXResult` additions

```go
type VEXResult struct {
    // ... existing fields unchanged ...
    CVE           string
    ComponentPURL string
    Status        VEXStatus
    Justification Justification
    Confidence    Confidence
    ResolvedBy    string
    Evidence      string // human-readable; still populated

    // Reachability evidence — populated when ResolvedBy == "reachability_analysis"
    CallPaths    []CallPath // structured call chains; nil if not from reachability
    Symbols      []string   // vulnerable symbols confirmed reachable
    MaxCallDepth int        // max(path.Depth()) across all paths; 0 if none
    EntryFiles   []string   // deduplicated entry-point files (Nodes[0].File)
}
```

`MaxCallDepth` and `EntryFiles` are derived at filter time, not on-demand, so consumers get them for free.

### Reachability filter

`reachability_filter.go` populates the new fields when building `VEXResult`:

```go
vexResult.CallPaths    = result.Paths
vexResult.Symbols      = result.Symbols
vexResult.MaxCallDepth = maxDepth(result.Paths)
vexResult.EntryFiles   = entryFiles(result.Paths)
```

The existing `Evidence` string continues to be populated.

## PolicyKit

### OPA input (`pkg/policykit/input.go`)

`buildVEX` expands the VEX statement map:

```go
stmt := map[string]any{
    "cve":            v.CVE,
    "purl":           v.ComponentPURL,
    "status":         string(v.Status),
    "justification":  string(v.Justification),
    "confidence":     string(v.Confidence),
    "resolved_by":    v.ResolvedBy,
    "max_call_depth": v.MaxCallDepth,
    "entry_files":    v.EntryFiles,
    "symbols":        v.Symbols,
    "call_paths":     buildCallPathsInput(v.CallPaths), // [][]map{"symbol","file","line"}
}
```

### Example policy additions (`policies/annex1.rego`)

```rego
# Reachability not_affected requires High confidence
deny[msg] {
    s := input.vex.statements[_]
    s.status == "not_affected"
    s.resolved_by == "reachability_analysis"
    s.confidence != "High"
    msg := sprintf("CVE %v: reachability not_affected requires High confidence, got %v",
                   [s.cve, s.confidence])
}

# Affected reachability claim must have at least one call path
deny[msg] {
    s := input.vex.statements[_]
    s.status == "affected"
    s.resolved_by == "reachability_analysis"
    count(s.call_paths) == 0
    msg := sprintf("CVE %v: reachability affected claim has no supporting call paths", [s.cve])
}
```

### LLM judge

`pkg/policykit/llm_judge_test.go` gains assertions on:
- Confidence gate enforcement (correct deny for Medium/Low confidence reachability claims)
- Call path presence enforcement
- Policy reasoning quality over the new structured fields

## CSAF Advisory

### Notes structure (`pkg/csaf/notes.go`)

`buildReachabilityNotes(vexResult *formats.VEXResult) []note` is added and called from `buildVulnNotes`. It emits:

1. **One note per call path** — `category: "details"`, title `"Reachability Call Path N"`, text is a JSON blob:
   ```json
   {"call_path": [{"symbol":"...","file":"...","line":47},...], "depth": 3, "confidence": "High"}
   ```

2. **One summary note** — `category: "details"`, title `"Reachability Analysis Summary"`:
   ```
   confidence=High symbols=ObjectMapper.readValue max_depth=3 entry_files=src/api/UserController.java
   ```

CSAF viewers render the `Title` for humans. Consumers that parse the JSON body get full structured access within the CSAF schema.

### LLM judge

`pkg/csaf/llm_judge_test.go` adds assertions that reachability-sourced VEX results produce:
- Well-formed call path notes with valid JSON body
- Accurate symbol and depth metadata in the summary note
- Correct note count (one per path + one summary)

## Art. 14 Notification Report

### Rendered evidence block

Each reachability-assessed vulnerability in the notification gets:

```
Vulnerability: CVE-2024-1234
Component:     com.example:jackson-databind:2.13.0
Status:        not_affected
Justification: vulnerable_code_not_in_execute_path
Confidence:    High
Resolved by:   reachability_analysis

Reachability Evidence:
  Symbols: ObjectMapper.readValue
  Call paths (1):
    Path 1 (depth 3):
      com.example.api.UserController.createUser  [src/main/java/.../UserController.java:47]
        → com.example.service.UserService.parse  [src/main/java/.../UserService.java:112]
          → com.fasterxml.jackson.databind.ObjectMapper.readValue  [<dependency>:0]
```

For confirmed non-reachable (`not_affected` with no paths):

```
Reachability Evidence:
  No call path found from application entry points to vulnerable symbol.
  Symbols checked: ObjectMapper.readValue
  Confidence: High
```

### `pkg/report/` changes

- `parseVEXResults` returns `[]formats.VEXResult`; `CallPaths` come through automatically once `VEXResult` carries them
- `builder.go` adds `ReachabilityDetail(v formats.VEXResult) string` helper used in templates
- Templates gain `{{if eq .ResolvedBy "reachability_analysis"}}...{{end}}` block per VEX entry

### LLM judge

`pkg/report/llm_judge_test.go` adds assertions that rendered call paths are accurate, readable, and sufficient for an auditor to verify the claim without re-running the tool.

## Evidence Bundle

### New bundle artifact: `vex_evidence.json`

Emitted alongside the existing VEX file. Contains complete per-vulnerability reachability reasoning:

```go
type VEXEvidence struct {
    CVE           string          `json:"cve"`
    ComponentPURL string          `json:"component_purl"`
    Status        string          `json:"status"`
    Justification string          `json:"justification"`
    Confidence    string          `json:"confidence"`
    ResolvedBy    string          `json:"resolved_by"`
    Evidence      string          `json:"evidence"`
    Symbols       []string        `json:"symbols"`
    CallPaths     []CallPathEntry `json:"call_paths"`
    MaxCallDepth  int             `json:"max_call_depth"`
    EntryFiles    []string        `json:"entry_files"`
}

type CallPathEntry struct {
    Nodes []CallNodeEntry `json:"nodes"`
    Depth int             `json:"depth"`
}

type CallNodeEntry struct {
    Symbol string `json:"symbol"`
    File   string `json:"file"`
    Line   int    `json:"line"`
}
```

`VulnHandlingStats` gains `ReachabilityBased int` — count of results sourced from reachability analysis.

### `pkg/evidence/collect.go` changes

- `parseVEXData` returns `[]formats.VEXResult` (not a private `vexInfo` struct)
- New `buildVEXEvidence(results []formats.VEXResult) []VEXEvidence` maps to the bundle type
- Bundle writer emits `vex_evidence.json` as a new artifact, signed using the same mechanism as existing bundle artifacts

### LLM judge

`pkg/evidence/llm_judge_test.go` adds assertions that `vex_evidence.json` contains complete, accurate call paths for reachability-assessed vulnerabilities and that the evidence is sufficient for an independent compliance audit.

## Testing Strategy

All changes follow TDD:
1. Write failing tests first (unit + LLM judge additions)
2. Implement to make them pass
3. Run `task quality` before committing each package

### Integration test coverage

- **formats**: unit tests for `CallPath.String()`, `Depth()`, `EntryPoint()`; table-driven tests for `VEXResult` field population
- **vex/reachability filter**: existing tests extended to assert `CallPaths`, `Symbols`, `MaxCallDepth`, `EntryFiles` in output
- **policykit**: integration tests using real Rego evaluation asserting confidence gate and call path presence rules fire correctly
- **csaf**: integration tests asserting note count, JSON body validity, summary note content
- **report**: integration tests asserting evidence block rendered for reachability results; absent for non-reachability results
- **evidence**: integration tests asserting `vex_evidence.json` present in bundle, correct shape, signed

## Dependency Graph (unchanged)

```
pkg/formats           (no deps on other internal packages)
    ↑
pkg/vex/reachability  (imports formats)
    ↑
pkg/vex               (imports reachability, formats)
    ↑
pkg/csaf              (imports formats)
pkg/policykit         (imports formats)
pkg/report            (imports formats)
pkg/evidence          (imports formats)
```

No circular dependencies introduced.
