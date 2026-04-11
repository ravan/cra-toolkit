# Showcase Docs Page — Design Spec

**Date:** 2026-04-07
**Location:** `site/docs/guides/showcase.md`
**Nav:** Guides > "Real-World Analysis — Grafana"

## Goal

Add a documentation page that shows real toolkit output from analyzing Grafana, with curated snippets, a reachability deep-dive using two Go programs, and a verification table linking every determination to public advisories. Also add Taskfile tasks to regenerate the showcase data.

## Two Deliverables

1. **`site/docs/guides/showcase.md`** — the docs page
2. **Taskfile showcase tasks** — `task showcase` to regenerate `showcase/` from scratch

---

## Deliverable 1: Docs Page

### Page Structure

```
# Real-World Analysis — Grafana

1. Intro & target project table
2. Pipeline overview (commands, brief)
3. Tool-by-tool results
   3a. VEX
   3b. PolicyKit
   3c. Report
   3d. CSAF
   3e. Evidence
4. Reachability deep-dive (Go pair)
5. Verification tables with external proof
6. Reproduce it yourself
```

### Section Details

#### 1. Intro

Summary table:

| Field | Value |
|-------|-------|
| Target project | Grafana v12.1.0-pre |
| SBOM components | 8,301 |
| Grype matches | 40 |
| Trivy findings | 45 |
| SBOM tool | syft 1.42.3 |
| Scanners | grype 0.110.0, trivy |

One paragraph explaining: this page shows real output from running the toolkit against a real project. Every determination is verified against public advisory databases. Links to the `showcase/` folder in the repo for full files.

#### 2. Pipeline Overview

The commands used, as bash code blocks. Brief — one block per tool, matching what's in the Taskfile. Link to `guides/workflow.md` for detailed explanations of each step.

#### 3a. VEX

Show two curated JSON snippets:

**Snippet 1 — not_affected (version filter):**
The `qs@6.14.1` / CVE-2025-15284 statement. Shows `status: "not_affected"`, `justification: "vulnerable_code_not_present"`, and `impact_statement` explaining the version comparison.

**Snippet 2 — under_investigation:**
The `lodash@4.17.23` / CVE-2026-4800 statement. Shows `status: "under_investigation"` with impact statement about manual review.

Plain-English explanation: the toolkit automatically filtered out CVEs where the installed version is at or above the fix. For others, it flags them for further analysis.

#### 3b. PolicyKit

Summary table: 5 PASS, 3 FAIL, 2 SKIP, 8 HUMAN.

**Snippet 1 — FAIL (KEV match):**
The CRA-AI-2.1 result showing `kev_matches: ["CVE-2025-30066"]`. Explain: this is the tj-actions supply chain attack, confirmed in CISA KEV — the toolkit correctly flags it.

**Snippet 2 — PASS (support period):**
The CRA-AI-4.1 result showing `support_years: 5`. Brief.

Explain the 8 HUMAN results: CRA Annex I requirements like "secure by default" and "data minimisation" cannot be evaluated by machines — the toolkit correctly routes them for human review.

#### 3c. Report

Use the markdown output. Show the early-warning stage in a collapsible block, then a brief comparison showing how the same CVE gains detail across the 3 stages (early-warning: just CVE ID + severity → notification: adds description + corrective actions → final-report: adds root cause + preventive measures).

#### 3d. CSAF

One snippet: a single vulnerability entry from the CSAF advisory showing `product_tree` mapping, `scores` (CVSS), and `remediations`. Brief section — CSAF is a standard format.

#### 3e. Evidence

Show the `completeness.md` content (which Annex VII sections have artifacts, which are gaps). Show a snippet of `manifest.sha256`. Explain: the 52% score is because optional manufacturer documents weren't supplied — the toolkit is transparent about gaps.

#### 4. Reachability Deep-Dive

This is the showcase centerpiece. Uses CVE-2022-32149 (golang.org/x/text ReDoS).

**Intro:** Both programs depend on `golang.org/x/text@v0.3.7`. A traditional scanner flags both. The CRA Toolkit's reachability analysis distinguishes them.

**Tabbed content block** (MkDocs Material `content.tabs`):

=== "Reachable — affected"

Show `go-realworld-direct-call/source/main.go` (calls `language.ParseAcceptLanguage(os.Args[1])` with user input). Show the VEX command. Show the output snippet: `status: "affected"`, confidence: high.

Explain: the toolkit traces that `main()` calls `language.ParseAcceptLanguage()` which internally calls the vulnerable `parse()` function, with untrusted user input from `os.Args`.

=== "Not Reachable — not_affected"

Show `go-realworld-imported-unused/source/main.go` (only uses `language.English` constant + `cases.Title()`). Show the VEX command. Show the output snippet: `status: "not_affected"`, confidence: high.

Explain: the toolkit sees the `language` package is imported but the vulnerable `Parse()` / `ParseAcceptLanguage()` functions are never called. Only the `English` constant is used.

**After the tabs:** A brief note on supported languages (Go, Rust, Python, JavaScript, Java, C#, PHP, Ruby) with link to the VEX tool page for details.

#### 5. Verification Tables

Three tables, each with a summary row:

**Table 1 — VEX Not-Affected Determinations (6/6 verified)**

| CVE | Component | Toolkit Justification | Advisory Confirms | Source |
|-----|-----------|----------------------|-------------------|--------|

Each "Source" cell is a markdown link to the GHSA/NVD page.

**Table 2 — Scanner Findings Verified (7/7 verified)**

| CVE | Component@Version | Affected Range | Fix Version | Source |

**Table 3 — Policy Results Verified (5/5 verified)**

| Rule | Status | Evidence | Confirmed | Source |

Below: note explaining what `under_investigation` means, why HUMAN results are correct by design.

#### 6. Reproduce It Yourself

```bash
task showcase
```

Brief explanation that this regenerates everything. Link to the `showcase/` folder for full output files.

### Formatting Conventions

Follow existing docs patterns:
- `!!! abstract "CRA Reference"` admonition at top linking to relevant CRA articles
- `!!! tip` for cross-references to other pages
- Code blocks with `bash` or `json` language tags
- Collapsible `??? info` for long output blocks
- Tabbed content for the reachability comparison
- Tables for structured data

---

## Deliverable 2: Taskfile Showcase Tasks

Added to `Taskfile.yml`:

### Variables

```yaml
vars:
  SHOWCASE_DIR: showcase
  SHOWCASE_TARGET_REPO: https://github.com/grafana/grafana.git
  SHOWCASE_TARGET_NAME: grafana
  SHOWCASE_CLONE_DIR: /tmp/cra-showcase-grafana
```

### Tasks

**`showcase`** (alias for `showcase:all`)
- desc: "Generate the full showcase with real-world analysis"
- deps: [build]
- cmds: runs subtasks in order

**`showcase:clean`**
- Removes `showcase/` except `00-inputs/product-config.yaml` and `00-inputs/product-config-policykit.yaml`

**`showcase:inputs`**
- Clones Grafana (shallow), runs `syft` and `grype` and `trivy`
- Writes to `showcase/00-inputs/`
- `status:` check — skips if `showcase/00-inputs/sbom.cdx.json` already exists (avoids re-cloning)
- Cleans up the clone after scanning

**`showcase:vex`**
- Runs `cra vex` twice (OpenVEX + CSAF output formats)
- Writes to `showcase/01-vex/`

**`showcase:reachability`**
- Runs `cra vex` against `testdata/integration/go-realworld-direct-call/` with `--source-dir`
- Runs `cra vex` against `testdata/integration/go-realworld-imported-unused/` with `--source-dir`
- Writes to `showcase/01-vex/reachability-affected.openvex.json` and `showcase/01-vex/reachability-not-affected.openvex.json`

**`showcase:policykit`**
- Runs `cra policykit` twice (JSON + markdown)
- Writes to `showcase/02-policykit/`

**`showcase:report`**
- Runs `cra report` for all 3 stages, both formats (6 runs total)
- Writes to `showcase/03-report/{early-warning,notification,final-report}/`

**`showcase:csaf`**
- Runs `cra csaf`
- Writes to `showcase/04-csaf/`

**`showcase:evidence`**
- Runs `cra evidence` with all artifacts + `--archive`
- Writes to `showcase/05-evidence/`

**`showcase:all`**
- desc: "Generate complete showcase (requires syft, grype, trivy)"
- cmds: runs subtasks in sequence: clean → inputs → vex → reachability → policykit → report → csaf → evidence

---

## Files Changed

| File | Change |
|------|--------|
| `site/docs/guides/showcase.md` | New file — the showcase docs page |
| `site/mkdocs.yml` | Add nav entry: `"Real-World Analysis": guides/showcase.md` under Guides |
| `Taskfile.yml` | Add showcase task group (showcase, showcase:clean, showcase:inputs, showcase:vex, showcase:reachability, showcase:policykit, showcase:report, showcase:csaf, showcase:evidence, showcase:all) |
| `showcase/01-vex/reachability-affected.openvex.json` | New — VEX output for direct-call fixture |
| `showcase/01-vex/reachability-not-affected.openvex.json` | New — VEX output for imported-unused fixture |

## Out of Scope

- Automated VERIFICATION.md regeneration (requires web lookups — not automatable in Taskfile)
- Additional target projects beyond Grafana
- Docs page for the verification methodology itself
