# Documentation Site Design Spec

**Date:** 2026-04-05  
**Status:** Approved  
**Scope:** Comprehensive MkDocs Material documentation site for the SUSE CRA Compliance Toolkit

---

## 1. Goals

- Create a production-grade documentation site that serves as both a **EU CRA reference** and a **toolkit integration guide**
- Serve two audiences equally: compliance/legal stakeholders and DevOps/security engineers
- Build trust and drive adoption through accuracy, completeness, and visual clarity
- Generate SVG diagrams to visually convey CRA concepts and tool architectures
- Show how the five tools work together and how to integrate them into CI/CD pipelines

## 2. Site Location & Separation

The MkDocs site source lives at **`site/`** (top-level directory), completely separate from `docs/`.

- `site/mkdocs.yml` — MkDocs configuration
- `site/docs/` — all public documentation pages
- `docs/` — remains the internal workspace (strategy, specs, plans, CRA PDF, call-graph ideas)

This prevents accidental publication of internal documents.

The existing `mkdocs.yml`, `pyproject.toml`, and `uv.lock` at the repo root are relocated into `site/`. The old root-level `mkdocs.yml` is removed.

## 3. Directory Structure

```
site/
  mkdocs.yml
  docs/
    index.md                          # Problem-first landing page
    cra/
      overview.md                     # Visual CRA structure explainer
      article-14.md                   # Vulnerability notification obligations
      annex-i.md                      # Essential cybersecurity requirements
      annex-vii.md                    # Technical documentation & conformity
      compliance-mapping.md           # CRA requirement -> tool -> artifact matrix
    tools/
      overview.md                     # Pipeline diagram, how tools compose
      vex.md                          # VEX determination pipeline
      policykit.md                    # Policy evaluation engine
      report.md                       # Article 14 notifications
      evidence.md                     # Evidence bundling & signing
      csaf.md                         # CSAF advisory generation
    ecosystem/
      index.md                        # Visual landscape overview
      standards.md                    # OpenVEX, CSAF 2.0, CycloneDX, SPDX, SLSA, SARIF
      scanners.md                     # Grype, Trivy, SARIF producers
      infrastructure.md              # OPA/Rego, Cosign, tree-sitter
    guides/
      ci-cd.md                        # GitHub Actions reference pipeline
      workflow.md                     # End-to-end compliance workflow
    assets/
      diagrams/                       # All SVG diagrams (11 total)
        cra-overview.svg
        cra-article14-timeline.svg
        cra-annex-mapping.svg
        tool-pipeline.svg
        vex-filter-chain.svg
        policykit-evaluation.svg
        report-stages.svg
        evidence-bundle.svg
        csaf-generation.svg
        ecosystem-landscape.svg
        ci-cd-pipeline.svg
```

## 4. MkDocs Configuration

### Theme

Material theme with green/slate palette (light/dark toggle), matching the existing branding.

### Features

- `navigation.tabs` — top-level tab bar (Home, CRA Reference, Tools, Ecosystem, Guides)
- `navigation.sections` — expandable sidebar sections
- `navigation.top` — back-to-top button
- `navigation.indexes` — section index pages
- `navigation.path` — breadcrumbs
- `search.suggest` + `search.highlight`
- `content.code.copy` — copy buttons on code blocks
- `content.tabs.link` — sync tab selections across page

### Navigation

```yaml
nav:
  - Home: index.md
  - CRA Reference:
    - Overview: cra/overview.md
    - Article 14 — Vulnerability Notification: cra/article-14.md
    - Annex I — Essential Requirements: cra/annex-i.md
    - Annex VII — Technical Documentation: cra/annex-vii.md
    - Compliance Mapping: cra/compliance-mapping.md
  - Tools:
    - Overview: tools/overview.md
    - VEX: tools/vex.md
    - PolicyKit: tools/policykit.md
    - Report: tools/report.md
    - Evidence: tools/evidence.md
    - CSAF: tools/csaf.md
  - Ecosystem:
    - ecosystem/index.md
    - Standards & Formats: ecosystem/standards.md
    - Vulnerability Scanners: ecosystem/scanners.md
    - Infrastructure: ecosystem/infrastructure.md
  - Guides:
    - End-to-End Workflow: guides/workflow.md
    - CI/CD Integration: guides/ci-cd.md
```

### Markdown Extensions

- `admonition` — CRA callout boxes
- `pymdownx.details` — collapsible sections
- `pymdownx.superfences` — fenced code blocks
- `pymdownx.tabbed` (alternate_style) — input/output format tabs
- `pymdownx.emoji` — icons
- `attr_list` — image/SVG attributes
- `md_in_html` — markdown inside HTML for SVG containers
- `tables` — compliance matrix tables
- `toc` with `permalink: true` — anchor links on headings

## 5. Landing Page (`index.md`)

### Structure

1. **Hero** — "You ship software in the EU. The Cyber Resilience Act changes everything." 2-3 sentence hook establishing the compliance challenge.
2. **CRA overview diagram** (`cra-overview.svg`) — visual map of who's affected, key obligations, enforcement timeline (Sep 2026 reporting, Sep 2027 full application).
3. **What you need to do** — 4-5 bullet points mapping CRA obligations to concrete actions.
4. **How this toolkit helps** — the five tools with one-line descriptions and links.
5. **Pipeline diagram** (`tool-pipeline.svg`) — visual showing SBOM → Scan → VEX → Policy → Report → Evidence → CSAF flow.
6. **Quick start** — install command + minimal example.

## 6. CRA Reference Track

### `cra/overview.md` — The EU Cyber Resilience Act

- What the CRA is (EU regulation for products with digital elements, adopted Dec 2024)
- Who it affects — manufacturers, importers, distributors (visual scope diagram)
- Key dates — timeline SVG showing adoption, reporting obligations, full application
- Structure of the Act — Articles, Annex I-VIII breakdown
- Product categories — default, important (Class I/II), critical, with examples
- Penalties — non-compliance consequences

**SVG:** `cra-overview.svg`

### `cra/article-14.md` — Vulnerability Notification

- The obligation: manufacturers must notify ENISA/CSIRTs of actively exploited vulnerabilities
- Three-stage timeline with SVG (`cra-article14-timeline.svg`):
  - 24h early warning — awareness of active exploitation
  - 72h notification — severity, impact, corrective measures status
  - 14-day final report — root cause, remediation, affected products
- What each notification must contain — mapped to Article 14(2)(a-g) subsections
- User notification — Article 14(8) obligation
- Cross-links to `tools/report.md`

**SVG:** `cra-article14-timeline.svg`

### `cra/annex-i.md` — Essential Cybersecurity Requirements

- Part I: Security requirements — the 13 essential requirements
- Part II: Vulnerability handling — coordinated disclosure, update mechanisms, tracking
- Requirement-by-requirement breakdown, each with:
  - The obligation (plain language)
  - Exact Annex I reference
  - How the toolkit addresses it (cross-link)
  - What artifact demonstrates compliance

**SVG:** `cra-annex-mapping.svg`

### `cra/annex-vii.md` — Technical Documentation & Conformity

- What technical documentation must include
- Conformity assessment paths: Module A (internal) vs Module H (third-party)
- How the Evidence tool bundles the documentation package
- Cross-link to `tools/evidence.md`

### `cra/compliance-mapping.md` — Compliance Matrix

Central cross-reference table:

| CRA Requirement | Reference | Toolkit Tool | CLI Command | Output Artifact |
|---|---|---|---|---|
| Known vulnerability assessment | Annex I, Part I, (2) | VEX | `cra vex` | OpenVEX / CSAF VEX |
| Vulnerability notification | Art. 14 | Report | `cra report` | Art. 14 notifications |
| Security policy evaluation | Annex I | PolicyKit | `cra policykit` | Policy report |
| Security advisories | Art. 14(8) | CSAF | `cra csaf` | CSAF 2.0 advisory |
| Technical documentation | Annex VII | Evidence | `cra evidence` | Signed evidence bundle |

Plus visual SVG version showing requirement-to-artifact flow.

## 7. Tool Documentation Track

### Standard Tool Page Structure

Every tool page follows this template:

1. **Purpose** — what the tool does, one paragraph
2. **CRA Context** — which articles/annexes this tool addresses, with admonition callouts linking to CRA reference track
3. **How It Works** — architecture/pipeline with dedicated SVG diagram
4. **Usage** — CLI command, all flags in a table (required vs optional)
5. **Input Formats** — what it accepts, format detection explanation
6. **Output Formats** — what it produces, with complete real example output
7. **Examples** — 2-3 realistic scenarios with full commands and annotated output
8. **Integration** — how this tool connects to others in the pipeline

### `tools/overview.md` — How the Tools Work Together

- Compliance pipeline SVG (`tool-pipeline.svg`) showing full data flow
- Composability — tools work standalone or chained
- Format auto-detection — probes JSON structure, no format flags needed
- Shared concepts — PURLs, findings, call paths, confidence scores

**SVG:** `tool-pipeline.svg`

### `tools/vex.md` — VEX Determination Pipeline

- **CRA Context** — Annex I Part I (2), Annex I Part II
- **How it works** — SVG (`vex-filter-chain.svg`) showing 6-filter chain: Upstream → Presence → Version → Platform → Patch → Reachability
- **Reachability analysis** — 8 supported languages (Go, Rust, Python, JavaScript, Java, C#, PHP, Ruby), tree-sitter interprocedural call graph analysis, confidence scoring
- **Examples**: basic OpenVEX output, upstream VEX short-circuit, reachability with call path evidence
- **Output** — complete real OpenVEX and CSAF VEX documents

**SVG:** `vex-filter-chain.svg`

### `tools/policykit.md` — Policy Evaluation Engine

- **CRA Context** — Annex I (all essential requirements), Annex VII (conformity)
- **How it works** — SVG (`policykit-evaluation.svg`): Artifact parsing → KEV fetch → Policy loading → OPA evaluation → Report
- **10 built-in policies** — table with rule ID, name, CRA reference, what it checks, severity
- **Custom policies** — writing and loading Rego policies via `--policy-dir`
- **Examples**: basic evaluation, with provenance/signatures, markdown output

**SVG:** `policykit-evaluation.svg`

### `tools/report.md` — Article 14 Notification Generator

- **CRA Context** — Article 14(1-8), each subsection mapped to report fields
- **How it works** — SVG (`report-stages.svg`): three stages with timeline, data requirements per stage
- **Signal detection** — CISA KEV, EPSS thresholds, exploitation evidence
- **Reachability evidence** — call paths and confidence in notifications
- **Examples**: early warning, 72h notification, final report with human input

**SVG:** `report-stages.svg`

### `tools/evidence.md` — Evidence Bundling & Signing

- **CRA Context** — Annex VII (technical documentation), Annex V (EU declaration)
- **How it works** — SVG (`evidence-bundle.svg`): Collection → Validation → Cross-validation → Assembly → Signing → Archive
- **Artifact inventory** — every type with source tool or manual input
- **Signing** — Cosign keyless (Fulcio/Rekor) and key-based
- **Completeness scoring** — assessment against CRA requirements
- **Examples**: minimal bundle, full bundle, signed archive

**SVG:** `evidence-bundle.svg`

### `tools/csaf.md` — CSAF Advisory Generation

- **CRA Context** — Article 14(8) user notification, CSAF 2.0 standard
- **How it works** — SVG (`csaf-generation.svg`): SBOM + Scan + VEX → Document → Product tree → Vulnerabilities → Scores → Remediations → CSAF 2.0
- **CSAF document anatomy** — each section explained
- **Examples**: basic advisory, VEX-enriched, multi-vulnerability

**SVG:** `csaf-generation.svg`

## 8. Ecosystem Track

### `ecosystem/index.md` — The CRA Compliance Landscape

- "The toolkit doesn't replace existing security tools — it orchestrates them into a compliance pipeline"
- Landscape SVG (`ecosystem-landscape.svg`) — three layers: Standards → Tools → CRA Toolkit

**SVG:** `ecosystem-landscape.svg`

### `ecosystem/standards.md` — Standards & Formats

Per standard: what it is, CRA relevance, how the toolkit uses it, link to official spec.

- OpenVEX, CSAF 2.0, CycloneDX, SPDX, SLSA, SARIF

### `ecosystem/scanners.md` — Vulnerability Scanners

- Grype, Trivy, SARIF producers (CodeQL, Semgrep)
- Per scanner: how to generate scan output the toolkit accepts

### `ecosystem/infrastructure.md` — Infrastructure Components

- OPA/Rego — policy engine, custom policy authoring
- Cosign — signing, keyless vs key-based
- Tree-sitter — parser framework, 8-language reachability support

## 9. Guides Track

### `guides/workflow.md` — End-to-End Compliance Workflow

Narrative walkthrough using a real open-source project:

1. Generate SBOM (syft/cdxgen)
2. Scan for vulnerabilities (Grype/Trivy)
3. Determine exploitability (`cra vex`)
4. Evaluate compliance policies (`cra policykit`)
5. Generate notifications if needed (`cra report`)
6. Produce security advisories (`cra csaf`)
7. Bundle and sign evidence (`cra evidence`)

Each step: exact command, output produced, how it feeds the next step.

### `guides/ci-cd.md` — CI/CD Integration

**Primary: GitHub Actions reference pipeline**

- Complete, working `.github/workflows/cra-compliance.yml`
- Jobs: SBOM generation → scan → VEX → policy check → conditional report → CSAF → evidence
- Artifact upload between jobs
- Policy violation gates (block merge on failure)
- Scheduled runs for ongoing compliance
- Secrets handling for signing

**SVG:** `ci-cd-pipeline.svg`

**Secondary: Conceptual pipeline guide**

- Stage-by-stage breakdown mapping to any CI system
- Decision points (when to gate, when to warn)
- Artifact storage considerations
- Mapping table: GitHub Actions → GitLab CI → Tekton equivalents

## 10. SVG Diagram Specifications

### Visual Language

- **Color scheme** — SUSE green palette matching Material theme, accent colors per category
- **Style** — clean, technical, no 3D/gradients. Rounded rectangles for processes, parallelograms for inputs/outputs, diamonds for decisions
- **Typography** — sans-serif, readable at small sizes
- **Annotations** — CRA article references as small badges on relevant elements
- **Responsiveness** — viewBox-based sizing, readable on mobile

### Diagram Inventory

| Diagram | Page(s) | Content |
|---|---|---|
| `cra-overview.svg` | Landing, CRA overview | Act structure, scope, enforcement timeline |
| `cra-article14-timeline.svg` | Article 14 | Three-stage notification timeline with data requirements |
| `cra-annex-mapping.svg` | Annex I | Requirements → tools → artifacts visual mapping |
| `tool-pipeline.svg` | Landing, tools overview | Full tool chain data flow |
| `vex-filter-chain.svg` | VEX | 6-stage deterministic filter chain |
| `policykit-evaluation.svg` | PolicyKit | 5-stage evaluation pipeline |
| `report-stages.svg` | Report | Three notification stages with timeline |
| `evidence-bundle.svg` | Evidence | Collection → signing pipeline + bundle anatomy |
| `csaf-generation.svg` | CSAF | Input → CSAF document assembly |
| `ecosystem-landscape.svg` | Ecosystem | Three-layer integration landscape |
| `ci-cd-pipeline.svg` | CI/CD guide | GitHub Actions workflow visualization |

## 11. Cross-Linking Strategy

Three types of cross-references:

1. **CRA → Tool** — admonition boxes on CRA pages linking to implementing tool:
   ```markdown
   !!! tip "Toolkit Implementation"
       The `cra vex` tool automates this requirement.
       See [VEX Determination Pipeline](../tools/vex.md).
   ```

2. **Tool → CRA** — CRA context section on every tool page:
   ```markdown
   !!! abstract "CRA Reference"
       This tool addresses **Annex I, Part I, (2)**: products shall be delivered
       without known exploitable vulnerabilities.
       See [Annex I — Essential Requirements](../cra/annex-i.md).
   ```

3. **Compliance mapping as hub** — `cra/compliance-mapping.md` links every requirement to its tool and every tool to its CRA basis.

## 12. Content Quality Standards

- **Real output** — all example outputs generated from actual toolkit runs against real OSS projects, not fabricated
- **CRA accuracy** — all article/annex references verified against the EU CRA PDF
- **Complete CLI reference** — every flag, every option documented
- **Diagrams match code** — SVGs reflect actual implementation (e.g., 6 VEX filters, 10 PolicyKit policies, 8 reachability languages)
- **No placeholders** — every page is complete and useful on its own

## 13. Taskfile Integration

Update `Taskfile.yml` to point docs tasks at the new `site/` directory:

- `docs:serve` — `cd site && mkdocs serve`
- `docs:build` — `cd site && mkdocs build`

## 14. Out of Scope

- CSAF LLM judge fix (pre-existing, separate issue)
- Phase 2 AI agent documentation (not yet implemented)
- Automated doc generation from code (future enhancement)
- Custom Material theme overrides beyond configuration
