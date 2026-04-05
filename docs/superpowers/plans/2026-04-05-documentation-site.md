# Documentation Site Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a comprehensive MkDocs Material documentation site at `site/` that serves as both an EU CRA reference and toolkit integration guide.

**Architecture:** Dual-track site (CRA Reference + Tools) with cross-linking via compliance mapping. 20+ markdown pages, 11 SVG diagrams. Site source at `site/` separated from internal docs at `docs/`. Content accuracy verified against the EU CRA PDF (Regulation EU 2024/2847) and actual CLI source code.

**Tech Stack:** MkDocs, mkdocs-material, Python/uv, hand-crafted SVG diagrams

**Key CRA dates (from PDF):**
- Adopted: 23 October 2024
- Article 14 applies: 11 September 2026
- Chapter IV (conformity assessment bodies): 11 June 2026
- Full application: 11 December 2027

---

### Task 1: Site Scaffolding

**Files:**
- Move: `mkdocs.yml` -> `site/mkdocs.yml` (rewrite content)
- Move: `pyproject.toml` -> `site/pyproject.toml`
- Move: `uv.lock` -> `site/uv.lock`
- Create: `site/docs/.gitkeep`
- Modify: `Taskfile.yml` (update docs tasks)
- Delete: root-level `mkdocs.yml`

- [ ] **Step 1: Create site directory and move Python config**

```bash
mkdir -p site
mv pyproject.toml site/pyproject.toml
mv uv.lock site/uv.lock
```

- [ ] **Step 2: Create new mkdocs.yml at site/**

Create `site/mkdocs.yml`:

```yaml
site_name: SUSE CRA Compliance Toolkit
site_description: >
  Open-source toolkit for EU Cyber Resilience Act compliance.
  Reference guide for the CRA and tools to automate compliance.
repo_url: https://github.com/ravan/suse-cra-toolkit

theme:
  name: material
  palette:
    - media: "(prefers-color-scheme: light)"
      scheme: default
      primary: green
      accent: light green
      toggle:
        icon: material/brightness-7
        name: Switch to dark mode
    - media: "(prefers-color-scheme: dark)"
      scheme: slate
      primary: green
      accent: light green
      toggle:
        icon: material/brightness-4
        name: Switch to light mode
  features:
    - navigation.tabs
    - navigation.sections
    - navigation.top
    - navigation.indexes
    - navigation.path
    - search.suggest
    - search.highlight
    - content.code.copy
    - content.tabs.link

nav:
  - Home: index.md
  - CRA Reference:
    - Overview: cra/overview.md
    - "Article 14 \u2014 Vulnerability Notification": cra/article-14.md
    - "Annex I \u2014 Essential Requirements": cra/annex-i.md
    - "Annex VII \u2014 Technical Documentation": cra/annex-vii.md
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
    - "Standards & Formats": ecosystem/standards.md
    - Vulnerability Scanners: ecosystem/scanners.md
    - Infrastructure: ecosystem/infrastructure.md
  - Guides:
    - "End-to-End Workflow": guides/workflow.md
    - "CI/CD Integration": guides/ci-cd.md

markdown_extensions:
  - admonition
  - pymdownx.details
  - pymdownx.superfences
  - pymdownx.tabbed:
      alternate_style: true
  - pymdownx.emoji:
      emoji_index: !!python/name:material.extensions.emoji.twemoji
      emoji_generator: !!python/name:material.extensions.emoji.to_svg
  - attr_list
  - md_in_html
  - tables
  - toc:
      permalink: true
```

- [ ] **Step 3: Remove old root mkdocs.yml**

```bash
rm mkdocs.yml
```

- [ ] **Step 4: Create directory structure**

```bash
mkdir -p site/docs/{cra,tools,ecosystem,guides,assets/diagrams}
```

- [ ] **Step 5: Create placeholder index.md so build works**

Create `site/docs/index.md`:

```markdown
# SUSE CRA Compliance Toolkit

Placeholder — content will be added in subsequent tasks.
```

- [ ] **Step 6: Create placeholder pages for all nav entries**

Create a minimal placeholder for every page referenced in the nav so `mkdocs build` succeeds. Each file should contain only:

```markdown
# Page Title

Placeholder — content will be added in a subsequent task.
```

Files to create:
- `site/docs/cra/overview.md`
- `site/docs/cra/article-14.md`
- `site/docs/cra/annex-i.md`
- `site/docs/cra/annex-vii.md`
- `site/docs/cra/compliance-mapping.md`
- `site/docs/tools/overview.md`
- `site/docs/tools/vex.md`
- `site/docs/tools/policykit.md`
- `site/docs/tools/report.md`
- `site/docs/tools/evidence.md`
- `site/docs/tools/csaf.md`
- `site/docs/ecosystem/index.md`
- `site/docs/ecosystem/standards.md`
- `site/docs/ecosystem/scanners.md`
- `site/docs/ecosystem/infrastructure.md`
- `site/docs/guides/workflow.md`
- `site/docs/guides/ci-cd.md`

- [ ] **Step 7: Update Taskfile.yml docs tasks**

Change the `docs:serve` and `docs:build` tasks to run from `site/`:

```yaml
  docs:serve:
    desc: Serve the documentation site
    dir: site
    cmds:
      - uv run mkdocs serve

  docs:build:
    desc: Build the documentation site
    dir: site
    cmds:
      - uv run mkdocs build
```

- [ ] **Step 8: Verify site builds**

```bash
cd site && uv run mkdocs build --strict 2>&1
```

Expected: Build succeeds with no errors.

- [ ] **Step 9: Commit**

```bash
git add site/ Taskfile.yml
git rm mkdocs.yml pyproject.toml uv.lock
git commit -m "docs: scaffold site/ directory for documentation site"
```

---

### Task 2: Landing Page and Tool Pipeline SVG

**Files:**
- Create: `site/docs/index.md`
- Create: `site/docs/assets/diagrams/tool-pipeline.svg`

- [ ] **Step 1: Create tool-pipeline.svg**

Create `site/docs/assets/diagrams/tool-pipeline.svg` — a horizontal flow diagram showing the compliance pipeline:

```
SBOM + Source Code --> Vulnerability Scanners --> cra vex --> cra policykit
                                                    |              |
                                                    v              v
                                                cra csaf    Policy Report
                                                    |              |
                                                    v              v
                                              cra report --> cra evidence
```

Design requirements:
- viewBox-based sizing (e.g., `viewBox="0 0 1200 500"`)
- SUSE green palette: `#30BA78` (primary), `#0C322C` (dark), `#E8F5E9` (light bg), `#2E7D32` (secondary)
- Rounded rectangles (`rx="8"`) for process nodes
- Parallelogram shapes for inputs/outputs
- Arrows connecting stages with labels
- Sans-serif font (`font-family="Inter, Helvetica, Arial, sans-serif"`)
- CRA article badges as small rounded labels on relevant nodes (e.g., "Art. 14" on Report, "Annex I" on PolicyKit, "Annex VII" on Evidence)

- [ ] **Step 2: Write landing page content**

Replace `site/docs/index.md` with problem-first landing page:

1. **Hero section** — "You ship software in the EU. The Cyber Resilience Act changes everything." Explain that Regulation (EU) 2024/2847 introduces mandatory cybersecurity requirements for all products with digital elements. Enforcement begins 11 September 2026 (reporting) with full application from 11 December 2027.

2. **What you need to do** section — bullet points:
   - Maintain an SBOM for every product (Annex I, Part II, point 1)
   - Assess and document all known vulnerabilities (Annex I, Part I, point 2(a))
   - Notify ENISA/CSIRTs of actively exploited vulnerabilities within 24 hours (Article 14)
   - Provide security advisories to downstream users (Article 14(8))
   - Bundle technical documentation for conformity assessment (Annex VII)

3. **How this toolkit helps** — table of five tools with one-line descriptions linking to tool pages

4. **Pipeline diagram** — embed `tool-pipeline.svg` using: `![CRA Compliance Pipeline](assets/diagrams/tool-pipeline.svg)`

5. **Quick start** section:
```bash
# Install
go install github.com/ravan/suse-cra-toolkit/cmd/cra@latest

# Run VEX determination
cra vex --sbom sbom.cdx.json --scan grype.json -o vex.json

# Evaluate compliance policies
cra policykit --sbom sbom.cdx.json --scan grype.json --vex vex.json

# Generate Article 14 notification
cra report --sbom sbom.cdx.json --scan grype.json --stage early-warning --product-config product.yaml
```

- [ ] **Step 3: Verify site builds**

```bash
cd site && uv run mkdocs build --strict 2>&1
```

- [ ] **Step 4: Commit**

```bash
git add site/docs/index.md site/docs/assets/diagrams/tool-pipeline.svg
git commit -m "docs: add landing page with tool pipeline diagram"
```

---

### Task 3: CRA Overview Page and SVG

**Files:**
- Create: `site/docs/cra/overview.md`
- Create: `site/docs/assets/diagrams/cra-overview.svg`

- [ ] **Step 1: Create cra-overview.svg**

Create `site/docs/assets/diagrams/cra-overview.svg` — a structured overview of the CRA:

Layout: A timeline at top showing key dates (Oct 2024 adoption, Sep 2026 Art. 14, Dec 2027 full). Below, a grid showing the Act's structure: Articles on left (key ones: Art. 13 Manufacturer obligations, Art. 14 Reporting, Art. 19/20 Importers/Distributors, Art. 24 OSS stewards, Art. 31 Technical docs, Art. 32 Conformity), Annexes on right (I: Essential requirements, II: User info, III: Important products, IV: Critical products, V: EU declaration, VII: Technical documentation, VIII: Conformity procedures).

Same visual language as Task 2 SVG (green palette, rounded rectangles, sans-serif, viewBox-based).

- [ ] **Step 2: Write CRA overview page**

Replace `site/docs/cra/overview.md` with comprehensive content covering:

**What the CRA is:** Regulation (EU) 2024/2847, adopted 23 October 2024, published OJ L 20.11.2024. First EU-wide horizontal cybersecurity regulation for products with digital elements.

**Who it affects:**
- **Manufacturers** (Art. 13) — primary obligation holders: design, develop, produce compliant products
- **Importers** (Art. 19) — must verify manufacturer compliance before placing on EU market
- **Distributors** (Art. 20) — must verify CE marking and documentation
- **Open-source software stewards** (Art. 24) — cybersecurity policy, voluntary reporting

**Key enforcement dates** (embed SVG):
- 23 October 2024 — Regulation adopted
- 11 June 2026 — Conformity assessment body rules apply (Chapter IV, Art. 35-51)
- 11 September 2026 — Article 14 reporting obligations apply
- 11 December 2027 — Full application of all provisions

**Structure of the Act** — describe key articles and annexes with brief summaries.

**Product categories:**
- **Default** — standard conformity assessment (Module A, internal control)
- **Important Class I** (Annex III, Class I) — identity mgmt, browsers, password managers, VPNs, network mgmt, SIEM, boot managers, PKI, network interfaces, OS, routers, security microprocessors, smart home assistants/devices, connected toys, health wearables
- **Important Class II** (Annex III, Class II) — hypervisors/container runtimes, firewalls/IDS/IPS, tamper-resistant microprocessors/microcontrollers
- **Critical** (Annex IV) — hardware devices with security boxes, smart meter gateways, smartcards/secure elements

**Penalties:** Up to EUR 15 million or 2.5% of worldwide annual turnover for non-compliance with essential requirements.

Add toolkit callout:

```markdown
!!! tip "Toolkit Implementation"
    The SUSE CRA Compliance Toolkit automates key requirements across the CRA.
    See the [Compliance Mapping](compliance-mapping.md) for a complete requirement-to-tool matrix.
```

- [ ] **Step 3: Verify build**

```bash
cd site && uv run mkdocs build --strict 2>&1
```

- [ ] **Step 4: Commit**

```bash
git add site/docs/cra/overview.md site/docs/assets/diagrams/cra-overview.svg
git commit -m "docs: add CRA overview page with structure diagram"
```

---

### Task 4: Article 14 Page and Timeline SVG

**Files:**
- Create: `site/docs/cra/article-14.md`
- Create: `site/docs/assets/diagrams/cra-article14-timeline.svg`

- [ ] **Step 1: Create article-14 timeline SVG**

Create `site/docs/assets/diagrams/cra-article14-timeline.svg` — a horizontal timeline diagram showing the three notification stages:

Left to right:
1. **24h Early Warning** (Art. 14(2)(a)) — light green box. Label: "Awareness of active exploitation". Content: Member States affected, product identified.
2. **72h Notification** (Art. 14(2)(b)) — medium green box. Label: "Vulnerability details". Content: Product info, nature of exploit, corrective/mitigating measures, sensitivity assessment.
3. **14-day Final Report** (Art. 14(2)(c)) — dark green box. Label: "After corrective measure available". Content: Vulnerability description + severity + impact, malicious actor info, security update details.

Timeline arrows between stages with duration labels. Small badge "Art. 14(8)" below with arrow to "User Notification" box showing structured machine-readable format requirement.

- [ ] **Step 2: Write Article 14 page**

Replace `site/docs/cra/article-14.md`. Source all content directly from Article 14 of Regulation (EU) 2024/2847.

**The Obligation** — Art. 14(1): Manufacturers shall notify any actively exploited vulnerability to the CSIRT designated as coordinator and to ENISA, via the single reporting platform (Art. 16).

**Three-Stage Notification** (embed SVG):

*24-hour Early Warning — Art. 14(2)(a):*
- Without undue delay, within 24 hours of becoming aware
- Indicate Member States where product has been made available
- This is a minimum viable notification

*72-hour Notification — Art. 14(2)(b):*
- Within 72 hours of becoming aware
- General information about the product with digital elements concerned
- General nature of the exploit and the vulnerability
- Corrective or mitigating measures taken and that users can take
- How sensitive the manufacturer considers the information to be

*14-day Final Report — Art. 14(2)(c):*
- No later than 14 days after a corrective or mitigating measure is available
- (i) Description of vulnerability, including severity and impact
- (ii) Information concerning any malicious actor (where available)
- (iii) Details about the security update or corrective measures

**Severe Incidents** — Art. 14(3-5): Manufacturers must also notify severe incidents. An incident is severe when it (a) negatively affects availability, authenticity, integrity, or confidentiality, or (b) leads to introduction/execution of malicious code.

**User Notification** — Art. 14(8): After becoming aware of an actively exploited vulnerability or severe incident, the manufacturer shall inform impacted users of the vulnerability or incident and, where necessary, of any risk mitigation and corrective measures. Where appropriate, notification shall be in a structured, machine-readable format that is easily automatically processable.

**Reporting Platform** — Art. 16: ENISA establishes and maintains the single reporting platform.

Add toolkit callout:

```markdown
!!! tip "Toolkit Implementation"
    The `cra report` tool generates all three notification stages automatically from your SBOM, scan results, and VEX assessments.
    See [Report — Article 14 Notification Generator](../tools/report.md).

    The `cra csaf` tool produces the structured, machine-readable advisories required by Art. 14(8).
    See [CSAF — Advisory Generation](../tools/csaf.md).
```

- [ ] **Step 3: Verify build**

```bash
cd site && uv run mkdocs build --strict 2>&1
```

- [ ] **Step 4: Commit**

```bash
git add site/docs/cra/article-14.md site/docs/assets/diagrams/cra-article14-timeline.svg
git commit -m "docs: add Article 14 vulnerability notification page"
```

---

### Task 5: Annex I Page and Mapping SVG

**Files:**
- Create: `site/docs/cra/annex-i.md`
- Create: `site/docs/assets/diagrams/cra-annex-mapping.svg`

- [ ] **Step 1: Create annex mapping SVG**

Create `site/docs/assets/diagrams/cra-annex-mapping.svg` — a visual mapping from Annex I requirements to toolkit tools and output artifacts.

Layout: Three columns — left "CRA Requirement", center "Toolkit Tool", right "Output Artifact". Lines connecting each requirement to its implementing tool and output. Use color coding: green for Part I requirements, teal for Part II requirements.

- [ ] **Step 2: Write Annex I page**

Replace `site/docs/cra/annex-i.md`. Source all content from Annex I of Regulation (EU) 2024/2847.

**Part I — Cybersecurity requirements relating to the properties of products with digital elements:**

(1) Products shall be designed, developed and produced to ensure an appropriate level of cybersecurity based on the risks.

(2) On the basis of the cybersecurity risk assessment (Art. 13(2)), products shall:
- (a) be made available without known exploitable vulnerabilities
- (b) be made available with a secure by default configuration
- (c) ensure vulnerabilities can be addressed through security updates, including automatic updates with opt-out
- (d) ensure protection from unauthorised access
- (e) protect confidentiality of stored/transmitted data
- (f) protect integrity of stored/transmitted data
- (g) process only data that is adequate, relevant and limited (data minimisation)
- (h) protect availability of essential functions (resilience, DoS mitigation)
- (i) minimise negative impact on availability of other services
- (j) be designed to limit attack surfaces
- (k) reduce impact of incidents using exploitation mitigation
- (l) provide security-related information by recording/monitoring internal activity
- (m) provide secure data removal capability

For each sub-requirement, add a row to a table showing: requirement text (plain language), exact reference, which toolkit tool addresses it (if applicable), and what artifact demonstrates compliance.

**Part II — Vulnerability handling requirements:**

Manufacturers shall:
(1) Identify and document vulnerabilities/components via SBOM
(2) Address and remediate vulnerabilities without delay via security updates
(3) Apply effective and regular security tests and reviews
(4) Publicly disclose fixed vulnerabilities with descriptions and impact
(5) Put in place and enforce coordinated vulnerability disclosure policy
(6) Facilitate sharing of information about potential vulnerabilities
(7) Provide mechanisms to securely distribute updates
(8) Ensure security updates are disseminated without delay, free of charge, with advisory messages

Embed the SVG diagram and add per-requirement toolkit callouts linking to relevant tool pages.

- [ ] **Step 3: Verify build**

```bash
cd site && uv run mkdocs build --strict 2>&1
```

- [ ] **Step 4: Commit**

```bash
git add site/docs/cra/annex-i.md site/docs/assets/diagrams/cra-annex-mapping.svg
git commit -m "docs: add Annex I essential requirements page with mapping diagram"
```

---

### Task 6: Annex VII Page

**Files:**
- Create: `site/docs/cra/annex-vii.md`

- [ ] **Step 1: Write Annex VII page**

Replace `site/docs/cra/annex-vii.md`. Source from Annex VII and Articles 31-32 of Regulation (EU) 2024/2847.

**Content of Technical Documentation** (Annex VII):

1. General description of the product: (a) intended purpose, (b) software versions affecting compliance, (c) hardware photos/layout if applicable, (d) user information per Annex II

2. Description of design, development, production and vulnerability handling: (a) system architecture and how software components integrate, (b) vulnerability handling processes — SBOM, CVD policy, contact address, technical solutions for secure update distribution, (c) production and monitoring processes and their validation

3. Cybersecurity risk assessment per Art. 13, including how Annex I Part I requirements are met

4. Relevant information for determining the support period per Art. 13(8)

5. List of harmonised standards applied, common specifications, or cybersecurity certification schemes per Art. 27

6. Test reports verifying conformity with Annex I Parts I and II

7. Copy of the EU declaration of conformity

8. Where applicable, SBOM for market surveillance authorities (upon reasoned request)

**Conformity Assessment Procedures** (Art. 32, Annex VIII):

- **Module A** (internal control) — manufacturer self-declares. Available for all default-category products and free/open-source software (Art. 32(5)).
- **Module B + C** (EU-type examination + internal production control) — notified body examines design. Required for Important Class I products where harmonised standards not fully applied (Art. 32(2)).
- **Module H** (full quality assurance) — notified body assesses quality system. Required for Important Class II products (Art. 32(3)). Also an option for Important Class I.
- **Critical products** (Annex IV) — must use European cybersecurity certification scheme per Art. 8(1), or fall back to Module B+C or H (Art. 32(4)).

Add toolkit callout:

```markdown
!!! tip "Toolkit Implementation"
    The `cra evidence` tool bundles all required technical documentation into a signed evidence package.
    It validates completeness against Annex VII requirements and cross-validates artifact consistency.
    See [Evidence — Bundling & Signing](../tools/evidence.md).
```

- [ ] **Step 2: Verify build**

```bash
cd site && uv run mkdocs build --strict 2>&1
```

- [ ] **Step 3: Commit**

```bash
git add site/docs/cra/annex-vii.md
git commit -m "docs: add Annex VII technical documentation page"
```

---

### Task 7: Compliance Mapping Page

**Files:**
- Create: `site/docs/cra/compliance-mapping.md`

- [ ] **Step 1: Write compliance mapping page**

Replace `site/docs/cra/compliance-mapping.md`.

**Introduction:** Central cross-reference linking CRA requirements to toolkit tools, CLI commands, and output artifacts. Use this page to find which tool addresses which obligation.

**Primary Compliance Matrix** — full table:

| CRA Requirement | Reference | Toolkit Tool | CLI Command | Output Artifact |
|---|---|---|---|---|
| No known exploitable vulnerabilities | Annex I, Part I, 2(a) | VEX | `cra vex` | OpenVEX / CSAF VEX |
| SBOM identification and documentation | Annex I, Part II, (1) | Evidence | `cra evidence --sbom` | SBOM in evidence bundle |
| Vulnerability assessment and remediation | Annex I, Part II, (2) | VEX + PolicyKit | `cra vex` + `cra policykit` | VEX + Policy report |
| Coordinated vulnerability disclosure | Annex I, Part II, (5) | Evidence | `cra evidence --cvd-policy` | CVD policy in bundle |
| Secure update distribution | Annex I, Part II, (7) | PolicyKit | `cra policykit` | Update mechanism policy check |
| Security advisory dissemination | Annex I, Part II, (8) | CSAF | `cra csaf` | CSAF 2.0 advisory |
| 24h early warning notification | Art. 14(2)(a) | Report | `cra report --stage early-warning` | Early warning JSON/MD |
| 72h vulnerability notification | Art. 14(2)(b) | Report | `cra report --stage notification` | Notification JSON/MD |
| 14-day final report | Art. 14(2)(c) | Report | `cra report --stage final-report` | Final report JSON/MD |
| User notification (machine-readable) | Art. 14(8) | CSAF | `cra csaf` | CSAF 2.0 advisory |
| Technical documentation | Annex VII | Evidence | `cra evidence` | Signed evidence bundle |
| EU declaration of conformity | Annex V | Evidence | `cra evidence --eu-declaration` | Declaration in bundle |
| Risk assessment | Art. 13(2) | Evidence | `cra evidence --risk-assessment` | Risk assessment in bundle |
| Build provenance (SLSA) | Art. 13 | PolicyKit | `cra policykit --provenance` | CRA-AI-3.1 policy check |
| Artifact signatures | Art. 13 | PolicyKit | `cra policykit --signature` | CRA-AI-3.2 policy check |
| Support period declaration | Annex I, Part II | PolicyKit | `cra policykit --product-config` | CRA-AI-4.1 policy check |
| KEV vulnerability management | Annex I, Part I, 2(a) | PolicyKit | `cra policykit --kev` | CRA-AI-2.1 policy check |
| Reachability evidence quality | Annex I, Part I, 2(a) | VEX + PolicyKit | `cra vex --source-dir` | CRA-REACH-1/2/3 checks |

**PolicyKit Policy Reference** — table of all 10 built-in policies:

| Rule ID | Name | CRA Reference | Checks | Severity |
|---|---|---|---|---|
| CRA-AI-1.1 | SBOM exists and is valid | Annex I Part II.1 | Format, metadata, components, PURL coverage | critical |
| CRA-AI-2.1 | No known exploited vulnerabilities | Annex I Part I.2(a) | Scan findings vs CISA KEV catalog | critical |
| CRA-AI-2.2 | All critical/high CVEs have VEX assessment | Annex I Part I.2(a) | VEX coverage for CVSS >= 7.0 findings | high |
| CRA-AI-3.1 | Build provenance exists (SLSA L1+) | Art. 13 | SLSA attestation: builder_id, source_repo, build_type | high |
| CRA-AI-3.2 | Artifacts cryptographically signed | Art. 13 | Signature file presence and format | high |
| CRA-AI-4.1 | Support period declared and >= 5 years | Annex I Part II | Product config: release/end dates, >= 5 years | medium |
| CRA-AI-4.2 | Secure update mechanism documented | Annex I Part II.7 | Update type, URL, auto-update, security-separate | medium |
| CRA-REACH-1 | not_affected claims require high confidence | Annex I Part I.2(a) | VEX reachability confidence scoring | high |
| CRA-REACH-2 | affected claims must have call paths | Annex I Part I.2(a) | VEX reachability call path evidence | high |
| CRA-REACH-3 | Pattern-match alone cannot justify not_affected | Annex I Part I.2(a) | VEX analysis method validation | medium |

Each row links to the relevant CRA reference page and tool page.

- [ ] **Step 2: Verify build**

```bash
cd site && uv run mkdocs build --strict 2>&1
```

- [ ] **Step 3: Commit**

```bash
git add site/docs/cra/compliance-mapping.md
git commit -m "docs: add compliance mapping matrix page"
```

---

### Task 8: Tools Overview Page

**Files:**
- Create: `site/docs/tools/overview.md`

- [ ] **Step 1: Write tools overview page**

Replace `site/docs/tools/overview.md`.

**How the Tools Work Together** — explain the composability philosophy: each tool takes standard inputs (SBOM, scan results, VEX) and produces standard outputs that feed the next tool.

Embed the `tool-pipeline.svg` diagram (already created in Task 2).

**Pipeline data flow:**
1. External tools generate SBOM (syft, cdxgen) and scan results (Grype, Trivy)
2. `cra vex` consumes SBOM + scans, produces VEX document (OpenVEX or CSAF)
3. `cra policykit` consumes SBOM + scans + VEX + provenance, produces policy report
4. `cra report` consumes SBOM + scans + VEX + product config, produces Art. 14 notifications
5. `cra csaf` consumes SBOM + scans + VEX, produces CSAF 2.0 advisories
6. `cra evidence` consumes all outputs + manual artifacts, produces signed evidence bundle

**Format Auto-Detection:** The toolkit automatically detects input formats by probing JSON structure. Discriminating keys: `bomFormat` (CycloneDX), `spdxVersion` (SPDX), `matches` (Grype), `Results` (Trivy), `runs` (SARIF), `@context` (OpenVEX), `document` (CSAF). No format flags needed.

**Shared Concepts:**
- **PURLs** — Package URL identifiers used across all tools for component identification
- **Findings** — Unified vulnerability finding structure with CVE, PURL, severity, CVSS
- **Call Paths** — Reachability evidence propagated from VEX through Report and Evidence
- **Confidence Scores** — Reachability confidence levels (high, medium, low) for assessment quality

**Global CLI Flags:**

| Flag | Description | Default |
|---|---|---|
| `--format`, `-f` | Output format: json or text | json |
| `--output`, `-o` | Output file path | stdout |
| `--quiet`, `-q` | Suppress non-essential output | false |
| `--verbose` | Enable debug logging | false |

- [ ] **Step 2: Verify build**

```bash
cd site && uv run mkdocs build --strict 2>&1
```

- [ ] **Step 3: Commit**

```bash
git add site/docs/tools/overview.md
git commit -m "docs: add tools overview page with pipeline flow"
```

---

### Task 9: VEX Tool Page and Filter Chain SVG

**Files:**
- Create: `site/docs/tools/vex.md`
- Create: `site/docs/assets/diagrams/vex-filter-chain.svg`

- [ ] **Step 1: Create VEX filter chain SVG**

Create `site/docs/assets/diagrams/vex-filter-chain.svg` — a vertical or horizontal flow showing 6 filters in sequence:

1. **Upstream Filter** — checks upstream VEX documents
2. **Presence Filter** — verifies component presence in product
3. **Version Filter** — validates version in vulnerable range
4. **Platform Filter** — checks OS/architecture specificity
5. **Patch Filter** — detects if vulnerability is patched
6. **Reachability Filter** — code analysis for vulnerable code reachability

Each filter box should show: filter name, what it checks, possible outcomes (not_affected / affected / under_investigation / pass-through). Arrows showing the flow, with short-circuit paths when a filter makes a determination. The Reachability filter box should be larger, showing the 8 supported languages.

- [ ] **Step 2: Write VEX tool page**

Replace `site/docs/tools/vex.md` following the standard tool page template:

**1. Purpose:** `cra vex` is a VEX determination pipeline that automates vulnerability exploitability assessment for software products. It takes SBOMs and scanner output as input and produces VEX statements communicating whether each vulnerability is applicable and why.

**2. CRA Context:**

```markdown
!!! abstract "CRA Reference"
    This tool addresses **Annex I, Part I, point 2(a)**: products shall be made available
    on the market without known exploitable vulnerabilities.
    See [Annex I — Essential Requirements](../cra/annex-i.md).

    It also supports **Annex I, Part II**: vulnerability handling requirements including
    identification, documentation, and remediation of vulnerabilities.
```

**3. How It Works:** Embed `vex-filter-chain.svg`. Explain the deterministic filter chain: each finding passes through all 6 filters in sequence. The first filter to make a definitive determination (not_affected or affected) short-circuits the chain.

**Reachability Analysis** section — expanded coverage:
- Uses tree-sitter for interprocedural call graph analysis
- 8 supported languages: Go, Rust, Python, JavaScript, Java, C#, PHP, Ruby
- Confidence scoring: high (full call graph traced), medium (partial analysis), low (pattern match only)
- Call path evidence: records the exact function call chain from application entry points to vulnerable code

**4. Usage:**

```bash
cra vex --sbom <path> --scan <path> [flags]
```

| Flag | Description | Required | Default |
|---|---|---|---|
| `--sbom` | Path to SBOM file (CycloneDX or SPDX) | Yes | — |
| `--scan` | Path to scan results (Grype, Trivy, or SARIF); repeatable | Yes | — |
| `--upstream-vex` | Path to upstream VEX document (OpenVEX or CSAF); repeatable | No | — |
| `--source-dir` | Path to source code for reachability analysis | No | — |
| `--output-format` | Output format: `openvex` or `csaf` | No | openvex |
| `--output`, `-o` | Output file path | No | stdout |

**5. Input Formats:**
- **SBOM:** CycloneDX (JSON), SPDX (JSON)
- **Scans:** Grype (JSON), Trivy (JSON), SARIF
- **Upstream VEX:** OpenVEX (JSON), CSAF (JSON)

All formats are auto-detected.

**6. Output Formats:**
- **OpenVEX** (default) — industry standard VEX format
- **CSAF 2.0** — structured advisory format with VEX profile

**7. Examples:**

*Example 1: Basic VEX determination*
```bash
cra vex --sbom sbom.cdx.json --scan grype.json -o vex.json
```

Show what the output OpenVEX JSON structure looks like (key fields: `@context`, `author`, `statements` array with `vulnerability`, `products`, `status`, `justification`).

*Example 2: With upstream VEX*
```bash
cra vex --sbom sbom.cdx.json --scan grype.json --upstream-vex vendor-vex.json
```

Explain that upstream VEX statements are checked first, allowing vendors to pre-classify vulnerabilities.

*Example 3: With reachability analysis*
```bash
cra vex --sbom sbom.cdx.json --scan trivy.json --source-dir ./src --output-format csaf
```

Show how reachability evidence appears in the output: call paths, confidence scores, analysis method.

**8. Integration:** VEX output feeds into `cra policykit` (for VEX coverage checks), `cra report` (for vulnerability context), `cra csaf` (for enriched advisories), and `cra evidence` (as a bundle artifact).

- [ ] **Step 3: Verify build**

```bash
cd site && uv run mkdocs build --strict 2>&1
```

- [ ] **Step 4: Commit**

```bash
git add site/docs/tools/vex.md site/docs/assets/diagrams/vex-filter-chain.svg
git commit -m "docs: add VEX tool page with filter chain diagram"
```

---

### Task 10: PolicyKit Tool Page and Evaluation SVG

**Files:**
- Create: `site/docs/tools/policykit.md`
- Create: `site/docs/assets/diagrams/policykit-evaluation.svg`

- [ ] **Step 1: Create PolicyKit evaluation pipeline SVG**

Create `site/docs/assets/diagrams/policykit-evaluation.svg` — a flow diagram showing the 5-stage evaluation pipeline:

1. **Parse Artifacts** — SBOM, VEX, provenance, product config, signatures
2. **Fetch KEV** — auto-download CISA KEV catalog or load local
3. **Load Policies** — embedded Rego defaults + optional custom policy directory
4. **OPA Evaluation** — run all policies against structured input
5. **Generate Report** — JSON or Markdown output with PASS/FAIL/SKIP per policy

Show input files entering stage 1, KEV catalog entering stage 2, policy files entering stage 3, and output report emerging from stage 5.

- [ ] **Step 2: Write PolicyKit tool page**

Replace `site/docs/tools/policykit.md` following the standard template:

**1. Purpose:** `cra policykit` evaluates CRA Annex I compliance policies against product artifacts using embedded OPA (Open Policy Agent) and Rego rules. It provides machine-checkable compliance verification.

**2. CRA Context:**

```markdown
!!! abstract "CRA Reference"
    This tool evaluates compliance with **Annex I** essential cybersecurity requirements
    and supports **Annex VII** conformity assessment documentation.
    See [Annex I — Essential Requirements](../cra/annex-i.md) and
    [Annex VII — Technical Documentation](../cra/annex-vii.md).
```

**3. How It Works:** Embed SVG. Describe the 5-stage pipeline.

**Built-in Policies** — table with all 10 policies (rule_id, name, CRA reference, what it checks, severity). Copy exact data from Task 7's policy table.

**Custom Policies:** Users can write their own Rego policies and load them via `--policy-dir`. Custom policies follow the same rule structure: `rule_id`, `name`, `cra_reference`, `status`, `severity`, `evidence`. They are evaluated alongside the built-in policies.

**4. Usage:**

```bash
cra policykit --sbom <path> --scan <path> --vex <path> [flags]
```

| Flag | Description | Required | Default |
|---|---|---|---|
| `--sbom` | Path to SBOM file (CycloneDX or SPDX) | Yes | — |
| `--scan` | Path to scan results (Grype, Trivy, or SARIF); repeatable | Yes | — |
| `--vex` | Path to VEX document (OpenVEX or CSAF) | Yes | — |
| `--provenance` | Path to SLSA provenance attestation JSON | No | — |
| `--signature` | Path to signature file; repeatable | No | — |
| `--product-config` | Path to product metadata YAML/JSON | No | — |
| `--kev` | Path to local CISA KEV catalog JSON (auto-fetched if omitted) | No | auto-fetch |
| `--policy-dir` | Directory of custom Rego policies | No | — |
| `--format` | Output format: `json` or `markdown` | No | json |

**5. Input Formats:** SBOM (CycloneDX/SPDX), scans (Grype/Trivy/SARIF), VEX (OpenVEX/CSAF), SLSA provenance JSON, signature files, product config YAML.

**6. Output Formats:** JSON report or Markdown summary. Show example output structure: `policies` array with `rule_id`, `name`, `cra_reference`, `status` (PASS/FAIL/SKIP), `severity`, `evidence`.

**7. Examples:**

*Example 1: Basic evaluation*
```bash
cra policykit --sbom sbom.cdx.json --scan grype.json --vex vex.json
```

*Example 2: Full evaluation with provenance and signatures*
```bash
cra policykit --sbom sbom.cdx.json --scan grype.json --vex vex.json \
  --provenance provenance.json --signature sig.bundle \
  --product-config product.yaml --format markdown
```

*Example 3: With custom policies*
```bash
cra policykit --sbom sbom.cdx.json --scan grype.json --vex vex.json \
  --policy-dir ./custom-policies/
```

**8. Integration:** Policy report feeds into `cra evidence` as a bundle artifact. Run after `cra vex` to validate VEX coverage.

- [ ] **Step 3: Verify build**

```bash
cd site && uv run mkdocs build --strict 2>&1
```

- [ ] **Step 4: Commit**

```bash
git add site/docs/tools/policykit.md site/docs/assets/diagrams/policykit-evaluation.svg
git commit -m "docs: add PolicyKit tool page with evaluation pipeline diagram"
```

---

### Task 11: Report Tool Page and Stages SVG

**Files:**
- Create: `site/docs/tools/report.md`
- Create: `site/docs/assets/diagrams/report-stages.svg`

- [ ] **Step 1: Create report stages SVG**

Create `site/docs/assets/diagrams/report-stages.svg` — shows three report stages on a timeline with data requirements:

Left to right:
1. **24h Early Warning** (`--stage early-warning`) — inputs: SBOM, scan, product-config. Outputs: CVE list, product ID, Member State indication.
2. **72h Notification** (`--stage notification`) — inputs: + VEX, KEV, EPSS. Outputs: + exploit nature, severity assessment, corrective measures, sensitivity level.
3. **14-day Final Report** (`--stage final-report`) — inputs: + human-input YAML, CSAF advisory ref, corrective-measure-date. Outputs: + root cause, malicious actor info, security update details, user notification requirements.

Show each stage accumulating more inputs and producing richer outputs.

- [ ] **Step 2: Write Report tool page**

Replace `site/docs/tools/report.md`:

**1. Purpose:** `cra report` generates CRA Article 14 vulnerability notification documents, automating the three-stage notification process required when a manufacturer becomes aware of an actively exploited vulnerability.

**2. CRA Context:**

```markdown
!!! abstract "CRA Reference"
    This tool implements **Article 14** — Reporting obligations of manufacturers.
    It generates the three mandatory notification stages: 24h early warning (Art. 14(2)(a)),
    72h notification (Art. 14(2)(b)), and 14-day final report (Art. 14(2)(c)).
    See [Article 14 — Vulnerability Notification](../cra/article-14.md).
```

**3. How It Works:** Embed SVG. Describe three stages and what data each requires/produces.

**Signal Detection:** Explains how the tool detects exploitation signals:
- CISA KEV catalog matching — identifies vulnerabilities known to be actively exploited
- EPSS scoring — Exploit Prediction Scoring System, configurable threshold (default 0.7)
- VEX status — reachability and exploitability context from `cra vex`

**Reachability Evidence in Reports:** When VEX data includes reachability analysis, the report incorporates call paths and confidence scores to provide context on whether the vulnerable code is actually reachable in the product.

**4. Usage:**

```bash
cra report --sbom <path> --scan <path> --stage <stage> --product-config <path> [flags]
```

| Flag | Description | Required | Default |
|---|---|---|---|
| `--sbom` | Path to SBOM file (CycloneDX or SPDX) | Yes | — |
| `--scan` | Path to scan results (Grype, Trivy, or SARIF); repeatable | Yes | — |
| `--stage` | Notification stage: `early-warning`, `notification`, `final-report` | Yes | — |
| `--product-config` | Path to product config YAML with manufacturer section | Yes | — |
| `--kev` | Path to local CISA KEV catalog JSON (auto-fetched if omitted) | No | auto-fetch |
| `--epss-path` | Path to EPSS scores JSON | No | — |
| `--epss-threshold` | EPSS score threshold for exploitation signal (0.0-1.0) | No | 0.7 |
| `--vex` | Path to VEX results (OpenVEX or CSAF VEX) | No | — |
| `--human-input` | Path to human input YAML for final report | No | — |
| `--csaf-advisory-ref` | Companion CSAF advisory ID for Art. 14(8) user notification | No | — |
| `--corrective-measure-date` | ISO 8601 date when corrective measure became available | No | — |
| `--format` | Output format: `json` or `markdown` | No | json |

**5-7. Examples for each stage** — show commands and describe output structure.

**8. Integration:** Report output feeds into `cra evidence`. Use alongside `cra csaf` for the Art. 14(8) user notification requirement.

- [ ] **Step 3: Verify build and commit**

```bash
cd site && uv run mkdocs build --strict 2>&1
git add site/docs/tools/report.md site/docs/assets/diagrams/report-stages.svg
git commit -m "docs: add Report tool page with notification stages diagram"
```

---

### Task 12: Evidence Tool Page and Bundle SVG

**Files:**
- Create: `site/docs/tools/evidence.md`
- Create: `site/docs/assets/diagrams/evidence-bundle.svg`

- [ ] **Step 1: Create evidence bundle SVG**

Create `site/docs/assets/diagrams/evidence-bundle.svg` — shows the 6-stage pipeline: Collection -> Validation -> Cross-validation -> Assembly -> Signing -> Archive. Below the pipeline, show the bundle anatomy: a directory tree showing the evidence bundle structure with all artifact types.

- [ ] **Step 2: Write Evidence tool page**

Replace `site/docs/tools/evidence.md`:

**1. Purpose:** `cra evidence` bundles and signs compliance outputs into a versioned CRA evidence package for Annex VII technical documentation and conformity assessment.

**2. CRA Context:**

```markdown
!!! abstract "CRA Reference"
    This tool addresses **Annex VII** — Content of the Technical Documentation, and
    **Annex V** — EU Declaration of Conformity. It assembles the evidence package
    required for conformity assessment under **Article 32**.
    See [Annex VII — Technical Documentation](../cra/annex-vii.md).
```

**3. How It Works:** Embed SVG. Describe each stage:
- **Collection** — gathers artifacts from specified paths
- **Validation** — verifies format correctness of each artifact
- **Cross-validation** — checks consistency between artifacts (e.g., SBOM components match VEX subjects)
- **Assembly** — constructs the evidence bundle directory structure with manifest
- **Signing** — signs the bundle using Cosign (keyless via Fulcio/Rekor, or key-based)
- **Archive** — optionally creates a `.tar.gz` archive

**Artifact Inventory:**

| Artifact | Flag | Source | Annex VII Section |
|---|---|---|---|
| SBOM | `--sbom` | External tool (syft, cdxgen) | 2(b) |
| VEX document | `--vex` | `cra vex` | 2(b) |
| Scan results | `--scan` | Grype, Trivy, SARIF | 6 |
| Policy report | `--policy-report` | `cra policykit` | 6 |
| CSAF advisory | `--csaf` | `cra csaf` | 2(b) |
| Art. 14 notification | `--art14-report` | `cra report` | 2(b) |
| Risk assessment | `--risk-assessment` | Manual | 3 |
| Architecture docs | `--architecture` | Manual | 2(a) |
| Production process | `--production-process` | Manual | 2(c) |
| EU declaration | `--eu-declaration` | Manual | 7 |
| CVD policy | `--cvd-policy` | Manual | 2(b) |
| Harmonised standards | `--standards` | Manual | 5 |
| Product config | `--product-config` | Manual | 1, 4 |

**4. Usage:** Full flag table:

| Flag | Description | Required | Default |
|---|---|---|---|
| `--product-config` | Path to product configuration YAML | Yes | — |
| `--output-dir` | Output directory for evidence bundle | Yes | — |
| `--sbom` | Path to SBOM (CycloneDX or SPDX) | No | — |
| `--vex` | Path to VEX document (OpenVEX or CSAF) | No | — |
| `--scan` | Path to scan results; repeatable | No | — |
| `--policy-report` | Path to PolicyKit report JSON | No | — |
| `--csaf` | Path to CSAF advisory | No | — |
| `--art14-report` | Path to Art. 14 notification JSON | No | — |
| `--risk-assessment` | Path to cybersecurity risk assessment | No | — |
| `--architecture` | Path to design/development architecture doc | No | — |
| `--production-process` | Path to production/monitoring process doc | No | — |
| `--eu-declaration` | Path to EU declaration of conformity | No | — |
| `--cvd-policy` | Path to coordinated vulnerability disclosure policy | No | — |
| `--standards` | Path to harmonised standards document | No | — |
| `--format` | Output format: `json` or `markdown` | No | json |
| `--archive` | Also produce .tar.gz archive | No | false |
| `--signing-key` | Cosign key path (keyless if omitted) | No | keyless |

**5-7. Examples:** Minimal bundle, full bundle, signed archive.

**8. Integration:** Evidence is the final tool in the pipeline — it consumes outputs from all other tools plus manual artifacts.

- [ ] **Step 3: Verify build and commit**

```bash
cd site && uv run mkdocs build --strict 2>&1
git add site/docs/tools/evidence.md site/docs/assets/diagrams/evidence-bundle.svg
git commit -m "docs: add Evidence tool page with bundle anatomy diagram"
```

---

### Task 13: CSAF Tool Page and Generation SVG

**Files:**
- Create: `site/docs/tools/csaf.md`
- Create: `site/docs/assets/diagrams/csaf-generation.svg`

- [ ] **Step 1: Create CSAF generation SVG**

Create `site/docs/assets/diagrams/csaf-generation.svg` — shows inputs (SBOM + Scan + optional VEX) flowing into the CSAF document assembly process: Document metadata -> Product tree -> Vulnerabilities -> Scores (CVSS/EPSS) -> Remediations -> Threats -> Notes -> CSAF 2.0 output.

- [ ] **Step 2: Write CSAF tool page**

Replace `site/docs/tools/csaf.md`:

**1. Purpose:** `cra csaf` converts vulnerability scanner output and VEX assessments into CSAF 2.0 (Common Security Advisory Framework) security advisories, the industry-standard machine-readable format for vulnerability communication.

**2. CRA Context:**

```markdown
!!! abstract "CRA Reference"
    This tool addresses **Article 14(8)**: after becoming aware of an actively exploited
    vulnerability, the manufacturer shall inform impacted users in a structured,
    machine-readable format that is easily automatically processable.
    See [Article 14 — Vulnerability Notification](../cra/article-14.md).

    It also supports **Annex I, Part II, point (8)**: security updates shall be
    accompanied by advisory messages providing users with relevant information.
```

**3. How It Works:** Embed SVG. Describe the CSAF document anatomy:
- **Document** — metadata, publisher, tracking, distribution
- **Product tree** — product/component hierarchy derived from SBOM
- **Vulnerabilities** — CVE data from scan results, enriched with VEX status
- **Scores** — CVSS scores from scan data, optional EPSS
- **Remediations** — remediation guidance per vulnerability
- **Threats** — threat classification (impact type)
- **Notes** — assessment summaries, reachability information

**4. Usage:**

```bash
cra csaf --sbom <path> --scan <path> --publisher-name <name> --publisher-namespace <url> [flags]
```

| Flag | Description | Required | Default |
|---|---|---|---|
| `--sbom` | Path to SBOM file (CycloneDX or SPDX) | Yes | — |
| `--scan` | Path to scan results (Grype, Trivy, or SARIF); repeatable | Yes | — |
| `--publisher-name` | Organization name for the advisory publisher | Yes | — |
| `--publisher-namespace` | Organization URL for the advisory publisher | Yes | — |
| `--vex` | Path to VEX results (OpenVEX or CSAF VEX) | No | — |
| `--tracking-id` | Advisory tracking ID (auto-generated if omitted) | No | auto |
| `--title` | Advisory title (auto-generated if omitted) | No | auto |

**5-7. Examples:** Basic advisory, VEX-enriched, multi-vulnerability.

**8. Integration:** CSAF output feeds into `cra evidence`. Use alongside `cra report` for complete Art. 14 compliance.

- [ ] **Step 3: Verify build and commit**

```bash
cd site && uv run mkdocs build --strict 2>&1
git add site/docs/tools/csaf.md site/docs/assets/diagrams/csaf-generation.svg
git commit -m "docs: add CSAF tool page with generation pipeline diagram"
```

---

### Task 14: Ecosystem Pages and Landscape SVG

**Files:**
- Create: `site/docs/ecosystem/index.md`
- Create: `site/docs/ecosystem/standards.md`
- Create: `site/docs/ecosystem/scanners.md`
- Create: `site/docs/ecosystem/infrastructure.md`
- Create: `site/docs/assets/diagrams/ecosystem-landscape.svg`

- [ ] **Step 1: Create ecosystem landscape SVG**

Create `site/docs/assets/diagrams/ecosystem-landscape.svg` — three horizontal layers:

**Top: CRA Toolkit Layer** — five tool boxes (VEX, PolicyKit, Report, Evidence, CSAF)
**Middle: Tools Layer** — Grype, Trivy, Cosign, govulncheck, syft/cdxgen
**Bottom: Standards Layer** — OpenVEX, CSAF 2.0, CycloneDX, SPDX, SLSA, SARIF, OPA/Rego

Lines connecting tools to standards they implement and toolkit tools they feed.

- [ ] **Step 2: Write ecosystem index page**

Replace `site/docs/ecosystem/index.md`:

Opening: "The CRA toolkit doesn't replace existing security tools — it orchestrates them into a compliance pipeline." Explain the three-layer architecture. Embed the landscape SVG. Brief descriptions of each layer linking to detailed pages.

- [ ] **Step 3: Write standards page**

Replace `site/docs/ecosystem/standards.md`:

For each standard, cover: what it is, CRA relevance, how the toolkit uses it, link to official spec.

- **OpenVEX** — Vulnerability Exploitability eXchange. Default output of `cra vex`. Communicates whether a vulnerability is exploitable in a specific product context.
- **CSAF 2.0** — Common Security Advisory Framework (OASIS standard). Output of `cra csaf`, alternate output of `cra vex`. Machine-readable security advisory format.
- **CycloneDX** — OASIS SBOM standard. Supported input format. JSON format with `bomFormat: "CycloneDX"` discriminator.
- **SPDX** — Linux Foundation/ISO SBOM standard. Supported input format. JSON format with `spdxVersion` discriminator.
- **SLSA** — Supply-chain Levels for Software Artifacts. Provenance attestation format verified by `cra policykit` (CRA-AI-3.1 policy).
- **SARIF** — Static Analysis Results Interchange Format (OASIS). Supported scan input format. JSON format with `runs` discriminator.

- [ ] **Step 4: Write scanners page**

Replace `site/docs/ecosystem/scanners.md`:

For each scanner: what it is, how to generate output the toolkit accepts, format details.

**Grype** (Anchore):
```bash
grype sbom:sbom.cdx.json -o json > grype.json
```

**Trivy** (Aqua Security):
```bash
trivy fs --format json --output trivy.json .
```

**SARIF producers** — any tool that outputs SARIF (CodeQL, Semgrep, etc.):
```bash
# CodeQL example
codeql database analyze --format=sarif-latest --output=results.sarif
```

- [ ] **Step 5: Write infrastructure page**

Replace `site/docs/ecosystem/infrastructure.md`:

**OPA / Rego** — Open Policy Agent powers the PolicyKit evaluation engine. Policies are written in Rego, a declarative query language. The toolkit embeds 10 default policies and supports loading custom policies. Link to OPA docs for Rego syntax.

**Cosign** (Sigstore) — signs evidence bundles for integrity and authenticity. Two modes: keyless (using Fulcio for certificates and Rekor for transparency log) and key-based (using a local private key). Used by `cra evidence`.

**Tree-sitter** — incremental parsing framework that powers reachability analysis in `cra vex`. The toolkit includes tree-sitter grammars for 8 languages (Go, Rust, Python, JavaScript, Java, C#, PHP, Ruby) to build interprocedural call graphs and determine whether vulnerable functions are actually reachable from application entry points.

- [ ] **Step 6: Verify build and commit**

```bash
cd site && uv run mkdocs build --strict 2>&1
git add site/docs/ecosystem/ site/docs/assets/diagrams/ecosystem-landscape.svg
git commit -m "docs: add ecosystem pages with landscape diagram"
```

---

### Task 15: End-to-End Workflow Guide

**Files:**
- Create: `site/docs/guides/workflow.md`

- [ ] **Step 1: Write workflow guide**

Replace `site/docs/guides/workflow.md`:

**Title:** End-to-End CRA Compliance Workflow

**Introduction:** Walk through a complete compliance cycle using a real-world scenario. This guide uses example files from the toolkit's test data to demonstrate each step.

**Prerequisites:**
- `cra` binary installed
- A vulnerability scanner (Grype or Trivy)
- An SBOM generator (syft or cdxgen)
- Source code access (for reachability analysis)

**Step 1: Generate SBOM**
```bash
# Using syft
syft . -o cyclonedx-json > sbom.cdx.json

# Or using cdxgen
cdxgen -o sbom.cdx.json
```
Explain what the SBOM contains and why it's required (Annex I, Part II, point 1).

**Step 2: Scan for Vulnerabilities**
```bash
# Using Grype
grype sbom:sbom.cdx.json -o json > grype.json

# Or using Trivy
trivy fs --format json --output trivy.json .
```
Explain what scan results contain: CVE IDs, affected packages, severity, CVSS scores.

**Step 3: Determine Exploitability (VEX)**
```bash
cra vex --sbom sbom.cdx.json --scan grype.json --source-dir . -o vex.json
```
Explain that VEX determination reduces false positives by checking whether vulnerabilities are actually exploitable. Reference the filter chain.

**Step 4: Evaluate Compliance Policies**
```bash
cra policykit --sbom sbom.cdx.json --scan grype.json --vex vex.json \
  --product-config product.yaml --format markdown -o policy-report.md
```
Explain that PolicyKit evaluates 10 CRA compliance policies. Show example product config YAML:
```yaml
product:
  name: "my-product"
  version: "1.0.0"
  release_date: "2026-01-15"
  support_end_date: "2031-01-15"
  update_mechanism:
    type: "automatic"
    url: "https://updates.example.com"
    auto_update_default: true
    security_updates_separate: true
```

**Step 5: Generate Notifications (if needed)**
```bash
# If actively exploited vulnerability found:
cra report --sbom sbom.cdx.json --scan grype.json --vex vex.json \
  --stage early-warning --product-config product.yaml -o early-warning.json
```
Explain the three stages and when each is required.

**Step 6: Produce Security Advisories**
```bash
cra csaf --sbom sbom.cdx.json --scan grype.json --vex vex.json \
  --publisher-name "My Company" --publisher-namespace "https://mycompany.example.com" \
  -o advisory.json
```
Explain how CSAF advisories fulfil Art. 14(8) user notification.

**Step 7: Bundle and Sign Evidence**
```bash
cra evidence --product-config product.yaml --output-dir ./evidence \
  --sbom sbom.cdx.json --vex vex.json --scan grype.json \
  --policy-report policy-report.json --csaf advisory.json \
  --archive --format json
```
Explain the evidence bundle structure and signing. Show expected output directory layout.

- [ ] **Step 2: Verify build and commit**

```bash
cd site && uv run mkdocs build --strict 2>&1
git add site/docs/guides/workflow.md
git commit -m "docs: add end-to-end compliance workflow guide"
```

---

### Task 16: CI/CD Integration Guide and Pipeline SVG

**Files:**
- Create: `site/docs/guides/ci-cd.md`
- Create: `site/docs/assets/diagrams/ci-cd-pipeline.svg`

- [ ] **Step 1: Create CI/CD pipeline SVG**

Create `site/docs/assets/diagrams/ci-cd-pipeline.svg` — shows a GitHub Actions workflow:

Horizontal flow of jobs: `generate-sbom` -> `scan` -> `vex` -> `policykit` (with gate: fail if critical policies fail) -> `report` (conditional: only if exploited vulns) -> `csaf` -> `evidence` (with signing)

Show artifacts flowing between jobs and the policy gate decision point.

- [ ] **Step 2: Write CI/CD guide**

Replace `site/docs/guides/ci-cd.md`:

**Title:** CI/CD Integration

**Introduction:** Embed CRA compliance checks into your CI/CD pipeline to automate compliance artifact generation on every build or release.

Embed the pipeline SVG.

**GitHub Actions Reference Pipeline:**

Provide a complete, working `.github/workflows/cra-compliance.yml`:

```yaml
name: CRA Compliance

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am

jobs:
  generate-sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install syft
        uses: anchore/sbom-action/download-syft@v0
      - name: Generate SBOM
        run: syft . -o cyclonedx-json > sbom.cdx.json
      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.cdx.json

  scan:
    needs: generate-sbom
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with: { name: sbom }
      - name: Install Grype
        uses: anchore/scan-action/download-grype@v4
      - name: Scan SBOM
        run: grype sbom:sbom.cdx.json -o json > grype.json
      - uses: actions/upload-artifact@v4
        with:
          name: scan
          path: grype.json

  vex:
    needs: scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with: { name: sbom }
      - uses: actions/download-artifact@v4
        with: { name: scan }
      - name: Install CRA toolkit
        run: go install github.com/ravan/suse-cra-toolkit/cmd/cra@latest
      - name: VEX determination
        run: cra vex --sbom sbom.cdx.json --scan grype.json --source-dir . -o vex.json
      - uses: actions/upload-artifact@v4
        with:
          name: vex
          path: vex.json

  policykit:
    needs: vex
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with: { name: sbom }
      - uses: actions/download-artifact@v4
        with: { name: scan }
      - uses: actions/download-artifact@v4
        with: { name: vex }
      - name: Install CRA toolkit
        run: go install github.com/ravan/suse-cra-toolkit/cmd/cra@latest
      - name: Evaluate policies
        run: |
          cra policykit --sbom sbom.cdx.json --scan grype.json --vex vex.json \
            --product-config product.yaml -o policy-report.json
      - uses: actions/upload-artifact@v4
        with:
          name: policy-report
          path: policy-report.json

  csaf:
    needs: vex
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with: { name: sbom }
      - uses: actions/download-artifact@v4
        with: { name: scan }
      - uses: actions/download-artifact@v4
        with: { name: vex }
      - name: Install CRA toolkit
        run: go install github.com/ravan/suse-cra-toolkit/cmd/cra@latest
      - name: Generate CSAF advisory
        run: |
          cra csaf --sbom sbom.cdx.json --scan grype.json --vex vex.json \
            --publisher-name "${{ vars.PUBLISHER_NAME }}" \
            --publisher-namespace "${{ vars.PUBLISHER_NAMESPACE }}" \
            -o advisory.json
      - uses: actions/upload-artifact@v4
        with:
          name: csaf
          path: advisory.json

  evidence:
    needs: [policykit, csaf]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - name: Install CRA toolkit
        run: go install github.com/ravan/suse-cra-toolkit/cmd/cra@latest
      - name: Bundle evidence
        run: |
          cra evidence --product-config product.yaml --output-dir ./evidence \
            --sbom sbom/sbom.cdx.json --vex vex/vex.json \
            --scan scan/grype.json --policy-report policy-report/policy-report.json \
            --csaf csaf/advisory.json --archive
      - uses: actions/upload-artifact@v4
        with:
          name: evidence-bundle
          path: ./evidence/
```

**Key design decisions:**
- Policy gate: PolicyKit job fails the pipeline if critical policies (CRA-AI-1.1, CRA-AI-2.1) report FAIL
- Report job is conditional — only runs when actively exploited vulnerabilities are detected
- Evidence job runs last, consuming all upstream artifacts
- Scheduled weekly runs ensure ongoing compliance monitoring
- Signing: add `--signing-key` or use keyless Cosign in evidence job for production

**Conceptual Pipeline Mapping:**

| Stage | GitHub Actions | GitLab CI | Tekton |
|---|---|---|---|
| SBOM generation | `actions/checkout` + syft | `stage: sbom` + syft binary | `Task: generate-sbom` |
| Vulnerability scan | grype/trivy action | `stage: scan` + grype/trivy | `Task: scan` |
| VEX determination | `cra vex` step | `stage: vex` + `cra vex` | `Task: vex` |
| Policy evaluation | `cra policykit` step | `stage: policy` + `cra policykit` | `Task: policykit` |
| Advisory generation | `cra csaf` step | `stage: csaf` + `cra csaf` | `Task: csaf` |
| Evidence bundling | `cra evidence` step | `stage: evidence` + `cra evidence` | `Task: evidence` |
| Artifact passing | `upload/download-artifact` | `artifacts:` / `dependencies:` | PVC / workspace |
| Failure gating | `needs:` + step exit code | `allow_failure: false` | `runAfter:` + condition |

- [ ] **Step 3: Verify build and commit**

```bash
cd site && uv run mkdocs build --strict 2>&1
git add site/docs/guides/ci-cd.md site/docs/assets/diagrams/ci-cd-pipeline.svg
git commit -m "docs: add CI/CD integration guide with GitHub Actions pipeline"
```

---

### Task 17: Final Verification and Cleanup

**Files:**
- Modify: `site/docs/` (remove any remaining placeholders)

- [ ] **Step 1: Run full site build with strict mode**

```bash
cd site && uv run mkdocs build --strict 2>&1
```

Expected: Clean build with no warnings or errors.

- [ ] **Step 2: Verify all cross-links resolve**

Check that all internal links between pages resolve correctly. The `--strict` flag in mkdocs build will catch broken links.

- [ ] **Step 3: Verify all SVG diagrams are referenced**

Ensure all 11 SVGs in `site/docs/assets/diagrams/` are referenced from at least one page:
- `cra-overview.svg` — cra/overview.md, index.md
- `cra-article14-timeline.svg` — cra/article-14.md
- `cra-annex-mapping.svg` — cra/annex-i.md
- `tool-pipeline.svg` — index.md, tools/overview.md
- `vex-filter-chain.svg` — tools/vex.md
- `policykit-evaluation.svg` — tools/policykit.md
- `report-stages.svg` — tools/report.md
- `evidence-bundle.svg` — tools/evidence.md
- `csaf-generation.svg` — tools/csaf.md
- `ecosystem-landscape.svg` — ecosystem/index.md
- `ci-cd-pipeline.svg` — guides/ci-cd.md

- [ ] **Step 4: Serve locally and visual check**

```bash
cd site && uv run mkdocs serve
```

Open http://127.0.0.1:8000 and verify:
- Navigation tabs work (Home, CRA Reference, Tools, Ecosystem, Guides)
- Light/dark mode toggle works
- SVG diagrams render correctly
- Cross-links between CRA and Tool pages work
- Code blocks have copy buttons
- Search works

- [ ] **Step 5: Commit final state**

```bash
git add -A site/
git commit -m "docs: complete documentation site with all pages and diagrams"
```
