

**SUSE**

Digital Sovereignty Unit

**CRA Compliance Toolkit**

Product Strategy & Implementation Plan

Five composable CLI tools filling verified gaps in the open-source supply chain security ecosystem,

evolved into an autonomous CRA compliance agent powered by a fine-tuned Gemma 4 model.

**CONFIDENTIAL**

April 2026 | Version 5.0

Prepared for SUSE Digital Sovereignty Unit Leadership

# **Table of Contents**

[**Table of Contents	2**](#heading=)

[**1\. Executive Summary	4**](#heading=)

[**2\. CRA Regulatory Context	5**](#heading=)

[2.1 Key Compliance Deadlines	5](#heading=)

[2.2 What the CRA Requires (Relevant to Our Tools)	5](#heading=)

[**3\. The Open-Source Landscape: What Exists vs What’s Missing	6**](#heading=)

[3.1 What Exists (Solid OSS Tools)	6](#heading=)

[3.2 What’s Missing (Verified Gaps)	6](#heading=)

[**4\. Phase 1: Deterministic CLI Tools	7**](#heading=)

[4.1 cra-vex — VEX Status Determination (Deterministic Mode)	7](#heading=)

[How It Works (Phase 1 — No LLM)	7](#heading=)

[4.2 cra-policykit — CRA Annex I Rules as Code	8](#heading=)

[What It Checks	8](#heading=)

[4.3 cra-report — Art. 14 Notification Generator	8](#heading=)

[Three-Stage Pipeline	8](#heading=)

[4.4 cra-evidence — Compliance Evidence Bundler	9](#heading=)

[What Goes In the Bundle	9](#heading=)

[4.5 cra-csaf — Scanner-to-Advisory Bridge	10](#heading=)

[4.6 The Composed Pipeline (Phase 1\)	10](#heading=)

[4.7 Phase 1 Investment	10](#heading=)

[**5\. Phase 2: AI-Powered CRA Agent (Gemma 4\)	12**](#heading=)

[5.1 Why Gemma 4	12](#heading=)

[5.2 The Model Stack	12](#heading=)

[5.3 The CRA Agent Architecture	13](#heading=)

[Agent Modes	13](#heading=)

[What Makes This Different From a Script	13](#heading=)

[5.4 cra-vex Enhanced: LLM-Assisted VEX Determination	14](#heading=)

[5.5 Fine-Tuning: The Competitive Moat	14](#heading=)

[Training Data SUSE Already Has	14](#heading=)

[Fine-Tuning Pipeline	14](#heading=)

[Honest Risks of Fine-Tuning	15](#heading=)

[**6\. The Digital Sovereignty Play	16**](#heading=)

[6.1 Why This Resonates Now	16](#heading=)

[6.2 Deployment Profiles	16](#heading=)

[**7\. Business Model	17**](#heading=)

[7.1 Free vs Paid	17](#heading=)

[7.2 The Adoption Funnel	17](#heading=)

[7.3 SUSE Product Integration	17](#heading=)

[**8\. Investment & Timeline	19**](#heading=)

[8.1 Combined Investment	19](#heading=)

[8.2 Timeline	19](#heading=)

[2026	19](#heading=)

[2027	19](#heading=)

[**9\. Risks & Mitigations	21**](#heading=)

[**10\. What SUSE Ships	22**](#heading=)

[Phase 1 Deliverable (Q4 2026\)	22](#heading=)

[Phase 2 Deliverable (Q3 2027\)	22](#heading=)

[Immediate Action: Fix SUSE VEX Feed	22](#heading=)

[**11\. Recommendation	23**](#heading=)

# **1\. Executive Summary**

The EU Cyber Resilience Act (CRA 2024/2847) creates entirely new compliance obligations for every manufacturer of products with digital elements sold in the EU. Full compliance is required by **December 11, 2027**, with vulnerability reporting obligations starting **September 11, 2026**.

After extensive analysis of the CRA requirements, the open-source supply chain security ecosystem, and SUSE’s existing assets, this strategy proposes a **two-phase approach**:

* **Phase 1: Deterministic CLI Tools (Q2–Q4 2026).** Five focused, composable command-line tools that fill verified gaps between existing open-source tools. No AI/ML dependency. Pure automation using deterministic logic, standard formats, and policy-as-code. Ships before the Art. 14 vulnerability reporting deadline (Sep 2026).

* **Phase 2: AI-Powered CRA Agent (Q1–Q3 2027).** A fine-tuned Gemma 4 model (suse-cra-gemma4) transforms the CLI tools into an autonomous compliance agent with native tool calling. Local deployment, zero cloud dependency, full digital sovereignty. Ships before the full CRA compliance deadline (Dec 2027).

| Why Two Phases? Phase 1 delivers immediate value with zero AI risk. Each tool works today, with deterministic logic, standard inputs/outputs, and no model dependency. Phase 2 adds intelligence on top of a proven foundation. The fine-tuned model enhances accuracy but is never a hard dependency — every tool works without it. This de-risks the investment: if AI delivery slips, Phase 1 still meets the CRA deadlines. |
| :---- |

**Total Investment:** $2.5–3.5M across both phases, 12–15 people, 9–12 months.

**Revenue Model:** Open core. CLI tools are Apache 2.0 open source. The fine-tuned SUSE CRA model, curated policy library, agent Watch Mode, and support are commercial.

# **2\. CRA Regulatory Context**

The Cyber Resilience Act (Regulation 2024/2847) establishes mandatory cybersecurity requirements for all products with digital elements placed on the EU market. It applies to hardware and software manufacturers, importers, and distributors.

## **2.1 Key Compliance Deadlines**

| Date | Obligation | Urgency |
| :---- | :---- | :---- |
| Sep 11, 2026 | Vulnerability reporting to ENISA (Art. 14): 24h early warning, 72h notification, 14-day final report for actively exploited vulnerabilities | **HIGH** |
| Dec 11, 2027 | Full CRA compliance: Annex I essential requirements, Annex VII technical documentation, conformity assessment, SBOM, secure update mechanisms | **CRITICAL** |

## **2.2 What the CRA Requires (Relevant to Our Tools)**

* **Art. 13 — Manufacturer Obligations:** Risk assessment, SBOM generation, vulnerability handling, security update mechanism, unique product identification, conformity marking.

* **Art. 14 — Vulnerability Reporting:** 24h early warning to ENISA/CSIRT for actively exploited vulnerabilities. 72h notification with impact assessment. 14-day final report with root cause and remediation. User notification (Art. 14(8)).

* **Annex I — Essential Cybersecurity Requirements:** \~30 requirements covering secure defaults, cryptography, access control, data protection, update mechanisms, vulnerability handling. \~15 are machine-checkable; \~15 require human judgment.

* **Annex VII — Technical Documentation:** Complete technical file including design description, risk assessment, SBOM, test reports, vulnerability handling process, and evidence of conformity.

# **3\. The Open-Source Landscape: What Exists vs What’s Missing**

The supply chain security ecosystem has strong point solutions for SBOM generation, vulnerability scanning, artifact signing, and dependency graphing. The gaps are in the spaces between these tools — where outputs need to become CRA compliance artifacts.

## **3.1 What Exists (Solid OSS Tools)**

| SBOM Generation | Vuln Scanning | Signing/Provenance | Databases |
| :---- | :---- | :---- | :---- |
| Syft, cdxgen, Trivy, CycloneDX plugins | Grype, Trivy, OSV-Scanner, Scorecard | Cosign (Sigstore), Witness (in-toto), SLSA, Chainloop | OSV.dev, NVD, GHSA, CISA KEV, EPSS, deps.dev, GUAC |

## **3.2 What’s Missing (Verified Gaps)**

| \# | Gap | Detail |
| :---- | :---- | :---- |
| 1 | VEX Status Determination | Nobody automates “is this CVE exploitable in MY specific build?” VexLLM is a PoC. All existing VEX tools (vexctl) require manual status input. |
| 2 | CRA Policy-as-Code | Zero OPA/Rego policies encoding CRA Annex I rules exist. OCCTET is early-stage. No CI/CD gate for CRA compliance. |
| 3 | Art. 14 Report Generation | CRA’s 24h/72h/14d reporting is entirely new. Zero tools generate the notification documents. ENISA SRP format TBD. |
| 4 | Evidence Assembly | No tool bundles SBOM \+ VEX \+ provenance \+ scans into a signed CRA evidence package for Annex VII. |
| 5 | Scanner-to-CSAF Bridge | No tool converts Trivy/Grype output into CSAF 2.0 advisories for downstream user notification (Art. 14(8)). |

| Design Principle Unix philosophy: each tool does one thing well, takes standard inputs (CycloneDX/SPDX SBOMs, SARIF scans, OpenVEX/CSAF), and produces standard outputs. Each works standalone. Composed together, they produce end-to-end CRA compliance. SUSE fills the missing pieces; existing OSS does the heavy lifting. |
| :---- |

# **4\. Phase 1: Deterministic CLI Tools**

Phase 1 delivers five CLI tools with **zero AI/ML dependency**. Every tool operates on deterministic logic: version comparisons, format validation, schema checking, policy evaluation, and document generation from structured data. This ensures the tools are reliable, auditable, and deployable in any environment from day one.

| Phase 1 Timeline Q2–Q4 2026\. All tools developed in parallel. cra-report ships first (ahead of Art. 14 deadline Sep 2026). Full toolkit available by Q4 2026\. |
| :---- |

## **4.1 cra-vex — VEX Status Determination (Deterministic Mode)**

Takes an SBOM \+ vulnerability scan results and auto-determines VEX status for each CVE using deterministic filters. In Phase 1, this covers the mechanical checks that eliminate 40–60% of CVEs without any model.

### **How It Works (Phase 1 — No LLM)**

* **Component presence check:** Is the affected component in the SBOM? If not: status \= not\_affected, justification \= component\_not\_present.

* **Version range check:** Is the installed version within the affected range? If not: status \= not\_affected, justification \= vulnerable\_code\_not\_present.

* **Platform/OS match:** Does the CVE apply to this platform (linux vs windows, x86 vs arm)? If not: not\_affected.

* **Patch status:** Is the SBOM version ≥ the fix version? If yes: status \= fixed.

* **Upstream VEX ingestion:** If the upstream vendor has published a VEX or CSAF advisory, ingest their status determination directly.

* **Remaining CVEs:** Status \= under\_investigation, queued for manual review. In Phase 2, the LLM handles these.

**Inputs:** SBOM (CycloneDX/SPDX), vulnerability scan results (SARIF, Grype/Trivy JSON), optional build config/feature flags.

**Outputs:** VEX document (OpenVEX or CSAF VEX profile) with per-CVE status, justification code, and evidence chain.

**CRA Articles:** Art. 13(6), Annex I Part II.

**Engineering:** 2 engineers, 2–3 months. Deterministic filters, format parsing, VEX document generation.

| Phase 1 Value Even without LLM, cra-vex eliminates 40–60% of CVEs from manual review immediately. For a product with 200 CVEs, that’s 80–120 auto-resolved with full justification. The remaining 80–120 go to the human review queue (Phase 2 reduces this further to \~15–30). |
| :---- |

## **4.2 cra-policykit — CRA Annex I Rules as Code**

An OPA/Rego policy library encoding CRA Annex I essential cybersecurity requirements as machine-checkable rules. Runs against product artifacts and returns a pass/fail compliance report.

### **What It Checks**

| Rule | Source | Result |
| :---- | :---- | :---- |
| SBOM exists and is valid CycloneDX/SPDX | Annex I | PASS/FAIL |
| No known exploited vulnerabilities (CISA KEV cross-check) | Annex I | PASS/FAIL |
| All critical/high CVEs have VEX assessment | Annex I | PASS/FAIL |
| Build provenance exists (SLSA L1+) | Art. 13 | PASS/FAIL |
| All artifacts cryptographically signed | Art. 13 | PASS/FAIL |
| Support period declared and \> 5 years | Annex I Part II | PASS/FAIL |
| Secure update mechanism documented | Annex I Part II | PASS/FAIL |
| “Appropriate level of cybersecurity” (subjective) | Annex I | HUMAN |
| Risk assessment performed (process, not artifact) | Art. 13(2) | HUMAN |

About 15 of the \~30 Annex I requirements are machine-checkable. The PolicyKit checks what it can and explicitly flags what it cannot. It does not pretend to automate conformity assessment — it automates the checkable subset and creates a clear checklist for the rest.

**Engineering:** 2 engineers \+ CRA legal review, 2–3 months. The Rego engineering is straightforward; the hard part is CRA interpretation — translating regulatory text into precise, testable rules.

## **4.3 cra-report — Art. 14 Notification Generator**

Generates CRA Article 14 vulnerability notification documents from structured data. Tracks the 24h/72h/14d deadline pipeline. In Phase 1, uses template-based generation (no LLM).

### **Three-Stage Pipeline**

* **24h Early Warning:** CVE identifier, affected product, severity (CVSS/EPSS), whether vulnerability is actively exploited. Generated from structured CVE \+ SBOM data.

* **72h Notification:** Impact assessment, corrective actions planned, estimated affected user count, preliminary technical details. Template-filled from scan results \+ VEX.

* **14-day Final Report:** Root cause analysis, remediation applied, preventive measures. Requires human input for root cause (Phase 1\) or LLM draft (Phase 2).

**Watch Mode:** Monitors CISA KEV \+ EPSS feeds continuously. When a new actively exploited CVE matches a product SBOM, auto-generates the 24h early warning and schedules follow-up deadlines.

**Engineering:** 2 engineers, 2–3 months. CVE fetching (NVD/OSV API clients), CSIRT routing (static lookup table for \~30 EU member states), template system, deadline scheduler.

| ENISA SRP Dependency The ENISA Single Reporting Platform launches Sep 2026 but the API schema is still being defined. cra-report starts with a generic structured format based on Art. 14(2) required fields. When ENISA publishes the schema, a format adapter is added. If ENISA requires a web portal only (no API), the tool generates documents for manual upload. |
| :---- |

## **4.4 cra-evidence — Compliance Evidence Bundler**

Bundles outputs from all other tools (SBOM, VEX, provenance, scan results, policy evaluation) into a signed, versioned CRA evidence package suitable for Annex VII technical documentation.

### **What Goes In the Bundle**

* SBOM (CycloneDX/SPDX) — from Syft, cdxgen, Trivy

* VEX document — from cra-vex

* SLSA provenance — from Witness, GitHub SLSA generator

* Scan results (SARIF) — from Trivy, Grype, Semgrep

* Policy evaluation report — from cra-policykit

* Product metadata (name, version, class, support period, manufacturer)

* Completeness report: what’s included vs what’s missing

* SHA-256 manifest of all files, Cosign signature, in-toto attestation

In Phase 1, the Annex VII summary is a structured template. In Phase 2, the LLM generates a coherent narrative from all inputs.

**Engineering:** 2 engineers, 2 months. Schema validation, cross-referencing (SBOM components match VEX subjects), Cosign/Sigstore integration, packaging.

## **4.5 cra-csaf — Scanner-to-Advisory Bridge**

Converts vulnerability scanner output (Trivy, Grype, OSV-Scanner) \+ VEX assessment into CSAF 2.0 advisories for downstream user notification per CRA Art. 14(8).

Today, generating CSAF advisories from scanner results is manual: security teams copy-paste CVE details into Secvisogram. This tool automates the entire flow: scanner finds vulnerability → VEX assesses exploitability → CSAF advisory published.

**Engineering:** 1–2 engineers, 2 months. Scanner output parsing, CSAF 2.0 document generation, VEX integration, schema validation.

## **4.6 The Composed Pipeline (Phase 1\)**

Each tool works standalone. Together, they create end-to-end CRA compliance automation:

1. Developer pushes code → existing CI/CD builds artifact

2. **Existing OSS:** Syft/cdxgen generates SBOM; Grype/Trivy scans for CVEs; Cosign signs artifact

3. **cra-vex:** Takes SBOM \+ scan results → auto-determines VEX status (deterministic filters)

4. **cra-csaf:** Takes scan results \+ VEX → generates CSAF advisories for downstream users

5. **cra-policykit:** Evaluates SBOM \+ VEX \+ provenance against CRA Annex I rules

6. **cra-evidence:** Bundles all outputs into signed evidence package

7. **If actively exploited CVE:** cra-report generates Art. 14 notification, routes to CSIRT/ENISA

| No Source Code Access Required Every tool operates on outputs from existing tools — SBOMs, scan results, provenance records. None requires access to the customer’s source code. SBOM generation is where source-level analysis happens, and that’s already solved by the OSS ecosystem. SUSE’s tools fill the gaps between generation and CRA compliance. |
| :---- |

## **4.7 Phase 1 Investment**

| Tool | Timeline | Team | Cost |
| :---- | :---- | :---- | :---- |
| cra-vex (deterministic) | 2–3 months | 2 engineers | $250–350K |
| cra-policykit | 2–3 months | 2 engineers \+ legal | $250–400K |
| cra-report | 2–3 months | 2 engineers | $250–350K |
| cra-evidence | 2 months | 2 engineers | $200–300K |
| cra-csaf | 2 months | 1–2 engineers | $150–250K |
| **Phase 1 Total** | **6–9 months (parallel)** | **\~8–10 people** | **$1.1–1.65M** |

# **5\. Phase 2: AI-Powered CRA Agent (Gemma 4\)**

Gemma 4 was released under Apache 2.0 license with native function/tool calling, structured JSON output, and models that run on a laptop. This transforms Phase 1’s CLI tools from individual utilities into an autonomous CRA compliance agent.

| Phase 2 Timeline Q1–Q3 2027\. Begins after Phase 1 tools are stable and SUSE’s training data has been extracted and cleaned. Fine-tuned model ships before the full CRA compliance deadline (Dec 2027). |
| :---- |

## **5.1 Why Gemma 4**

Three properties make Gemma 4 uniquely suited for this strategy:

* **Apache 2.0 license:** No usage restrictions. Can be fine-tuned, redistributed, embedded in commercial products. Customers can run it without license negotiation.

* **Local deployment at every scale:** E2B (2GB RAM), E4B (3GB RAM), 26B MoE (14GB quantized), 31B Dense (18GB quantized). From edge devices to CI runners to dedicated servers. No cloud API required.

* **Native tool calling:** Generates structured JSON function calls. Supports parallel tool calling for independent operations. 256K context window fits entire SBOMs \+ multiple CVE descriptions.

## **5.2 The Model Stack**

Different CRA tasks need different model sizes. Phase 2 deploys the right model for each task:

| Task | Model | Why |
| :---- | :---- | :---- |
| Deterministic VEX filters | No LLM | Pure logic. Version comparison, platform matching. Handles 40–60% of CVEs. |
| VEX status determination (complex CVEs) | 26B MoE / 31B | Needs reasoning over CVE advisory \+ SBOM \+ config. Hardest task. |
| VEX justification text | E4B / 26B MoE | Text generation from structured input. Smaller model sufficient. |
| Art. 14 report drafting | E4B | Structured data to regulatory language. Low hallucination risk. |
| CSAF advisory descriptions | E4B | Formulaic advisory prose from scan \+ VEX data. |
| Evidence summary narrative | E4B | Summarize evidence bundle. Template-guided generation. |
| Agent orchestration | 26B MoE | Reason about which tools to call, in what order, with what parameters. Fast inference (3.8B active params). |

## **5.3 The CRA Agent Architecture**

The five Phase 1 CLI tools become Gemma 4 function definitions. The agent calls them natively using structured JSON output. This is a standard ReAct (Reason \+ Act) loop:

* **Trigger:** New CVE in NVD/OSV matching product SBOM, new CI build, scheduled compliance check, or human query.

* **Reason:** Agent analyzes the situation and plans which tools to call, in what order.

* **Act:** Agent calls tools (cra-vex, cra-report, cra-csaf, cra-policykit, cra-evidence) via native function calling.

* **Observe:** Agent processes tool outputs, decides next action. If VEX says “not\_affected,” skip report generation. If multiple products affected, parallelize.

* **Output:** Complete CRA compliance artifacts: VEX, advisories, reports, evidence bundle. Low-confidence items flagged for human review.

### **Agent Modes**

* **Watch Mode (Daemon):** Runs 24/7. Monitors vulnerability feeds. Auto-triggers full assessment pipeline when new exploited CVE matches product SBOM. Tracks Art. 14 deadlines. This is the killer feature.

* **CI Mode (Per-Build):** Runs as CI pipeline step. On every build: SBOM → scan → VEX → policy check → evidence bundle. Build fails if critical CRA rules fail.

* **Interactive Mode:** Security team asks questions. “Is CVE-2026-XXXX exploitable in our Node.js image?” Agent runs assessment, explains reasoning.

### **What Makes This Different From a Script**

A shell script runs tools in a fixed order. The agent **reasons**. If VEX says “not\_affected,” it skips report generation. If the SBOM doesn’t contain the affected component, it stops. If multiple products are affected, it parallelizes. If confidence is low, it flags for human review. The 256K context window means it carries full context through the workflow — when generating the Art. 14 report, it has the VEX justification, SBOM analysis, and policy results all in context.

## **5.4 cra-vex Enhanced: LLM-Assisted VEX Determination**

Phase 2 adds LLM analysis for CVEs that pass through Phase 1’s deterministic filters (the remaining 40–60%). Per CVE, Gemma 4 receives the CVE advisory, SBOM excerpt, build configuration, and upstream advisories as context, then generates a structured VEX status with justification and confidence score.

* **No source code required:** The model analyzes CVE descriptions against build context (SBOM \+ config), not application code. It answers “given what’s in the SBOM and how it’s configured, is this CVE exploitable?”

* **Processing time:** \~2–5 seconds per CVE on 26B MoE (CPU), \~1–2 seconds with GPU. For 100 CVEs through Phase 2: \~5–8 minutes.

* **Confidence scoring:** High-confidence results auto-resolved. Low-confidence results go to human review queue. Target: reduce manual review from \~100 CVEs to \~15–30 per release.

## **5.5 Fine-Tuning: The Competitive Moat**

The CLI tools are open source. Gemma 4 base weights are open source. The fine-tuned model trained on SUSE’s proprietary data — that’s the moat.

### **Training Data SUSE Already Has**

| Data Source | Training Value |
| :---- | :---- |
| SUSE CSAF advisories | Thousands of published advisories. Train the model on SUSE’s advisory language. Directly improves cra-csaf and cra-report output. |
| Backport decisions | Every backport decision across 140K+ packages is effectively a VEX assessment with justification. This is the single most valuable training dataset for VEX determination. |
| OBS build metadata | Build configs, feature flags, dependency trees for 140K+ packages. The model learns how packages are configured in enterprise Linux. |
| SLES lifecycle data | 13-year support windows, patching patterns, remediation timelines. Improves cra-report “corrective actions” sections. |

### **Fine-Tuning Pipeline**

8. **Supervised fine-tune on VEX determination.** Base: Gemma 4 31B Dense. Dataset: SUSE backport decisions \+ CVE context → VEX status \+ justification. Target: 10K–50K training examples.

9. **Distill to smaller models.** Teacher: suse-cra-vex-31b. Students: 26B MoE (for servers), E4B (for CI/edge). Knowledge distillation using teacher outputs as labels.

10. **RLHF from expert feedback.** SUSE security engineers review VEX assessments. Corrections fed back as preference data. Continuous improvement loop.

| Why Competitors Can’t Replicate This Any company can download Gemma 4 and write VEX prompts. What they cannot replicate is SUSE’s decades of backport decisions across 140K packages. Each decision contains implicit VEX reasoning. This institutional knowledge, encoded as training data, produces a model that is fundamentally more accurate at VEX determination for enterprise Linux than any generic model. Red Hat has similar data but is IBM-owned (EU sovereignty concern). Chainguard has it for containers but not enterprise Linux. First mover with a fine-tuned CRA model wins the narrative. |
| :---- |

### **Honest Risks of Fine-Tuning**

* **Data preparation:** Backport decisions aren’t in a clean (CVE, context, decision, justification) format. Extracting from OBS, Bugzilla, and internal systems: 2–3 months of data engineering.

* **Evaluation:** Need a gold-standard test set with expert-verified VEX assessments (\~500–1000 examples). This doesn’t exist; must be created. Budget 1–2 months.

* **Ongoing cost:** New CVE patterns emerge. Model needs periodic retraining. Budget \~0.5 FTE ongoing.

# **6\. The Digital Sovereignty Play**

This is where everything converges: SUSE’s Digital Sovereignty Unit positioning, the CRA’s EU-centric requirements, and Gemma 4’s local deployment.

| The Pitch CRA compliance that never leaves your infrastructure. Your SBOMs, vulnerability assessments, build configurations, and regulatory reports are some of the most sensitive information in your organization. Under the CRA, you’re generating more of this data than ever. SUSE’s CRA agent runs entirely inside your infrastructure. The LLM is a local binary (Gemma 4, Apache 2.0). The tools are local CLIs (Apache 2.0). Nothing leaves your network. This is sovereign compliance automation. |
| :---- |

## **6.1 Why This Resonates Now**

* **CRA \+ NIS2 \+ DORA convergence:** EU regulated entities face three overlapping regulations. All require supply chain transparency. All have data sovereignty concerns. An air-gapped compliance agent solves a category.

* **Gaia-X / EU cloud sovereignty:** EU public sector building sovereign infrastructure. They need sovereign AI tools. A CRA agent on open-source AI running in EU data centers is a procurement checkbox win.

* **Data transfer uncertainty:** EU–US data transfers remain legally fragile. Local LLM means zero transfer risk regardless of future court decisions.

* **Air-gapped mandates:** Defense and critical infrastructure operate air-gapped by policy. SUSE’s CRA agent may be the only option that works in their environment.

## **6.2 Deployment Profiles**

| Profile | Hardware | Models | Use Case |
| :---- | :---- | :---- | :---- |
| CI Runner | 4–8 vCPU, 16 GB RAM | E4B quantized (\~3 GB) | Per-build CRA compliance |
| Compliance Server | 16+ vCPU, 32–64 GB | 26B MoE \+ E4B | Centralized agent, Watch Mode, multi-product |
| Air-Gapped | On-prem server | 31B Dense (pre-loaded) | Defense, critical infra, EU public sector |
| Edge / Embedded | Jetson, RPi5, ARM | E2B (\~2 GB) | IoT manufacturers, build stations |

# **7\. Business Model**

Open core with the fine-tuned model as the commercial moat. The tools are the open-source top-of-funnel. The intelligence is the paid product.

## **7.1 Free vs Paid**

| Component | License | Tier |
| :---- | :---- | :---- |
| cra-vex, cra-policykit, cra-report, cra-evidence, cra-csaf (CLI tools) | Apache 2.0 | Free / OSS |
| cra-agent orchestrator (basic) | Apache 2.0 | Free / OSS |
| Rego policy library (community rules) | Apache 2.0 | Free / OSS |
| Gemma 4 base models (no fine-tune) | Apache 2.0 | Free / OSS |
| SUSE-tuned VEX model (suse-cra-gemma4) | Proprietary | Commercial |
| Curated Rego policy library (tested, SLA) | Proprietary | Commercial |
| Agent Watch Mode (continuous monitoring) | Proprietary | Commercial |
| Multi-product portfolio management | Proprietary | Commercial |
| ENISA SRP API integration | Proprietary | Commercial |
| Model updates \+ retraining | Subscription | Subscription |
| Support \+ CRA consulting | Subscription | Subscription |

## **7.2 The Adoption Funnel**

11. **Developer discovers cra-vex (OSS).** “This auto-generates VEX from my SBOM \+ scan results. Deterministic mode resolves 40–60% of CVEs.”

12. **Team adopts the toolkit (OSS).** “We use all five tools in CI. Policy checks catch issues early. But we still manually review 100+ CVEs per release.”

13. **Organization buys SUSE CRA Agent (Commercial).** “The SUSE-tuned model gets 90%+ VEX accuracy. Watch Mode runs 24/7. We review only the 15 the agent flagged as low-confidence.”

14. **Enterprise subscribes (Subscription).** “30 products, 5000 dependencies. The agent handles it across the portfolio. Model updates keep accuracy high.”

## **7.3 SUSE Product Integration**

These tools make SUSE’s existing products more valuable:

* **SUSE BCI:** CRA-Ready images ship with pre-generated SBOM \+ VEX \+ provenance. Customers add their application layer evidence on top.

* **SLES:** 13-year support lifecycle directly maps to CRA support period requirements. cra-policykit validates this automatically.

* **NeuVector:** Runtime monitoring detects exploitation at OS/system library level, feeding into cra-report for Art. 14 notifications.

* **Rancher:** Cluster-wide CRA evidence across all deployed workloads.

# **8\. Investment & Timeline**

## **8.1 Combined Investment**

| Item | Effort | Timeline | Cost |
| :---- | :---- | :---- | :---- |
| **PHASE 1** |  |  |  |
| Five CLI tools (deterministic) | 8–10 engineers | 6–9 months | $1.1–1.65M |
| **PHASE 2** |  |  |  |
| Data engineering (extract training data) | 2 data engineers | 3 months | $200–300K |
| Evaluation dataset (gold-standard VEX) | 2 security engineers | 2 months | $150–200K |
| Fine-tuning pipeline \+ model training | 2 ML engineers | 4 months | $300–400K |
| Distillation (31B → 26B MoE → E4B) | 1 ML engineer | 2 months | $100–150K |
| Agent orchestrator \+ tool calling runtime | 2 engineers | 3 months | $200–300K |
| **TOTAL** | **12–15 people** | **9–12 months** | **$2.1–3.0M** |

## **8.2 Timeline**

### **2026**

* **Q2:** Start Phase 1 CLI tool development. Begin data engineering for Phase 2 training set (parallel workstream).

* **Q3:** cra-report ships first (ahead of Art. 14 deadline Sep 11, 2026). cra-policykit, cra-evidence, cra-csaf follow. Begin fine-tuning on extracted SUSE advisory data.

* **Q4:** cra-vex deterministic mode ships. Full Phase 1 toolkit available. Fine-tuned 31B model first internal evaluation.

### **2027**

* **Q1:** Agent orchestrator alpha. SUSE-tuned model ships to early customers. Distilled E4B model for CI/edge deployment.

* **Q2:** Agent Watch Mode. ENISA SRP integration (if spec available). Multi-product portfolio management.

* **Q3:** General availability of SUSE CRA Compliance Agent.

* **Q4:** CRA full compliance deadline: December 11, 2027\. Every EU software manufacturer needs this.

| Why the Phased Approach De-Risks Everything If AI/ML delivery slips, Phase 1 tools still ship on time and meet CRA deadlines with deterministic automation. If the fine-tuned model underperforms, the tools work with base Gemma 4 or without any model at all. If ENISA delays the SRP spec, cra-report generates documents for manual upload. Every dependency has a fallback. The phased approach means SUSE never misses a CRA deadline regardless of what happens with the AI work. |
| :---- |

# **9\. Risks & Mitigations**

| Risk | Impact | Likelihood | Mitigation |
| :---- | :---- | :---- | :---- |
| ENISA SRP requires web portal only, no API | cra-report can’t auto-submit | Medium | Generate documents for manual upload. API adapter added when/if available. |
| Fine-tuned model doesn’t achieve target accuracy | Reduced Phase 2 value | Medium | Phase 1 tools work without model. Base Gemma 4 provides partial improvement. RLHF loop improves over time. |
| Training data extraction harder than expected | Phase 2 delay | Medium-High | Start data engineering in Q2 2026 (parallel with Phase 1). Early assessment of data quality. |
| CRA interpretation ambiguity | PolicyKit rules contested | Medium | Collaborate with SUSE legal \+ EU standards bodies. Open-source rules for community review. Version and update. |
| Competitor ships similar toolkit first | Market narrative loss | Medium | Phase 1 speed advantage (6–9 months). Fine-tuned model is the long-term moat. |
| VEX automation liability concerns | Customer hesitation | Low-Medium | Confidence scoring \+ human review queue. Tool suggests, human decides. Clear disclaimers. |
| SUSE VEX feed stalled (discovered: Feb 2026\) | Credibility gap | Known Issue | Fix immediately. Required for credibility as CRA tooling vendor. |

# **10\. What SUSE Ships**

## **Phase 1 Deliverable (Q4 2026\)**

**SUSE CRA Toolkit — Open Source Edition**

* cra-vex CLI (deterministic VEX status determination)

* cra-policykit CLI \+ community Rego policy library

* cra-report CLI (Art. 14 notification generation \+ deadline tracking)

* cra-evidence CLI (signed evidence bundling)

* cra-csaf CLI (scanner-to-advisory bridge)

* CI/CD integration examples (GitHub Actions, GitLab CI, Tekton)

* Documentation \+ getting-started guides

## **Phase 2 Deliverable (Q3 2027\)**

**SUSE CRA Compliance Agent — Sovereign Edition**

* All Phase 1 tools (enhanced with LLM capabilities)

* cra-agent orchestrator with Watch, CI, and Interactive modes

* suse-cra-gemma4-26b-moe.gguf (fine-tuned model, SUSE proprietary)

* suse-cra-gemma4-e4b.gguf (distilled model for CI/edge)

* Curated Rego policy library (tested, updated, SLA-backed)

* ENISA SRP integration (if spec available)

* Multi-product portfolio management

* Deployment: Helm chart / RPM / container image

* Runtime: Ollama or vLLM (bundled)

* Zero external network dependencies. Vuln DB mirror included.

## **Immediate Action: Fix SUSE VEX Feed**

| Pre-Requisite During research for this strategy, we discovered that SUSE’s VEX feed has been stalled since February 17, 2026\. This must be fixed immediately. SUSE cannot credibly sell CRA compliance tooling while its own VEX feed is broken. This is a separate, urgent action item independent of the product strategy. |
| :---- |

# **11\. Recommendation**

We recommend proceeding with both phases in parallel tracks:

* **Approve Phase 1 immediately (Q2 2026 start).** 8–10 engineers. $1.1–1.65M. Ship cra-report before Sep 2026 Art. 14 deadline. Full toolkit by Q4 2026\.

* **Approve Phase 2 data engineering now (Q2 2026 start).** 2 data engineers extracting and cleaning training data from OBS/Bugzilla. This is the longest lead-time item and must start early to avoid delaying the ML work.

* **Phase 2 ML work decision point: Q4 2026\.** By then, Phase 1 tools are proven, training data quality is assessed, and we can make an informed go/no-go on the fine-tuning investment ($750K–1.15M additional).

The phased approach means SUSE has a shipped, working CRA compliance toolkit before the first CRA deadline, with a clear path to AI-powered differentiation for the full compliance deadline. The open-source tools build community and adoption. The fine-tuned model creates a defensible commercial position. The digital sovereignty angle is unique to SUSE.

| The Opportunity CRA creates a new, mandatory market. Every EU software manufacturer needs compliance tooling. Today, zero tools exist that automate the gaps between SBOM generation and CRA compliance. SUSE has the regulatory understanding, the open-source credibility, and the proprietary training data to own this space. The question is not whether to invest — it’s whether to move fast enough to be first. |
| :---- |

