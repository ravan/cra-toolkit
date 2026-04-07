# Real-World Analysis — Grafana

!!! abstract "What is this?"
    This page shows **real output** from running the CRA Toolkit against
    [Grafana](https://github.com/grafana/grafana), a production observability
    platform with 8,301 dependencies. Every determination is
    [verified against public advisories](#verification). Nothing is mocked.

## Target Project

| Field | Value |
|-------|-------|
| Project | [grafana/grafana](https://github.com/grafana/grafana) |
| SBOM components | 8,301 |
| Grype CVE matches | 40 |
| Trivy findings | 45 |
| SBOM tool | syft 1.42.3 (CycloneDX) |
| Scanners | grype 0.110.0, trivy |

!!! tip "Full output files"
    The complete input and output files are in the
    [`showcase/`](https://github.com/ravan/cra-toolkit/tree/main/showcase) folder
    of the repository.

---

## Pipeline

The toolkit was run as a sequential pipeline — each tool's output feeds the next:

```bash
# 1. Generate SBOM (external tool)
syft grafana/ -o cyclonedx-json=sbom.cdx.json

# 2. Scan for vulnerabilities (external tools)
grype sbom:sbom.cdx.json -o json > grype-scan.json
trivy fs --scanners vuln --format json grafana/ > trivy-scan.json

# 3. VEX — determine exploitability
cra vex --sbom sbom.cdx.json --scan grype-scan.json --scan trivy-scan.json \
  --output-format openvex --output vex-results.openvex.json

# 4. PolicyKit — evaluate CRA Annex I compliance
cra policykit --sbom sbom.cdx.json --scan grype-scan.json --scan trivy-scan.json \
  --vex vex-results.openvex.json --product-config product-config.yaml \
  --format json --output policy-report.json

# 5. Report — generate Art. 14 notifications
cra report --sbom sbom.cdx.json --scan grype-scan.json --scan trivy-scan.json \
  --vex vex-results.openvex.json --stage early-warning \
  --product-config product-config.yaml --output report-early-warning.md

# 6. CSAF — generate security advisory
cra csaf --sbom sbom.cdx.json --scan grype-scan.json --scan trivy-scan.json \
  --vex vex-results.openvex.json --publisher-name "Grafana Labs" \
  --publisher-namespace "https://grafana.com" --output advisory.csaf.json

# 7. Evidence — bundle for Annex VII
cra evidence --sbom sbom.cdx.json --vex vex-results.openvex.json \
  --scan grype-scan.json --policy-report policy-report.json \
  --csaf advisory.csaf.json --art14-report report-notification.json \
  --product-config product-config.yaml --output-dir evidence/ --archive
```

For a detailed walkthrough of each step, see the [End-to-End Workflow](workflow.md) guide.

---

## Tool Results

### VEX — Vulnerability Exploitability

The VEX tool produced **85 statements** from the combined Grype and Trivy findings:

| Status | Count | Meaning |
|--------|-------|---------|
| `not_affected` | 6 | Toolkit proved the CVE doesn't apply |
| `under_investigation` | 79 | Needs further analysis or manual review |

**Example — not_affected (version filter):**

The toolkit determined that `qs@6.14.1` is not affected by CVE-2025-15284 because
the installed version is at or above the fix version:

```json
{
  "vulnerability": { "name": "CVE-2025-15284" },
  "products": [{ "@id": "pkg:npm/qs@6.14.1" }],
  "status": "not_affected",
  "justification": "vulnerable_code_not_present",
  "impact_statement": "Installed version 6.14.1 >= fix version 6.14.1; component is outside the affected range."
}
```

**Example — under_investigation (no filter matched):**

For `lodash@4.17.23` / CVE-2026-4800, the toolkit cannot determine exploitability
without source-code reachability analysis, so it queues the finding for manual review:

```json
{
  "vulnerability": { "name": "CVE-2026-4800" },
  "products": [{ "@id": "pkg:npm/lodash@4.17.23" }],
  "status": "under_investigation",
  "impact_statement": "No filter could determine VEX status. Queued for manual review."
}
```

!!! tip "Reducing under_investigation"
    Pass `--source-dir` to enable reachability analysis. The toolkit traces call paths
    in Go, Rust, Python, JavaScript, Java, C#, PHP, and Ruby to determine whether
    vulnerable code is actually executed. See the [Reachability Deep-Dive](#reachability-deep-dive)
    below.

---

### PolicyKit — CRA Annex I Compliance

PolicyKit evaluated **18 policies** against the Grafana artifacts:

| Status | Count | Meaning |
|--------|-------|---------|
| PASS | 5 | Automated check passed |
| FAIL | 3 | Automated check failed — action required |
| SKIP | 2 | Input not provided (e.g., no provenance attestation) |
| HUMAN | 8 | Requires human review — cannot be evaluated by machine |

**Example — FAIL (CISA KEV match):**

The toolkit checks all CVEs against the CISA Known Exploited Vulnerabilities catalog.
It found CVE-2025-30066 — the [tj-actions/changed-files supply chain attack](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction):

```json
{
  "rule_id": "CRA-AI-2.1",
  "name": "No known exploited vulnerabilities",
  "cra_reference": "Annex I Part I.2(a)",
  "status": "FAIL",
  "severity": "critical",
  "evidence": {
    "kev_catalog_date": "2026-04-06T14:59:12.2467Z",
    "kev_matches": ["CVE-2025-30066"],
    "total_cves_checked": 37
  }
}
```

**Example — PASS (support period):**

```json
{
  "rule_id": "CRA-AI-4.1",
  "name": "Support period declared and > 5 years",
  "cra_reference": "Annex I Part II",
  "status": "PASS",
  "severity": "medium",
  "evidence": {
    "release_date": "2025-06-01",
    "support_end_date": "2030-06-01",
    "support_years": 5
  }
}
```

The 8 HUMAN results cover CRA Annex I requirements like "appropriate cybersecurity
level", "secure by default", and "data minimisation" — these require human judgment
and the toolkit correctly routes them for manual review rather than guessing.

??? info "Full PolicyKit Markdown Report"
    See [`showcase/02-policykit/policy-report.md`](https://github.com/ravan/cra-toolkit/blob/main/showcase/02-policykit/policy-report.md)
    for the complete formatted report.

---

### Report — Article 14 Notifications

The CRA requires three progressively detailed notifications when an actively
exploited vulnerability is discovered:

| Stage | Deadline | Content |
|-------|----------|---------|
| Early Warning | 24 hours | CVE ID, severity, affected products |
| Notification | 72 hours | + description, corrective actions |
| Final Report | 14 days | + root cause, threat actor info, preventive measures |

The toolkit detected exploitation signals for **CVE-2025-30066** (listed in CISA KEV)
and generated all three stages. Here is the early warning:

??? info "Early Warning (24h) — Art. 14(2)(a)"
    ```markdown
    # CRA Article 14 Vulnerability Notification

    ## Metadata

    | Field | Value |
    | --- | --- |
    | Notification ID | CRA-NOTIF-20260407T102536Z |
    | Stage | Early Warning (24h) — Art. 14(2)(a) |
    | Generated | 2026-04-07T10:25:36Z |
    | Submission Channel | ENISA Single Reporting Platform (Art. 16) |

    ## Manufacturer

    | Field | Value |
    | --- | --- |
    | Name | Grafana Labs |
    | Member State | SE |
    | Contact | security@grafana.com |

    ## CSIRT Coordinator (Informational)

    | Field | Value |
    | --- | --- |
    | CSIRT | CERT-SE (MSB) |
    | Country | SE |

    ## Vulnerabilities with Exploitation Signals

    ### CVE-2025-30066

    - **Exploitation Signals:** KEV (Listed in CISA Known Exploited Vulnerabilities catalog)
    - **Severity:** High (CVSS 8.6)
    - **Affected:** tj-actions/changed-files
    ```

As the stages progress, the same CVE gains detail: the 72-hour notification adds a
description and corrective actions, and the 14-day final report adds root cause
analysis and preventive measures. See the full reports in
[`showcase/03-report/`](https://github.com/ravan/cra-toolkit/blob/main/showcase/03-report/).

---

### CSAF — Security Advisory

The CSAF tool generates a machine-readable [CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html)
advisory for downstream user notification per CRA Art. 14(8). Here is one
vulnerability entry:

```json
{
  "cve": "CVE-2026-33672",
  "notes": [{
    "category": "description",
    "text": "Picomatch: Method Injection in POSIX Character Classes causes incorrect Glob Matching"
  }],
  "scores": [{
    "products": ["pkg:npm/picomatch@2.3.1"],
    "cvss_v3": {
      "version": "3.1",
      "baseScore": 5.3,
      "baseSeverity": "MEDIUM"
    }
  }],
  "product_status": {
    "under_investigation": ["pkg:npm/picomatch@2.3.1"]
  },
  "remediations": [{
    "category": "vendor_fix",
    "details": "Upgrade picomatch to version 4.0.4, 3.0.2, 2.3.2 or later.",
    "product_ids": ["pkg:npm/picomatch@2.3.1"]
  }]
}
```

Each vulnerability includes CVSS scores, affected product PURLs, remediation
guidance, and VEX status — all auto-generated from the scan and VEX results.

---

### Evidence — Annex VII Bundle

The evidence tool bundles all artifacts into a structured package mapped to
CRA Annex VII sections, with integrity hashing and a completeness assessment.

**Completeness: 52%** (7 of 15 sections covered)

| ID | Section | Status |
|----|---------|--------|
| 1a | General description — intended purpose | COVERED |
| 1b | Versions affecting compliance | COVERED |
| 2a | Design/development/architecture | MISSING |
| 2b-sbom | Vulnerability handling — SBOM | COVERED |
| 2b-cvd | Vulnerability handling — CVD policy | COVERED |
| 3 | Cybersecurity risk assessment | MISSING |
| 6 | Test/verification reports | COVERED |
| 7 | EU declaration of conformity | MISSING |
| 8 | SBOM (market surveillance) | COVERED |

The 52% score reflects that optional manufacturer documents (risk assessment,
architecture docs, EU declaration of conformity) were not supplied. The toolkit
is transparent about gaps — this is by design.

**Integrity manifest** — every artifact is SHA256-hashed:

```text
50df4914...  annex-vii/1-general-description/product-config.yaml
3f5caddd...  annex-vii/2b-vulnerability-handling/sbom.cdx.json
a67902fb...  annex-vii/6-test-reports/advisory.csaf.json
4053814e...  annex-vii/6-test-reports/grype-scan.json
6f5be4d6...  annex-vii/6-test-reports/policy-report.json
31f5489a...  annex-vii/6-test-reports/report.json
c310a9a5...  annex-vii/6-test-reports/vex-results.openvex.json
3f5caddd...  annex-vii/8-sbom/sbom.cdx.json
```

The bundle is also available as a `.tar.gz` archive for distribution to auditors
or notified bodies.

---

## Reachability Deep-Dive

Traditional scanners flag every dependency with a known CVE. The CRA Toolkit
goes further — it analyzes source code to determine whether the vulnerable
function is actually **called** in your application.

Both programs below depend on `golang.org/x/text@v0.3.7`, which has
[CVE-2022-32149](https://nvd.nist.gov/vuln/detail/CVE-2022-32149) (ReDoS in
`language.ParseAcceptLanguage`). A traditional scanner flags both. The CRA
Toolkit distinguishes them:

=== "Reachable — affected"

    **Source code** (`main.go`):

    ```go
    package main

    import (
        "fmt"
        "os"

        "golang.org/x/text/language"
    )

    func main() {
        tags, _, err := language.ParseAcceptLanguage(os.Args[1])
        if err != nil {
            fmt.Fprintf(os.Stderr, "invalid accept-language: %v\n", err)
            os.Exit(1)
        }
        fmt.Println(tags)
    }
    ```

    **Command:**

    ```bash
    cra vex --sbom sbom.cdx.json --scan grype.json \
      --source-dir ./source --output-format openvex
    ```

    **Result:** `status: "affected"` — the toolkit traces that `main()` calls
    `language.ParseAcceptLanguage()` with untrusted user input from `os.Args[1]`,
    which internally calls the vulnerable `parse()` function. The ReDoS
    vulnerability is exploitable.

=== "Not Reachable — not_affected"

    **Source code** (`main.go`):

    ```go
    package main

    import (
        "fmt"

        "golang.org/x/text/cases"
        "golang.org/x/text/language"
    )

    func main() {
        c := cases.Title(language.English)
        fmt.Println(c.String("hello world"))
    }
    ```

    **Command:**

    ```bash
    cra vex --sbom sbom.cdx.json --scan grype.json \
      --source-dir ./source --output-format openvex
    ```

    **Result:** `status: "not_affected"` — the toolkit sees that the `language`
    package is imported but `ParseAcceptLanguage()` and `Parse()` are never
    called. Only the `language.English` constant and `cases.Title()` are used —
    neither triggers the ReDoS vulnerability.

The reachability analyzer supports **Go, Rust, Python, JavaScript, Java, C#, PHP,
and Ruby**. See the [VEX tool documentation](../tools/vex.md) for details on the
filter chain and confidence scoring.

---

## Verification

Every toolkit determination was independently verified against public vulnerability
databases. A third party can click any source link below to confirm.

### VEX Not-Affected Determinations — 6/6 verified

| CVE | Component | Toolkit Justification | Advisory Confirms | Source |
|-----|-----------|----------------------|-------------------|--------|
| GHSA-cxww-7g56-2vh6 | actions/download-artifact@v4.1.8 | Version v4.1.8 >= fix 4.1.3 | Affected < 4.1.3, fixed in 4.1.3 | [GHSA](https://github.com/advisories/GHSA-cxww-7g56-2vh6) |
| CVE-2025-15284 | qs@6.14.1 | Version 6.14.1 >= fix 6.14.1 | Affected < 6.14.1, fixed in 6.14.1 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-15284) |
| CVE-2026-31808 | file-type | Component not in SBOM | Affects npm file-type 13.0.0–21.3.0 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-31808) |
| CVE-2026-3455 | mailparser | Component not in SBOM | Affects npm mailparser < 3.9.3 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-3455) |
| GHSA-c7w3-x93f-qmm8 | nodemailer | Component not in SBOM | Affects npm nodemailer < 8.0.4 | [GHSA](https://github.com/advisories/GHSA-c7w3-x93f-qmm8) |

### Scanner Findings Verified — 7/7 sampled

| CVE | Component | Affected Range | Fix | Source |
|-----|-----------|---------------|-----|--------|
| CVE-2026-4800 | lodash@4.17.23 | 4.0.0–4.17.23 | 4.18.0 | [GHSA](https://github.com/advisories/GHSA-r5fr-rjxr-66jc) |
| GHSA-5m6q-g25r-mvwx | node-forge@1.3.3 | < 1.4.0 | 1.4.0 | [GHSA](https://github.com/advisories/GHSA-5m6q-g25r-mvwx) |
| GHSA-3v7f-55p6-f55p | picomatch@2.3.1 | < 2.3.2 | 2.3.2 | [GHSA](https://github.com/advisories/GHSA-3v7f-55p6-f55p) |
| CVE-2026-29063 | immutable@3.8.2 | 3.x < 3.8.3 | 3.8.3 | [GHSA](https://github.com/advisories/GHSA-wf6x-7x77-mvgw) |
| CVE-2026-33532 | yaml@2.8.2 | 2.0.0–2.8.2 | 2.8.3 | [GHSA](https://github.com/advisories/GHSA-48c2-rrv3-qjmp) |
| GHSA-f886-m6hf-6m8v | brace-expansion@1.1.12 | < 1.1.13 | 1.1.13 | [GHSA](https://github.com/advisories/GHSA-f886-m6hf-6m8v) |
| GHSA-qj8w-gfj5-8c6v | serialize-javascript@6.0.2 | < 7.0.5 | 7.0.5 | [GHSA](https://github.com/advisories/GHSA-qj8w-gfj5-8c6v) |

### Policy Results Verified — 5/5 machine-evaluable

| Rule | Status | Evidence | Confirmed | Source |
|------|--------|----------|-----------|--------|
| CRA-AI-2.1 | FAIL | KEV match: CVE-2025-30066 | CVE-2025-30066 is in CISA KEV | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-30066) |
| CRA-AI-3.1 | SKIP | No provenance provided | No `--provenance` flag was passed | — |
| CRA-AI-3.2 | SKIP | No signatures provided | No `--signature` flag was passed | — |
| CRA-AI-4.1 | PASS | support_years = 5 | (2030-06-01) - (2025-06-01) = 5.0 years | — |
| CRA-AI-4.2 | PASS | type=automatic, url present | Matches product config input | — |

!!! note "About under_investigation and HUMAN results"
    **under_investigation** means the toolkit found a real CVE in a real dependency
    but cannot determine exploitability without deeper analysis (e.g., source-code
    reachability). This is the conservative, correct default.

    **HUMAN** policy results cover CRA requirements that require human judgment —
    "appropriate cybersecurity level", "secure by default", "data minimisation", etc.
    The toolkit routes these for manual review rather than guessing.

---

## Reproduce It Yourself

All showcase data can be regenerated from scratch:

```bash
task showcase
```

This requires `syft`, `grype`, and `trivy` installed locally. The task clones
Grafana, generates the SBOM, runs all scanners, then runs each toolkit tool
in sequence. See `Taskfile.yml` for the individual subtasks.

The full output is written to `showcase/` — the same files referenced on this page.
