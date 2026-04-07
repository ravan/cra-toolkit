# CRA PolicyKit Compliance Report

## Metadata

| Field | Value |
| --- | --- |
| Report ID | CRA-RPT-20260407T110041Z |
| Generated | 2026-04-07T11:00:41Z |
| Toolkit Version | 0.1.0 |

## Summary

| Status | Count |
| --- | --- |
| PASS | 5 |
| FAIL | 3 |
| SKIP | 2 |
| HUMAN | 8 |
| **Total** | **18** |

## Machine-Checked Policies

### FAIL: CRA-AI-2.1 — No known exploited vulnerabilities

- **CRA Reference:** Annex I Part I.2(a)
- **Severity:** Critical
- **Evidence:**
  - kev_matches: [CVE-2025-30066]
  - total_cves_checked: 37
  - kev_catalog_date: 2026-04-06T14:59:12.2467Z

### FAIL: CRA-AI-1.1 — SBOM exists and is valid

- **CRA Reference:** Annex I Part II.1
- **Severity:** Critical

### FAIL: CRA-AI-2.2 — All critical/high CVEs have VEX assessment

- **CRA Reference:** Annex I Part I.2(a)
- **Severity:** High
- **Evidence:**
  - assessed: 45
  - total_critical_high: 48
  - unassessed: [GHSA-cxww-7g56-2vh6 CVE-2025-15284 CVE-2025-15284]

### PASS: CRA-REACH-2 — Reachability affected claims must have supporting call paths

- **CRA Reference:** Annex I Part I.2(a)
- **Severity:** High
- **Evidence:**
  - total_reachability_affected: 0
  - missing_call_paths_cves: []

### PASS: CRA-REACH-1 — Reachability not_affected claims require high confidence

- **CRA Reference:** Annex I Part I.2(a)
- **Severity:** High
- **Evidence:**
  - low_confidence_cves: []
  - total_reachability_not_affected: 0

### PASS: CRA-REACH-3 — Pattern-match reachability alone cannot justify not_affected

- **CRA Reference:** Annex I Part I.2(a)
- **Severity:** Medium
- **Evidence:**
  - pattern_match_not_affected_cves: []

### PASS: CRA-AI-4.1 — Support period declared and > 5 years

- **CRA Reference:** Annex I Part II
- **Severity:** Medium
- **Evidence:**
  - release_date: 2025-06-01
  - support_end_date: 2030-06-01
  - support_years: 5

### PASS: CRA-AI-4.2 — Secure update mechanism documented

- **CRA Reference:** Annex I Part II.7
- **Severity:** Medium
- **Evidence:**
  - security_updates_separate: true
  - url_present: true
  - auto_update_default: true
  - mechanism_type: automatic

### SKIP: CRA-AI-3.1 — Build provenance exists (SLSA L1+)

- **CRA Reference:** Art. 13
- **Severity:** High
- **Evidence:**
  - reason: No provenance attestation provided (--provenance flag)

### SKIP: CRA-AI-3.2 — Artifacts cryptographically signed

- **CRA Reference:** Art. 13
- **Severity:** High
- **Evidence:**
  - reason: No signature files provided (--signature flag)

## Requires Human Review

### HUMAN: CRA-HU-1.1 — Appropriate cybersecurity level

- **CRA Reference:** Annex I Part I.1
- **Severity:** High
- **Guidance:** Verify risk assessment performed and cybersecurity measures are proportionate to identified risks.

### HUMAN: CRA-HU-1.2 — Secure by default configuration

- **CRA Reference:** Annex I Part I.2(b)
- **Severity:** High
- **Guidance:** Verify product ships with secure defaults and users can reset to original state.

### HUMAN: CRA-HU-1.3 — Access control mechanisms

- **CRA Reference:** Annex I Part I.2(d)
- **Severity:** High
- **Guidance:** Verify authentication, identity, and access management systems protect against unauthorised access.

### HUMAN: CRA-HU-1.4 — Data encryption at rest and in transit

- **CRA Reference:** Annex I Part I.2(e)
- **Severity:** High
- **Guidance:** Verify confidentiality of stored, transmitted, and processed data using state of the art encryption.

### HUMAN: CRA-HU-1.5 — Data integrity protection

- **CRA Reference:** Annex I Part I.2(f)
- **Severity:** High
- **Guidance:** Verify integrity of stored, transmitted data, commands, programs, and configuration against unauthorised modification.

### HUMAN: CRA-HU-1.6 — Data minimisation

- **CRA Reference:** Annex I Part I.2(g)
- **Severity:** Medium
- **Guidance:** Verify only adequate, relevant, and limited data is processed for the product's intended purpose.

### HUMAN: CRA-HU-1.7 — Attack surface minimisation

- **CRA Reference:** Annex I Part I.2(j)
- **Severity:** High
- **Guidance:** Verify product is designed to limit attack surfaces including external interfaces.

### HUMAN: CRA-HU-1.8 — Risk assessment performed

- **CRA Reference:** Art. 13(2)
- **Severity:** High
- **Guidance:** Verify cybersecurity risk assessment has been carried out and is documented.

