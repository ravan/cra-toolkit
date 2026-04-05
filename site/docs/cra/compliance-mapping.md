# Compliance Mapping

This page provides a central cross-reference linking CRA requirements to toolkit tools, CLI commands, and output artifacts. Use it to find which tool addresses which obligation.

![CRA Requirement-to-Artifact Compliance Flow](../assets/diagrams/compliance-mapping-flow.svg)

---

## Primary Compliance Matrix

| CRA Requirement | Reference | Toolkit Tool | CLI Command | Output Artifact |
|---|---|---|---|---|
| No known exploitable vulnerabilities | [Annex I, Part I, 2(a)](annex-i.md#specific-requirements) | [VEX](../tools/vex.md) | `cra vex` | OpenVEX / CSAF VEX |
| SBOM identification and documentation | [Annex I, Part II, (1)](annex-i.md#part-ii-vulnerability-handling-requirements) | [Evidence](../tools/evidence.md) | `cra evidence --sbom` | SBOM in evidence bundle |
| Vulnerability assessment and remediation | [Annex I, Part II, (2)](annex-i.md#part-ii-vulnerability-handling-requirements) | [VEX](../tools/vex.md) + [PolicyKit](../tools/policykit.md) | `cra vex` + `cra policykit` | VEX + Policy report |
| Coordinated vulnerability disclosure | [Annex I, Part II, (5)](annex-i.md#part-ii-vulnerability-handling-requirements) | [Evidence](../tools/evidence.md) | `cra evidence --cvd-policy` | CVD policy in bundle |
| Secure update distribution | [Annex I, Part II, (7)](annex-i.md#part-ii-vulnerability-handling-requirements) | [PolicyKit](../tools/policykit.md) | `cra policykit` | Update mechanism policy check |
| Security advisory dissemination | [Annex I, Part II, (8)](annex-i.md#part-ii-vulnerability-handling-requirements) | [CSAF](../tools/csaf.md) | `cra csaf` | CSAF 2.0 advisory |
| 24h early warning notification | [Art. 14(2)(a)](article-14.md) | [Report](../tools/report.md) | `cra report --stage early-warning` | Early warning JSON/MD |
| 72h vulnerability notification | [Art. 14(2)(b)](article-14.md) | [Report](../tools/report.md) | `cra report --stage notification` | Notification JSON/MD |
| 14-day final report | [Art. 14(2)(c)](article-14.md) | [Report](../tools/report.md) | `cra report --stage final-report` | Final report JSON/MD |
| User notification (machine-readable) | [Art. 14(8)](article-14.md) | [CSAF](../tools/csaf.md) | `cra csaf` | CSAF 2.0 advisory |
| Technical documentation | [Annex VII](annex-vii.md) | [Evidence](../tools/evidence.md) | `cra evidence` | Signed evidence bundle |
| EU declaration of conformity | Annex V | [Evidence](../tools/evidence.md) | `cra evidence --eu-declaration` | Declaration in bundle |
| Risk assessment | Art. 13(2) | [Evidence](../tools/evidence.md) | `cra evidence --risk-assessment` | Risk assessment in bundle |
| Build provenance (SLSA) | Art. 13 | [PolicyKit](../tools/policykit.md) | `cra policykit --provenance` | CRA-AI-3.1 policy check |
| Artifact signatures | Art. 13 | [PolicyKit](../tools/policykit.md) | `cra policykit --signature` | CRA-AI-3.2 policy check |
| Support period declaration | [Annex I, Part II](annex-i.md#part-ii-vulnerability-handling-requirements) | [PolicyKit](../tools/policykit.md) | `cra policykit --product-config` | CRA-AI-4.1 policy check |
| KEV vulnerability management | [Annex I, Part I, 2(a)](annex-i.md#specific-requirements) | [PolicyKit](../tools/policykit.md) | `cra policykit --kev` | CRA-AI-2.1 policy check |
| Reachability evidence quality | [Annex I, Part I, 2(a)](annex-i.md#specific-requirements) | [VEX](../tools/vex.md) + [PolicyKit](../tools/policykit.md) | `cra vex --source-dir` | CRA-REACH-1/2/3 checks |

---

## PolicyKit Built-in Policies

| Rule ID | Name | CRA Reference | What It Checks | Severity |
|---|---|---|---|---|
| CRA-AI-1.1 | SBOM exists and is valid | [Annex I Part II.1](annex-i.md#part-ii-vulnerability-handling-requirements) | Format, metadata, components, PURL coverage | critical |
| CRA-AI-2.1 | No known exploited vulnerabilities | [Annex I Part I.2(a)](annex-i.md#specific-requirements) | Scan findings vs CISA KEV catalog | critical |
| CRA-AI-2.2 | All critical/high CVEs have VEX assessment | [Annex I Part I.2(a)](annex-i.md#specific-requirements) | VEX coverage for CVSS >= 7.0 findings | high |
| CRA-AI-3.1 | Build provenance exists (SLSA L1+) | Art. 13 | SLSA attestation: builder_id, source_repo, build_type | high |
| CRA-AI-3.2 | Artifacts cryptographically signed | Art. 13 | Signature file presence and format | high |
| CRA-AI-4.1 | Support period declared and >= 5 years | [Annex I Part II](annex-i.md#part-ii-vulnerability-handling-requirements) | Product config: release/end dates, >= 5 years | medium |
| CRA-AI-4.2 | Secure update mechanism documented | [Annex I Part II.7](annex-i.md#part-ii-vulnerability-handling-requirements) | Update type, URL, auto-update, security-separate | medium |
| CRA-REACH-1 | not_affected claims require high confidence | [Annex I Part I.2(a)](annex-i.md#specific-requirements) | VEX reachability confidence scoring | high |
| CRA-REACH-2 | affected claims must have call paths | [Annex I Part I.2(a)](annex-i.md#specific-requirements) | VEX reachability call path evidence | high |
| CRA-REACH-3 | Pattern-match alone cannot justify not_affected | [Annex I Part I.2(a)](annex-i.md#specific-requirements) | VEX analysis method validation | medium |
