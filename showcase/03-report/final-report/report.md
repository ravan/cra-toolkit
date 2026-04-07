# CRA Article 14 Vulnerability Notification

## Metadata

| Field | Value |
| --- | --- |
| Notification ID | CRA-NOTIF-20260407T110045Z |
| Stage | Final Report (14d) — Art. 14(2)(c) |
| Generated | 2026-04-07T11:00:45Z |
| Submission Channel | ENISA Single Reporting Platform (Art. 16) |
| Toolkit Version | 0.1.0 |

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

> **Note:** Per Art. 14(7), this notification is submitted via the ENISA Single
> Reporting Platform, which routes to the CSIRT coordinator simultaneously with ENISA.

## Vulnerabilities with Exploitation Signals

### CVE-2025-30066

- **Exploitation Signals:** KEV (Listed in CISA Known Exploited Vulnerabilities catalog)
- **Severity:** High (CVSS 8.6)
- **Affected:** tj-actions/changed-files ed68ef82c095e0d48ec87eccea555d944a631a4c
- **Description:** tj-actions changed-files through 45.0.7 allows remote attackers to discover secrets by reading actions logs.
- **Corrective Actions:** Update tj-actions/changed-files to version 46.0.1
- **Mitigating Measures:**
  ```
No filter could determine VEX status. Queued for manual review.  ```
- **Root Cause:** [HUMAN INPUT REQUIRED]
- **Threat Actor Info:** [HUMAN INPUT REQUIRED]
- **Security Update:** Update tj-actions/changed-files to version 46.0.1

> **Note:** Exploitation signals are provided to support the manufacturer's
> determination per Art. 14(1). The manufacturer is responsible for the
> regulatory decision to notify.

## User Notification (Art. 14(8))

- **Severity:** high
- **Action:** Update tj-actions/changed-files to version 46.0.1 or later

## Completeness (Toolkit Quality Metric)

| Metric | Value |
| --- | --- |
| Score | 77% |
| Machine Generated | 9 |
| Human Provided | 1 |
| Pending | 3 |

> Toolkit quality metric. CRA Art. 14 does not define completeness thresholds.
