# Report

`cra report` generates CRA Article 14 vulnerability notification documents. These documents are necessary to inform national authorities and ENISA (European Union Agency for Cybersecurity) about discovered vulnerabilities.

## Overview

The Cyber Resilience Act mandates specific notification timelines for vulnerabilities:
- **24-hour Early Warning:** Immediate notification of the discovery.
- **72-hour Notification:** More detailed information.
- **14-day Final Report:** Comprehensive analysis and remediation plan.

`cra report` simplifies the generation of these documents by extracting information from your SBOM, scan results, and VEX statements.

## Usage

*This tool is currently in development.*

```bash
cra report --vulnerability <cve-id> --stage 24h --output report.json
```
