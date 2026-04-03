# CSAF (Common Security Advisory Framework)

`cra csaf` converts vulnerability scanner outputs and VEX assessments into CSAF 2.0 advisories.

## Overview

The CRA Article 14(8) requires manufacturers to provide vulnerability notifications to downstream users. CSAF is the industry-standard machine-readable format for security advisories, enabling automated ingestion and response.

## Key Features

- **Standardized Advisories:** Produces compliant CSAF 2.0 documents.
- **Scanner Integration:** Directly converts scan results (e.g., from Trivy) into advisories.
- **VEX Integration:** Enriches advisories with VEX status information.

## Usage

*This tool is currently in development.*

```bash
cra csaf --scan <path-to-scan> --vex <path-to-vex> --output advisory.json
```
