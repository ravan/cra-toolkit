## Cross-Validation Results

Passed: 7 | Failed: 4 | Warnings: 0

| Check | Status | Details |
| --- | --- | --- |
| FV-2b | PASS | Detected format: CycloneDX |
| FV-6 | PASS | Detected format: OpenVEX |
| FV-6 | FAIL | Unrecognized format for showcase/02-policykit/policy-report.json |
| FV-6 | PASS | Detected format: CSAF |
| FV-6 | FAIL | Unrecognized format for showcase/03-report/notification/report.json |
| FV-6 | PASS | Detected format: Grype |
| FV-6 | PASS | Detected format: Trivy |
| CV-SBOM-VEX-PURL | FAIL | VEX references 15 PURLs not in SBOM: pkg:npm/ajv@8.17.1, pkg:npm/brace-expansion@2.0.2, pkg:npm/file-type@16.5.4, pkg:npm/glob@10.4.1, pkg:npm/mailparser@3.7.1, pkg:npm/nodemailer@7.0.12, pkg:npm/path-to-regexp@8.2.0, pkg:npm/path-to-regexp@8.2.0, pkg:npm/picomatch@4.0.3, pkg:npm/picomatch@4.0.3, pkg:npm/qs@6.13.0, pkg:npm/qs@6.14.0, pkg:npm/tar@7.5.8, pkg:npm/tar@7.5.8, pkg:npm/yaml@1.10.2 |
| CV-SBOM-SCAN-COMP | FAIL | Scan references 12 PURLs not in SBOM: pkg:npm/ajv@8.17.1, pkg:npm/brace-expansion@2.0.2, pkg:npm/file-type@16.5.4, pkg:npm/glob@10.4.1, pkg:npm/mailparser@3.7.1, pkg:npm/nodemailer@7.0.12, pkg:npm/path-to-regexp@8.2.0, pkg:npm/picomatch@4.0.3, pkg:npm/qs@6.13.0, pkg:npm/qs@6.14.0, pkg:npm/tar@7.5.8, pkg:npm/yaml@1.10.2 |
| CV-SCAN-VEX-CVE | PASS | All scan CVEs have VEX assessments |
| CV-REPORT-SCAN | PASS | All Art. 14 notification CVEs found in scan results |

