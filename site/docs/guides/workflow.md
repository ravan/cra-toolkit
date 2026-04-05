# End-to-End Compliance Workflow

This guide walks through a complete CRA compliance cycle, from SBOM generation through evidence bundling. Each step shows the exact command, explains what it produces, and shows how its output feeds into the next step.

## Prerequisites

Before starting, ensure you have the following tools available:

- **`cra` binary installed** -- `go install github.com/ravan/suse-cra-toolkit/cmd/cra@latest`
- **A vulnerability scanner** -- [Grype](https://github.com/anchore/grype) or [Trivy](https://github.com/aquasecurity/trivy)
- **An SBOM generator** -- [syft](https://github.com/anchore/syft) or [cdxgen](https://github.com/CycloneDX/cdxgen)
- **Source code access** -- required for reachability analysis during VEX determination
- **A product configuration file** (YAML) -- describes your product metadata for CRA reporting

### Product Configuration

Create a `product.yaml` file in your project root. This file provides the manufacturer and product metadata required by CRA Annex VII:

```yaml
product:
  name: "my-product"
  version: "1.0.0"
  release_date: "2026-01-15"
  support_end_date: "2031-01-15"
  manufacturer:
    name: "ACME Corp"
    address: "123 Main Street, Berlin, Germany"
    email: "security@acme.example.com"
    website: "https://acme.example.com"
  update_mechanism:
    type: "automatic"
    url: "https://updates.acme.example.com"
    auto_update_default: true
    security_updates_separate: true
```

---

## Step 1: Generate SBOM

**CRA Reference:** Annex I, Part II, point 1 -- identification and documentation of components via SBOM.

```bash
syft . -o cyclonedx-json > sbom.cdx.json
```

The SBOM (Software Bill of Materials) captures every component and dependency in your product. The CRA requires manufacturers to identify and document all components integrated into a product with digital elements. The CycloneDX JSON format provides a machine-readable inventory that downstream tools consume for vulnerability matching, policy evaluation, and evidence bundling.

**Output:** `sbom.cdx.json` -- a CycloneDX JSON document listing all components, their versions, licenses, and dependency relationships.

---

## Step 2: Scan for Vulnerabilities

```bash
grype sbom:sbom.cdx.json -o json > grype.json
```

The vulnerability scanner matches each component in the SBOM against known vulnerability databases (NVD, GitHub Advisory Database, OSV). This produces a list of CVEs that potentially affect your product. The raw scan results will contain both exploitable and non-exploitable findings -- the next step separates them.

**Input:** `sbom.cdx.json` from Step 1.

**Output:** `grype.json` -- scanner results containing matched CVEs, severity scores, and affected component details.

---

## Step 3: Determine Exploitability

**CRA Reference:** Annex I, Part I, 2(a) -- products shall be delivered without known exploitable vulnerabilities.

```bash
cra vex --sbom sbom.cdx.json --scan grype.json --source-dir . -o vex.json
```

The VEX (Vulnerability Exploitability eXchange) command applies a 6-filter chain to determine which vulnerabilities are actually exploitable in the context of your product:

1. **Known Exploited Vulnerabilities** -- checks against CISA KEV catalog
2. **EPSS Score** -- evaluates exploitation probability
3. **Temporal Analysis** -- considers vulnerability age and patch availability
4. **Component Scope** -- determines whether the vulnerable component is in the runtime dependency path
5. **VEX Statement Matching** -- applies existing upstream VEX statements
6. **Reachability Analysis** -- traces call paths from your source code into vulnerable library functions

Each vulnerability receives a status: `exploitable`, `not_affected`, or `under_investigation`, along with a justification and supporting evidence.

**Input:** `sbom.cdx.json` from Step 1, `grype.json` from Step 2, source code directory.

**Output:** `vex.json` -- an OpenVEX document with per-vulnerability exploitability determinations.

---

## Step 4: Evaluate Compliance Policies

**CRA Reference:** Annex I -- essential cybersecurity requirements.

```bash
cra policykit --sbom sbom.cdx.json --scan grype.json --vex vex.json \
  --product-config product.yaml -o policy-report.json
```

PolicyKit evaluates 10 CRA compliance policies implemented as OPA Rego rules. Each policy maps to a specific Annex I requirement and produces a PASS, FAIL, or WARNING result. Review the output carefully -- any FAIL result indicates a gap that must be addressed before the product can be considered CRA-compliant.

Key policies include:

- **CRA-AI-1.1** -- No known exploitable vulnerabilities shipped
- **CRA-AI-2.1** -- Secure default configuration
- **CRA-AI-3.1** -- Vulnerability handling process in place
- **CRA-AII-1.1** -- SBOM present and complete

**Input:** `sbom.cdx.json` from Step 1, `grype.json` from Step 2, `vex.json` from Step 3, `product.yaml`.

**Output:** `policy-report.json` -- per-policy evaluation results with CRA article references and remediation guidance.

---

## Step 5: Generate Notifications (Conditional)

**CRA Reference:** Article 14 -- vulnerability notification obligations.

!!! warning "This step is conditional"
    Notification generation is only required when actively exploited vulnerabilities are detected. If the VEX determination in Step 3 found no exploitable vulnerabilities, skip this step.

```bash
cra report --sbom sbom.cdx.json --scan grype.json --vex vex.json \
  --stage early-warning --product-config product.yaml -o early-warning.json
```

Article 14 defines three notification stages, each with its own deadline:

| Stage | Deadline | Content |
|---|---|---|
| **Early warning** | 24 hours | Indication that an actively exploited vulnerability exists |
| **Vulnerability notification** | 72 hours | Technical details, severity, and initial assessment |
| **Final report** | 14 days | Root cause analysis, remediation measures, and impact assessment |

Generate the appropriate stage based on your timeline since discovery. Each stage builds on the previous one by adding more detail.

**Input:** `sbom.cdx.json`, `grype.json`, `vex.json`, `product.yaml`.

**Output:** `early-warning.json` (or `notification.json`, `final-report.json`) -- Article 14 compliant notification document.

---

## Step 6: Produce Security Advisories

**CRA Reference:** Article 14(8) -- manufacturers shall inform affected users and provide machine-readable advisories.

```bash
cra csaf --sbom sbom.cdx.json --scan grype.json --vex vex.json \
  --publisher-name "ACME Corp" --publisher-namespace "https://acme.example.com" \
  -o advisory.json
```

The CSAF (Common Security Advisory Framework) command generates a machine-readable security advisory that downstream users and automated systems can consume. The advisory includes affected products, vulnerability details, exploitability status from the VEX determination, and remediation instructions. This fulfills the Article 14(8) requirement to inform users about vulnerabilities and their corrective measures.

**Input:** `sbom.cdx.json`, `grype.json`, `vex.json`, publisher metadata.

**Output:** `advisory.json` -- a CSAF 2.0 advisory document.

---

## Step 7: Bundle and Sign Evidence

**CRA Reference:** Annex VII -- technical documentation requirements.

```bash
cra evidence --product-config product.yaml --output-dir ./evidence \
  --sbom sbom.cdx.json --vex vex.json --scan grype.json \
  --policy-report policy-report.json --csaf advisory.json \
  --archive --format json
```

The evidence command bundles all artifacts produced in the previous steps into a single, validated package suitable for conformity assessment. It:

1. **Validates consistency** -- ensures all artifacts reference the same product and version
2. **Cross-references** -- verifies that the VEX document covers all scanner findings
3. **Signs the bundle** -- produces a cryptographic signature for integrity verification
4. **Creates an archive** -- packages everything into a distributable `.tar.gz` file

The resulting evidence bundle contains the complete compliance record for your product, ready for review by market surveillance authorities or notified bodies.

**Input:** All artifacts from Steps 1--7, `product.yaml`.

**Output:** `./evidence/` directory containing the signed evidence bundle and archive.

---

## Complete Pipeline Script

The following script runs the entire compliance workflow end-to-end:

```bash
#!/usr/bin/env bash
set -euo pipefail

PRODUCT_CONFIG="product.yaml"
PUBLISHER_NAME="ACME Corp"
PUBLISHER_NAMESPACE="https://acme.example.com"
OUTPUT_DIR="./evidence"

echo "==> Step 1: Generate SBOM"
syft . -o cyclonedx-json > sbom.cdx.json

echo "==> Step 2: Scan for vulnerabilities"
grype sbom:sbom.cdx.json -o json > grype.json

echo "==> Step 3: Determine exploitability (VEX)"
cra vex --sbom sbom.cdx.json --scan grype.json --source-dir . -o vex.json

echo "==> Step 4: Evaluate compliance policies"
cra policykit --sbom sbom.cdx.json --scan grype.json --vex vex.json \
  --product-config "$PRODUCT_CONFIG" -o policy-report.json

echo "==> Step 5: Generate notifications (if exploitable vulns found)"
if jq -e '.statements[] | select(.status == "exploitable")' vex.json > /dev/null 2>&1; then
  echo "    Actively exploited vulnerabilities detected -- generating early warning"
  cra report --sbom sbom.cdx.json --scan grype.json --vex vex.json \
    --stage early-warning --product-config "$PRODUCT_CONFIG" -o early-warning.json
else
  echo "    No actively exploited vulnerabilities -- skipping notification"
fi

echo "==> Step 6: Produce security advisories (CSAF)"
cra csaf --sbom sbom.cdx.json --scan grype.json --vex vex.json \
  --publisher-name "$PUBLISHER_NAME" --publisher-namespace "$PUBLISHER_NAMESPACE" \
  -o advisory.json

echo "==> Step 7: Bundle and sign evidence"
cra evidence --product-config "$PRODUCT_CONFIG" --output-dir "$OUTPUT_DIR" \
  --sbom sbom.cdx.json --vex vex.json --scan grype.json \
  --policy-report policy-report.json --csaf advisory.json \
  --archive --format json

echo "==> Compliance workflow complete. Evidence bundle: $OUTPUT_DIR/"
```

Save this script as `cra-compliance.sh`, make it executable with `chmod +x cra-compliance.sh`, and run it from your project root directory.
