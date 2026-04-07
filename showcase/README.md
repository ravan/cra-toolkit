# CRA Toolkit Showcase — Grafana Analysis

Real output from running the SUSE CRA Toolkit against **Grafana v12.1.0-pre** (cloned 2026-04-07).

All data is reproducible. No mock data was used.

## Target Project

| Field | Value |
|-------|-------|
| Project | [grafana/grafana](https://github.com/grafana/grafana) |
| Cloned | 2026-04-07 (HEAD at time of clone) |
| SBOM tool | syft 1.42.3 |
| Scanners | grype 0.110.0, trivy (latest) |
| Toolkit | suse-cra-toolkit (built from source) |

## Summary

| Metric | Value |
|--------|-------|
| SBOM components | 8,301 |
| Grype CVE matches | 40 |
| Trivy findings | 45 |
| VEX statements produced | 85 (6 not_affected, 79 under_investigation) |
| Policy results | 18 (5 PASS, 3 FAIL, 2 SKIP, 8 HUMAN review) |
| Evidence completeness | 52% (no optional docs supplied) |
| Evidence artifacts bundled | 9 |

## Folder Structure

```
showcase/
├── 00-inputs/                          # Raw inputs — nothing toolkit-generated
│   ├── sbom.cdx.json                   # CycloneDX SBOM (syft)
│   ├── grype-scan.json                 # Grype vulnerability scan
│   ├── trivy-scan.json                 # Trivy vulnerability scan
│   ├── product-config.yaml             # Product metadata (report/evidence)
│   └── product-config-policykit.yaml   # Product metadata (policykit — different schema)
│
├── 01-vex/                             # Tool 1: VEX determination
│   ├── vex-results.openvex.json        # OpenVEX format output
│   └── vex-results.csaf.json           # CSAF VEX format output
│
├── 02-policykit/                       # Tool 2: CRA Annex I policy evaluation
│   ├── policy-report.json              # Machine-readable results
│   └── policy-report.md                # Human-readable report
│
├── 03-report/                          # Tool 3: Art. 14 vulnerability notification
│   ├── early-warning/                  # 24-hour early warning (Art. 14(2)(a))
│   │   ├── report.json
│   │   └── report.md
│   ├── notification/                   # 72-hour notification (Art. 14(2)(b))
│   │   ├── report.json
│   │   └── report.md
│   └── final-report/                   # 14-day final report (Art. 14(2)(c))
│       ├── report.json
│       └── report.md
│
├── 04-csaf/                            # Tool 4: CSAF 2.0 security advisory
│   └── advisory.csaf.json             # CSAF advisory for downstream notification
│
└── 05-evidence/                        # Tool 5: Annex VII evidence bundle
    ├── evidence-summary.json           # Bundle metadata and completeness
    ├── bundle.tar.gz                   # Signed archive (distributable)
    └── bundle/                         # Unpacked bundle
        ├── bundle.json                 # Manifest metadata
        ├── manifest.sha256             # SHA256 checksums of all artifacts
        ├── annex-vii-summary.md        # Annex VII section mapping
        ├── completeness.md             # Completeness assessment
        ├── validation.md               # Cross-validation results
        └── annex-vii/                  # Artifacts organized by Annex VII section
            ├── 1-general-description/
            ├── 2b-vulnerability-handling/
            ├── 6-test-reports/
            └── 8-sbom/
```

## How to Reproduce

### 1. Generate inputs

```bash
# Clone the target project
git clone --depth 1 https://github.com/grafana/grafana.git /tmp/grafana

# Generate SBOM
syft /tmp/grafana -o cyclonedx-json=sbom.cdx.json

# Scan with Grype
grype sbom:sbom.cdx.json -o json > grype-scan.json

# Scan with Trivy
trivy fs --scanners vuln --format json /tmp/grafana 2>/dev/null > trivy-scan.json
```

### 2. Run the toolkit

```bash
# Build
task build

# VEX — determine vulnerability exploitability
./bin/cra vex \
  --sbom sbom.cdx.json \
  --scan grype-scan.json \
  --scan trivy-scan.json \
  --output-format openvex \
  --output vex-results.openvex.json

# PolicyKit — evaluate CRA Annex I compliance
./bin/cra policykit \
  --sbom sbom.cdx.json \
  --scan grype-scan.json \
  --scan trivy-scan.json \
  --vex vex-results.openvex.json \
  --product-config product-config-policykit.yaml \
  --format markdown \
  --output policy-report.md

# Report — generate Art. 14 notifications (3 stages)
for stage in early-warning notification final-report; do
  ./bin/cra report \
    --sbom sbom.cdx.json \
    --scan grype-scan.json \
    --scan trivy-scan.json \
    --vex vex-results.openvex.json \
    --stage $stage \
    --product-config product-config.yaml \
    --format markdown \
    --output report-${stage}.md
done

# CSAF — generate security advisory
./bin/cra csaf \
  --sbom sbom.cdx.json \
  --scan grype-scan.json \
  --scan trivy-scan.json \
  --vex vex-results.openvex.json \
  --publisher-name "Grafana Labs" \
  --publisher-namespace "https://grafana.com" \
  --output advisory.csaf.json

# Evidence — bundle everything for Annex VII
./bin/cra evidence \
  --sbom sbom.cdx.json \
  --vex vex-results.openvex.json \
  --scan grype-scan.json \
  --scan trivy-scan.json \
  --policy-report policy-report.json \
  --csaf advisory.csaf.json \
  --art14-report report-notification.json \
  --product-config product-config.yaml \
  --output-dir evidence-bundle \
  --archive
```

## What to Look For

### 01-vex — VEX Results
- Each CVE gets a status: `not_affected`, `affected`, or `under_investigation`
- `not_affected` entries include a justification (e.g., "component not present", "version not in affected range")
- Without source code reachability analysis, most findings remain `under_investigation`

### 02-policykit — Policy Evaluation
- Each policy maps to a CRA Annex I requirement (rule IDs like `CRA-AI-1.1`)
- PASS/FAIL/SKIP/HUMAN status per policy
- HUMAN items require manual review by a compliance officer
- The markdown report is formatted for direct inclusion in compliance documentation

### 03-report — Art. 14 Notifications
- Three progressive stages matching CRA Article 14 timelines
- Early warning (24h): minimal — just CVE IDs, severity, affected products
- Notification (72h): adds descriptions, corrective actions
- Final report (14d): full root cause analysis, threat actor info, preventive measures

### 04-csaf — Security Advisory
- CSAF 2.0 format — machine-readable, standardized
- Contains product tree, vulnerability scores, remediations
- Suitable for publishing to downstream users per Art. 14(8)

### 05-evidence — Annex VII Bundle
- `completeness.md` — shows which Annex VII sections have artifacts vs. gaps
- `validation.md` — cross-validation checks (e.g., SBOM-VEX PURL alignment)
- `manifest.sha256` — integrity verification for all bundled artifacts
- `bundle.tar.gz` — distributable archive for auditors/notified bodies

## Notes

- The SBOM contains 8,301 components because Grafana has both Go and JavaScript dependencies
- Vulnerability counts differ between Grype (40) and Trivy (45) — this is expected; scanners have different vulnerability databases
- The 52% evidence completeness score reflects that optional manufacturer documents (risk assessment, architecture docs, EU declaration) were not supplied — this is expected for a showcase run
- Product config files use slightly different schemas for report vs. policykit tools
