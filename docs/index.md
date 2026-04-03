# SUSE CRA Compliance Toolkit

The SUSE CRA Compliance Toolkit is an open-source suite of tools designed to help software manufacturers comply with the European Union's **Cyber Resilience Act (CRA)**.

## Goals

- **Automated Compliance:** Streamline the generation of compliance artifacts required by the CRA.
- **Transparency:** Provide machine-readable evidence of security assessments.
- **Integration:** Work seamlessly with existing CI/CD pipelines and vulnerability scanners.

## Toolkit Components

The toolkit consists of five primary tools:

1.  **[VEX (Vulnerability Exploitability eXchange)](tools/vex.md):** Auto-determine vulnerability exploitability using a deterministic filter chain and reachability analysis.
2.  **[PolicyKit](tools/policykit.md):** Evaluate compliance policies against product artifacts using embedded OPA/Rego rules.
3.  **[Report](tools/report.md):** Generate CRA Article 14 vulnerability notification documents for different notification stages.
4.  **[Evidence](tools/evidence.md):** Bundle and sign compliance outputs into a versioned CRA evidence package for Annex VII documentation.
5.  **[CSAF](tools/csaf.md):** Convert scanner output and VEX results into standardized CSAF 2.0 advisories.

## Getting Started

To get started with the toolkit, check out our [installation guide](getting-started.md) and the documentation for individual tools.
