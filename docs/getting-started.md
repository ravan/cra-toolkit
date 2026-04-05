# Getting Started

Follow these steps to set up the SUSE CRA Compliance Toolkit and start generating compliance artifacts.

## Installation

### Prerequisites

- **Go:** Version 1.24 or higher.
- **Task:** Taskfile runner (optional, but recommended).
- **Vulnerability Scanner:** Grype, Trivy, or SARIF-compatible scanner.

### Installing the CLI

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/ravan/cra-toolkit.git
    cd cra-toolkit
    ```
2.  **Build the Tool:**
    ```bash
    task build
    ```
    This will create the `cra` binary in the `bin/` directory.

## Basic Workflow

1.  **Generate an SBOM:** Use tools like `syft` or `trivy` to generate a CycloneDX or SPDX SBOM for your product.
2.  **Scan for Vulnerabilities:** Run a vulnerability scan (e.g., `grype`) and save the results in JSON or SARIF format.
3.  **Generate VEX Statements:** Use `cra vex` to determine the exploitability of the found vulnerabilities.
4.  **Evaluate Policies:** Use `cra policykit` to verify that your SBOM and VEX artifacts meet the CRA compliance requirements.
5.  **Generate Reports:** Use `cra report` to create the necessary Article 14 notification documents.

## Next Steps

- Explore the [VEX tool](tools/vex.md) for automated vulnerability assessment.
- Check out our [design strategy](strategy.md) to understand the architecture.
