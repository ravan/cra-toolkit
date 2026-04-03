# PolicyKit

`cra policykit` evaluates compliance policies against product artifacts (SBOM, VEX, Evidence, etc.) using embedded OPA (Open Policy Agent) and Rego rules.

## Overview

The toolkit provides a predefined set of machine-checkable CRA rules that your artifacts must meet. PolicyKit allows you to verify that your product is ready for CRA assessment before submitting it.

## Key Features

- **Embedded Policies:** Comes with a set of default CRA compliance policies.
- **Custom Policies:** You can provide your own Rego policies for internal security and compliance checks.
- **Automated Validation:** Easily integrated into CI/CD for constant compliance monitoring.

## Usage

*This tool is currently in development.*

```bash
cra policykit --artifact <path-to-artifact> --policy-dir <path-to-policies>
```
