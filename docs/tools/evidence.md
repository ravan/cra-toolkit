# Evidence

`cra evidence` bundles and signs compliance outputs into a versioned CRA evidence package for Annex VII technical documentation.

## Overview

The CRA requires software manufacturers to maintain technical documentation as evidence of compliance. `cra evidence` automates this by gathering SBOMs, VEX documents, scan results, and policy reports into a single, signed package.

## Key Features

- **Standardized Bundling:** Creates a uniform package of compliance evidence.
- **Digital Signatures:** Supports signing the entire evidence package for authenticity and integrity.
- **Version Control:** Keeps track of compliance evidence over the product's lifecycle.

## Usage

*This tool is currently in development.*

```bash
cra evidence --input-dir ./compliance-artifacts --output-bundle evidence.tar.gz --sign
```
