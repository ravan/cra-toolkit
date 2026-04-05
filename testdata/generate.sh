#!/usr/bin/env bash
# Copyright 2026 Ravan Naidoo
# SPDX-License-Identifier: GPL-3.0-only
#
# Regenerate all scan data from source fixtures.
# Prerequisites: syft, grype, trivy, govulncheck
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INT_DIR="$SCRIPT_DIR/integration"

echo "=== Generating Go reachable fixture ==="
pushd "$INT_DIR/go-reachable" > /dev/null
(cd source && go mod tidy)
(cd source && govulncheck -json ./... > ../govulncheck.json 2>&1 || true)
syft source/. -o cyclonedx-json > sbom.cdx.json 2>/dev/null
syft source/. -o spdx-json > sbom.spdx.json 2>/dev/null
grype sbom:sbom.cdx.json -o json > grype.json 2>/dev/null
trivy fs source/. --format json > trivy.json 2>/dev/null
popd > /dev/null

echo "=== Generating Go not-reachable fixture ==="
pushd "$INT_DIR/go-not-reachable" > /dev/null
(cd source && go mod tidy)
(cd source && govulncheck -json ./... > ../govulncheck.json 2>&1 || true)
syft source/. -o cyclonedx-json > sbom.cdx.json 2>/dev/null
syft source/. -o spdx-json > sbom.spdx.json 2>/dev/null
grype sbom:sbom.cdx.json -o json > grype.json 2>/dev/null
trivy fs source/. --format json > trivy.json 2>/dev/null
popd > /dev/null

echo "=== Generating Python reachable fixture ==="
pushd "$INT_DIR/python-reachable" > /dev/null
syft source/. -o cyclonedx-json > sbom.cdx.json 2>/dev/null
trivy fs source/. --format json > trivy.json 2>/dev/null
popd > /dev/null

echo "=== Generating Python not-reachable fixture ==="
pushd "$INT_DIR/python-not-reachable" > /dev/null
syft source/. -o cyclonedx-json > sbom.cdx.json 2>/dev/null
trivy fs source/. --format json > trivy.json 2>/dev/null
popd > /dev/null

echo "=== Generating upstream VEX fixture ==="
pushd "$INT_DIR/upstream-vex" > /dev/null
(cd source && go mod tidy)
syft source/. -o cyclonedx-json > sbom.cdx.json 2>/dev/null
grype sbom:sbom.cdx.json -o json > grype.json 2>/dev/null
popd > /dev/null

echo "=== Rust fixtures ==="
echo "Skipped: cargo-scan is not installed. See rust-reachable/README.txt"

echo ""
echo "All fixtures generated successfully."
