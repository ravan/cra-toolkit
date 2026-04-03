Rust Reachable Fixture
======================

This fixture requires cargo-scan to generate reachability data.
cargo-scan is not currently installed.

To generate scan data once cargo-scan is available:

  cd source
  cargo build 2>/dev/null  # download deps
  cargo scan --json > ../cargo-scan.json
  syft source/. -o cyclonedx-json > ../sbom.cdx.json
  grype sbom:../sbom.cdx.json -o json > ../grype.json
  trivy fs source/. --format json > ../trivy.json

The vulnerable dependency is hyper 0.14.10 (CVE-2023-26964).
The source code calls Http::new().http2_only(true), which exercises
the vulnerable HTTP/2 server code path.
