// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package transitive implements transitive dependency reachability analysis
// by walking SBOM-derived dependency paths in reverse and running per-hop
// tree-sitter reachability checks against fetched package source.
package transitive

// Degradation reason constants surfaced as VEX evidence when analysis cannot
// proceed cleanly. Each reason is a stable identifier that appears in
// reachability.Result.Degradations.
const (
	ReasonTransitiveNotApplicable = "transitive_not_applicable"
	ReasonManifestFetchFailed     = "manifest_fetch_failed"
	ReasonTarballFetchFailed      = "tarball_fetch_failed"
	ReasonDigestMismatch          = "digest_mismatch"
	ReasonSourceUnavailable       = "source_unavailable"
	ReasonBoundExceeded           = "bound_exceeded"
	ReasonExtractorError          = "extractor_error"
	ReasonPathBroken              = "path_broken"
	ReasonNoApplicationRoot       = "no_application_root"
)
