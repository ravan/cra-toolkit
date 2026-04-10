// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"strings"
)

// Fetcher acquires package source code and metadata from an ecosystem registry.
// Implementations are registered per ecosystem key ("pypi", "npm", ...).
type Fetcher interface {
	// Ecosystem returns the ecosystem key, e.g. "pypi" or "npm".
	Ecosystem() string

	// Fetch retrieves the source tarball for (name, version) and returns a
	// directory containing readable source. If expectedDigest is non-nil,
	// the fetched artifact's digest must match; otherwise the result is an
	// error with Digest mismatch semantics.
	Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error)

	// Manifest returns the package's declared metadata for (name, version)
	// without downloading the tarball.
	Manifest(ctx context.Context, name, version string) (PackageManifest, error)
}

// FetchResult describes the outcome of a package fetch.
type FetchResult struct {
	// SourceDir is the absolute path to the unpacked source tree, if available.
	SourceDir string

	// SourceUnavailable is true when the registry reported the package exists
	// at the requested version but no source form was available. This is the
	// case for Python packages with only binary (compiled) wheels and no sdist.
	SourceUnavailable bool

	// Digest is the digest of the fetched artifact (for audit and cache
	// indexing). May be the zero value when SourceUnavailable is true.
	Digest Digest
}

// PackageManifest captures the registry-declared metadata for one package version.
// Only fields required by the dependency graph builder are populated.
type PackageManifest struct {
	// Dependencies maps dependency name → version constraint as declared by the
	// package (pyproject.toml's requires_dist, package.json's dependencies).
	Dependencies map[string]string
}

// Digest is a content digest with a named algorithm.
type Digest struct {
	Algorithm string
	Hex       string
}

// String returns the digest in "alg:hex" form.
func (d Digest) String() string {
	return strings.ToLower(d.Algorithm) + ":" + strings.ToLower(d.Hex)
}

// Equals compares two digests case-insensitively on algorithm and hex.
func (d Digest) Equals(other Digest) bool {
	return strings.EqualFold(d.Algorithm, other.Algorithm) &&
		strings.EqualFold(d.Hex, other.Hex)
}

// IsZero reports whether the digest is unset.
func (d Digest) IsZero() bool {
	return d.Algorithm == "" && d.Hex == ""
}
