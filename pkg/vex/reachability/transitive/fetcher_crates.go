// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"fmt"
	"net/http"
	"os"
)

// CratesFetcher implements Fetcher for the crates.io ecosystem.
type CratesFetcher struct {
	// BaseURL is the crates.io API base. Defaults to https://crates.io.
	BaseURL    string
	HTTPClient *http.Client
	Cache      *Cache
}

func (f *CratesFetcher) Ecosystem() string { return "crates.io" }

func (f *CratesFetcher) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return http.DefaultClient
}

func (f *CratesFetcher) baseURL() string {
	if f.BaseURL != "" {
		return f.BaseURL
	}
	return "https://crates.io"
}

// cratesVersionMeta is the subset of the crates.io version schema we consume.
type cratesVersionMeta struct {
	Version struct {
		Num      string `json:"num"`
		DlPath   string `json:"dl_path"`
		Checksum string `json:"checksum"`
	} `json:"version"`
}

// cratesDepsResponse is the response from the crates.io dependencies endpoint.
type cratesDepsResponse struct {
	Dependencies []cratesDep `json:"dependencies"`
}

// cratesDep represents a single dependency entry from crates.io.
type cratesDep struct {
	CrateID  string `json:"crate_id"`
	Req      string `json:"req"`
	Kind     string `json:"kind"`
	Optional bool   `json:"optional"`
}

// fetchMeta retrieves version metadata (dl_path + checksum) for a crate version.
func (f *CratesFetcher) fetchMeta(ctx context.Context, name, version string) (*cratesVersionMeta, error) {
	url := fmt.Sprintf("%s/api/v1/crates/%s/%s", f.baseURL(), name, version)
	var m cratesVersionMeta
	if err := httpGetJSON(ctx, f.client(), url, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Manifest fetches and parses crates.io dependency metadata for (name, version).
// Only normal (non-dev, non-build) dependencies are included regardless of
// the optional flag — optional normal deps are still part of the public API
// surface and may be activated by downstream consumers.
func (f *CratesFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	url := fmt.Sprintf("%s/api/v1/crates/%s/%s/dependencies", f.baseURL(), name, version)
	var resp cratesDepsResponse
	if err := httpGetJSON(ctx, f.client(), url, &resp); err != nil {
		return PackageManifest{}, err
	}

	deps := make(map[string]string)
	for _, dep := range resp.Dependencies {
		if dep.Kind != "normal" {
			continue
		}
		deps[dep.CrateID] = dep.Req
	}
	return PackageManifest{Dependencies: deps}, nil
}

// crateTarballURL constructs the full URL for a crate tarball given its dl_path.
func (f *CratesFetcher) crateTarballURL(dlPath string) string {
	return f.baseURL() + dlPath
}

// Fetch downloads the crate tarball for (name, version), verifies its SHA-256
// digest against the crates.io metadata, optionally checks against an expected
// digest, unpacks it into the cache and returns the result.
func (f *CratesFetcher) Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error) {
	meta, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}

	registryDigest := Digest{Algorithm: "sha256", Hex: meta.Version.Checksum}

	if f.Cache != nil {
		if p, ok := f.Cache.Get(registryDigest.String()); ok {
			return FetchResult{SourceDir: p, Digest: registryDigest}, nil
		}
	}

	tarURL := f.crateTarballURL(meta.Version.DlPath)
	body, err := httpGetBytes(ctx, f.client(), tarURL)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonTarballFetchFailed, err)
	}

	actual := Digest{Algorithm: "sha256", Hex: hashHex(body)}
	if !actual.Equals(registryDigest) {
		return FetchResult{}, fmt.Errorf("%s: expected %s, got %s", ReasonDigestMismatch, registryDigest, actual)
	}
	if expectedDigest != nil && !expectedDigest.IsZero() && !expectedDigest.Equals(actual) {
		return FetchResult{}, fmt.Errorf("%s: SBOM expected %s, registry returned %s", ReasonDigestMismatch, expectedDigest, actual)
	}

	tmp, err := os.MkdirTemp("", "crates-*")
	if err != nil {
		return FetchResult{}, err
	}
	if err := untarGz(body, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return FetchResult{}, fmt.Errorf("unpack crate %s: %w", name, err)
	}

	srcDir := tmp
	if f.Cache != nil {
		p, putErr := f.Cache.Put(actual.String(), tmp)
		_ = os.RemoveAll(tmp)
		if putErr != nil {
			return FetchResult{}, putErr
		}
		srcDir = p
	}
	return FetchResult{SourceDir: srcDir, Digest: actual}, nil
}
