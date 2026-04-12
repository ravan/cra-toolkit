// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// PackagistFetcher implements Fetcher for the Packagist/Composer ecosystem.
type PackagistFetcher struct {
	// BaseURL is the Packagist API base. Defaults to https://repo.packagist.org.
	BaseURL    string
	HTTPClient *http.Client
	Cache      *Cache
}

func (f *PackagistFetcher) Ecosystem() string { return "packagist" }

func (f *PackagistFetcher) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return http.DefaultClient
}

func (f *PackagistFetcher) baseURL() string {
	if f.BaseURL != "" {
		return f.BaseURL
	}
	return "https://repo.packagist.org"
}

// packagistMeta is the subset of the Packagist p2 API response we consume.
type packagistMeta struct {
	Packages map[string][]packagistVersion `json:"packages"`
}

type packagistVersion struct {
	Version string            `json:"version"`
	Require map[string]string `json:"require"`
	Dist    struct {
		URL    string `json:"url"`
		Type   string `json:"type"`
		SHASum string `json:"shasum"`
	} `json:"dist"`
}

// fetchMeta retrieves the package metadata from the Packagist p2 API
// and finds the entry matching the requested version.
func (f *PackagistFetcher) fetchMeta(ctx context.Context, name, version string) (*packagistVersion, error) {
	url := fmt.Sprintf("%s/p2/%s.json", f.baseURL(), name)
	var meta packagistMeta
	if err := httpGetJSON(ctx, f.client(), url, &meta); err != nil {
		return nil, err
	}
	versions := meta.Packages[name]
	for i := range versions {
		if versions[i].Version == version {
			return &versions[i], nil
		}
	}
	return nil, fmt.Errorf("version %s not found for %s", version, name)
}

// Manifest fetches package metadata and returns runtime dependencies.
func (f *PackagistFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	meta, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return PackageManifest{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}
	deps := filterPlatformDeps(meta.Require)
	return PackageManifest{Dependencies: deps}, nil
}

// Fetch downloads the ZIP archive, verifies its digest, and unpacks it.
//
//nolint:gocyclo,gocognit // download-verify-unpack pipeline
func (f *PackagistFetcher) Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error) {
	meta, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}

	if meta.Dist.URL == "" {
		return FetchResult{SourceUnavailable: true}, nil
	}

	registryDigest := Digest{Algorithm: "sha256", Hex: meta.Dist.SHASum}

	if f.Cache != nil && registryDigest.Hex != "" {
		if p, ok := f.Cache.Get(registryDigest.String()); ok {
			return FetchResult{SourceDir: p, Digest: registryDigest}, nil
		}
	}

	body, err := httpGetBytes(ctx, f.client(), meta.Dist.URL)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonTarballFetchFailed, err)
	}

	actual := Digest{Algorithm: "sha256", Hex: hashHex(body)}
	if registryDigest.Hex != "" && !actual.Equals(registryDigest) {
		return FetchResult{}, fmt.Errorf("%s: expected %s, got %s", ReasonDigestMismatch, registryDigest, actual)
	}
	if expectedDigest != nil && !expectedDigest.IsZero() && !expectedDigest.Equals(actual) {
		return FetchResult{}, fmt.Errorf("%s: SBOM expected %s, registry returned %s", ReasonDigestMismatch, expectedDigest, actual)
	}

	tmp, err := os.MkdirTemp("", "packagist-*")
	if err != nil {
		return FetchResult{}, err
	}

	if err := unzip(body, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return FetchResult{}, fmt.Errorf("unpack composer %s: %w", name, err)
	}

	// Composer ZIPs typically contain a single root directory. Locate it.
	// When no cache is provided the caller owns the entire tmp tree.
	if f.Cache == nil {
		return FetchResult{SourceDir: locateSourceRoot(tmp), Digest: actual}, nil
	}
	p, putErr := f.Cache.Put(actual.String(), locateSourceRoot(tmp))
	_ = os.RemoveAll(tmp)
	if putErr != nil {
		return FetchResult{}, putErr
	}
	return FetchResult{SourceDir: p, Digest: actual}, nil
}

// locateSourceRoot finds the single subdirectory in dir (common for composer
// ZIPs), or returns dir itself if there isn't exactly one subdirectory.
func locateSourceRoot(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return dir
	}
	var dirs []os.DirEntry
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e)
		}
	}
	if len(dirs) == 1 {
		return filepath.Join(dir, dirs[0].Name())
	}
	return dir
}

// filterPlatformDeps removes PHP platform requirements (php, ext-*)
// from a dependency map since they are not fetchable packages.
func filterPlatformDeps(deps map[string]string) map[string]string {
	filtered := make(map[string]string, len(deps))
	for k, v := range deps {
		if k == "php" || strings.HasPrefix(k, "ext-") {
			continue
		}
		filtered[k] = v
	}
	return filtered
}
