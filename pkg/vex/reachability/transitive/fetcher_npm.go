// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

// NPMFetcher implements Fetcher for the npm ecosystem.
type NPMFetcher struct {
	BaseURL    string // default https://registry.npmjs.org
	HTTPClient *http.Client
	Cache      *Cache
}

func (f *NPMFetcher) Ecosystem() string { return "npm" }

func (f *NPMFetcher) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return http.DefaultClient
}

func (f *NPMFetcher) baseURL() string {
	if f.BaseURL != "" {
		return f.BaseURL
	}
	return "https://registry.npmjs.org"
}

// npmMeta is the subset of the npm registry schema we consume.
type npmMeta struct {
	Dependencies map[string]string `json:"dependencies"`
	Dist         struct {
		Tarball   string `json:"tarball"`
		SHASum    string `json:"shasum"`    // sha1
		Integrity string `json:"integrity"` // "sha512-..." base64
	} `json:"dist"`
}

// Manifest fetches and parses npm registry metadata for (name, version).
func (f *NPMFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	m, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return PackageManifest{}, err
	}
	deps := make(map[string]string, len(m.Dependencies))
	for k, v := range m.Dependencies {
		deps[k] = v
	}
	return PackageManifest{Dependencies: deps}, nil
}

// Fetch downloads the npm tarball for (name, version), verifies its digest if
// expectedDigest is non-nil, unpacks it into the cache and returns the result.
func (f *NPMFetcher) Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error) {
	m, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}
	if m.Dist.Tarball == "" {
		return FetchResult{SourceUnavailable: true}, nil
	}

	body, actual, err := f.downloadAndVerify(ctx, m.Dist.Tarball, expectedDigest)
	if err != nil {
		return FetchResult{}, err
	}

	cacheKey := actual.String()
	if f.Cache != nil {
		if p, ok := f.Cache.Get(cacheKey); ok {
			return FetchResult{SourceDir: p, Digest: actual}, nil
		}
	}

	srcDir, err := f.unpackAndCache(name, cacheKey, body)
	if err != nil {
		return FetchResult{}, err
	}
	return FetchResult{SourceDir: srcDir, Digest: actual}, nil
}

func (f *NPMFetcher) downloadAndVerify(ctx context.Context, tarball string, expectedDigest *Digest) ([]byte, Digest, error) {
	body, err := httpGetBytes(ctx, f.client(), tarball)
	if err != nil {
		return nil, Digest{}, fmt.Errorf("%s: %w", ReasonTarballFetchFailed, err)
	}
	actual := Digest{Algorithm: "sha256", Hex: hashHex(body)}
	if expectedDigest != nil && !expectedDigest.IsZero() && !expectedDigest.Equals(actual) {
		return nil, Digest{}, fmt.Errorf("%s: SBOM expected %s, registry returned %s",
			ReasonDigestMismatch, expectedDigest, actual)
	}
	return body, actual, nil
}

func (f *NPMFetcher) unpackAndCache(name, cacheKey string, body []byte) (string, error) {
	tmp, err := os.MkdirTemp("", "npm-*")
	if err != nil {
		return "", err
	}
	if err := untarGz(body, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return "", fmt.Errorf("unpack npm %s: %w", name, err)
	}

	// npm tarballs always unpack to a "package/" subdirectory. Rename it to
	// "<name>/" so modulePrefix can find the package name in the file path.
	packageDir := filepath.Join(tmp, "package")
	namedDir := filepath.Join(tmp, name)
	if st, err := os.Stat(packageDir); err == nil && st.IsDir() {
		if renameErr := os.Rename(packageDir, namedDir); renameErr != nil {
			_ = os.RemoveAll(tmp)
			return "", fmt.Errorf("rename npm package dir %s → %s: %w", packageDir, namedDir, renameErr)
		}
	}

	if f.Cache == nil {
		return tmp, nil
	}
	p, putErr := f.Cache.Put(cacheKey, tmp)
	_ = os.RemoveAll(tmp)
	if putErr != nil {
		return "", putErr
	}
	return p, nil
}

func (f *NPMFetcher) fetchMeta(ctx context.Context, name, version string) (*npmMeta, error) {
	url := fmt.Sprintf("%s/%s/%s", f.baseURL(), name, version)
	var m npmMeta
	if err := httpGetJSON(ctx, f.client(), url, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
