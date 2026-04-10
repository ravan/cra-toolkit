// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// PyPIFetcher implements Fetcher for the PyPI ecosystem.
type PyPIFetcher struct {
	// BaseURL is the PyPI JSON API base. Defaults to https://pypi.org/pypi.
	BaseURL    string
	HTTPClient *http.Client
	Cache      *Cache
}

func (f *PyPIFetcher) Ecosystem() string { return "pypi" }

func (f *PyPIFetcher) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return http.DefaultClient
}

func (f *PyPIFetcher) baseURL() string {
	if f.BaseURL != "" {
		return f.BaseURL
	}
	return "https://pypi.org/pypi"
}

// pypiMeta is the subset of the PyPI JSON schema we consume.
type pypiMeta struct {
	Info struct {
		RequiresDist []string `json:"requires_dist"`
	} `json:"info"`
	URLs []struct {
		PackageType string `json:"packagetype"`
		URL         string `json:"url"`
		Filename    string `json:"filename"`
		Digests     struct {
			SHA256 string `json:"sha256"`
		} `json:"digests"`
	} `json:"urls"`
}

// Manifest fetches and parses PyPI metadata.
func (f *PyPIFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	meta, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return PackageManifest{}, err
	}
	deps := make(map[string]string)
	for _, r := range meta.Info.RequiresDist {
		n, constraint := splitRequiresDist(r)
		if n == "" {
			continue
		}
		deps[n] = constraint
	}
	return PackageManifest{Dependencies: deps}, nil
}

// Fetch downloads the sdist (or falls back to a pure-Python wheel), verifies
// its digest if expectedDigest is non-nil, and unpacks it into the cache.
func (f *PyPIFetcher) Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error) {
	meta, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}
	url, digest, kind := pickArtifact(meta)
	if url == "" {
		return FetchResult{SourceUnavailable: true}, nil
	}

	cacheKey := digest.String()
	if f.Cache != nil {
		if p, ok := f.Cache.Get(cacheKey); ok {
			return FetchResult{SourceDir: p, Digest: digest}, nil
		}
	}

	body, err := f.download(ctx, url)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonTarballFetchFailed, err)
	}
	actual := Digest{Algorithm: "sha256", Hex: hashHex(body)}
	if !actual.Equals(digest) {
		return FetchResult{}, fmt.Errorf("%s: expected %s, got %s", ReasonDigestMismatch, digest, actual)
	}
	if expectedDigest != nil && !expectedDigest.IsZero() && !expectedDigest.Equals(actual) {
		return FetchResult{}, fmt.Errorf("%s: SBOM expected %s, registry returned %s", ReasonDigestMismatch, expectedDigest, actual)
	}

	tmp, err := os.MkdirTemp("", "pypi-*")
	if err != nil {
		return FetchResult{}, err
	}
	if err := unpack(body, kind, tmp); err != nil {
		os.RemoveAll(tmp)
		return FetchResult{}, fmt.Errorf("unpack %s: %w", name, err)
	}

	srcDir := tmp
	if f.Cache != nil {
		p, err := f.Cache.Put(cacheKey, tmp)
		os.RemoveAll(tmp)
		if err != nil {
			return FetchResult{}, err
		}
		srcDir = p
	}
	return FetchResult{SourceDir: srcDir, Digest: actual}, nil
}

func (f *PyPIFetcher) fetchMeta(ctx context.Context, name, version string) (*pypiMeta, error) {
	url := fmt.Sprintf("%s/%s/%s/json", f.baseURL(), name, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pypi metadata %s: status %d", url, resp.StatusCode)
	}
	var m pypiMeta
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode pypi metadata: %w", err)
	}
	return &m, nil
}

func (f *PyPIFetcher) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pypi download %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// pickArtifact chooses the best source artifact from the available URLs.
func pickArtifact(m *pypiMeta) (url string, digest Digest, kind string) {
	for _, u := range m.URLs {
		if u.PackageType == "sdist" && u.URL != "" {
			return u.URL, Digest{Algorithm: "sha256", Hex: u.Digests.SHA256}, "sdist"
		}
	}
	for _, u := range m.URLs {
		if u.PackageType == "bdist_wheel" && strings.HasSuffix(u.Filename, "-py3-none-any.whl") {
			return u.URL, Digest{Algorithm: "sha256", Hex: u.Digests.SHA256}, "wheel"
		}
	}
	return "", Digest{}, ""
}

// splitRequiresDist parses a requires_dist entry into (name, constraint).
func splitRequiresDist(s string) (name, constraint string) {
	if idx := strings.Index(s, ";"); idx >= 0 {
		s = s[:idx]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	for i, r := range s {
		if r == ' ' || r == '(' || r == '>' || r == '<' || r == '=' || r == '!' || r == '~' {
			name = strings.TrimSpace(s[:i])
			rest := strings.TrimSpace(s[i:])
			rest = strings.TrimPrefix(rest, "(")
			rest = strings.TrimSuffix(rest, ")")
			return name, strings.TrimSpace(rest)
		}
	}
	return s, ""
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// unpack extracts a tar.gz or zip (wheel) into dst.
func unpack(data []byte, kind, dst string) error {
	if kind == "sdist" {
		return untarGz(data, dst)
	}
	return unzip(data, dst)
}

func untarGz(data []byte, dst string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dst, sanitizeTarPath(hdr.Name))
		if !strings.HasPrefix(target, dst) {
			continue // path traversal guard
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		}
	}
}

func sanitizeTarPath(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(name, "/")
	parts := strings.Split(name, "/")
	out := parts[:0]
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, "/")
}
