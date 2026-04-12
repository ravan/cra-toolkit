// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// RubyGemsFetcher implements Fetcher for the RubyGems ecosystem.
type RubyGemsFetcher struct {
	// BaseURL is the RubyGems API base. Defaults to https://rubygems.org.
	BaseURL    string
	HTTPClient *http.Client
	Cache      *Cache
}

func (f *RubyGemsFetcher) Ecosystem() string { return "rubygems" }

func (f *RubyGemsFetcher) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return http.DefaultClient
}

func (f *RubyGemsFetcher) baseURL() string {
	if f.BaseURL != "" {
		return f.BaseURL
	}
	return "https://rubygems.org"
}

type rubygemsVersionMeta struct {
	SHA    string `json:"sha"`
	GemURI string `json:"gem_uri"`
}

func (f *RubyGemsFetcher) fetchMeta(ctx context.Context, name, version string) (*rubygemsVersionMeta, error) {
	url := fmt.Sprintf("%s/api/v2/rubygems/%s/versions/%s.json", f.baseURL(), name, version)
	var m rubygemsVersionMeta
	if err := httpGetJSON(ctx, f.client(), url, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Manifest fetches the .gem file and extracts dependency metadata from metadata.gz.
func (f *RubyGemsFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	gemBody, err := f.downloadGem(ctx, name, version)
	if err != nil {
		return PackageManifest{}, err
	}

	gemspecYAML, err := extractMetadataGz(gemBody)
	if err != nil {
		return PackageManifest{}, fmt.Errorf("%s: parse gemspec: %w", ReasonManifestFetchFailed, err)
	}

	deps := parseGemspecDeps(gemspecYAML)
	return PackageManifest{Dependencies: deps}, nil
}

func (f *RubyGemsFetcher) downloadGem(ctx context.Context, name, version string) ([]byte, error) {
	meta, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}
	gemURL := resolveGemURL(meta.GemURI, f.baseURL(), name, version)
	body, err := httpGetBytes(ctx, f.client(), gemURL)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ReasonTarballFetchFailed, err)
	}
	return body, nil
}

// Fetch downloads the .gem file, verifies its digest, and unpacks it into the cache.
//
//nolint:gocyclo // download-verify-unpack pipeline
func (f *RubyGemsFetcher) Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error) {
	meta, err := f.fetchMeta(ctx, name, version)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}

	registryDigest := Digest{Algorithm: "sha256", Hex: meta.SHA}

	if f.Cache != nil {
		if p, ok := f.Cache.Get(registryDigest.String()); ok {
			return FetchResult{SourceDir: p, Digest: registryDigest}, nil
		}
	}

	gemURL := resolveGemURL(meta.GemURI, f.baseURL(), name, version)
	body, err := httpGetBytes(ctx, f.client(), gemURL)
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

	tmp, err := os.MkdirTemp("", "rubygems-*")
	if err != nil {
		return FetchResult{}, err
	}

	if err := extractDataTarGz(body, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return FetchResult{}, fmt.Errorf("unpack gem %s: %w", name, err)
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

// resolveGemURL returns a fully-qualified download URL for a gem.
// If gemURI is non-empty and absolute it is used as-is; if it is a path-only
// (starts with "/") it is resolved against baseURL; otherwise the canonical
// rubygems.org download path is constructed.
func resolveGemURL(gemURI, baseURL, name, version string) string {
	switch {
	case gemURI == "":
		return fmt.Sprintf("%s/downloads/%s-%s.gem", baseURL, name, version)
	case strings.HasPrefix(gemURI, "/"):
		return baseURL + gemURI
	default:
		return gemURI
	}
}

// extractDataTarGz reads a .gem file (plain tar), finds data.tar.gz, and unpacks it into dst.
func extractDataTarGz(gemData []byte, dst string) error {
	tr := tar.NewReader(bytes.NewReader(gemData))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("data.tar.gz not found in gem")
		}
		if err != nil {
			return err
		}
		if hdr.Name == "data.tar.gz" {
			data, err := io.ReadAll(io.LimitReader(tr, 500<<20)) // 500 MiB limit
			if err != nil {
				return err
			}
			return untarGz(data, dst)
		}
	}
}

// extractMetadataGz reads a .gem file and extracts the gemspec YAML from metadata.gz.
func extractMetadataGz(gemData []byte) (string, error) {
	tr := tar.NewReader(bytes.NewReader(gemData))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return "", fmt.Errorf("metadata.gz not found in gem")
		}
		if err != nil {
			return "", err
		}
		if hdr.Name == "metadata.gz" {
			return readGzippedString(tr)
		}
	}
}

// readGzippedString decompresses a gzip stream from r and returns its contents as a string.
func readGzippedString(r io.Reader) (string, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return "", err
	}
	data, readErr := io.ReadAll(io.LimitReader(gz, 10<<20)) // 10 MiB limit
	closeErr := gz.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return string(data), nil
}

// parseGemspecDeps extracts runtime dependencies from gemspec YAML.
// It is a line-oriented parser; it does not require a full YAML library.
func parseGemspecDeps(yaml string) map[string]string {
	deps := make(map[string]string)
	p := &gemspecParser{}
	for _, line := range strings.Split(yaml, "\n") {
		p.processLine(strings.TrimSpace(line), deps)
	}
	p.flushDep(deps)
	return deps
}

// gemspecParser holds line-parser state for parseGemspecDeps.
type gemspecParser struct {
	inDep       bool
	currentName string
	isRuntime   bool
}

func (p *gemspecParser) processLine(trimmed string, deps map[string]string) {
	if strings.HasPrefix(trimmed, "- !ruby/object:Gem::Dependency") {
		p.flushDep(deps)
		p.inDep = true
		p.currentName = ""
		p.isRuntime = false
		return
	}
	if !p.inDep {
		return
	}
	switch {
	case strings.HasPrefix(trimmed, "name: "):
		p.currentName = strings.TrimPrefix(trimmed, "name: ")
	case strings.HasPrefix(trimmed, "type: "):
		p.isRuntime = strings.TrimPrefix(trimmed, "type: ") == ":runtime"
	case isDepBlockTerminator(trimmed):
		p.flushDep(deps)
		p.inDep = false
	}
}

// isDepBlockTerminator returns true when a line signals the end of the current
// Gem::Dependency block without starting a new one.
func isDepBlockTerminator(trimmed string) bool {
	if strings.HasPrefix(trimmed, "- !ruby/object:Gem::") {
		return true
	}
	return trimmed != "" &&
		!strings.HasPrefix(trimmed, " ") &&
		!strings.HasPrefix(trimmed, "-") &&
		!strings.HasPrefix(trimmed, "requirement") &&
		!strings.HasPrefix(trimmed, "version")
}

func (p *gemspecParser) flushDep(deps map[string]string) {
	if p.inDep && p.isRuntime && p.currentName != "" {
		deps[p.currentName] = ">= 0"
	}
}
