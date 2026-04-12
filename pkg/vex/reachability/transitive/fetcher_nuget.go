// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// NuGetFetcher implements Fetcher for the NuGet ecosystem.
type NuGetFetcher struct {
	// BaseURL is the NuGet API base. Defaults to https://api.nuget.org.
	BaseURL    string
	HTTPClient *http.Client
	Cache      *Cache
}

func (f *NuGetFetcher) Ecosystem() string { return "nuget" }

func (f *NuGetFetcher) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return http.DefaultClient
}

func (f *NuGetFetcher) baseURL() string {
	if f.BaseURL != "" {
		return f.BaseURL
	}
	return "https://api.nuget.org"
}

// nuspecPackage is the subset of the .nuspec XML schema we consume.
type nuspecPackage struct {
	XMLName  xml.Name        `xml:"package"`
	Metadata nuspecMetadata  `xml:"metadata"`
}

type nuspecMetadata struct {
	Dependencies nuspecDependencies `xml:"dependencies"`
	Repository   nuspecRepository   `xml:"repository"`
}

type nuspecDependencies struct {
	Groups []nuspecGroup `xml:"group"`
	Deps   []nuspecDep   `xml:"dependency"` // top-level (no framework group)
}

type nuspecGroup struct {
	TargetFramework string      `xml:"targetFramework,attr"`
	Deps            []nuspecDep `xml:"dependency"`
}

type nuspecDep struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

type nuspecRepository struct {
	Type   string `xml:"type,attr"`
	URL    string `xml:"url,attr"`
	Commit string `xml:"commit,attr"`
}

// nuspecURL constructs the nuspec URL for a NuGet package.
func (f *NuGetFetcher) nuspecURL(name, version string) string {
	lc := strings.ToLower(name)
	return fmt.Sprintf("%s/v3-flatcontainer/%s/%s/%s.nuspec",
		f.baseURL(), lc, version, lc)
}

// nupkgURL constructs the nupkg URL for a NuGet package.
func (f *NuGetFetcher) nupkgURL(name, version string) string {
	lc := strings.ToLower(name)
	return fmt.Sprintf("%s/v3-flatcontainer/%s/%s/%s.%s.nupkg",
		f.baseURL(), lc, version, lc, version)
}

// fetchNuspec downloads and parses the .nuspec metadata.
func (f *NuGetFetcher) fetchNuspec(ctx context.Context, name, version string) (*nuspecPackage, error) {
	url := f.nuspecURL(name, version)
	body, err := httpGetBytes(ctx, f.client(), url)
	if err != nil {
		return nil, err
	}
	var pkg nuspecPackage
	if err := xml.Unmarshal(body, &pkg); err != nil {
		return nil, fmt.Errorf("parse nuspec %s: %w", url, err)
	}
	return &pkg, nil
}

// Manifest fetches nuspec and returns dependencies (union of all framework groups).
func (f *NuGetFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	nuspec, err := f.fetchNuspec(ctx, name, version)
	if err != nil {
		return PackageManifest{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}
	deps := make(map[string]string)
	// Top-level dependencies (no framework group).
	for _, dep := range nuspec.Metadata.Dependencies.Deps {
		deps[dep.ID] = dep.Version
	}
	// Union of all framework groups.
	for _, group := range nuspec.Metadata.Dependencies.Groups {
		for _, dep := range group.Deps {
			if _, exists := deps[dep.ID]; !exists {
				deps[dep.ID] = dep.Version
			}
		}
	}
	return PackageManifest{Dependencies: deps}, nil
}

// Fetch downloads the nupkg and checks for source files. If no source
// is found, falls back to cloning from the repository URL in the nuspec.
//
//nolint:gocyclo // download-verify-unpack pipeline with SCM fallback
func (f *NuGetFetcher) Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error) {
	url := f.nupkgURL(name, version)
	body, err := httpGetBytes(ctx, f.client(), url)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonTarballFetchFailed, err)
	}

	actual := Digest{Algorithm: "sha256", Hex: hashHex(body)}
	if expectedDigest != nil && !expectedDigest.IsZero() && !expectedDigest.Equals(actual) {
		return FetchResult{}, fmt.Errorf("%s: SBOM expected %s, got %s", ReasonDigestMismatch, expectedDigest, actual)
	}

	// Unpack and check for .cs source files.
	tmp, err := os.MkdirTemp("", "nuget-*")
	if err != nil {
		return FetchResult{}, err
	}
	if err := unzip(body, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return FetchResult{}, fmt.Errorf("unpack nupkg %s: %w", name, err)
	}

	if hasSourceFiles(tmp, ".cs") {
		if f.Cache == nil {
			return FetchResult{SourceDir: tmp, Digest: actual}, nil
		}
		p, putErr := f.Cache.Put(actual.String(), tmp)
		_ = os.RemoveAll(tmp)
		if putErr != nil {
			return FetchResult{}, putErr
		}
		return FetchResult{SourceDir: p, Digest: actual}, nil
	}
	_ = os.RemoveAll(tmp)

	// No source in nupkg — fall back to SCM clone.
	nuspec, nuspecErr := f.fetchNuspec(ctx, name, version)
	if nuspecErr != nil || nuspec.Metadata.Repository.URL == "" {
		return FetchResult{}, fmt.Errorf("%s: no source in nupkg and no repository URL for %s", ReasonSourceUnavailable, name)
	}
	res, cloneErr := scmClone(ctx, nuspec.Metadata.Repository.URL, version, f.Cache)
	if cloneErr != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonSourceUnavailable, cloneErr)
	}
	return FetchResult{SourceDir: res.SourceDir, Digest: res.Digest}, nil
}

// hasSourceFiles checks if a directory contains files with the given extension,
// excluding obj/ and bin/ directories.
func hasSourceFiles(dir, ext string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "obj" || name == "bin" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ext) {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}
