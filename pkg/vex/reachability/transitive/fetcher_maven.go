// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// MavenFetcher implements Fetcher for the Maven Central ecosystem.
type MavenFetcher struct {
	// BaseURL is the Maven Central repository base. Defaults to https://repo1.maven.org/maven2.
	BaseURL    string
	HTTPClient *http.Client
	Cache      *Cache
}

func (f *MavenFetcher) Ecosystem() string { return "maven" }

func (f *MavenFetcher) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return http.DefaultClient
}

func (f *MavenFetcher) baseURL() string {
	if f.BaseURL != "" {
		return f.BaseURL
	}
	return "https://repo1.maven.org/maven2"
}

// pomProject is the subset of the POM XML schema we consume.
type pomProject struct {
	XMLName      xml.Name `xml:"project"`
	Dependencies pomDeps  `xml:"dependencies"`
	SCM          pomSCM   `xml:"scm"`
}

type pomDeps struct {
	Dependency []pomDependency `xml:"dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

type pomSCM struct {
	URL string `xml:"url"`
	Tag string `xml:"tag"`
}

// parseMavenCoordinate splits "groupId:artifactId" into its parts.
func parseMavenCoordinate(name string) (groupID, artifactID string, err error) {
	idx := strings.IndexByte(name, ':')
	if idx < 0 {
		return "", "", fmt.Errorf("invalid Maven coordinate %q: missing ':'", name)
	}
	return name[:idx], name[idx+1:], nil
}

// groupPath converts a Maven groupId to a URL path segment.
// "com.google.code.gson" → "com/google/code/gson"
func groupPath(groupID string) string {
	return strings.ReplaceAll(groupID, ".", "/")
}

// pomURL constructs the POM URL for a Maven artifact.
func (f *MavenFetcher) pomURL(groupID, artifactID, version string) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom",
		f.baseURL(), groupPath(groupID), artifactID, version, artifactID, version)
}

// sourcesJARURL constructs the sources JAR URL.
func (f *MavenFetcher) sourcesJARURL(groupID, artifactID, version string) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s-%s-sources.jar",
		f.baseURL(), groupPath(groupID), artifactID, version, artifactID, version)
}

// fetchPOM downloads and parses the POM XML.
func (f *MavenFetcher) fetchPOM(ctx context.Context, groupID, artifactID, version string) (*pomProject, error) {
	url := f.pomURL(groupID, artifactID, version)
	body, err := httpGetBytes(ctx, f.client(), url)
	if err != nil {
		return nil, err
	}
	var pom pomProject
	if err := xml.Unmarshal(body, &pom); err != nil {
		return nil, fmt.Errorf("parse POM %s: %w", url, err)
	}
	return &pom, nil
}

// Manifest fetches POM and returns runtime/compile dependencies.
func (f *MavenFetcher) Manifest(ctx context.Context, name, version string) (PackageManifest, error) {
	groupID, artifactID, err := parseMavenCoordinate(name)
	if err != nil {
		return PackageManifest{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}
	pom, err := f.fetchPOM(ctx, groupID, artifactID, version)
	if err != nil {
		return PackageManifest{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}
	deps := make(map[string]string)
	for _, dep := range pom.Dependencies.Dependency {
		scope := dep.Scope
		if scope == "" {
			scope = "compile"
		}
		if scope != "compile" && scope != "runtime" {
			continue
		}
		key := dep.GroupID + ":" + dep.ArtifactID
		deps[key] = dep.Version
	}
	return PackageManifest{Dependencies: deps}, nil
}

// Fetch downloads the sources JAR for a Maven artifact. If the sources
// JAR is not available (404), it falls back to cloning from the SCM URL
// declared in the POM.
//
//nolint:gocyclo // download-verify-unpack pipeline with SCM fallback
func (f *MavenFetcher) Fetch(ctx context.Context, name, version string, expectedDigest *Digest) (FetchResult, error) {
	groupID, artifactID, err := parseMavenCoordinate(name)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonManifestFetchFailed, err)
	}

	// Try sources JAR first.
	srcURL := f.sourcesJARURL(groupID, artifactID, version)
	body, srcErr := httpGetBytes(ctx, f.client(), srcURL)
	if srcErr == nil {
		return f.unpackSourcesJAR(body, name, expectedDigest)
	}

	// Sources JAR unavailable — fall back to SCM clone.
	pom, pomErr := f.fetchPOM(ctx, groupID, artifactID, version)
	if pomErr != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonTarballFetchFailed, pomErr)
	}
	if pom.SCM.URL == "" {
		return FetchResult{}, fmt.Errorf("%s: no sources JAR and no SCM URL in POM for %s", ReasonSourceUnavailable, name)
	}
	res, cloneErr := scmClone(ctx, pom.SCM.URL, version, f.Cache)
	if cloneErr != nil {
		return FetchResult{}, fmt.Errorf("%s: %w", ReasonSourceUnavailable, cloneErr)
	}
	return FetchResult{SourceDir: res.SourceDir, Digest: res.Digest}, nil
}

// unpackSourcesJAR unpacks a sources JAR (which is a ZIP), caches and returns.
func (f *MavenFetcher) unpackSourcesJAR(body []byte, name string, expectedDigest *Digest) (FetchResult, error) {
	actual := Digest{Algorithm: "sha256", Hex: hashHex(body)}
	if expectedDigest != nil && !expectedDigest.IsZero() && !expectedDigest.Equals(actual) {
		return FetchResult{}, fmt.Errorf("%s: SBOM expected %s, got %s", ReasonDigestMismatch, expectedDigest, actual)
	}

	if f.Cache != nil {
		if p, ok := f.Cache.Get(actual.String()); ok {
			return FetchResult{SourceDir: p, Digest: actual}, nil
		}
	}

	tmp, err := os.MkdirTemp("", "maven-*")
	if err != nil {
		return FetchResult{}, err
	}
	if err := unzip(body, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return FetchResult{}, fmt.Errorf("unpack sources JAR %s: %w", name, err)
	}

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
