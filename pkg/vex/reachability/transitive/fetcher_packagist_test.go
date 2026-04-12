// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackagistFetcher_Ecosystem(t *testing.T) {
	f := &PackagistFetcher{}
	if f.Ecosystem() != "packagist" {
		t.Errorf("Ecosystem() = %q, want %q", f.Ecosystem(), "packagist")
	}
}

func TestPackagistFetcher_Manifest_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/p2/guzzlehttp/psr7.json") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"packages":{"guzzlehttp/psr7":[{
				"version":"2.1.0",
				"require":{"php":">=7.2","psr/http-message":"^1.0"},
				"dist":{"url":"http://example.com/psr7.zip","type":"zip","shasum":"abc123"}
			}]}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	f := &PackagistFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	m, err := f.Manifest(context.Background(), "guzzlehttp/psr7", "2.1.0")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if _, ok := m.Dependencies["psr/http-message"]; !ok {
		t.Error("psr/http-message not in dependencies")
	}
	// Platform requirements should be filtered
	if _, ok := m.Dependencies["php"]; ok {
		t.Error("php platform requirement should have been filtered")
	}
}

func TestPackagistFetcher_Fetch_HappyPath(t *testing.T) {
	zipData := buildTestZip(t, "guzzlehttp-psr7-abc123", map[string]string{
		"src/Utils.php": "<?php\nclass Utils {}\n",
		"composer.json": `{"name":"guzzlehttp/psr7"}`,
	})
	digest := sha256Hex(zipData)

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/p2/guzzlehttp/psr7.json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"packages":{"guzzlehttp/psr7":[{
				"version":"2.1.0",
				"require":{},
				"dist":{"url":"%s/downloads/psr7.zip","type":"zip","shasum":%q}
			}]}}`, srvURL, digest)
		case strings.HasSuffix(r.URL.Path, "/downloads/psr7.zip"):
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(zipData)
		default:
			http.NotFound(w, r)
		}
	}))
	srvURL = srv.URL
	defer srv.Close()

	f := &PackagistFetcher{BaseURL: srv.URL, HTTPClient: srv.Client(), Cache: NewCache(t.TempDir())}
	fr, err := f.Fetch(context.Background(), "guzzlehttp/psr7", "2.1.0", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fr.SourceDir == "" {
		t.Fatal("SourceDir empty")
	}
	// Check that .php files exist
	found := false
	_ = filepath.WalkDir(fr.SourceDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(path, ".php") {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("no .php files found in unpacked source")
	}
}

func TestPackagistFetcher_Fetch_DigestMismatch(t *testing.T) {
	zipData := buildTestZip(t, "bad-pkg", map[string]string{
		"src/Bad.php": "<?php class Bad {}",
	})

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/p2/vendor/bad.json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"packages":{"vendor/bad":[{
				"version":"1.0.0",
				"require":{},
				"dist":{"url":"` + srvURL + `/downloads/bad.zip","type":"zip","shasum":"deadbeef"}
			}]}}`))
		case strings.HasSuffix(r.URL.Path, "/downloads/bad.zip"):
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(zipData)
		default:
			http.NotFound(w, r)
		}
	}))
	srvURL = srv.URL
	defer srv.Close()

	f := &PackagistFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.Fetch(context.Background(), "vendor/bad", "1.0.0", nil)
	if err == nil || !strings.Contains(err.Error(), ReasonDigestMismatch) {
		t.Errorf("Fetch: want %q in error, got %v", ReasonDigestMismatch, err)
	}
}

func TestPackagistFetcher_Manifest_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	f := &PackagistFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.Manifest(context.Background(), "nope/nope", "0.0.1")
	if err == nil {
		t.Fatal("Manifest: expected error, got nil")
	}
}

// buildTestZip creates a zip archive with a root directory and the given files.
func buildTestZip(t *testing.T, rootDir string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		path := rootDir + "/" + name
		w, err := zw.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
