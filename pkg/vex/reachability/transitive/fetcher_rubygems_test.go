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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRubyGemsFetcher_Ecosystem(t *testing.T) {
	f := &RubyGemsFetcher{}
	if f.Ecosystem() != "rubygems" {
		t.Errorf("Ecosystem() = %q, want %q", f.Ecosystem(), "rubygems")
	}
}

func TestRubyGemsFetcher_Manifest_HappyPath(t *testing.T) {
	gemData := buildTestGem(t, "mygem", "1.0.0", "class MyGem; end",
		"--- !ruby/object:Gem::Specification\nname: mygem\nversion: !ruby/object:Gem::Version\n  version: 1.0.0\ndependencies:\n- !ruby/object:Gem::Dependency\n  name: json\n  type: :runtime\n  requirement: !ruby/object:Gem::Requirement\n    requirements:\n    - - \">=\"\n      - !ruby/object:Gem::Version\n        version: '0'\n- !ruby/object:Gem::Dependency\n  name: rspec\n  type: :development\n  requirement: !ruby/object:Gem::Requirement\n    requirements:\n    - - \">=\"\n      - !ruby/object:Gem::Version\n        version: '0'\n")
	digest := sha256Hex(gemData)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v2/rubygems/mygem/versions/1.0.0.json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"sha": %q, "gem_uri": "%s/downloads/mygem-1.0.0.gem"}`, digest, "")
		case strings.HasSuffix(r.URL.Path, "/downloads/mygem-1.0.0.gem"):
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(gemData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f := &RubyGemsFetcher{BaseURL: srv.URL, HTTPClient: srv.Client(), Cache: NewCache(t.TempDir())}
	m, err := f.Manifest(context.Background(), "mygem", "1.0.0")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if _, ok := m.Dependencies["json"]; !ok {
		t.Error("json not in dependencies")
	}
	if _, ok := m.Dependencies["rspec"]; ok {
		t.Error("rspec (development) should have been filtered")
	}
}

func TestRubyGemsFetcher_Fetch_HappyPath(t *testing.T) {
	gemData := buildTestGem(t, "mini", "0.1.0", "class Mini; def hello; end; end",
		"--- !ruby/object:Gem::Specification\nname: mini\nversion: !ruby/object:Gem::Version\n  version: 0.1.0\ndependencies: []\n")
	digest := sha256Hex(gemData)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v2/rubygems/mini/versions/0.1.0.json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"sha": %q, "gem_uri": "%s/downloads/mini-0.1.0.gem"}`, digest, "")
		case strings.HasSuffix(r.URL.Path, "/downloads/mini-0.1.0.gem"):
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(gemData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f := &RubyGemsFetcher{BaseURL: srv.URL, HTTPClient: srv.Client(), Cache: NewCache(t.TempDir())}
	fr, err := f.Fetch(context.Background(), "mini", "0.1.0", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fr.SourceDir == "" {
		t.Fatal("SourceDir empty")
	}
	// Check that the .rb file exists in the unpacked source
	found := false
	_ = filepath.WalkDir(fr.SourceDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(path, ".rb") {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("no .rb files found in unpacked source")
	}
}

func TestRubyGemsFetcher_Fetch_DigestMismatch(t *testing.T) {
	gemData := buildTestGem(t, "bad", "0.1.0", "class Bad; end",
		"--- !ruby/object:Gem::Specification\nname: bad\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v2/rubygems/bad/versions/0.1.0.json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sha": "deadbeef", "gem_uri": ""}`))
		case strings.HasSuffix(r.URL.Path, "/downloads/bad-0.1.0.gem"):
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(gemData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f := &RubyGemsFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.Fetch(context.Background(), "bad", "0.1.0", nil)
	if err == nil || !strings.Contains(err.Error(), ReasonDigestMismatch) {
		t.Errorf("Fetch: want %q in error, got %v", ReasonDigestMismatch, err)
	}
}

func TestRubyGemsFetcher_Manifest_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	f := &RubyGemsFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.Manifest(context.Background(), "nope", "0.0.1")
	if err == nil {
		t.Fatal("Manifest: expected error, got nil")
	}
}

// buildTestGem creates a minimal .gem file (tar containing data.tar.gz and metadata.gz).
func buildTestGem(t *testing.T, name, version, libContent, gemspecYAML string) []byte {
	t.Helper()

	// Build data.tar.gz (the source files)
	var dataBuf bytes.Buffer
	dataGz := gzip.NewWriter(&dataBuf)
	dataTar := tar.NewWriter(dataGz)
	writeTestTarFile(t, dataTar, "lib/"+name+".rb", libContent)
	if err := dataTar.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dataGz.Close(); err != nil {
		t.Fatal(err)
	}

	// Build metadata.gz
	var metaBuf bytes.Buffer
	metaGz := gzip.NewWriter(&metaBuf)
	if _, err := metaGz.Write([]byte(gemspecYAML)); err != nil {
		t.Fatal(err)
	}
	if err := metaGz.Close(); err != nil {
		t.Fatal(err)
	}

	// Build the outer .gem tar (NOT gzipped)
	var gemBuf bytes.Buffer
	gemTar := tar.NewWriter(&gemBuf)
	writeTestTarBytes(t, gemTar, "data.tar.gz", dataBuf.Bytes())
	writeTestTarBytes(t, gemTar, "metadata.gz", metaBuf.Bytes())
	if err := gemTar.Close(); err != nil {
		t.Fatal(err)
	}

	return gemBuf.Bytes()
}

func writeTestTarFile(t *testing.T, tw *tar.Writer, path, content string) {
	t.Helper()
	hdr := &tar.Header{Name: path, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
}

func writeTestTarBytes(t *testing.T, tw *tar.Writer, path string, data []byte) {
	t.Helper()
	hdr := &tar.Header{Name: path, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
