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

func TestCratesFetcher_Ecosystem(t *testing.T) {
	f := &CratesFetcher{}
	if f.Ecosystem() != "crates.io" {
		t.Errorf("Ecosystem() = %q, want %q", f.Ecosystem(), "crates.io")
	}
}

func TestCratesFetcher_Manifest_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v1/crates/hyper/0.14.10"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"version": {
					"num": "0.14.10",
					"dl_path": "/api/v1/crates/hyper/0.14.10/download",
					"checksum": "0000000000000000000000000000000000000000000000000000000000000000"
				}
			}`))
		case strings.HasSuffix(r.URL.Path, "/api/v1/crates/hyper/0.14.10/dependencies"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"dependencies": [
					{"crate_id": "tokio", "req": "^1", "kind": "normal", "optional": false},
					{"crate_id": "mockito", "req": "^0.31", "kind": "dev", "optional": false},
					{"crate_id": "cc", "req": "^1", "kind": "build", "optional": false},
					{"crate_id": "tracing", "req": "^0.1", "kind": "normal", "optional": true}
				]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f := &CratesFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	m, err := f.Manifest(context.Background(), "hyper", "0.14.10")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if _, ok := m.Dependencies["tokio"]; !ok {
		t.Error("tokio not in dependencies")
	}
	if _, ok := m.Dependencies["mockito"]; ok {
		t.Error("mockito (dev) should have been filtered")
	}
	if _, ok := m.Dependencies["cc"]; ok {
		t.Error("cc (build) should have been filtered")
	}
	if _, ok := m.Dependencies["tracing"]; !ok {
		t.Error("tracing (optional but normal) should have been included")
	}
}

func TestCratesFetcher_Manifest_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	f := &CratesFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.Manifest(context.Background(), "nope", "0.0.1")
	if err == nil {
		t.Fatal("Manifest: expected error, got nil")
	}
}

//nolint:gocritic // unnamedResult: the two returns (tarball, digest) are self-descriptive at call sites
func buildTestCrate(t *testing.T, name, version, libContents string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	rootDir := name + "-" + version + "/"
	writeTarDir := func(path string) {
		if err := tw.WriteHeader(&tar.Header{Name: path, Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
			t.Fatalf("tar dir %s: %v", path, err)
		}
	}
	writeTarFile := func(path, content string) {
		hdr := &tar.Header{
			Name:     path,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", path, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar write %s: %v", path, err)
		}
	}
	writeTarDir(rootDir)
	writeTarDir(rootDir + "src/")
	writeTarFile(rootDir+"Cargo.toml", fmt.Sprintf("[package]\nname = %q\nversion = %q\n", name, version))
	writeTarFile(rootDir+"src/lib.rs", libContents)
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	raw := buf.Bytes()
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:])
}

func TestCratesFetcher_Fetch_HappyPath(t *testing.T) {
	body, digest := buildTestCrate(t, "mini", "0.1.0", "pub fn hello() {}\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v1/crates/mini/0.1.0"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{
				"version": {
					"num": "0.1.0",
					"dl_path": "/api/v1/crates/mini/0.1.0/download",
					"checksum": %q
				}
			}`, digest)
		case strings.HasSuffix(r.URL.Path, "/api/v1/crates/mini/0.1.0/download"):
			w.Header().Set("Content-Type", "application/x-gzip")
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f := &CratesFetcher{BaseURL: srv.URL, HTTPClient: srv.Client(), Cache: NewCache(t.TempDir())}
	fr, err := f.Fetch(context.Background(), "mini", "0.1.0", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fr.SourceDir == "" {
		t.Fatal("SourceDir empty")
	}
	libPath := filepath.Join(fr.SourceDir, "mini-0.1.0", "src", "lib.rs")
	if _, err := os.Stat(libPath); err != nil {
		t.Errorf("unpacked lib.rs missing at %s: %v", libPath, err)
	}
}

func TestCratesFetcher_Fetch_DigestMismatch(t *testing.T) {
	body, _ := buildTestCrate(t, "bad", "0.1.0", "pub fn hello() {}\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v1/crates/bad/0.1.0"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"version": {
					"num": "0.1.0",
					"dl_path": "/api/v1/crates/bad/0.1.0/download",
					"checksum": "deadbeef"
				}
			}`))
		case strings.HasSuffix(r.URL.Path, "/api/v1/crates/bad/0.1.0/download"):
			w.Header().Set("Content-Type", "application/x-gzip")
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f := &CratesFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.Fetch(context.Background(), "bad", "0.1.0", nil)
	if err == nil || !strings.Contains(err.Error(), ReasonDigestMismatch) {
		t.Errorf("Fetch: want %q in error, got %v", ReasonDigestMismatch, err)
	}
}
