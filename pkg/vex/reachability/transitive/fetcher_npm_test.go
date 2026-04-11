// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newNPMTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 2 {
			http.NotFound(w, r)
			return
		}
		pkg := parts[0]
		ver := parts[1]
		path := filepath.Join("..", "..", "..", "..", "testdata", "transitive", "npm", pkg+"_"+ver+".json")
		data, err := os.ReadFile(path) //nolint:gosec // test reads known fixture file path
		if err != nil {
			http.NotFound(w, r)
			return
		}
		var obj map[string]interface{}
		_ = json.Unmarshal(data, &obj)
		if dist, ok := obj["dist"].(map[string]interface{}); ok {
			dist["tarball"] = "http://" + r.Host + "/files/" + pkg + "-" + ver + ".tgz"
		}
		out, _ := json.Marshal(obj)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	})
	mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/files/")
		path := filepath.Join("..", "..", "..", "..", "testdata", "transitive", "npm", name) //nolint:gosec // test reads known fixture file path
		data, err := os.ReadFile(path)                                                       //nolint:gosec // test reads known fixture file path
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	})
	return httptest.NewServer(mux)
}

func TestNPMFetcher_Manifest(t *testing.T) {
	srv := newNPMTestServer(t)
	defer srv.Close()
	f := &NPMFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	m, err := f.Manifest(context.Background(), "express", "4.17.1")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if _, ok := m.Dependencies["body-parser"]; !ok {
		t.Errorf("expected body-parser dependency, got %v", m.Dependencies)
	}
}

func TestNPMFetcher_Fetch(t *testing.T) {
	srv := newNPMTestServer(t)
	defer srv.Close()
	cache := NewCache(t.TempDir())
	f := &NPMFetcher{BaseURL: srv.URL, HTTPClient: srv.Client(), Cache: cache}
	res, err := f.Fetch(context.Background(), "lodash", "4.17.20", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.SourceDir == "" {
		t.Fatal("empty SourceDir")
	}
	found := false
	_ = filepath.WalkDir(res.SourceDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".js") {
			found = true
		}
		return nil
	})
	if !found {
		t.Errorf("no .js files in %s", res.SourceDir)
	}

	// Verify the package is unpacked under <pkgname>/ not package/
	lodashDir := filepath.Join(res.SourceDir, "lodash")
	if _, err := os.Stat(lodashDir); os.IsNotExist(err) {
		t.Errorf("expected lodash/ subdir in SourceDir %s; old package/ layout still used", res.SourceDir)
	}
}

func TestNPMFetcher_Ecosystem(t *testing.T) {
	f := &NPMFetcher{}
	if f.Ecosystem() != "npm" {
		t.Errorf("expected 'npm'")
	}
}
