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

// newPyPITestServer serves fixtures from testdata/transitive/pypi/.
// Routes:
//
//	/pypi/<pkg>/<version>/json      → <pkg>_<version>.json
//	/files/<pkg>-<ver>.tar.gz       → <pkg>-<ver>.tar.gz
func newPyPITestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/pypi/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 4 {
			http.NotFound(w, r)
			return
		}
		pkg := parts[1]
		ver := parts[2]
		path := filepath.Join("..", "..", "..", "..", "testdata", "transitive", "pypi", pkg+"_"+ver+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		// Rewrite URLs so the test can fetch through the httptest server.
		var obj map[string]interface{}
		_ = json.Unmarshal(data, &obj)
		if urls, ok := obj["urls"].([]interface{}); ok {
			for _, u := range urls {
				if m, ok := u.(map[string]interface{}); ok {
					if rel, _ := m["filename"].(string); rel != "" {
						m["url"] = "http://" + r.Host + "/files/" + rel
					}
				}
			}
		}
		out, _ := json.Marshal(obj)
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	})
	mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/files/")
		path := filepath.Join("..", "..", "..", "..", "testdata", "transitive", "pypi", name)
		data, err := os.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(data)
	})
	return httptest.NewServer(mux)
}

func TestPyPIFetcher_Manifest(t *testing.T) {
	srv := newPyPITestServer(t)
	defer srv.Close()

	f := &PyPIFetcher{BaseURL: srv.URL + "/pypi", HTTPClient: srv.Client()}
	m, err := f.Manifest(context.Background(), "urllib3", "1.26.5")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if len(m.Dependencies) == 0 {
		t.Errorf("expected some dependencies for urllib3 1.26.5")
	}
}

func TestPyPIFetcher_Fetch(t *testing.T) {
	srv := newPyPITestServer(t)
	defer srv.Close()

	cache := NewCache(t.TempDir())
	f := &PyPIFetcher{BaseURL: srv.URL + "/pypi", HTTPClient: srv.Client(), Cache: cache}

	res, err := f.Fetch(context.Background(), "urllib3", "1.26.5", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.SourceUnavailable {
		t.Fatalf("unexpected SourceUnavailable")
	}
	if res.SourceDir == "" {
		t.Fatalf("empty SourceDir")
	}
	// Verify at least one .py file was unpacked.
	found := false
	filepath.WalkDir(res.SourceDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".py") {
			found = true
		}
		return nil
	})
	if !found {
		t.Errorf("no .py files found in fetched source %s", res.SourceDir)
	}
}

func TestPyPIFetcher_Ecosystem(t *testing.T) {
	f := &PyPIFetcher{}
	if f.Ecosystem() != "pypi" {
		t.Errorf("expected 'pypi'")
	}
}
