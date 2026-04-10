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

const pypiFixtureDir = "../../../../testdata/transitive/pypi"

// rewriteURLs updates the "url" fields in a PyPI JSON response to point to
// the in-process test server.
func rewriteURLs(data []byte, host string) []byte {
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return data
	}
	urls, ok := obj["urls"].([]interface{})
	if !ok {
		return data
	}
	for _, u := range urls {
		m, ok := u.(map[string]interface{})
		if !ok {
			continue
		}
		if rel, _ := m["filename"].(string); rel != "" {
			m["url"] = "http://" + host + "/files/" + rel
		}
	}
	out, _ := json.Marshal(obj)
	return out
}

func handlePyPIMeta(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		http.NotFound(w, r)
		return
	}
	pkg, ver := parts[1], parts[2]
	path := filepath.Join(pypiFixtureDir, pkg+"_"+ver+".json")
	data, err := os.ReadFile(path) //nolint:gosec // test reads known fixture file path
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(rewriteURLs(data, r.Host))
}

func handlePyPIFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/files/")
	path := filepath.Join(pypiFixtureDir, name)
	data, err := os.ReadFile(path) //nolint:gosec // test reads known fixture file path
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(data)
}

// newPyPITestServer serves fixtures from testdata/transitive/pypi/.
// Routes:
//
//	/pypi/<pkg>/<version>/json      → <pkg>_<version>.json
//	/files/<pkg>-<ver>.tar.gz       → <pkg>-<ver>.tar.gz
func newPyPITestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/pypi/", handlePyPIMeta)
	mux.HandleFunc("/files/", handlePyPIFile)
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
	// urllib3 1.26.5 has only extras-conditional deps; after filtering extras
	// the unconditional dep list is empty, which is correct behaviour.
	for dep := range m.Dependencies {
		if strings.Contains(dep, "extra ==") {
			t.Errorf("extras dep leaked into manifest: %s", dep)
		}
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
	_ = filepath.WalkDir(res.SourceDir, func(p string, d os.DirEntry, err error) error {
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
