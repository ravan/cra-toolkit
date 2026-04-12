// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNuGetFetcher_Ecosystem(t *testing.T) {
	f := &NuGetFetcher{}
	if f.Ecosystem() != "nuget" {
		t.Errorf("Ecosystem() = %q, want %q", f.Ecosystem(), "nuget")
	}
}

func TestNuGetFetcher_Manifest_HappyPath(t *testing.T) {
	nuspec := `<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <dependencies>
      <group targetFramework="net6.0">
        <dependency id="Microsoft.Extensions.Logging" version="6.0.0" />
      </group>
      <group targetFramework="netstandard2.0">
        <dependency id="Newtonsoft.Json" version="13.0.1" />
      </group>
    </dependencies>
  </metadata>
</package>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/mylib.nuspec") {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(nuspec))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	f := &NuGetFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	m, err := f.Manifest(context.Background(), "MyLib", "1.0.0")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	// Union of all framework groups.
	if _, ok := m.Dependencies["Microsoft.Extensions.Logging"]; !ok {
		t.Error("Microsoft.Extensions.Logging not in dependencies")
	}
	if _, ok := m.Dependencies["Newtonsoft.Json"]; !ok {
		t.Error("Newtonsoft.Json not in dependencies")
	}
}

func TestNuGetFetcher_Fetch_WithSourceInNupkg(t *testing.T) {
	zipData := buildTestZip(t, "", map[string]string{
		"src/MyLib/Service.cs": `namespace MyLib { public class Service { public void Run() {} } }`,
		"MyLib.nuspec": `<?xml version="1.0"?><package><metadata>
		<repository type="git" url="https://github.com/example/mylib" /></metadata></package>`,
	})
	digest := sha256Hex(zipData)

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".nupkg"):
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(zipData)
		case strings.HasSuffix(r.URL.Path, ".nuspec"):
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0"?><package><metadata>
			<repository type="git" url="https://github.com/example/mylib" /></metadata></package>`))
		default:
			http.NotFound(w, r)
		}
	}))
	srvURL = srv.URL
	_ = srvURL
	_ = digest
	defer srv.Close()

	f := &NuGetFetcher{BaseURL: srv.URL, HTTPClient: srv.Client(), Cache: NewCache(t.TempDir())}
	fr, err := f.Fetch(context.Background(), "MyLib", "1.0.0", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fr.SourceDir == "" {
		t.Fatal("SourceDir empty")
	}
	found := false
	_ = filepath.WalkDir(fr.SourceDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(path, ".cs") {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("no .cs files found in unpacked source")
	}
}

func TestNuGetFetcher_Manifest_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	f := &NuGetFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.Manifest(context.Background(), "Nope", "0.0.1")
	if err == nil {
		t.Fatal("Manifest: expected error, got nil")
	}
}
