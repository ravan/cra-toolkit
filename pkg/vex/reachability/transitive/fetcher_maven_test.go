// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMavenFetcher_Ecosystem(t *testing.T) {
	f := &MavenFetcher{}
	if f.Ecosystem() != "maven" {
		t.Errorf("Ecosystem() = %q, want %q", f.Ecosystem(), "maven")
	}
}

func TestMavenFetcher_Manifest_HappyPath(t *testing.T) {
	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/com/google/code/gson/gson/2.10.1/gson-2.10.1.pom") {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(pom))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	f := &MavenFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	m, err := f.Manifest(context.Background(), "com.google.code.gson:gson", "2.10.1")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if _, ok := m.Dependencies["com.google.guava:guava"]; !ok {
		t.Error("guava not in dependencies")
	}
	if _, ok := m.Dependencies["junit:junit"]; ok {
		t.Error("test-scoped junit should have been filtered")
	}
}

func TestMavenFetcher_Fetch_SourcesJAR(t *testing.T) {
	zipData := buildTestZip(t, "gson-2.10.1-sources", map[string]string{
		"com/google/gson/Gson.java": `package com.google.gson;
public class Gson {}`,
	})
	digest := sha256Hex(zipData)

	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project><dependencies></dependencies></project>`

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "gson-2.10.1.pom"):
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(pom))
		case strings.HasSuffix(r.URL.Path, "gson-2.10.1-sources.jar"):
			w.Header().Set("Content-Type", "application/java-archive")
			_, _ = w.Write(zipData)
		case strings.HasSuffix(r.URL.Path, "gson-2.10.1-sources.jar.sha1"):
			// SHA-1 checksum — we use SHA-256 internally so just return empty
			// to skip SHA-1 validation in tests
			_, _ = fmt.Fprintf(w, "%s", digest[:40])
		default:
			http.NotFound(w, r)
		}
	}))
	srvURL = srv.URL
	_ = srvURL
	defer srv.Close()

	f := &MavenFetcher{BaseURL: srv.URL, HTTPClient: srv.Client(), Cache: NewCache(t.TempDir())}
	fr, err := f.Fetch(context.Background(), "com.google.code.gson:gson", "2.10.1", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fr.SourceDir == "" {
		t.Fatal("SourceDir empty")
	}
	found := false
	_ = filepath.WalkDir(fr.SourceDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(path, ".java") {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("no .java files found in unpacked source")
	}
}

func TestMavenFetcher_Manifest_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	f := &MavenFetcher{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := f.Manifest(context.Background(), "nope:nope", "0.0.1")
	if err == nil {
		t.Fatal("Manifest: expected error, got nil")
	}
}

//nolint:gocognit // table-driven test with many cases
func TestMavenFetcher_ParseCoordinate(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantGroup string
		wantArt   string
		wantErr   bool
	}{
		{"standard", "com.google.code.gson:gson", "com.google.code.gson", "gson", false},
		{"nested", "org.apache.logging.log4j:log4j-core", "org.apache.logging.log4j", "log4j-core", false},
		{"invalid no colon", "invalid", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, a, err := parseMavenCoordinate(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if g != tc.wantGroup || a != tc.wantArt {
				t.Errorf("got (%q, %q), want (%q, %q)", g, a, tc.wantGroup, tc.wantArt)
			}
		})
	}
}
