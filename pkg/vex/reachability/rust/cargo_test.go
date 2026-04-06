// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/rust"
)

func TestParseCargoToml_ReachableFixture(t *testing.T) {
	meta, err := rust.ParseCargoToml("../../../../testdata/integration/rust-reachable/source")
	if err != nil {
		t.Fatalf("ParseCargoToml failed: %v", err)
	}

	// hyper dependency should exist and not be optional
	dep, ok := meta.Dependencies["hyper"]
	if !ok {
		t.Fatal("expected 'hyper' dependency")
	}
	if dep.Version != "=0.14.10" {
		t.Errorf("expected version '=0.14.10', got %q", dep.Version)
	}
	if dep.Optional {
		t.Error("expected hyper to not be optional")
	}
	// hyper has features: http2, server, runtime
	wantFeatures := map[string]bool{"http2": true, "server": true, "runtime": true}
	for _, f := range dep.Features {
		if !wantFeatures[f] {
			t.Errorf("unexpected feature %q", f)
		}
		delete(wantFeatures, f)
	}
	for f := range wantFeatures {
		t.Errorf("missing expected feature %q", f)
	}

	// hyper should be enabled (not optional)
	if !meta.IsDependencyEnabled("hyper") {
		t.Error("expected hyper to be enabled")
	}
}

func TestParseCargoToml_NotReachableFixture(t *testing.T) {
	meta, err := rust.ParseCargoToml("../../../../testdata/integration/rust-not-reachable/source")
	if err != nil {
		t.Fatalf("ParseCargoToml failed: %v", err)
	}

	dep, ok := meta.Dependencies["hyper"]
	if !ok {
		t.Fatal("expected 'hyper' dependency")
	}
	// Not-reachable fixture has client + http1 features, NOT http2/server
	hasHTTP2 := false
	hasServer := false
	for _, f := range dep.Features {
		if f == "http2" {
			hasHTTP2 = true
		}
		if f == "server" {
			hasServer = true
		}
	}
	if hasHTTP2 {
		t.Error("not-reachable fixture should NOT have http2 feature")
	}
	if hasServer {
		t.Error("not-reachable fixture should NOT have server feature")
	}
}

func TestParseCargoToml_OptionalDependency(t *testing.T) {
	dir := t.TempDir()
	cargoToml := `[package]
name = "test-optional"
version = "0.1.0"

[features]
default = ["tls"]
tls = ["dep:native-tls"]

[dependencies]
serde = "1.0"

[dependencies.native-tls]
version = "0.2"
optional = true
`
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(cargoToml), 0o600); err != nil {
		t.Fatal(err)
	}

	meta, err := rust.ParseCargoToml(dir)
	if err != nil {
		t.Fatalf("ParseCargoToml failed: %v", err)
	}

	// serde is non-optional, always enabled
	if !meta.IsDependencyEnabled("serde") {
		t.Error("serde should be enabled (non-optional)")
	}

	// native-tls is optional but activated via default feature "tls" -> "dep:native-tls"
	if !meta.IsDependencyEnabled("native-tls") {
		t.Error("native-tls should be enabled via default features")
	}

	// A non-existent dependency should not be enabled
	if meta.IsDependencyEnabled("nonexistent") {
		t.Error("nonexistent dependency should not be enabled")
	}
}

func TestParseCargoToml_DefaultFeatures(t *testing.T) {
	dir := t.TempDir()
	cargoToml := `[package]
name = "test-features"
version = "0.1.0"

[features]
default = ["json", "logging"]
json = []
logging = []
xml = []
`
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(cargoToml), 0o600); err != nil {
		t.Fatal(err)
	}

	meta, err := rust.ParseCargoToml(dir)
	if err != nil {
		t.Fatalf("ParseCargoToml failed: %v", err)
	}

	if !meta.IsFeatureEnabled("json") {
		t.Error("json should be enabled (default feature)")
	}
	if !meta.IsFeatureEnabled("logging") {
		t.Error("logging should be enabled (default feature)")
	}
	if !meta.IsFeatureEnabled("xml") {
		t.Error("xml should be enabled (explicit feature)")
	}
}

func TestParseCargoToml_MissingFile(t *testing.T) {
	_, err := rust.ParseCargoToml(t.TempDir())
	if err == nil {
		t.Fatal("expected error for missing Cargo.toml")
	}
}
