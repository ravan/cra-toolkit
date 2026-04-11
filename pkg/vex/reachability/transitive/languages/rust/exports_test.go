// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/rust"
)

// writeCrate writes a map of relative-path → file-content entries under
// tmp/<name>-<version>/ and returns the crate root path (the parent of the
// `<name>-<version>/` directory), matching the layout the CratesFetcher
// produces after unpacking a .crate tarball.
func writeCrate(t *testing.T, name, version string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	crateDir := filepath.Join(root, name+"-"+version)
	for rel, content := range files {
		full := filepath.Join(crateDir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return root
}

func TestListExports_NoLibraryAPI(t *testing.T) {
	root := writeCrate(t, "cli", "1.0.0", map[string]string{
		"src/main.rs": `fn main() { println!("hello"); }`,
	})
	lang := rust.New()
	_, err := lang.ListExports(root, "cli")
	if !errors.Is(err, rust.ErrNoLibraryAPI) {
		t.Errorf("ListExports returned %v, want ErrNoLibraryAPI", err)
	}
}

func TestListExports_SimpleLibrary(t *testing.T) {
	root := writeCrate(t, "mini", "0.1.0", map[string]string{
		"src/lib.rs": `pub fn greet() {}
fn private_helper() {}
`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "mini")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{"mini.greet": true}
	assertKeys(t, got, want)
}

func TestListExports_FileBackedSubmodule(t *testing.T) {
	root := writeCrate(t, "util", "0.2.0", map[string]string{
		"src/lib.rs":     `pub mod helpers;`,
		"src/helpers.rs": `pub fn run() {}
fn hidden() {}
`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "util")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{"util.helpers.run": true}
	assertKeys(t, got, want)
}

func TestListExports_SubmoduleAsModRs(t *testing.T) {
	root := writeCrate(t, "util", "0.2.0", map[string]string{
		"src/lib.rs":         `pub mod helpers;`,
		"src/helpers/mod.rs": `pub fn run() {}`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "util")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{"util.helpers.run": true}
	assertKeys(t, got, want)
}

func TestListExports_PrivateModuleExcluded(t *testing.T) {
	root := writeCrate(t, "app", "0.1.0", map[string]string{
		"src/lib.rs":      `mod internal; pub mod public;`,
		"src/internal.rs": `pub fn should_not_leak() {}`,
		"src/public.rs":   `pub fn visible() {}`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "app")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{"app.public.visible": true}
	assertKeys(t, got, want)
}

func TestListExports_NestedSubmodules(t *testing.T) {
	root := writeCrate(t, "nested", "0.1.0", map[string]string{
		"src/lib.rs": `pub mod a;`,
		"src/a.rs":   `pub mod b;`,
		"src/a/b.rs": `pub fn deep() {}`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "nested")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{"nested.a.b.deep": true}
	assertKeys(t, got, want)
}

// assertKeys compares the returned export key slice against the expected set
// (order-insensitive) and reports missing and unexpected keys.
func assertKeys(t *testing.T, got []string, want map[string]bool) {
	t.Helper()
	gotSet := make(map[string]bool, len(got))
	for _, k := range got {
		gotSet[k] = true
	}
	for w := range want {
		if !gotSet[w] {
			t.Errorf("missing key %q", w)
		}
	}
	for g := range gotSet {
		if !want[g] {
			t.Errorf("unexpected key %q", g)
		}
	}
}
