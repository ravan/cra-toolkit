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
		"src/lib.rs": `pub mod helpers;`,
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

func TestListExports_StructsEnumsTraits(t *testing.T) {
	root := writeCrate(t, "kinds", "0.1.0", map[string]string{
		"src/lib.rs": `pub struct Request;
struct PrivateReq;
pub enum Status { Ok, Err }
enum PrivateStatus { A }
pub trait Handler { fn handle(&self); }
trait PrivateTrait { fn x(&self); }
`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "kinds")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"kinds.Request": true,
		"kinds.Status":  true,
		"kinds.Handler": true,
		// Trait required-method: emitted as kinds.Handler.handle because
		// the trait itself is public, so downstream callers can reach it.
		"kinds.Handler.handle": true,
	}
	assertKeys(t, got, want)
}

func TestListExports_InherentImplMethods(t *testing.T) {
	root := writeCrate(t, "inh", "0.1.0", map[string]string{
		"src/lib.rs": `pub struct Server;

impl Server {
    pub fn serve(&self) {}
    fn internal(&self) {}
}

struct PrivateServer;
impl PrivateServer {
    pub fn unreachable(&self) {}
}
`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "inh")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"inh.Server":       true,
		"inh.Server.serve": true,
	}
	assertKeys(t, got, want)
}

func TestListExports_TraitImplMethodsOnPublicType(t *testing.T) {
	root := writeCrate(t, "trimpl", "0.1.0", map[string]string{
		"src/lib.rs": `pub struct Reader;
pub trait Read { fn read(&self); }
impl Read for Reader {
    fn read(&self) {}
}
`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "trimpl")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"trimpl.Reader":      true,
		"trimpl.Read":        true,
		"trimpl.Read.read":   true,
		"trimpl.Reader.read": true,
	}
	assertKeys(t, got, want)
}

func TestListExports_TraitImplOnPrivateTypeExcluded(t *testing.T) {
	root := writeCrate(t, "hidden", "0.1.0", map[string]string{
		"src/lib.rs": `pub trait Run { fn run(&self); }
struct Private;
impl Run for Private {
    fn run(&self) {}
}
`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "hidden")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"hidden.Run":     true,
		"hidden.Run.run": true,
	}
	assertKeys(t, got, want)
}

func TestListExports_SimpleReExport(t *testing.T) {
	root := writeCrate(t, "reexp", "0.1.0", map[string]string{
		"src/lib.rs":   `pub mod inner; pub use inner::Thing;`,
		"src/inner.rs": `pub struct Thing;`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "reexp")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"reexp.inner.Thing": true,
		"reexp.Thing":       true,
	}
	assertKeys(t, got, want)
}

func TestListExports_GroupedReExport(t *testing.T) {
	root := writeCrate(t, "reexp", "0.1.0", map[string]string{
		"src/lib.rs":   `pub mod inner; pub use inner::{Foo, Bar};`,
		"src/inner.rs": `pub struct Foo; pub struct Bar;`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "reexp")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"reexp.inner.Foo": true,
		"reexp.inner.Bar": true,
		"reexp.Foo":       true,
		"reexp.Bar":       true,
	}
	assertKeys(t, got, want)
}

func TestListExports_AliasedReExport(t *testing.T) {
	root := writeCrate(t, "reexp", "0.1.0", map[string]string{
		"src/lib.rs":   `pub mod inner; pub use inner::Thing as Renamed;`,
		"src/inner.rs": `pub struct Thing;`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "reexp")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"reexp.inner.Thing": true,
		"reexp.Renamed":     true,
	}
	assertKeys(t, got, want)
}

func TestListExports_WildcardReExport(t *testing.T) {
	root := writeCrate(t, "reexp", "0.1.0", map[string]string{
		"src/lib.rs":   `pub mod inner; pub use inner::*;`,
		"src/inner.rs": `pub struct Foo; pub struct Bar; pub fn run() {}`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "reexp")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"reexp.inner.Foo": true,
		"reexp.inner.Bar": true,
		"reexp.inner.run": true,
		"reexp.Foo":       true,
		"reexp.Bar":       true,
		"reexp.run":       true,
	}
	assertKeys(t, got, want)
}

func TestListExports_ChainedReExport(t *testing.T) {
	root := writeCrate(t, "chain", "0.1.0", map[string]string{
		"src/lib.rs": `pub mod a; pub mod b; pub use b::Thing;`,
		"src/a.rs":   `pub struct Thing;`,
		"src/b.rs":   `pub use crate::a::Thing;`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "chain")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	want := map[string]bool{
		"chain.a.Thing": true,
		"chain.b.Thing": true,
		"chain.Thing":   true,
	}
	assertKeys(t, got, want)
}

func TestListExports_ForeignReExportExcluded(t *testing.T) {
	root := writeCrate(t, "norelay", "0.1.0", map[string]string{
		"src/lib.rs": `pub use serde::Serialize; pub fn go() {}`,
	})
	lang := rust.New()
	got, err := lang.ListExports(root, "norelay")
	if err != nil {
		t.Fatalf("ListExports: %v", err)
	}
	gotSet := make(map[string]bool, len(got))
	for _, k := range got {
		gotSet[k] = true
	}
	if gotSet["norelay.Serialize"] {
		t.Error("foreign re-export leaked as norelay.Serialize")
	}
	if !gotSet["norelay.go"] {
		t.Error("missing norelay.go")
	}
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
