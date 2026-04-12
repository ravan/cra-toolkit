// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package ruby_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/ruby"
)

func writeGem(t *testing.T, name string, files map[string]string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), name)
	for path, content := range files {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func assertKeys(t *testing.T, got []string, want ...string) {
	t.Helper()
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Errorf("got %d keys %v, want %d keys %v", len(got), got, len(want), want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("key[%d]: got %q, want %q\nfull got: %v", i, got[i], want[i], got)
			return
		}
	}
}

func TestListExports_SimpleGem(t *testing.T) {
	root := writeGem(t, "mygem", map[string]string{
		"lib/mygem.rb": `class MyGem
  def hello
    "hi"
  end
end`,
	})
	lang := ruby.New()
	keys, err := lang.ListExports(root, "mygem")
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, keys,
		"mygem.mygem.MyGem",
		"mygem.mygem.MyGem.hello",
	)
}

func TestListExports_NestedRequires(t *testing.T) {
	root := writeGem(t, "mygem", map[string]string{
		"lib/mygem.rb": `require_relative "mygem/parser"

class MyGem
end`,
		"lib/mygem/parser.rb": `class MyGem::Parser
  def parse(input)
    input.strip
  end
end`,
	})
	lang := ruby.New()
	keys, err := lang.ListExports(root, "mygem")
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, keys,
		"mygem.mygem.MyGem",
		"mygem.mygem.parser.MyGem::Parser",
		"mygem.mygem.parser.MyGem::Parser.parse",
	)
}

func TestListExports_PrivateMethodsExcluded(t *testing.T) {
	root := writeGem(t, "mygem", map[string]string{
		"lib/mygem.rb": `class MyGem
  def public_api
    "ok"
  end

  private

  def internal_helper
    "secret"
  end
end`,
	})
	lang := ruby.New()
	keys, err := lang.ListExports(root, "mygem")
	if err != nil {
		t.Fatal(err)
	}
	// Should include public_api but not internal_helper
	found := false
	for _, k := range keys {
		if k == "mygem.mygem.MyGem.internal_helper" {
			t.Error("private method should not be exported")
		}
		if k == "mygem.mygem.MyGem.public_api" {
			found = true
		}
	}
	if !found {
		t.Errorf("missing public_api in exports: %v", keys)
	}
}

func TestListExports_AttrAccessors(t *testing.T) {
	root := writeGem(t, "mygem", map[string]string{
		"lib/mygem.rb": `class Config
  attr_accessor :host
  attr_reader :port
end`,
	})
	lang := ruby.New()
	keys, err := lang.ListExports(root, "mygem")
	if err != nil {
		t.Fatal(err)
	}
	assertKeys(t, keys,
		"mygem.mygem.Config",
		"mygem.mygem.Config.host",
		"mygem.mygem.Config.host=",
		"mygem.mygem.Config.port",
	)
}

func TestListExports_ExternalRequireSkipped(t *testing.T) {
	root := writeGem(t, "mygem", map[string]string{
		"lib/mygem.rb": `require "json"
require_relative "mygem/core"

class MyGem
end`,
		"lib/mygem/core.rb": `class MyGem::Core
  def run
    "running"
  end
end`,
	})
	lang := ruby.New()
	keys, err := lang.ListExports(root, "mygem")
	if err != nil {
		t.Fatal(err)
	}
	// json should not contribute any symbols
	for _, k := range keys {
		if k != "" && k[0] == 'j' {
			t.Errorf("external require 'json' leaked into exports: %q", k)
		}
	}
}

func TestListExports_CircularRequire(t *testing.T) {
	root := writeGem(t, "mygem", map[string]string{
		"lib/mygem.rb": `require_relative "mygem/a"`,
		"lib/mygem/a.rb": `require_relative "b"
class A; def x; end; end`,
		"lib/mygem/b.rb": `require_relative "a"
class B; def y; end; end`,
	})
	lang := ruby.New()
	keys, err := lang.ListExports(root, "mygem")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Error("circular require should not crash — expected some exports")
	}
}

func TestListExports_NoEntryFile(t *testing.T) {
	root := writeGem(t, "oddgem", map[string]string{
		"lib/something.rb": `class Something; def x; end; end`,
	})
	lang := ruby.New()
	keys, err := lang.ListExports(root, "oddgem")
	if err != nil {
		t.Fatal(err)
	}
	// Fallback: should still find symbols from lib/
	if len(keys) == 0 {
		t.Error("expected fallback to find symbols in lib/")
	}
}

func TestListExports_HyphenatedGemName(t *testing.T) {
	root := writeGem(t, "my-gem", map[string]string{
		"lib/my/gem.rb": `class MyGem; def x; end; end`,
	})
	lang := ruby.New()
	keys, err := lang.ListExports(root, "my-gem")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Error("hyphenated gem name should find entry file via lib/my/gem.rb")
	}
}
