// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package php_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/php"
)

func writePackage(t *testing.T, name string, files map[string]string) string {
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

func TestListExports_PSR4(t *testing.T) {
	root := writePackage(t, "guzzlehttp-psr7", map[string]string{
		"composer.json": `{"autoload":{"psr-4":{"GuzzleHttp\\Psr7\\":"src/"}}}`,
		"src/Utils.php": `<?php
namespace GuzzleHttp\Psr7;

class Utils {
    public static function readLine($stream) {
        return fgets($stream);
    }

    private static function internalHelper() {
        return null;
    }
}`,
	})
	lang := php.New()
	keys, err := lang.ListExports(root, "guzzlehttp/psr7")
	if err != nil {
		t.Fatal(err)
	}
	// Should include the class and public method, not private
	hasClass := false
	hasReadLine := false
	hasInternal := false
	for _, k := range keys {
		if k == "guzzlehttp/psr7.Utils.Utils" {
			hasClass = true
		}
		if k == "guzzlehttp/psr7.Utils.readLine" {
			hasReadLine = true
		}
		if k == "guzzlehttp/psr7.Utils.internalHelper" {
			hasInternal = true
		}
	}
	if !hasClass {
		t.Errorf("missing Utils class in exports: %v", keys)
	}
	if !hasReadLine {
		t.Errorf("missing readLine in exports: %v", keys)
	}
	if hasInternal {
		t.Errorf("private internalHelper should not be exported: %v", keys)
	}
}

func TestListExports_Fallback_NoComposerJSON(t *testing.T) {
	root := writePackage(t, "legacy-pkg", map[string]string{
		"src/Helper.php": `<?php
class Helper {
    public function run() {}
}`,
	})
	lang := php.New()
	keys, err := lang.ListExports(root, "vendor/legacy-pkg")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Error("fallback should find symbols from src/")
	}
}

func TestListExports_Fallback_LibDir(t *testing.T) {
	root := writePackage(t, "lib-pkg", map[string]string{
		"lib/Service.php": `<?php
class Service {
    public function handle() {}
}`,
	})
	lang := php.New()
	keys, err := lang.ListExports(root, "vendor/lib-pkg")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Error("fallback should find symbols from lib/")
	}
}

func TestListExports_SkipsTestFiles(t *testing.T) {
	root := writePackage(t, "tested-pkg", map[string]string{
		"composer.json": `{"autoload":{"psr-4":{"App\\":"src/"}}}`,
		"src/Core.php": `<?php
namespace App;
class Core { public function run() {} }`,
		"tests/CoreTest.php": `<?php
class CoreTest { public function testRun() {} }`,
	})
	lang := php.New()
	keys, err := lang.ListExports(root, "vendor/tested-pkg")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k == "vendor/tested-pkg.CoreTest.CoreTest" || k == "vendor/tested-pkg.CoreTest.testRun" {
			t.Errorf("test file leaked into exports: %q", k)
		}
	}
}
