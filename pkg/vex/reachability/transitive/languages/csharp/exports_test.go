// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csharp_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/csharp"
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

func TestListExports_SrcLayout(t *testing.T) {
	root := writePackage(t, "json-net", map[string]string{
		"src/Newtonsoft.Json/JsonConvert.cs": `namespace Newtonsoft.Json
{
    public class JsonConvert
    {
        public static T DeserializeObject<T>(string value) { return default; }
        private static void InternalHelper() {}
    }
}`,
	})
	lang := csharp.New()
	keys, err := lang.ListExports(root, "Newtonsoft.Json")
	if err != nil {
		t.Fatal(err)
	}
	hasClass := false
	hasDeserialize := false
	hasInternal := false
	for _, k := range keys {
		if k == "Newtonsoft.Json.JsonConvert" {
			hasClass = true
		}
		if k == "Newtonsoft.Json.JsonConvert.DeserializeObject" {
			hasDeserialize = true
		}
		if k == "Newtonsoft.Json.JsonConvert.InternalHelper" {
			hasInternal = true
		}
	}
	if !hasClass {
		t.Errorf("missing JsonConvert class in exports: %v", keys)
	}
	if !hasDeserialize {
		t.Errorf("missing DeserializeObject in exports: %v", keys)
	}
	if hasInternal {
		t.Errorf("private InternalHelper should not be exported: %v", keys)
	}
}

func TestListExports_RootLayout(t *testing.T) {
	root := writePackage(t, "mylib", map[string]string{
		"Service.cs": `namespace MyLib
{
    public class Service
    {
        public void Handle() {}
    }
}`,
	})
	lang := csharp.New()
	keys, err := lang.ListExports(root, "MyLib")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Error("expected exported symbols from root layout")
	}
}

func TestListExports_SkipsTestAndBuildDirs(t *testing.T) {
	root := writePackage(t, "tested", map[string]string{
		"src/MyLib/Core.cs": `namespace MyLib
{
    public class Core { public void Run() {} }
}`,
		"test/MyLib.Tests/CoreTest.cs": `namespace MyLib.Tests
{
    public class CoreTest { public void TestRun() {} }
}`,
		"obj/Debug/Generated.cs": `namespace MyLib
{
    public class Generated { public void Auto() {} }
}`,
		"bin/Release/Output.cs": `namespace MyLib
{
    public class Output { public void Run() {} }
}`,
	})
	lang := csharp.New()
	keys, err := lang.ListExports(root, "MyLib")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k == "MyLib.Tests.CoreTest" || k == "MyLib.Tests.CoreTest.TestRun" {
			t.Errorf("test file leaked into exports: %q", k)
		}
		if k == "MyLib.Generated" || k == "MyLib.Output" {
			t.Errorf("build output leaked into exports: %q", k)
		}
	}
}
