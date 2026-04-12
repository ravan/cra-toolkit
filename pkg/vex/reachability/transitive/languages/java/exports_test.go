// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package java_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/java"
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

func TestListExports_MavenLayout(t *testing.T) {
	root := writePackage(t, "gson", map[string]string{
		"src/main/java/com/google/gson/Gson.java": `package com.google.gson;

public class Gson {
    public <T> T fromJson(String json, Class<T> classOfT) {
        return null;
    }

    private void internalHelper() {}
}`,
	})
	lang := java.New()
	keys, err := lang.ListExports(root, "com.google.code.gson:gson")
	if err != nil {
		t.Fatal(err)
	}
	hasClass := false
	hasFromJson := false
	hasInternal := false
	for _, k := range keys {
		if k == "com.google.gson.Gson" {
			hasClass = true
		}
		if k == "com.google.gson.Gson.fromJson" {
			hasFromJson = true
		}
		if k == "com.google.gson.Gson.internalHelper" {
			hasInternal = true
		}
	}
	if !hasClass {
		t.Errorf("missing Gson class in exports: %v", keys)
	}
	if !hasFromJson {
		t.Errorf("missing fromJson in exports: %v", keys)
	}
	if hasInternal {
		t.Errorf("private internalHelper should not be exported: %v", keys)
	}
}

func TestListExports_FlatLayout(t *testing.T) {
	root := writePackage(t, "lib", map[string]string{
		"com/example/Service.java": `package com.example;

public class Service {
    public void handle() {}
}`,
	})
	lang := java.New()
	keys, err := lang.ListExports(root, "com.example:lib")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Error("expected exported symbols from flat layout")
	}
}

func TestListExports_SkipsTestDir(t *testing.T) {
	root := writePackage(t, "tested", map[string]string{
		"src/main/java/com/example/Core.java": `package com.example;

public class Core {
    public void run() {}
}`,
		"src/test/java/com/example/CoreTest.java": `package com.example;

public class CoreTest {
    public void testRun() {}
}`,
	})
	lang := java.New()
	keys, err := lang.ListExports(root, "com.example:tested")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k == "com.example.CoreTest" || k == "com.example.CoreTest.testRun" {
			t.Errorf("test file leaked into exports: %q", k)
		}
	}
}
