// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCache_PutAndGet(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	digest := "sha256:abc123"
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := c.Put(digest, src)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got == "" {
		t.Fatal("Put returned empty path")
	}
	data, err := os.ReadFile(filepath.Join(got, "hello.txt"))
	if err != nil {
		t.Fatalf("file not present in cache: %v", err)
	}
	if string(data) != "hi" {
		t.Errorf("expected 'hi', got %q", data)
	}

	got2, ok := c.Get(digest)
	if !ok {
		t.Fatal("Get: miss after Put")
	}
	if got2 != got {
		t.Errorf("Get returned different path: %q vs %q", got, got2)
	}
}

func TestCache_SingleFlight(t *testing.T) {
	dir := t.TempDir()
	c := NewCache(dir)
	var calls atomic.Int32
	var wg sync.WaitGroup
	digest := "sha256:deadbeef"
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Do(digest, func() (string, error) {
				calls.Add(1)
				src := t.TempDir()
				_ = os.WriteFile(filepath.Join(src, "data"), []byte("x"), 0o644)
				return c.Put(digest, src)
			})
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Errorf("expected exactly one work invocation, got %d", got)
	}
}
