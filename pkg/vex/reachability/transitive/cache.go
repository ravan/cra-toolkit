// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Cache is a content-addressed directory cache keyed by digest strings.
// Entries are laid out as <root>/<hex>/, with the "sha256:" prefix stripped
// and replaced by the raw hex when computing the directory name.
type Cache struct {
	root   string
	mu     sync.Mutex
	inProg map[string]*flight
}

type flight struct {
	done chan struct{}
	path string
	err  error
}

// NewCache returns a Cache rooted at dir. The directory is created on demand.
func NewCache(dir string) *Cache {
	return &Cache{
		root:   dir,
		inProg: make(map[string]*flight),
	}
}

// Get returns the cache path for digest and true if the entry exists.
func (c *Cache) Get(digest string) (string, bool) {
	p := c.pathFor(digest)
	if _, err := os.Stat(p); err == nil {
		return p, true
	}
	return "", false
}

// Put copies the contents of srcDir into the cache under digest. If the
// destination already exists, Put returns the existing path without copying.
func (c *Cache) Put(digest, srcDir string) (string, error) {
	dst := c.pathFor(digest)
	if _, err := os.Stat(dst); err == nil {
		return dst, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return "", fmt.Errorf("mkdir cache parent: %w", err)
	}
	tmp, err := os.MkdirTemp(filepath.Dir(dst), ".tmp-*")
	if err != nil {
		return "", fmt.Errorf("mkdir tmp: %w", err)
	}
	if err := copyTree(srcDir, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return "", err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.RemoveAll(tmp)
		return "", fmt.Errorf("rename cache: %w", err)
	}
	return dst, nil
}

// Do runs fn exactly once per digest across concurrent callers. Subsequent
// callers for the same digest block until the first invocation returns, then
// receive the same result. This prevents duplicate fetches when many findings
// need the same package.
func (c *Cache) Do(digest string, fn func() (string, error)) (string, error) {
	c.mu.Lock()
	if f, ok := c.inProg[digest]; ok {
		c.mu.Unlock()
		<-f.done
		return f.path, f.err
	}
	f := &flight{done: make(chan struct{})}
	c.inProg[digest] = f
	c.mu.Unlock()

	f.path, f.err = fn()

	c.mu.Lock()
	delete(c.inProg, digest)
	c.mu.Unlock()
	close(f.done)
	return f.path, f.err
}

// pathFor maps a digest string to its on-disk directory path.
func (c *Cache) pathFor(digest string) string {
	id := strings.TrimPrefix(digest, "sha256:")
	if id == "" {
		// Fall back to hashing the input so we never produce a collision at the root.
		h := sha256.Sum256([]byte(digest))
		id = hex.EncodeToString(h[:])
	}
	return filepath.Join(c.root, id[:2], id)
}

// copyTree recursively copies src into dst. dst must not exist.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // src is a validated path from filepath.WalkDir within a temp dir
	if err != nil {
		return err
	}
	defer in.Close() //nolint:errcheck // deferred read-path close, error not actionable
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	out, err := os.Create(dst) //nolint:gosec // dst is a validated target path within the cache dir
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close() //nolint:errcheck,gosec // error path, original error returned
		return err
	}
	return out.Close()
}
