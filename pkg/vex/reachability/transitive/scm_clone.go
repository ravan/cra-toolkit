// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SCMCloneResult describes the outcome of a source clone.
type SCMCloneResult struct {
	SourceDir string
	Digest    Digest
}

// scmClone clones a Git repository at the given version into a cache
// directory. It tries multiple tag formats (v1.2.3, 1.2.3, release-1.2.3,
// release/1.2.3), falling back to the default branch if none match.
// Only https:// and http:// schemes are accepted.
//
//nolint:gocyclo,gocognit // tag-matching loop with fallback
func scmClone(ctx context.Context, repoURL, version string, cache *Cache) (SCMCloneResult, error) {
	normalized, err := normalizeRepoURL(repoURL)
	if err != nil {
		return SCMCloneResult{}, err
	}

	cacheKey := "scm:" + normalized + "@" + version
	cacheDigest := Digest{Algorithm: "sha256", Hex: hashHex([]byte(cacheKey))}
	if cache != nil {
		if p, ok := cache.Get(cacheDigest.String()); ok {
			return SCMCloneResult{SourceDir: p, Digest: cacheDigest}, nil
		}
	}

	tmp, err := os.MkdirTemp("", "scm-clone-*")
	if err != nil {
		return SCMCloneResult{}, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	cloned := false
	for _, tag := range versionTags(version) {
		//nolint:gosec // repoURL validated by normalizeRepoURL; tag derived from version string
		cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--branch", tag, normalized, tmp+"/repo")
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		if err := cmd.Run(); err == nil {
			cloned = true
			break
		}
		_ = os.RemoveAll(tmp + "/repo")
	}
	if !cloned {
		// Fallback: clone default branch.
		//nolint:gosec // repoURL validated by normalizeRepoURL
		cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", normalized, tmp+"/repo")
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		if err := cmd.Run(); err != nil {
			return SCMCloneResult{}, fmt.Errorf("%s: git clone %s: %w", ReasonSCMCloneFailed, normalized, err)
		}
	}

	// Remove .git to save cache space.
	_ = os.RemoveAll(filepath.Join(tmp, "repo", ".git"))

	srcDir := filepath.Join(tmp, "repo")
	digest := Digest{Algorithm: "sha256", Hex: hashDir(srcDir)}

	if cache != nil {
		p, putErr := cache.Put(cacheDigest.String(), srcDir)
		if putErr != nil {
			return SCMCloneResult{}, putErr
		}
		return SCMCloneResult{SourceDir: p, Digest: digest}, nil
	}

	// Without cache, move to a stable temp dir the caller can use.
	stable, err := os.MkdirTemp("", "scm-result-*")
	if err != nil {
		return SCMCloneResult{}, err
	}
	if err := os.Rename(srcDir, filepath.Join(stable, "repo")); err != nil {
		_ = os.RemoveAll(stable)
		return SCMCloneResult{}, err
	}
	return SCMCloneResult{SourceDir: filepath.Join(stable, "repo"), Digest: digest}, nil
}

// normalizeRepoURL validates and normalizes a repository URL.
// Only https:// and http:// schemes are accepted. git:// is converted
// to https://. SSH URLs (git@) are rejected. The .git suffix is stripped.
func normalizeRepoURL(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("empty repository URL")
	}
	if strings.HasPrefix(raw, "git@") {
		return "", fmt.Errorf("SSH repository URLs are not supported: %s", raw)
	}
	if strings.HasPrefix(raw, "git://") {
		raw = "https://" + strings.TrimPrefix(raw, "git://")
	}
	if !strings.HasPrefix(raw, "https://") && !strings.HasPrefix(raw, "http://") {
		return "", fmt.Errorf("unsupported URL scheme: %s", raw)
	}
	raw = strings.TrimSuffix(raw, ".git")
	return raw, nil
}

// versionTags returns candidate Git tags for a semantic version string.
func versionTags(version string) []string {
	return []string{
		"v" + version,
		version,
		"release-" + version,
		"release/" + version,
	}
}

// hashDir computes a SHA-256 hash of a directory's file contents
// (names + content, lexicographically ordered).
func hashDir(dir string) string {
	h := sha256.New()
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		_, _ = h.Write([]byte(rel))
		data, err := os.ReadFile(path) //nolint:gosec // path from controlled walk
		if err == nil {
			_, _ = h.Write(data)
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))
}
