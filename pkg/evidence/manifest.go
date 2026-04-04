package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ComputeManifest walks a directory and computes SHA-256 hashes for all files.
func ComputeManifest(dir string) (Manifest, error) {
	entries := make(map[string]string)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("relative path: %w", err)
		}

		hash, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("hash %s: %w", rel, err)
		}

		entries[rel] = hash
		return nil
	})
	if err != nil {
		return Manifest{}, fmt.Errorf("walk directory: %w", err)
	}

	return Manifest{
		Algorithm: "sha256",
		Entries:   entries,
	}, nil
}

// WriteManifest writes the manifest in sha256sum format (hash  filename).
func WriteManifest(m Manifest, path string) error {
	keys := make([]string, 0, len(m.Entries))
	for k := range m.Entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		b.WriteString(fmt.Sprintf("%s  %s\n", m.Entries[k], k))
	}

	return os.WriteFile(path, []byte(b.String()), 0o644) //nolint:gosec // output file
}

// hashFile computes the SHA-256 of a single file.
func hashFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // internal path
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck // read-only

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
