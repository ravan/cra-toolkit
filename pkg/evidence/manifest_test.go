package evidence_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/evidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeManifest(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file1.txt"), []byte("hello"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file2.txt"), []byte("world"), 0o600))

	manifest, err := evidence.ComputeManifest(dir)
	require.NoError(t, err)
	assert.Equal(t, "sha256", manifest.Algorithm)
	assert.Len(t, manifest.Entries, 2)
	assert.Contains(t, manifest.Entries, "file1.txt")
	assert.Contains(t, manifest.Entries, "file2.txt")
	// SHA-256 of "hello"
	assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", manifest.Entries["file1.txt"])
}

func TestComputeManifest_Subdirectories(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "nested.txt"), []byte("nested"), 0o600))

	manifest, err := evidence.ComputeManifest(dir)
	require.NoError(t, err)
	assert.Contains(t, manifest.Entries, filepath.Join("sub", "nested.txt"))
}

func TestWriteManifest(t *testing.T) {
	dir := t.TempDir()
	manifest := evidence.Manifest{
		Algorithm: "sha256",
		Entries: map[string]string{
			"file1.txt": "abc123",
			"file2.txt": "def456",
		},
	}

	path := filepath.Join(dir, "manifest.sha256")
	err := evidence.WriteManifest(manifest, path)
	require.NoError(t, err)

	data, err := os.ReadFile(path) //nolint:gosec // test temp file
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "abc123  file1.txt")
	assert.Contains(t, content, "def456  file2.txt")
}
