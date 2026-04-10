// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// unzip extracts an in-memory zip into dst.
func unzip(data []byte, dst string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	dstClean := filepath.Clean(dst) + string(os.PathSeparator)
	for _, f := range zr.File {
		if err := extractZipEntry(f, dst, dstClean); err != nil {
			return err
		}
	}
	return nil
}

func extractZipEntry(f *zip.File, dst, dstClean string) error {
	target := filepath.Join(dst, sanitizeTarPath(f.Name))
	if !strings.HasPrefix(target, dstClean) {
		return nil // path traversal guard
	}
	if f.FileInfo().IsDir() {
		return os.MkdirAll(target, 0o750)
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close() //nolint:errcheck // deferred read-path close, error not actionable
	return writeFile(target, io.LimitReader(rc, maxUnpackedFileSize))
}
