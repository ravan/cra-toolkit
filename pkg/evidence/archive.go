package evidence

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// CreateArchive produces a .tar.gz of the output directory.
func CreateArchive(sourceDir, archivePath string) error {
	outFile, err := os.Create(archivePath) //nolint:gosec // output file
	if err != nil {
		return fmt.Errorf("create archive: %w", err)
	}
	defer outFile.Close() //nolint:errcheck // will check write err

	gw := gzip.NewWriter(outFile)
	defer gw.Close() //nolint:errcheck // will check write err

	tw := tar.NewWriter(gw)
	defer tw.Close() //nolint:errcheck // will check write err

	if err := walkIntoTar(sourceDir, tw); err != nil {
		return err
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar: %w", err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("close gzip: %w", err)
	}
	return outFile.Close()
}

// walkIntoTar walks sourceDir and writes each file into tw.
func walkIntoTar(sourceDir string, tw *tar.Writer) error {
	baseName := filepath.Base(sourceDir)

	err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return writeTarEntry(tw, sourceDir, baseName, path, info)
	})
	if err != nil {
		return fmt.Errorf("archive walk: %w", err)
	}
	return nil
}

// writeTarEntry writes a single file or directory entry into tw.
func writeTarEntry(tw *tar.Writer, sourceDir, baseName, path string, info os.FileInfo) error {
	rel, err := filepath.Rel(sourceDir, path)
	if err != nil {
		return err
	}

	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = filepath.Join(baseName, rel)

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	if info.IsDir() {
		return nil
	}

	f, err := os.Open(path) //nolint:gosec // internal path
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // read-only

	_, err = io.Copy(tw, f)
	return err
}
