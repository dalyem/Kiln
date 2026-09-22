//go:build !linux

package workspace

import (
	"errors"
	"os"
)

func readRegular(string, string, os.FileInfo) ([]byte, error) {
	return nil, errors.New("workspace capture is supported on Linux only")
}

func readSymlink(string, string, os.FileInfo) (string, error) {
	return "", errors.New("workspace capture is supported on Linux only")
}

func openSnapshotFile(path string) (*os.File, error) { return os.Open(path) }
