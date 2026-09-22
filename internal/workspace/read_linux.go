//go:build linux

package workspace

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func readRegular(root, path string, observed os.FileInfo) ([]byte, error) {
	if observed.Size() > maxBlobSize {
		return nil, fmt.Errorf("file exceeds %d bytes", maxBlobSize)
	}
	directory, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(directory) }()
	parts := strings.Split(path, "/")
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(directory, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, errors.New("symlink or missing parent while reading")
		}
		oldDirectory := directory
		directory = next
		_ = unix.Close(oldDirectory)
	}
	fileDescriptor, err := unix.Openat(directory, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fileDescriptor), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	before, ok := info.Sys().(*syscall.Stat_t)
	seen, seenOK := observed.Sys().(*syscall.Stat_t)
	if !ok || !seenOK || !info.Mode().IsRegular() || info.Mode() != observed.Mode() || info.Size() != observed.Size() || before.Dev != seen.Dev || before.Ino != seen.Ino || before.Ctim.Sec != seen.Ctim.Sec || before.Ctim.Nsec != seen.Ctim.Nsec || before.Mtim.Sec != seen.Mtim.Sec || before.Mtim.Nsec != seen.Mtim.Nsec {
		return nil, errors.New("file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBlobSize+1))
	if err != nil || len(data) > maxBlobSize {
		return nil, errors.New("file changed or exceeded limit while reading")
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Mode != before.Mode || after.Size != before.Size || after.Ctim.Sec != before.Ctim.Sec || after.Ctim.Nsec != before.Ctim.Nsec || after.Mtim.Sec != before.Mtim.Sec || after.Mtim.Nsec != before.Mtim.Nsec {
		return nil, errors.New("file changed while reading")
	}
	return data, nil
}

func readSymlink(root, path string, observed os.FileInfo) (string, error) {
	directory, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(directory) }()
	parts := strings.Split(path, "/")
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(directory, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return "", errors.New("symlink or missing parent while reading")
		}
		oldDirectory := directory
		directory = next
		_ = unix.Close(oldDirectory)
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(directory, parts[len(parts)-1], &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return "", err
	}
	seen, ok := observed.Sys().(*syscall.Stat_t)
	if !ok || stat.Mode&unix.S_IFMT != unix.S_IFLNK || stat.Dev != seen.Dev || stat.Ino != seen.Ino || stat.Ctim.Sec != seen.Ctim.Sec || stat.Ctim.Nsec != seen.Ctim.Nsec {
		return "", errors.New("symlink changed while reading")
	}
	buffer := make([]byte, maxPathSize+1)
	count, err := unix.Readlinkat(directory, parts[len(parts)-1], buffer)
	if err != nil || count > maxPathSize {
		return "", errors.New("symlink changed or exceeds limit while reading")
	}
	return string(buffer[:count]), nil
}

func openSnapshotFile(path string) (*os.File, error) {
	fileDescriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fileDescriptor), path), nil
}
