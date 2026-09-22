//go:build !linux

package workspace

import "errors"

func trustedOutputDirectory(string) error {
	return errors.New("workspace capture is supported on Linux only")
}
