//go:build !linux

package workspace

import "errors"

func materialize(snapshot, string) error {
	return errors.New("workspace materialization is supported on Linux only")
}
