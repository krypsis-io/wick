//go:build !unix && !windows

package cmd

import (
	"errors"
	"os"
)

func lockFile(*os.File) error {
	return errors.New("file locks are not supported on this platform")
}
