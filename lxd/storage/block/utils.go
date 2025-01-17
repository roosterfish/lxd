package block

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/canonical/lxd/shared"
)

// DiskSizeBytes returns the size of a block disk (path can be either block device or raw file).
func DiskSizeBytes(blockDiskPath string) (int64, error) {
	if shared.IsBlockdevPath(blockDiskPath) {
		// Attempt to open the device path.
		f, err := os.Open(blockDiskPath)
		if err != nil {
			return -1, err
		}

		defer func() { _ = f.Close() }()
		fd := int(f.Fd())

		// Retrieve the block device size.
		res, err := unix.IoctlGetInt(fd, unix.BLKGETSIZE64)
		if err != nil {
			return -1, err
		}

		return int64(res), nil
	}

	// Block device is assumed to be a raw file.
	fi, err := os.Lstat(blockDiskPath)
	if err != nil {
		return -1, err
	}

	return fi.Size(), nil
}

// DiskBlockSize returns the physical block size of a block device.
func DiskBlockSize(path string) (uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}

	defer func() { _ = f.Close() }()
	fd := int(f.Fd())

	// Retrieve the physical block size.
	res, err := unix.IoctlGetUint32(fd, unix.BLKPBSZGET)
	if err != nil {
		return 0, err
	}

	return res, nil
}

// WaitDiskSizeBytes waits until the block disk is resized to the expected size in bytes.
func WaitDiskSizeBytes(ctx context.Context, blockDiskPath string, newSizeBytes int64) error {
	// Set upper boundary for the timeout to ensure this function does not run
	// indefinitely. The caller can set a shorter timeout if necessary.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for {
		sizeBytes, err := DiskSizeBytes(blockDiskPath)
		if err != nil {
			return fmt.Errorf("Error getting disk size: %w", err)
		}

		if sizeBytes == newSizeBytes {
			return nil
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		time.Sleep(500 * time.Millisecond)
	}
}
