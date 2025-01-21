package connectors

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/canonical/lxd/lxd/locking"
	"github.com/canonical/lxd/lxd/resources"
	"github.com/canonical/lxd/shared"
	"github.com/canonical/lxd/shared/logger"
	"github.com/canonical/lxd/shared/revert"
)

// devicePathFilterFunc is a function that accepts device path and returns true
// if the path matches the required criteria.
type devicePathFilterFunc func(devPath string) bool

// GetDiskDevicePath checks whether the disk device with a given prefix and suffix
// exists in /dev/disk/by-id directory. A device path is returned if the device is
// found, otherwise an error is returned.
func GetDiskDevicePath(diskNamePrefix string, diskPathFilter devicePathFilterFunc) (string, error) {
	devPath, err := findDiskDevicePath(diskNamePrefix, diskPathFilter)
	if err != nil {
		return "", err
	}

	if devPath == "" {
		return "", fmt.Errorf("Device not found")
	}

	return devPath, nil
}

// WaitDiskDevicePath waits for the disk device to appear in /dev/disk/by-id.
// It periodically checks for the device to appear and returns the device path
// once it is found. If the device does not appear within the timeout, an error
// is returned.
func WaitDiskDevicePath(ctx context.Context, diskNamePrefix string, diskPathFilter devicePathFilterFunc) (string, error) {
	var err error
	var diskPath string

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for {
		// Check if the device is already present.
		diskPath, err = findDiskDevicePath(diskNamePrefix, diskPathFilter)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return "", err
		}

		// If the device is found, return the device path.
		if diskPath != "" {
			break
		}

		// Check if context is cancelled.
		if ctx.Err() != nil {
			return "", ctx.Err()
		}

		time.Sleep(500 * time.Millisecond)
	}

	return diskPath, nil
}

// findDiskDevivePath iterates over device names in /dev/disk/by-id directory and
// returns the path to the disk device that matches the given prefix and suffix.
// Disk partitions are skipped, and an error is returned if the device is not found.
func findDiskDevicePath(diskNamePrefix string, diskPathFilter devicePathFilterFunc) (string, error) {
	var diskPaths []string

	// If there are no other disks on the system by id, the directory might not
	// even be there. Returns ENOENT in case the by-id/ directory does not exist.
	diskPaths, err := resources.GetDisksByID(diskNamePrefix)
	if err != nil {
		return "", err
	}

	for _, diskPath := range diskPaths {
		// Skip the disk if it is only a partition of the actual volume.
		if strings.Contains(diskPath, "-part") {
			continue
		}

		// Use custom disk path filter, if one is provided.
		if diskPathFilter != nil && !diskPathFilter(diskPath) {
			continue
		}

		// The actual device might not already be created.
		// Returns ENOENT in case the device does not exist.
		devPath, err := filepath.EvalSymlinks(diskPath)
		if err != nil {
			return "", err
		}

		return devPath, nil
	}

	return "", nil
}

// WaitDiskDeviceGone waits for the disk device to disappear from /dev/disk/by-id.
// It periodically checks for the device to disappear and returns once the device
// is gone. If the device does not disappear within the timeout, an error is returned.
func WaitDiskDeviceGone(ctx context.Context, diskPath string) bool {
	// Set upper boundary for the timeout to ensure this function does not run
	// indefinitely. The caller can set a shorter timeout if necessary.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for {
		if !shared.PathExists(diskPath) {
			return true
		}

		if ctx.Err() != nil {
			return false
		}

		time.Sleep(500 * time.Millisecond)
	}
}

type connectFunc func(ctx context.Context, s *session, addr string) error

// connect attempts to establish connections to all provided addresses,
// succeeding if at least one connection is successful.
//
// It first checks for an existing session associated with the targetQN. If no
// session is found, "connectFunc" attempts to establish connections to all
// addresses. If a session exists, "connectFunc" is responsible for handling it
// appropriately; either by skipping connections to already connected addresses
// or by performing any necessary actions for established connections (such as
// running rescan to detect new volumes in case of iSCSI).
//
// Once a single connection is successfully established, the function returns
// immediately, while other connection attempts continue in the background. In
// case of an error, the function reverts any changes or returns a reverter to
// handle cleanup of established connections. Connections are reverted only if
// no existing session was found. Reverting connections when an active session
// exists would disconnect all volumes associated with the targetQN, potentially
// impacting other storage pools and volumes.
func connect(ctx context.Context, c Connector, targetQN string, targetAddrs []string, connectFunc connectFunc) (revert.Hook, error) {
	revert := revert.New()
	defer revert.Fail()

	// Acquire a lock to prevent concurrent connection attempts to the same
	// target.
	//
	// The lock is not deferred here because it must remain held until all
	// connection attempts are complete. Releasing the lock prematurely after
	// the first successful connection (when this function exits) could lead
	// to race conditions if other connection attempts are still ongoing.
	// For the same reason, relying on a higher-level lock from the caller
	// (e.g., the storage driver) is insufficient.
	unlock, err := locking.Lock(ctx, targetQN)
	if err != nil {
		return nil, err
	}

	// Once the lock is obtained, search for an existing session.
	session, err := c.findSession(targetQN)
	if err != nil {
		return nil, err
	}

	// Set a maximum timeout of 30 seconds for connection attempts.
	// The caller can override this with a shorter timeout if needed.
	//
	// Context cancellation is not deferred here to ensure connection attempts
	// continue even if the function exits before all attempts are completed.
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)

	var wg sync.WaitGroup
	doneChan := make(chan bool, len(targetAddrs))

	// Connect to all target addresses.
	for _, addr := range targetAddrs {
		wg.Add(1)

		go func(addr string) {
			defer wg.Done()

			err := connectFunc(timeoutCtx, session, addr)
			if err != nil {
				// Log warning for each failed connection attempt.
				logger.Warn("Failed connecting to target", logger.Ctx{"target_qualified_name": targetQN, "target_address": addr, "err": err})
			}

			doneChan <- (err == nil)
		}(addr)
	}

	// Cleanup routine. Ensures the error channel is closed and connection
	// lock released once all connection attempts have finished.
	go func() {
		wg.Wait()
		close(doneChan)
		cancel()
		unlock()
	}()

	// Revert successful connections in case of an unexpected error.
	revert.Add(func() {
		// Cancel the context to immediately stop all connection attempts.
		cancel()

		// Wait until all connection attempts have finished.
		wg.Wait()

		// If no active session was found, ensure all established
		// connections are closed. Otherwise, keep open connections
		// intact for other volumes using the session.
		if session == nil {
			revert.Add(func() { _ = c.Disconnect(targetQN) })
		}
	})

	// Wait until at least one successful connections is established, or
	// exit if all connections fail.
	doneConns := 0
	for {
		success := <-doneChan
		if success {
			// First connection established.
			break
		}

		doneConns++
		if doneConns == len(targetAddrs) {
			// No successfully established connections.
			return nil, fmt.Errorf("Failed to connect to any address on target %q", targetQN)
		}
	}

	cleanup := revert.Clone().Fail
	revert.Success()
	return cleanup, nil
}
