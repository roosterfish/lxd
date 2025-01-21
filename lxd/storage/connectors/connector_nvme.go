package connectors

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/canonical/lxd/lxd/util"
	"github.com/canonical/lxd/shared"
	"github.com/canonical/lxd/shared/revert"
)

var _ Connector = &connectorNVMe{}

type connectorNVMe struct {
	common
}

// Type returns the type of the connector.
func (c *connectorNVMe) Type() string {
	return TypeNVME
}

// Version returns the version of the NVMe CLI.
func (c *connectorNVMe) Version() (string, error) {
	// Detect and record the version of the NVMe CLI.
	out, err := shared.RunCommand("nvme", "version")
	if err != nil {
		return "", fmt.Errorf("Failed to get nvme-cli version: %w", err)
	}

	fields := strings.Split(strings.TrimSpace(out), " ")
	if strings.HasPrefix(out, "nvme version ") && len(fields) > 2 {
		return fmt.Sprintf("%s (nvme-cli)", fields[2]), nil
	}

	return "", fmt.Errorf("Failed to get nvme-cli version: Unexpected output %q", out)
}

// LoadModules loads the NVMe/TCP kernel modules.
// Returns true if the modules can be loaded.
func (c *connectorNVMe) LoadModules() error {
	err := util.LoadModule("nvme_fabrics")
	if err != nil {
		return err
	}

	return util.LoadModule("nvme_tcp")
}

// QualifiedName returns a custom NQN generated from the server UUID.
// Getting the NQN from /etc/nvme/hostnqn would require the nvme-cli
// package to be installed on the host.
func (c *connectorNVMe) QualifiedName() (string, error) {
	return fmt.Sprintf("nqn.2014-08.org.nvmexpress:uuid:%s", c.serverUUID), nil
}

// Connect establishes a connection with the target on the given address.
func (c *connectorNVMe) Connect(ctx context.Context, targetQN string, targetAddresses ...string) (revert.Hook, error) {
	// Connects to the provided target address, if the connection is not yet established.
	connectFunc := func(ctx context.Context, session *session, targetAddr string) error {
		if session != nil && slices.Contains(session.addresses, targetAddr) {
			// Already connected.
			return nil
		}

		hostNQN, err := c.QualifiedName()
		if err != nil {
			return err
		}

		_, stderr, err := shared.RunCommandSplit(ctx, nil, nil, "nvme", "connect", "--transport", "tcp", "--traddr", targetAddr, "--nqn", targetQN, "--hostnqn", hostNQN, "--hostid", c.serverUUID)
		if err != nil {
			return fmt.Errorf("Failed to connect to target %q on %q via NVMe: %w", targetQN, targetAddr, err)
		}

		if stderr != "" {
			return fmt.Errorf("Failed to connect to target %q on %q via NVMe: %s", targetQN, targetAddr, stderr)
		}

		return nil
	}

	return connect(ctx, c, targetQN, targetAddresses, connectFunc)
}

// ConnectAll establishes a connection with all targets available on the given address.
func (c *connectorNVMe) ConnectAll(ctx context.Context, targetAddr string) error {
	hostNQN, err := c.QualifiedName()
	if err != nil {
		return err
	}

	_, stderr, err := shared.RunCommandSplit(ctx, nil, nil, "nvme", "connect-all", "--transport", "tcp", "--traddr", targetAddr, "--hostnqn", hostNQN, "--hostid", c.serverUUID)
	if err != nil {
		return fmt.Errorf("Failed to connect to any target on %q via NVMe: %w", targetAddr, err)
	}

	if stderr != "" {
		return fmt.Errorf("Failed to connect to any target on %q via NVMe: %s", targetAddr, stderr)
	}

	return nil
}

// Disconnect terminates a connection with the target.
func (c *connectorNVMe) Disconnect(targetQN string) error {
	// Find an existing NVMe session.
	session, err := c.findSession(targetQN)
	if err != nil {
		return err
	}

	// Disconnect from the NVMe target if there is an existing session.
	if session != nil {
		_, err := shared.RunCommand("nvme", "disconnect", "--nqn", targetQN)
		if err != nil {
			return fmt.Errorf("Failed disconnecting from NVMe target %q: %w", targetQN, err)
		}
	}

	return nil
}

// DisconnectAll terminates all connections with all targets.
func (c *connectorNVMe) DisconnectAll() error {
	_, err := shared.RunCommand("nvme", "disconnect-all")
	if err != nil {
		return fmt.Errorf("Failed disconnecting from NVMe targets: %w", err)
	}

	return nil
}

// SessionID returns the identifier of a session that matches the targetQN.
// If no session is found, an empty string is returned.
func (c *connectorNVMe) SessionID(targetQN string) (string, error) {
	session, err := c.findSession(targetQN)
	if err != nil || session == nil {
		return "", err
	}

	return session.id, nil
}

// findSession returns an active NVMe subsystem (referred to as session for
// consistency across connectors) that matches the given targetQN.
// If the session is not found, nil is returned.
//
// This function handles the distinction between an "inactive" session (with no
// active controllers/connections) and a completely "non-existent" session. While
// checking "/sys/class/nvme" for active controllers is sufficient to identify if
// the session is currently in use, it does not account for cases where a session
// exists but is temporarily inactive (e.g., due to network issues). Removing
// such a session during this state would prevent it from automatically
// recovering once the connection is restored.
//
// To ensure we detect "existing" sessions, we first check for the session's
// presence in "/sys/class/nvme-subsystem", which tracks all associated NVMe
// subsystems regardless of their current connection state. If such session is
// found the function determines addresses of the active connections by checking
// "/sys/class/nvme", and returns a non-nil result (except if an error occurs).
func (c *connectorNVMe) findSession(targetQN string) (*session, error) {
	// Base path for NVMe sessions/subsystems.
	subsysBasePath := "/sys/class/nvme-subsystem"

	// Retrieve the list of existing NVMe subsystems on this host.
	subsystems, err := os.ReadDir(subsysBasePath)
	if err != nil {
		if os.IsNotExist(err) {
			// If NVMe subsystems directory does not exist,
			// there is no sessions.
			return nil, nil
		}

		return nil, fmt.Errorf("Failed getting a list of existing NVMe subsystems: %w", err)
	}

	sessionID := ""
	for _, subsys := range subsystems {
		// Get the target NQN.
		nqnBytes, err := os.ReadFile(filepath.Join(subsysBasePath, subsys.Name(), "subsysnqn"))
		if err != nil {
			return nil, fmt.Errorf("Failed getting the target NQN for subystem %q: %w", subsys.Name(), err)
		}

		// Trim newlines from the subsystem NQN and compare it
		// to  targetQN.
		nqn := strings.TrimSpace(string(nqnBytes))
		if nqn == targetQN {
			// Found matching session.
			sessionID = strings.TrimPrefix(subsys.Name(), "nvme-subsys")
			break
		}
	}

	if sessionID == "" {
		// No matching session found.
		return nil, nil
	}

	session := &session{
		id:       sessionID,
		targetQN: targetQN,
	}

	basePath := "/sys/class/nvme"

	// Retrieve the list of currently active (operational) NVMe controllers.
	controllers, err := os.ReadDir(basePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// No active connections for any session.
			return session, nil
		}

		return nil, fmt.Errorf("Failed getting a list of existing NVMe subsystems: %w", err)
	}

	// Iterate over active NVMe devices and extract addresses from those
	// that correspond to the targetQN.
	for _, c := range controllers {
		// Get device's target NQN.
		nqnBytes, err := os.ReadFile(filepath.Join(basePath, c.Name(), "subsysnqn"))
		if err != nil {
			return nil, fmt.Errorf("Failed getting the target NQN for controller %q: %w", c.Name(), err)
		}

		nqn := strings.TrimSpace(string(nqnBytes))
		if nqn != targetQN {
			// Subsystem does not belong to the targetQN.
			continue
		}

		// Read address file of an active NVMe connection.
		filePath := filepath.Join(basePath, c.Name(), "address")
		fileBytes, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("Failed getting connection address of controller %q for target %q: %w", c.Name(), targetQN, err)
		}

		// Extract the address from the file content.
		// File content is in format "traddr=<ip>,trsvcid=<port>,...".
		content := strings.TrimSpace(string(fileBytes))
		parts := strings.Split(string(content), ",")
		for _, part := range parts {
			addr, ok := strings.CutPrefix(part, "traddr=")
			if ok {
				session.addresses = append(session.addresses, addr)
				break
			}
		}
	}

	return session, nil
}
