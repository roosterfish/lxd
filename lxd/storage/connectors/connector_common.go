package connectors

import (
	"context"
	"fmt"

	"github.com/canonical/lxd/shared/revert"
)

var _ Connector = &common{}

type common struct {
	serverUUID string
}

// Type returns the name of the connector.
func (c *common) Type() string {
	return TypeUnknown
}

// Version returns the version of the connector.
func (c *common) Version() (string, error) {
	return "", fmt.Errorf("Version not implemented")
}

// QualifiedName returns the qualified name of the connector.
func (c *common) QualifiedName() (string, error) {
	return "", fmt.Errorf("QualifiedName not implemented")
}

// LoadModules loads the necessary kernel modules.
func (c *common) LoadModules() error {
	return nil
}

// Connect establishes a connection with the target on the given address.
func (c *common) Connect(ctx context.Context, targetQN string, targetAddresses ...string) (revert.Hook, error) {
	return nil, fmt.Errorf("Connect not implemented")
}

// ConnectAll establishes a connection with all targets available on the given address.
func (c *common) ConnectAll(ctx context.Context, targetAddr string) error {
	return fmt.Errorf("ConnectAll not implemented")
}

// Disconnect terminates a connection with the target.
func (c common) Disconnect(targetQN string) error {
	return fmt.Errorf("Disconnect not implemented")
}

// DisconnectAll terminates all connections with all targets.
func (c common) DisconnectAll() error {
	return fmt.Errorf("DisconnectAll not implemented")
}

// SessionID returns the identifier of a session that matches the connector's qualified name.
// If there is no such session, an empty string is returned.
func (c *common) SessionID(targetQN string) (string, error) {
	return "", fmt.Errorf("SessionID not implemented")
}

// findSession returns an active session that matches the given targetQN.
// If the session is not found, nil session is returned.
func (c *common) findSession(targetQN string) (session *session, err error) {
	return nil, fmt.Errorf("findSession not implemented")
}
