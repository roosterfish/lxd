package cluster

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/canonical/lxd/lxd/db/query"
	"github.com/canonical/lxd/shared/api"
	"github.com/canonical/lxd/shared/version"
)

// NetworksLoadBalancersPoolRow represents a single row of the networks_load_balancers_pools table.
// db:model networks_load_balancers_pools
type NetworksLoadBalancersPoolRow struct {
	ID          int64  `db:"id"`
	NetworkID   int64  `db:"network_id"`
	Name        string `db:"name"`
	Description string `db:"description"`
}

// APIName implements [query.APINamer] for API friendly error messages.
func (NetworksLoadBalancersPoolRow) APIName() string {
	return "Network load balancer pool"
}

// NetworksLoadBalancersPool represents a single row of the networks_load_balancers_pools table joined with the projects and networks tables.
// db:model networks_load_balancers_pools
type NetworksLoadBalancersPool struct {
	Row NetworksLoadBalancersPoolRow

	// db:join JOIN networks ON networks.id = networks_load_balancers_pools.network_id
	NetworkName string `db:"networks.name"`
	// db:join JOIN projects ON projects.id = networks.project_id
	ProjectName string `db:"projects.name"`
}

// NetworksLoadBalancersPoolInstanceRow represents a single row of the networks_load_balancers_pools_instances table.
// db:model networks_load_balancers_pools_instances
type NetworksLoadBalancersPoolInstanceRow struct {
	ID         int64          `db:"id"`
	PoolID     int64          `db:"network_load_balancer_pool_id"`
	InstanceID int64          `db:"instance_id"`
	TargetPort sql.NullString `db:"target_port"`
}

// APIName implements [query.APINamer] for API friendly error messages.
func (NetworksLoadBalancersPoolInstanceRow) APIName() string {
	return "Network load balancer pool instance"
}

// NetworksLoadBalancersPoolInstance represents a single row of the networks_load_balancers_pools_instances table joined with the instances table.
// db:model networks_load_balancers_pools_instances
type NetworksLoadBalancersPoolInstance struct {
	Row NetworksLoadBalancersPoolInstanceRow

	// db:join JOIN instances ON instances.id = networks_load_balancers_pools_instances.instance_id
	InstanceName string `db:"instances.name"`
}

// ToAPI converts the [NetworksLoadBalancersPool] to an [api.NetworkLoadBalancerPool], querying for extra data as necessary.
func (p *NetworksLoadBalancersPool) ToAPI(ctx context.Context, tx *sql.Tx) (*api.NetworkLoadBalancerPool, error) {
	// Get config.
	config, err := GetNetworksLoadBalancersPoolConfig(ctx, tx, p.Row.ID)
	if err != nil {
		return nil, fmt.Errorf("Failed getting network load balancer pool config: %w", err)
	}

	// Get instances.
	instances, err := query.Select[NetworksLoadBalancersPoolInstance](ctx, tx, "WHERE network_load_balancer_pool_id = ?", p.Row.ID)
	if err != nil {
		return nil, err
	}

	apiInstances := make([]api.NetworkLoadBalancerPoolInstance, 0, len(instances))
	for _, instance := range instances {
		apiInstances = append(apiInstances, *instance.ToAPI(ctx, tx))
	}

	// Get load balancers referencing this pool.
	loadBalancers, err := GetNetworksLoadBalancersUsingPool(ctx, tx, p.Row.NetworkID, p.Row.Name)
	if err != nil {
		return nil, fmt.Errorf("Failed getting load balancers referencing this pool: %w", err)
	}

	usedBy := make([]string, 0, len(loadBalancers))
	for _, listenAddress := range loadBalancers {
		usedBy = append(usedBy, api.NewURL().Path(version.APIVersion, "networks", p.NetworkName, "load-balancers", listenAddress).Project(p.ProjectName).String())
	}

	return &api.NetworkLoadBalancerPool{
		Name:        p.Row.Name,
		Description: p.Row.Description,
		Config:      config,
		Instances:   apiInstances,
		UsedBy:      usedBy,
	}, nil
}

// ToAPI converts the [NetworksLoadBalancersPoolInstance] to an [api.NetworkLoadBalancerPoolInstance], querying for extra data as necessary.
func (p *NetworksLoadBalancersPoolInstance) ToAPI(ctx context.Context, tx *sql.Tx) *api.NetworkLoadBalancerPoolInstance {
	return &api.NetworkLoadBalancerPoolInstance{
		Name:       p.InstanceName,
		TargetPort: p.Row.TargetPort.String,
	}
}

// GetNetworksLoadBalancersPool gets a single NetworksLoadBalancersPool by name.
func GetNetworksLoadBalancersPool(ctx context.Context, tx *sql.Tx, poolName string) (*NetworksLoadBalancersPool, error) {
	pool, err := query.SelectOne[NetworksLoadBalancersPool](ctx, tx, "WHERE networks_load_balancers_pools.name = ?", poolName)
	if err != nil {
		return nil, err
	}

	return pool, nil
}

// GetNetworksLoadBalancersPoolRowByID gets a single NetworksLoadBalancersPoolRow by ID.
func GetNetworksLoadBalancersPoolRowByID(ctx context.Context, tx *sql.Tx, poolID int64) (*NetworksLoadBalancersPoolRow, error) {
	return query.SelectOne[NetworksLoadBalancersPoolRow](ctx, tx, "WHERE networks_load_balancers_pools.id = ?", poolID)
}

// GetNetworksLoadBalancersUsingPool gets the names of all load balancers that reference the given pool.
// The returned slice contains the addresses of the load balancers referencing the pool.
func GetNetworksLoadBalancersUsingPool(ctx context.Context, tx *sql.Tx, networkID int64, poolName string) ([]string, error) {
	q := `
		SELECT 
			networks_load_balancers.listen_address
		FROM networks_load_balancers
		CROSS JOIN json_each(networks_load_balancers.ports)
			WHERE networks_load_balancers.network_id = ? 
			AND json_valid(networks_load_balancers.ports) 
			AND json_extract(value, "$.target_pool") = ?
	`
	var loadBalancers []string

	err := query.Scan(ctx, tx, q, func(scan func(dest ...any) error) error {
		var listenAddress string

		err := scan(&listenAddress)
		if err != nil {
			return err
		}

		loadBalancers = append(loadBalancers, listenAddress)
		return nil
	}, networkID, poolName)
	if err != nil {
		return nil, err
	}

	return loadBalancers, nil
}

// UpdateNetworksLoadBalancersPool updates a single NetworksLoadBalancersPool, replacing its config with the given config.
func UpdateNetworksLoadBalancersPool(ctx context.Context, tx *sql.Tx, pool *NetworksLoadBalancersPoolRow, config map[string]string) error {
	_, err := tx.ExecContext(ctx, "DELETE FROM networks_load_balancers_pools_config WHERE network_load_balancer_pool_id=?", pool.ID)
	if err != nil {
		return err
	}

	err = CreateNetworksLoadBalancersPoolConfig(ctx, tx, pool.ID, config)
	if err != nil {
		return err
	}

	return query.UpdateByPrimaryKey(ctx, tx, pool)
}

// GetNetworksLoadBalancersPools queries for all networks load balancers pools and then applies the given filter to the result.
func GetNetworksLoadBalancersPools(ctx context.Context, tx *sql.Tx, networkID int64, filter func(pool NetworksLoadBalancersPool) bool) ([]NetworksLoadBalancersPool, error) {
	var b strings.Builder
	b.WriteString("WHERE network_id = ? ORDER BY ")

	b.WriteString("networks_load_balancers_pools.name")
	clause := b.String()

	var loadBalancersPools []NetworksLoadBalancersPool
	err := query.SelectFunc[NetworksLoadBalancersPool](ctx, tx, clause, func(pool NetworksLoadBalancersPool) error {
		if filter != nil && !filter(pool) {
			return nil
		}

		loadBalancersPools = append(loadBalancersPools, pool)
		return nil
	}, networkID)
	if err != nil {
		return nil, err
	}

	return loadBalancersPools, nil
}

// DeleteNetworksLoadBalancersPool deletes the networks load balancers pool with the given name and network ID.
func DeleteNetworksLoadBalancersPool(ctx context.Context, tx *sql.Tx, networkID int64, poolName string) error {
	return query.DeleteOne[NetworksLoadBalancersPoolRow](ctx, tx, "WHERE network_id = ? AND name = ?", networkID, poolName)
}

// CreateNetworksLoadBalancersPoolConfig creates config for a new networks load balancers pool with the given ID.
func CreateNetworksLoadBalancersPoolConfig(ctx context.Context, tx *sql.Tx, poolID int64, config map[string]string) error {
	return createEntityConfig(ctx, tx, "networks_load_balancers_pools_config", "network_load_balancer_pool_id", poolID, config)
}

// GetNetworksLoadBalancersPoolConfig returns the config for the networks load balancers pool with the given ID.
func GetNetworksLoadBalancersPoolConfig(ctx context.Context, tx *sql.Tx, poolID int64) (map[string]string, error) {
	q := `SELECT key, value FROM networks_load_balancers_pools_config WHERE network_load_balancer_pool_id=?`

	config := map[string]string{}
	return config, query.Scan(ctx, tx, q, func(scan func(dest ...any) error) error {
		var key, value string

		err := scan(&key, &value)
		if err != nil {
			return err
		}

		_, found := config[key]
		if found {
			return fmt.Errorf("Duplicate config row found for key %q for networks load balancers pool ID %d", key, poolID)
		}

		config[key] = value
		return nil
	}, poolID)
}

// GetNetworksLoadBalancersPoolInstanceRowsByID returns all rows of the networks_load_balancers_pools_instances table for a given instance ID.
// It returns all memberships of the instance in any load balancer pool.
func GetNetworksLoadBalancersPoolInstanceRowsByID(ctx context.Context, tx *sql.Tx, instanceID int64) ([]NetworksLoadBalancersPoolInstanceRow, error) {
	return query.Select[NetworksLoadBalancersPoolInstanceRow](ctx, tx, "WHERE instance_id = ?", instanceID)
}

// UpdateNetworkLoadBalancersPoolInstanceRow updates a single row of the networks_load_balancers_pools_instances table.
func UpdateNetworkLoadBalancersPoolInstanceRow(ctx context.Context, tx *sql.Tx, instance *NetworksLoadBalancersPoolInstanceRow) error {
	return query.UpdateOne(ctx, tx, instance, "WHERE network_load_balancer_pool_id = ? AND instance_id = ?", instance.PoolID, instance.InstanceID)
}

// DeleteNetworksLoadBalancersPoolInstanceRow deletes the networks load balancers pool instance row with the given pool and instance IDs.
func DeleteNetworksLoadBalancersPoolInstanceRow(ctx context.Context, tx *sql.Tx, poolID int64, instanceID int64) error {
	return query.DeleteOne[NetworksLoadBalancersPoolInstanceRow](ctx, tx, "WHERE network_load_balancer_pool_id = ? AND instance_id = ?", poolID, instanceID)
}
