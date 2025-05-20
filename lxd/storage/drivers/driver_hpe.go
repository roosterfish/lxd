package drivers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/canonical/lxd/lxd/migration"
	"github.com/canonical/lxd/lxd/operations"
	"github.com/canonical/lxd/lxd/storage/connectors"
	"github.com/canonical/lxd/shared"
	"github.com/canonical/lxd/shared/api"
	"github.com/canonical/lxd/shared/logger"
	"github.com/canonical/lxd/shared/revert"
	"github.com/canonical/lxd/shared/units"
	"github.com/canonical/lxd/shared/validate"
)

// hpeLoaded indicates whether load() function was already called for the HPE Storage driver.
var hpeLoaded = false

// hpeVersion indicates HPE Storage version.
var hpeVersion = ""

// hpeSupportedConnectors represents a list of storage connectors that can be used with HPE Storage.
var hpeSupportedConnectors = []string{
	connectors.TypeISCSI,
	connectors.TypeNVME,
}

type hpe struct {
	common

	// Holds the low level connector for the HPE Storage driver.
	// Use hpe.connector() to retrieve the initialized connector.
	storageConnector connectors.Connector

	// Holds the low level HTTP client for the HPE Storage API.
	// Use hpe.client() to retrieve the client struct.
	httpClient *hpeClient

	// apiVersion indicates the HPE Storage API version.
	apiVersion string
}

// load is used initialize the driver. It should be used only once.
func (d *hpe) load() error {
	// Done if previously loaded.
	if hpeLoaded {
		return nil
	}

	versions := connectors.GetSupportedVersions(hpeSupportedConnectors)
	hpeVersion = strings.Join(versions, " / ")
	hpeLoaded = true

	// Load the kernel modules of the respective connector, ignoring those that cannot be loaded.
	// Support for a specific connector is checked during pool creation. However, this
	// ensures that the kernel modules are loaded, even if the host has been rebooted.
	connector, err := d.connector()
	if err == nil {
		_ = connector.LoadModules()
	}

	return nil
}

// connector retrieves an initialized storage connector based on the configured
// HPE Storage mode. The connector is cached in the driver struct.
func (d *hpe) connector() (connectors.Connector, error) {
	if d.storageConnector == nil {
		connector, err := connectors.NewConnector(d.config["hpe.mode"], d.state.ServerUUID)
		if err != nil {
			return nil, err
		}

		d.storageConnector = connector
	}

	return d.storageConnector, nil
}

// client returns the drivers HPE Storage client. A new client is created only if it does not already exist.
func (d *hpe) client() *hpeClient {
	if d.httpClient == nil {
		d.httpClient = newHpeClient(d)
	}

	return d.httpClient
}

// isRemote returns true indicating this driver uses remote storage.
func (d *hpe) isRemote() bool {
	return true
}

// Info returns info about the driver and its environment.
func (d *hpe) Info() Info {
	return Info{
		Name:                         "hpe",
		Version:                      hpeVersion,
		DefaultBlockSize:             d.defaultBlockVolumeSize(),
		DefaultVMBlockFilesystemSize: d.defaultVMBlockFilesystemSize(),
		OptimizedImages:              true,
		PreservesInodes:              false,
		Remote:                       d.isRemote(),
		VolumeTypes:                  []VolumeType{VolumeTypeCustom, VolumeTypeVM, VolumeTypeContainer, VolumeTypeImage},
		BlockBacking:                 true,
		RunningCopyFreeze:            true,
		DirectIO:                     true,
		IOUring:                      true,
		MountedRoot:                  false,
		PopulateParentVolumeUUID:     true,
	}
}

// FillConfig populates the storage pool's configuration file with the default values.
func (d *hpe) FillConfig() error {
	logger.Debug("HPE FillConfig()")
	// Use NVMe by default.
	if d.config["hpe.mode"] == "" {
		d.config["hpe.mode"] = connectors.TypeNVME
	}

	return nil
}

// Validate checks that all provided keys are supported and there is no conflicting or missing configuration.
func (d *hpe) Validate(config map[string]string) error {
	rules := map[string]func(value string) error{
		"hpe.description":            validate.IsAny,
		"hpe.wsapi.url":              validate.Optional(validate.IsRequestURL),
		"hpe.wsapi.verifyssl":        validate.Optional(validate.IsBool),
		"hpe.wsapi.username":         validate.IsAny,
		"hpe.wsapi.password":         validate.IsAny,
		"hpe.cpg.domain":             validate.IsAny,
		"hpe.target.nqn":             validate.Optional(validate.IsAny),
		"hpe.target.addresses":       validate.Optional(validate.IsListOf(validate.IsNetworkAddress)),
		"hpe.mode":                   validate.Optional(validate.IsOneOf(hpeSupportedConnectors...)),
		"hpe.cpg.growthLimitMiB":     validate.Optional(validate.IsSize),
		"hpe.cpg.growthIncrementMiB": validate.Optional(validate.IsSize),
		"volume.size":                validate.Optional(validate.IsMultipleOfUnit("512M")),
	}

	logger.Debug("HPE Validate()")

	err := d.validatePool(config, rules, d.commonVolumeRules())
	if err != nil {
		return err
	}

	newMode := config["hpe.mode"]
	oldMode := d.config["hpe.mode"]

	// Ensure hpe.mode cannot be changed to avoid leaving volume mappings
	// and prevent disturbing running instances.
	if oldMode != "" && oldMode != newMode {
		return fmt.Errorf("HPE Storage mode cannot be changed")
	}

	// Check if the selected HPE Storage mode is supported on this node.
	// Also when forming the storage pool on a LXD cluster, the mode
	// that got discovered on the creating machine needs to be validated
	// on the other cluster members too. This can be done here since Validate
	// gets executed on every cluster member when receiving the cluster
	// notification to finally create the pool.
	if newMode != "" {
		connector, err := connectors.NewConnector(newMode, "")
		if err != nil {
			return fmt.Errorf("HPE Storage mode %q is not supported: %w", newMode, err)
		}

		err = connector.LoadModules()
		if err != nil {
			return fmt.Errorf("HPE Storage mode %q is not supported due to missing kernel modules: %w", newMode, err)
		}
	}

	return nil
}

// Create is called during pool creation and is effectively using an empty driver struct.
// WARNING: The Create() function cannot rely on any of the struct attributes being set.
func (d *hpe) Create() error {
	logger.Debug("HPE Create()")

	err := d.FillConfig()
	if err != nil {
		return err
	}

	revert := revert.New()
	defer revert.Fail()

	// Validate required HPE Storage configuration keys and return an error if they are
	// not set. Since those keys are not cluster member specific, the general validation
	// rules allow empty strings in order to create the pending storage pools.

	if d.config["hpe.wsapi.url"] == "" {
		return fmt.Errorf("The hpe.wsapi.url cannot be empty")
	}

	if d.config["hpe.wsapi.username"] == "" {
		return fmt.Errorf("The hpe.wsapi.username cannot be empty")
	}

	if d.config["hpe.wsapi.password"] == "" {
		return fmt.Errorf("The hpe.wsapi.password cannot be empty")
	}

	growthIncrementMiB, err := units.ParseByteSizeString(d.config["hpe.cpg.growthIncrementMiB"])
	if err != nil {
		return fmt.Errorf("Failed to parse growthIncrementMiB size %q: %w", growthIncrementMiB, err)
	}

	growthLimitMiB, err := units.ParseByteSizeString(d.config["hpe.cpg.growthLimitMiB"])
	if err != nil {
		return fmt.Errorf("Failed to parse growthIncrementMiB size %q: %w", growthLimitMiB, err)
	}

	// Create the storage pool.
	err = d.client().createStoragePool(d.name, growthLimitMiB)
	if err != nil {
		return err
	}

	revert.Add(func() { _ = d.client().deleteStoragePool(d.name) })

	revert.Success()

	return nil
}

// Update applies any driver changes required from a configuration change.
func (d *hpe) Update(changedConfig map[string]string) error {
	logger.Debug("HPE Update()")

	newPoolSizeBytes, err := units.ParseByteSizeString(changedConfig["size"])
	if err != nil {
		return fmt.Errorf("Failed to parse storage size: %w", err)
	}

	oldPoolSizeBytes, err := units.ParseByteSizeString(d.config["size"])
	if err != nil {
		return fmt.Errorf("Failed to parse old storage size: %w", err)
	}

	if newPoolSizeBytes != oldPoolSizeBytes {
		err = d.client().updateStoragePool(d.name, newPoolSizeBytes)
		if err != nil {
			return err
		}
	}

	return nil
}

// Delete removes the storage pool (HPE Storage pod).
func (d *hpe) Delete(op *operations.Operation) error {
	logger.Debug("HPE Delete()")

	// First delete the storage pool on HPE Storage.
	err := d.client().deleteStoragePool(d.name)
	if err != nil && !api.StatusErrorCheck(err, http.StatusNotFound) {
		return err
	}

	// If the user completely destroyed it, call it done.
	if !shared.PathExists(GetPoolMountPath(d.name)) {
		return nil
	}

	// On delete, wipe everything in the directory.
	return wipeDirectory(GetPoolMountPath(d.name))
}

// Mount mounts the storage pool.
func (d *hpe) Mount() (bool, error) {
	// Nothing to do here.
	return true, nil
}

// Unmount unmounts the storage pool.
func (d *hpe) Unmount() (bool, error) {
	// Nothing to do here.
	return true, nil
}

// GetResources returns the pool resource usage information.
func (d *hpe) GetResources() (*api.ResourcesStoragePool, error) {
	_, err := d.client().getStoragePool(d.name)
	if err != nil {
		return nil, err
	}

	res := &api.ResourcesStoragePool{}

	// res.Space.Total = uint64(pool.Quota)
	// res.Space.Used = uint64(pool.Space.UsedBytes)

	// if pool.Quota == 0 {
	// 	// If quota is set to 0, it means that the storage pool is unbounded. Therefore,
	// 	// collect the total capacity of arrays where storage pool provisioned.
	// 	arrayNames := make([]string, 0, len(pool.Arrays))
	// 	for _, array := range pool.Arrays {
	// 		arrayNames = append(arrayNames, array.Name)
	// 	}

	// 	arrays, err := d.client().getStorageArrays(arrayNames...)
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	for _, array := range arrays {
	// 		res.Space.Total += uint64(array.Capacity)
	// 	}
	// }

	return res, nil
}

// MigrationTypes returns the type of transfer methods to be used when doing migrations between pools in preference order.
func (d *hpe) MigrationTypes(contentType ContentType, refresh bool, copySnapshots bool) []migration.Type {
	var rsyncFeatures []string

	// Do not pass compression argument to rsync if the associated
	// config key, that is rsync.compression, is set to false.
	if shared.IsFalse(d.Config()["rsync.compression"]) {
		rsyncFeatures = []string{"xattrs", "delete", "bidirectional"}
	} else {
		rsyncFeatures = []string{"xattrs", "delete", "compress", "bidirectional"}
	}

	if refresh {
		var transportType migration.MigrationFSType

		if IsContentBlock(contentType) {
			transportType = migration.MigrationFSType_BLOCK_AND_RSYNC
		} else {
			transportType = migration.MigrationFSType_RSYNC
		}

		return []migration.Type{
			{
				FSType:   transportType,
				Features: rsyncFeatures,
			},
		}
	}

	if contentType == ContentTypeBlock {
		return []migration.Type{
			{
				FSType:   migration.MigrationFSType_BLOCK_AND_RSYNC,
				Features: rsyncFeatures,
			},
		}
	}

	return []migration.Type{
		{
			FSType:   migration.MigrationFSType_RSYNC,
			Features: rsyncFeatures,
		},
	}
}
