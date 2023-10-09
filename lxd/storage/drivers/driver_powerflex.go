package drivers

import (
	"fmt"
	"strings"

	deviceConfig "github.com/canonical/lxd/lxd/device/config"
	"github.com/canonical/lxd/lxd/migration"
	"github.com/canonical/lxd/lxd/operations"
	"github.com/canonical/lxd/shared"
	"github.com/canonical/lxd/shared/api"
	"github.com/canonical/lxd/shared/validate"
)

// powerFlexDefaultUser represents the default PowerFlex user name.
const powerFlexDefaultUser = "admin"

// powerFlexDefaultSize represents the default PowerFlex volume size.
const powerFlexDefaultSize = "8GiB"

var powerFlexLoaded bool
var powerFlexVersion string

type powerflex struct {
	common

	// Holds the low level HTTP client for the PowerFlex API.
	// Use powerflex.client() to retrieve the client struct.
	httpClient *powerFlexClient
}

// load is used to run one-time action per-driver rather than per-pool.
func (d *powerflex) load() error {
	// Done if previously loaded.
	if powerFlexLoaded {
		return nil
	}

	// Detect and record the version.
	out, err := shared.RunCommand("nvme", "version")
	if err != nil {
		return fmt.Errorf("Failed to get nvme-cli version: %w", err)
	}

	fields := strings.Split(strings.TrimSpace(out), " ")
	if strings.HasPrefix(out, "nvme version ") && len(fields) > 2 {
		powerFlexVersion = fmt.Sprintf("%s (nvme-cli)", fields[2])
	}

	powerFlexLoaded = true
	return nil
}

// isRemote returns true indicating this driver uses remote storage.
func (d *powerflex) isRemote() bool {
	return true
}

// Info returns info about the driver and its environment.
func (d *powerflex) Info() Info {
	return Info{
		Name:                         "powerflex",
		Version:                      powerFlexVersion,
		DefaultVMBlockFilesystemSize: deviceConfig.DefaultVMPowerFlexBlockFilesystemSize,
		OptimizedImages:              true,
		PreservesInodes:              false,
		Remote:                       d.isRemote(),
		VolumeTypes:                  []VolumeType{VolumeTypeCustom, VolumeTypeVM, VolumeTypeContainer, VolumeTypeImage},
		BlockBacking:                 true,
		RunningCopyFreeze:            true,
		DirectIO:                     true,
		IOUring:                      true,
		MountedRoot:                  false,
	}
}

// FillConfig populates the storage pool's configuration file with the default values.
func (d *powerflex) FillConfig() error {
	if d.config["powerflex.user.name"] == "" {
		d.config["powerflex.user.name"] = powerFlexDefaultUser
	}

	if d.config["powerflex.mode"] == "" {
		if d.canNVMe() {
			d.config["powerflex.mode"] = "nvme"
		}
	}

	// Fail if no PowerFlex mode could be discovered.
	if d.config["powerflex.mode"] == "" {
		return fmt.Errorf("Failed to discover PowerFlex mode")
	}

	// PowerFlex volumes have to be at least 8GiB in size.
	if d.config["volume.size"] == "" {
		d.config["volume.size"] = powerFlexDefaultSize
	}

	return nil
}

// Create is called during pool creation and is effectively using an empty driver struct.
// WARNING: The Create() function cannot rely on any of the struct attributes being set.
func (d *powerflex) Create() error {
	err := d.FillConfig()
	if err != nil {
		return err
	}

	client := d.client()

	// Discover one of the storage pools SDS services.
	if d.config["powerflex.mode"] == "nvme" {
		if d.config["powerflex.sdt"] == "" {
			pool, err := client.getStoragePool(d.config["powerflex.pool"])
			if err != nil {
				return err
			}

			// TODO: check status of SDT or if they are applicable
			relations, err := client.getProtectionDomainSDTRelations(pool.ProtectionDomainID)
			if err != nil {
				return err
			}

			if len(relations) == 0 {
				return fmt.Errorf("Failed to retrieve at least one SDT for the given storage pool: %q", pool.ID)
			}

			if len(relations[0].IPList) == 0 {
				return fmt.Errorf("Failed to retrieve IP from SDT: %q", relations[0].Name)
			}

			d.config["powerflex.sdt"] = relations[0].IPList[0].IP
		}
	}

	return nil
}

// Delete removes the storage pool from the storage device.
func (d *powerflex) Delete(op *operations.Operation) error {
	// Disconnect from the NVMe/TCP subsystem.
	if d.config["powerflex.mode"] == "nvme" {
		err := d.disconnectNVMeSubsys()
		if err != nil {
			return err
		}
	}

	// If the user completely destroyed it, call it done.
	if !shared.PathExists(GetPoolMountPath(d.name)) {
		return nil
	}

	// On delete, wipe everything in the directory.
	return wipeDirectory(GetPoolMountPath(d.name))
}

// Validate checks that all provide keys are supported and that no conflicting or missing configuration is present.
func (d *powerflex) Validate(config map[string]string) error {
	rules := map[string]func(value string) error{
		"powerflex.user.name":      validate.IsAny,
		"powerflex.user.password":  validate.IsAny,
		"powerflex.gateway":        validate.IsRequestURL,
		"powerflex.gateway.verify": validate.Optional(validate.IsBool),
		"powerflex.pool":           validate.IsNotEmpty,
		"powerflex.domain":         validate.Optional(validate.IsAny),
		"powerflex.mode":           validate.Optional(validate.IsOneOf("nvme")),
		"powerflex.sdt":            validate.Optional(validate.IsNetworkAddress),
		"powerflex.clone_copy":     validate.Optional(validate.IsBool),
		"volume.size":              validate.Optional(validate.IsMultipleOfUnit("8GiB")),
	}

	return d.validatePool(config, rules, d.commonVolumeRules())
}

// Update applies any driver changes required from a configuration change.
func (d *powerflex) Update(changedConfig map[string]string) error {
	return nil
}

// Mount mounts the storage pool.
func (d *powerflex) Mount() (bool, error) {
	// Nothing to do here.
	return true, nil
}

// Unmount unmounts the storage pool.
func (d *powerflex) Unmount() (bool, error) {
	// Nothing to do here.
	return true, nil
}

// GetResources returns the pool resource usage information.
func (d *powerflex) GetResources() (*api.ResourcesStoragePool, error) {
	return &api.ResourcesStoragePool{
		Space:  api.ResourcesStoragePoolSpace{},
		Inodes: api.ResourcesStoragePoolInodes{},
	}, nil
}

// MigrationType returns the type of transfer methods to be used when doing migrations between pools in preference order.
func (d *powerflex) MigrationTypes(contentType ContentType, refresh bool, copySnapshots bool) []migration.Type {
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
