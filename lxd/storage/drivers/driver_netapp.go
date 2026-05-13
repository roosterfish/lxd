package drivers

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	"github.com/canonical/lxd/lxd/migration"
	"github.com/canonical/lxd/lxd/storage/connectors"
	"github.com/canonical/lxd/shared"
	"github.com/canonical/lxd/shared/api"
	"github.com/canonical/lxd/shared/ioprogress"
	"github.com/canonical/lxd/shared/validate"
)

var netappVersion = "1"
var netappLoaded bool
var netappSupportedConnectors = []string{
	connectors.TypeNVME,
}

type netapp struct {
	common

	storageConnector connectors.Connector
	httpClient       *netappClient
}

// load is used to run one-time action per-driver rather than per-pool.
func (d *netapp) load() error {
	if netappLoaded {
		return nil
	}

	netappLoaded = true
	return nil
}

// connector retrieves the initialised storage connector for this driver, lazily
// creating it on first use. The connector is bound to the host's stable
// ServerUUID so the derived NQN remains constant across LXD restarts.
func (d *netapp) connector() (connectors.Connector, error) {
	if d.storageConnector == nil {
		c, err := connectors.NewConnector(d.config["netapp.mode"], d.state.OS.ServerUUID)
		if err != nil {
			return nil, err
		}

		d.storageConnector = c
	}

	return d.storageConnector, nil
}

// commonVolumeRules returns the validation rules common to all ONTAP-backed
// volumes. Block-backed remote drivers all require this so block.* keys are
// recognised by the pool validator.
func (d *netapp) commonVolumeRules() map[string]func(value string) error {
	return map[string]func(value string) error{
		"block.filesystem":    validate.Optional(validate.IsOneOf(blockBackedAllowedFilesystems...)),
		"block.mount_options": validate.IsAny,
		"size":                validate.Optional(validate.IsMultipleOfUnit("4KiB")),
	}
}

// client returns the ONTAP client if established.
func (d *netapp) client() *netappClient {
	if d.httpClient == nil {
		skipVerify := shared.IsFalse(d.config["netapp.gateway.verify"])

		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
			Proxy:           http.ProxyFromEnvironment,
		}

		// The SVM is discovered from the aggregate at pool-create time and
		// persisted in volatile config; a stale config["netapp.svm"] entry
		// (legacy or test override) takes precedence so users can pin a
		// specific SVM if the aggregate later moves.
		svmName := d.config["netapp.svm"]
		if svmName == "" {
			svmName = d.config["volatile.svm.name"]
		}

		d.httpClient = &netappClient{
			gateway:    d.config["netapp.gateway"],
			username:   d.config["netapp.user.name"],
			password:   d.config["netapp.user.password"],
			skipVerify: skipVerify,
			aggregate:  d.config["netapp.aggregate"],
			svmName:    svmName,
			httpClient: &http.Client{
				Transport: transport,
			},
		}
	}

	return d.httpClient
}

// isRemote returns true indicating this driver uses remote storage.
func (d *netapp) isRemote() bool {
	return true
}

// Info returns info about the driver and its environment.
func (d *netapp) Info() Info {
	return Info{
		Name:                         "netapp",
		Version:                      netappVersion,
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
		UUIDVolumeNames:              true,
	}
}

// SourceIdentifier returns a combined string consisting of the gateway address and pool name.
func (d *netapp) SourceIdentifier() (string, error) {
	if d.config["netapp.gateway"] == "" {
		return "", errors.New("Cannot derive identifier from empty gateway address")
	}

	if d.name == "" {
		return "", errors.New("Cannot derive identifier from empty pool name")
	}

	return d.config["netapp.gateway"] + "-" + d.name, nil
}

// FillConfig populates the storage pool's configuration file with the default values.
func (d *netapp) FillConfig() error {
	if d.config["netapp.mode"] == "" {
		d.config["netapp.mode"] = "nvme"
	}

	if d.config["netapp.thin"] == "" {
		d.config["netapp.thin"] = "true"
	}

	return nil
}

// Validate checks that all provided keys are supported and that no conflicting or missing configuration is present.
func (d *netapp) Validate(config map[string]string) error {
	rules := map[string]func(value string) error{
		// lxdmeta:generate(entities=storage-ontap; group=pool-conf; key=netapp.gateway)
		//
		// ---
		//  type: string
		//  shortdesc: Address of the ONTAP Cluster Management interface
		//  scope: global
		"netapp.gateway": validate.Optional(validate.IsRequestURL),
		// lxdmeta:generate(entities=storage-ontap; group=pool-conf; key=netapp.gateway.verify)
		//
		// ---
		//  type: bool
		//  defaultdesc: `true`
		//  shortdesc: Whether to verify the ONTAP gateway's certificate
		//  scope: global
		"netapp.gateway.verify": validate.Optional(validate.IsBool),
		// lxdmeta:generate(entities=storage-ontap; group=pool-conf; key=netapp.user.name)
		//
		// ---
		//  type: string
		//  shortdesc: User for ONTAP API authentication
		//  scope: global
		"netapp.user.name": validate.IsAny,
		// lxdmeta:generate(entities=storage-ontap; group=pool-conf; key=netapp.user.password)
		//
		// ---
		//  type: string
		//  shortdesc: Password for ONTAP API authentication
		//  scope: global
		"netapp.user.password": validate.IsAny,
		// lxdmeta:generate(entities=storage-ontap; group=pool-conf; key=netapp.aggregate)
		//
		// ---
		//  type: string
		//  shortdesc: Aggregate Name for the pool
		//  scope: global
		"netapp.aggregate": validate.IsAny,
		// lxdmeta:generate(entities=storage-ontap; group=pool-conf; key=netapp.mode)
		//
		// ---
		//  type: string
		//  defaultdesc: `nvme`
		//  shortdesc: How volumes are mapped to the local server
		//  scope: global
		"netapp.mode": validate.Optional(validate.IsOneOf(netappSupportedConnectors...)),
		// lxdmeta:generate(entities=storage-ontap; group=pool-conf; key=netapp.target)
		//
		// ---
		//  type: string
		//  shortdesc: List of target addresses the LXD connects to.
		"netapp.target": validate.Optional(validate.IsListOf(validate.IsNetworkAddress)),
		// lxdmeta:generate(entities=storage-ontap; group=pool-conf; key=netapp.thin)
		//
		// ---
		//  type: bool
		//  defaultdesc: `true`
		//  shortdesc: Enable thin provisioning
		//  scope: global
		"netapp.thin": validate.Optional(validate.IsBool),
		// lxdmeta:generate(entities=storage-ontap; group=pool-conf; key=volume.size)
		// The size must be in multiples of 4KiB.
		// ---
		//  type: string
		//  defaultdesc: `10GiB`
		//  shortdesc: Size/quota of the storage volume
		//  scope: global
		"volume.size": validate.Optional(validate.IsMultipleOfUnit("4KiB")),
	}

	err := d.validatePool(config, rules, d.commonVolumeRules())
	if err != nil {
		return err
	}

	newMode := config["netapp.mode"]
	oldMode := d.config["netapp.mode"]

	if oldMode != "" && oldMode != newMode {
		return errors.New("NetApp ONTAP mode cannot be changed")
	}

	if newMode != "" {
		connector, err := connectors.NewConnector(newMode, "")
		if err != nil {
			return fmt.Errorf("NetApp ONTAP mode %q is not supported: %w", newMode, err)
		}

		err = connector.LoadModules()
		if err != nil {
			return fmt.Errorf("NetApp ONTAP mode %q is not supported due to missing kernel modules: %w", newMode, err)
		}
	}

	return nil
}

// ValidateSource checks whether the required config keys are set to access the remote source.
func (d *netapp) ValidateSource() error {
	if d.config["netapp.gateway"] == "" {
		return errors.New("The netapp.gateway cannot be empty")
	}

	if d.config["netapp.user.name"] == "" {
		return errors.New("The netapp.user.name cannot be empty")
	}

	if d.config["netapp.user.password"] == "" {
		return errors.New("The netapp.user.password cannot be empty")
	}

	if d.config["netapp.aggregate"] == "" {
		return errors.New("The netapp.aggregate cannot be empty")
	}

	return nil
}

// Create is called during pool creation and is effectively using an empty driver struct.
// WARNING: The Create() function cannot rely on any of the struct attributes being set.
func (d *netapp) Create() error {
	if d.config["netapp.aggregate"] == "" {
		return errors.New("Aggregate name is required for pool creation")
	}

	// Validate the aggregate exists and has capacity.
	aggr, err := d.client().getAggregate(context.TODO(), d.config["netapp.aggregate"])
	if err != nil {
		return fmt.Errorf("Failed verifying target aggregate: %w", err)
	}

	// Record the discovered SVM in volatile so subsequent driver loads don't
	// need to re-query the aggregate just to learn the owning Vserver.
	d.config["volatile.svm.name"] = aggr.SVM.Name
	d.config["volatile.svm.uuid"] = aggr.SVM.UUID
	d.client().svmName = aggr.SVM.Name

	err = d.client().getNVMeService(context.TODO(), aggr.SVM.Name)
	if err != nil {
		return fmt.Errorf("Failed verifying NVMe service: %w", err)
	}

	return nil
}

// Update applies any driver changes required from a configuration change.
func (d *netapp) Update(changedConfig map[string]string) error {
	return nil
}

// Mount mounts the storage pool.
func (d *netapp) Mount() (bool, error) {
	return true, nil
}

// Unmount unmounts the storage pool.
func (d *netapp) Unmount() (bool, error) {
	return true, nil
}

// Delete removes the storage pool from the storage device.
func (d *netapp) Delete(progressReporter ioprogress.ProgressReporter) error {
	// Refuse to delete the pool if any LXD-named FlexVol still exists in the
	// aggregate. The remote side has no concept of "pool", so we must
	// guarantee callers have torn down their volumes first.
	flexVols, err := d.client().listFlexVols(context.TODO(), d.client().svmName, d.config["netapp.aggregate"])
	if err != nil {
		return fmt.Errorf("Failed listing remaining FlexVols: %w", err)
	}

	for _, fv := range flexVols {
		if isOntapLXDVolume(fv.Name) {
			return fmt.Errorf("Pool still contains volume %q", fv.Name)
		}
	}

	return wipeDirectory(GetPoolMountPath(d.name))
}

// isOntapLXDVolume reports whether the FlexVol name follows the driver's
// `<prefix>-<uuid>[-<suffix>]` scheme and is therefore owned by LXD.
func isOntapLXDVolume(name string) bool {
	if len(name) < 3 || name[1] != '-' {
		return false
	}

	switch name[0] {
	case 'c', 'v', 'i', 'u', 's':
		return true
	}

	return false
}

// isOntapUUIDHex returns true when s is exactly 32 lower-case hex digits, the
// shape produced by stripping the hyphens from a canonical UUID.
func isOntapUUIDHex(s string) bool {
	if len(s) != 32 {
		return false
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		isLower := c >= 'a' && c <= 'f'
		if !isDigit && !isLower {
			return false
		}
	}

	return true
}

// GetResources returns the pool resource usage information.
func (d *netapp) GetResources() (*api.ResourcesStoragePool, error) {
	aggr, err := d.client().getAggregate(context.TODO(), d.config["netapp.aggregate"])
	if err != nil {
		return nil, fmt.Errorf("Failed getting aggregate resources: %w", err)
	}

	res := &api.ResourcesStoragePool{}
	res.Space.Total = uint64(aggr.Space.BlockStorage.Size)
	res.Space.Used = uint64(aggr.Space.BlockStorage.Size - aggr.Space.BlockStorage.Available)

	return res, nil
}

// MigrationTypes returns the supported migration types and options supported by the driver.
func (d *netapp) MigrationTypes(contentType ContentType, refresh bool, copySnapshots bool) []migration.Type {
	var rsyncFeatures []string

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

		return []migration.Type{{FSType: transportType, Features: rsyncFeatures}}
	}

	if contentType == ContentTypeBlock {
		return []migration.Type{
			{FSType: migration.MigrationFSType_BLOCK_AND_RSYNC, Features: rsyncFeatures},
		}
	}

	return []migration.Type{
		{FSType: migration.MigrationFSType_RSYNC, Features: rsyncFeatures},
	}
}
