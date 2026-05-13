# LXD Storage Driver Architecture and Validation Guide

This document maps the actual storage architecture in LXD, defines concrete entry points, and compares storage driver behavior with emphasis on remote drivers:

- HPE Alletra (`alletra`)
- Pure Storage (`pure`)
- Dell PowerFlex (`powerflex`)
- Dell PowerStore (`powerstore`)

The intent is spec validation. It is organized so an LLM validator can check explicit claims against code-level behavior.

## 1. Architectural Layers

LXD storage is layered and intentionally split between orchestration and backend implementation.

1. API and daemon entry points:
- Pool APIs in `lxd/storage_pools.go`
- Volume APIs in `lxd/storage_volumes.go`
- Lifecycle startup/mounting in `lxd/storage.go`

2. High-level storage backend orchestration:
- `Pool` interface in `lxd/storage/pool_interface.go`
- Concrete backend implementation in `lxd/storage/backend_lxd.go`

3. Driver abstraction:
- Driver interface in `lxd/storage/drivers/interface.go`
- Driver loading/registration in `lxd/storage/drivers/load.go`

4. Driver implementations:
- Local and remote drivers in `lxd/storage/drivers/driver_*.go`

5. Transport/connectivity layer for remote block devices:
- Connectors in `lxd/storage/connectors/`

6. Vendor API clients:
- Alletra and PowerStore clients in `lxd/storage/drivers/clients/`
- Pure and PowerFlex clients are implemented in their driver utility files.

## 2. Primary Entry Points

### 2.1 Pool creation and lifecycle

- REST entry: `storagePoolsPost()` in `lxd/storage_pools.go`
- Validation and DB insertion: `storagePoolValidate()`, `storagePoolDBCreate()`, `storagePoolCreateGlobal()` in `lxd/storage_pools_utils.go`
- Local member materialization: `storagePoolCreateLocal()` in `lxd/storage_pools_utils.go`
- Backend loading: `storagePools.LoadByName()` in `lxd/storage/pool_load.go`
- Backend create path: `(*lxdBackend).Create()` in `lxd/storage/backend_lxd.go`

Key backend path:

1. Validate name and pool config.
2. Fill defaults with `Driver.FillConfig()`.
3. Validate source uniqueness with `SourceIdentifier()` and `ValidateSource()`.
4. For remote drivers and non-normal client type: only create LXD-side structure and return.
5. Otherwise call `Driver.Create()`, then `Driver.Mount()`, then finalize DB status.

### 2.2 Volume creation and copy

- REST entry: `storagePoolVolumesPost()` in `lxd/storage_volumes.go`
- Main operation routing: `doVolumeCreateOrCopy()`, `doCustomVolumeRefresh()`, `doVolumeMigration()` in `lxd/storage_volumes.go`
- Backend methods called:
  - `CreateCustomVolume()`
  - `CreateCustomVolumeFromCopy()`
  - `RefreshCustomVolume()`
  - `CreateCustomVolumeFromMigration()`
  in `lxd/storage/backend_lxd.go`

### 2.3 Instance/image entry points into storage

- Empty instance create: `instanceCreateAsEmpty()` -> `pool.CreateInstance()` in `lxd/instance.go`
- Instance from image: `instanceCreateFromImage()` -> `pool.CreateInstanceFromImage()` in `lxd/instance.go`
- Image materialization in pool: `imageCreateInPool()` -> `pool.EnsureImage()` in `lxd/images.go`

### 2.4 Device attach/runtime mount path

- Disk device path resolution and mount usage in `lxd/device/disk.go`:
  - `storagePools.LoadByName()`
  - `MountInstance()`, `MountInstanceSnapshot()`
  - `MountCustomVolume()`
  - `Driver().GetVolumeDiskPath()`

This path is operationally critical for VM/custom-block attach behavior.

### 2.5 Startup and daemon-managed volumes

- Pool startup mount/retry loop in `storageStartup()` in `lxd/storage.go`
- Pool unmount on daemon stop in `storageStop()` in `lxd/storage.go`
- LXD internal images/backups volumes mount logic in `lxd/daemon_storage.go`

## 3. Core Control Flow (Canonical Sequence)

For most operations, the concrete flow is:

1. API handler receives request (`lxd/storage_pools.go`, `lxd/storage_volumes.go`, `lxd/instances_*.go`, `lxd/images.go`).
2. Handler loads pool via `storagePools.LoadByName()` or `LoadByInstance()`.
3. `storage/pool_load.go` resolves DB records and loads driver via `drivers.Load()`.
4. `drivers.Load()` instantiates driver by name from registry and runs `driver.load()`.
5. Handler invokes a `Pool` method on `lxdBackend`.
6. `lxdBackend` performs DB + orchestration + revert semantics.
7. `lxdBackend` delegates backend-specific work to `drivers.Driver` methods.
8. Remote drivers use connector + vendor client to map/attach, operate, and unmap block volumes.

This split is the main architectural invariant: API and backend own orchestration and consistency; driver owns storage-specific mechanics.

## 4. Driver Interface Surface (Validation Anchor)

The low-level driver contract is in `lxd/storage/drivers/interface.go` and includes:

- Pool-level: `FillConfig`, `Validate`, `ValidateSource`, `SourceIdentifier`, `Create`, `Delete`, `Mount`, `Unmount`, `GetResources`, `Update`.
- Volume-level: `CreateVolume`, `CreateVolumeFromCopy`, `RefreshVolume`, `DeleteVolume`, `SetVolumeQuota`, `GetVolumeDiskPath`, snapshot operations, migration operations.
- Migration/backup: `MigrationTypes`, `MigrateVolume`, `CreateVolumeFromMigration`, `BackupVolume`, `CreateVolumeFromBackup`.

Spec implication: any storage driver claiming support must provide behavior consistent with this interface contract.

## 5. Remote Driver Common Pattern

Alletra, Pure, PowerFlex, and PowerStore share the same macro-pattern:

1. `isRemote() == true`.
2. `Info().Remote == true`, `BlockBacking == true`.
3. Per-driver `Validate` and `ValidateSource` gate required credentials/endpoint config.
4. Per-driver volume name encoding depends on UUID (`volatile.uuid`) and type/content metadata.
5. Mapping path:
   - Ensure host object exists remotely.
   - Attach/map volume to host.
   - Connect host to target via connector (iSCSI/NVMe/SDC).
   - Resolve local block device path.
6. Unmapping path:
   - Remove local disk device.
   - Detach volume from host.
   - Potentially disconnect session and cleanup host object.

This is visible in all four driver families through methods named like:

- `ensureHost`
- `mapVolume`
- `unmapVolume`
- `getMappedDevPath` or `getMappedDevicePath`

## 6. Driver-Specific Deep Comparison

### 6.1 Configuration and transport modes

1. Alletra:
- Modes: `nvme`, `iscsi`
- Default mode: `nvme`
- Source identity: `alletra.wsapi + alletra.cpg + poolName`
- Pool object is created remotely (`CreateVolumeSet`) in `Driver.Create()`.

2. Pure:
- Modes: `nvme`, `iscsi`
- Default mode: `nvme`
- Source identity: `pure.gateway + poolName`
- Pool object is created remotely in `Driver.Create()` with pool size support.

3. PowerFlex:
- Modes: `nvme`, `sdc`
- Default mode: auto-discovered (NVMe first, then SDC)
- Source identity: `powerflex.gateway + protectionDomain + pool`
- `Driver.Create()` is no-op (pool pre-exists externally).

4. PowerStore:
- Mode: `iscsi` only in current implementation
- Source identity: `powerstore.gateway + poolName`
- `Driver.Create()` is no-op (pool abstraction is LXD-side scope over remote resources).

### 6.2 Volume naming strategy

1. Alletra:
- Uses UUID-derived name with type prefix/suffix and snapshot prefix.
- UUID is normalized by removing hyphens.

2. Pure:
- Uses encoded names and reports `UUIDVolumeNames=true`.
- Driver expects UUID-driven naming and parses remote names back into LXD volume metadata.

3. PowerFlex:
- Uses UUID-based translated naming with type-specific prefixes and suffixes.
- Also `UUIDVolumeNames=true`.

4. PowerStore:
- Uses deterministic scoped prefix (`storagePoolScopePrefix`) plus encoded `<type>_<uuid>[.<suffix>]` format.
- Uses a dedicated mountable snapshot clone prefix (`s`) to disambiguate temporary clone artifacts.

### 6.3 Snapshot and copy semantics

1. Alletra:
- Explicitly handles platform limitation: snapshots are copied sequentially, not as one atomic copy-with-snapshots operation.
- Uses destination-volume staging when copying snapshots.

2. Pure:
- Same high-level limitation: no single operation for volume+snapshots copy.
- Implements sequential snapshot copy and refresh logic with temporary reverter snapshot behavior.

3. PowerStore:
- Same limitation and same workaround class (sequential refresh/copy of snapshots).
- Adds mountable snapshot via temporary clone volume that is mounted instead of mounting snapshot directly.

4. PowerFlex:
- Supports `powerflex.snapshot_copy` policy.
- If enabled and no snapshots requested, can use sparse snapshot-style copy path.
- Otherwise often falls back to generic VFS copy/migration helpers.

### 6.4 Resize behavior

1. Alletra:
- Block/image resize safety behavior mirrors other remote block drivers and uses explicit quota/set-volume logic.
- Notes include no shrink support in copy path commentary.

2. Pure:
- Supports grow and shrink for filesystem volumes where filesystem permits shrinking.
- Block volumes cannot be shrunk in normal mode.

3. PowerStore:
- 1 MiB rounding and explicit min/max bounds.
- Uses remote resize plus local device size wait before filesystem actions.

4. PowerFlex:
- 8 GiB allocation granularity (minimum and rounding unit).
- Capacity can only be increased.

### 6.5 Resource reporting

1. Alletra: CPG space report (`GetCPGSpaceReport`).
2. Pure: pool quota/usage with unbounded-pool total computed from arrays.
3. PowerFlex: storage pool statistics from gateway.
4. PowerStore: currently returns empty/default pool resource struct.

## 7. Connectors and Their Architectural Role

Connectors in `lxd/storage/connectors/` abstract host-side transport operations.

Supported connector types:

- `iscsi`
- `nvme`
- `sdc`

Important properties:

1. iSCSI connector:
- Uses `iscsiadm`.
- Maintains/discovers sessions from sysfs.

2. NVMe connector:
- Uses `nvme` CLI.
- Handles discovery log parsing and subsystem/session mapping.

3. SDC connector (PowerFlex-specific):
- No connect/disconnect action in LXD (handled by Dell SDC stack).
- Primarily validates module presence and device path behavior.

Spec implication: remote-driver logic must be validated together with connector mode constraints, not in isolation.

## 8. Validation Matrix for Third-Party Remote Drivers

Use this checklist as a deterministic spec validation matrix.

1. Driver registration:
- Driver appears in `drivers` map in `lxd/storage/drivers/load.go`.

2. Interface compliance:
- Driver implements all methods required by `drivers.Driver`.

3. Remote marker correctness:
- `isRemote() == true`
- `Info().Remote == true`

4. Source identity and validation:
- `ValidateSource()` rejects empty mandatory endpoint/credential keys.
- `SourceIdentifier()` is non-empty and stable for uniqueness checks.

5. Mode validation:
- `Validate()` enforces allowed modes and blocks mode mutation after pool creation.

6. Host mapping workflow:
- Driver has host ensure/map/unmap/get-device-path sequence.

7. Snapshot strategy:
- Copy/refresh path defines explicit behavior when backend cannot atomically copy volume+snapshots.

8. VM dual-volume behavior:
- Driver handles VM block + VM filesystem companion volume in create/copy/snapshot/restore paths.

9. Quota and resize safety:
- Resize logic includes in-use checks, image constraints, and filesystem/device sequencing.

10. Unknown volume discovery and UUID naming:
- `ListVolumes()` and UUID naming semantics align with `Info().UUIDVolumeNames` and backend recovery logic.

## 9. Commonalities vs Differences (Concise Summary)

Common points:

1. All remote drivers are block-backed and integrate through the same `Driver` interface.
2. All use backend orchestration in `lxdBackend` for lifecycle/revert/DB integration.
3. All use connector-driven host-side block mapping before filesystem-level operations.
4. All are integrated into the same migration and backup abstractions.

Differences that matter for spec validation:

1. Transport mode model differs:
- Alletra and Pure: NVMe/iSCSI.
- PowerFlex: NVMe/SDC.
- PowerStore: iSCSI only.

2. Pool creation ownership differs:
- Alletra/Pure create a remote pool construct.
- PowerFlex/PowerStore rely more on existing backend structures (create no-op at pool level).

3. Snapshot attach model differs:
- PowerStore uses temporary clone volumes for snapshot mount.
- Others generally map direct snapshot/block representations.

4. Capacity semantics differ:
- PowerFlex strict 8 GiB granularity and grow-only.
- PowerStore 1 MiB granularity with explicit bounds.
- Pure allows richer filesystem-aware resize behavior.

## 10. Suggested Spec Assertions (LLM-Friendly)

If your validator is an LLM, these assertions are robust and low-ambiguity:

1. "All storage pool API create paths eventually call `storagePools.LoadByName()` and then backend `Create()` for local realization."
2. "The backend-driver boundary is `Pool` (high-level) to `drivers.Driver` (low-level) and this boundary is stable across all drivers."
3. "Remote third-party drivers implement host mapping via connector abstractions, not by embedding transport shell code directly in API handlers."
4. "Alletra, Pure, and PowerStore explicitly implement sequential snapshot copy logic due to backend limitations around copy-with-snapshots."
5. "PowerFlex is the only compared driver supporting SDC mode and auto mode discovery between NVMe and SDC."
6. "PowerStore implements mountable snapshot access by creating and deleting temporary clone volumes."

## 11. File Landmarks

Use these files as the primary code anchors:

- `lxd/storage/pool_interface.go`
- `lxd/storage/pool_load.go`
- `lxd/storage/backend_lxd.go`
- `lxd/storage/drivers/interface.go`
- `lxd/storage/drivers/load.go`
- `lxd/storage/drivers/driver_alletra.go`
- `lxd/storage/drivers/driver_alletra_volumes.go`
- `lxd/storage/drivers/driver_pure.go`
- `lxd/storage/drivers/driver_pure_volumes.go`
- `lxd/storage/drivers/driver_pure_util.go`
- `lxd/storage/drivers/driver_powerflex.go`
- `lxd/storage/drivers/driver_powerflex_volumes.go`
- `lxd/storage/drivers/driver_powerflex_utils.go`
- `lxd/storage/drivers/driver_powerstore.go`
- `lxd/storage/drivers/driver_powerstore_volumes.go`
- `lxd/storage/connectors/connector.go`
- `lxd/storage/connectors/connector_iscsi.go`
- `lxd/storage/connectors/connector_nvme.go`
- `lxd/storage/connectors/connector_sdc.go`
- `lxd/storage/drivers/clients/alletra_wsapi1.go`
- `lxd/storage/drivers/clients/powerstore.go`
- `lxd/storage_pools.go`
- `lxd/storage_pools_utils.go`
- `lxd/storage_volumes.go`
- `lxd/instance.go`
- `lxd/images.go`
- `lxd/device/disk.go`
- `lxd/storage.go`
- `lxd/daemon_storage.go`
